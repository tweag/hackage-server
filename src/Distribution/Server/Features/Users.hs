{-# LANGUAGE RankNTypes, NamedFieldPuns, RecordWildCards, RecursiveDo, BangPatterns, OverloadedStrings, TemplateHaskell, FlexibleContexts #-}
{-# LANGUAGE ScopedTypeVariables                                                                                                          #-}
{-# LANGUAGE TypeApplications                                                                                                             #-}

{-# OPTIONS_GHC -fno-warn-orphans #-}
module Distribution.Server.Features.Users (
    initUserFeature,
    UserFeature(..),
    UserResource(..),

    GroupResource(..),
  ) where

import Data.Functor.Identity (Identity(..))
import Data.Bool (bool)
import Distribution.Server.Features.UserDetails.Types (AccountKind(..))
import Distribution.Server.Users.AuthToken (parseAuthToken, viewOriginalToken, convertToken, generateOriginalToken)
import Distribution.Server.Framework
import Distribution.Server.Framework.Templating
import qualified Distribution.Server.Framework.Auth as Auth

import Distribution.Server.Users.Types (UserId(..), UserName(..), PasswdPlain(..), ErrUserNameClash(..), ErrNoSuchUserId(..), ErrDeletedUser(..), UserAuth(..), PasswdHash(..))

import Distribution.Server.Database.Schemas.Users

import qualified Distribution.Server.Users.Group as Group
import Distribution.Server.Users.Group
         (UserGroup(..), GroupDescription(..), UserIdSet, nullDescription)

import Data.IntMap (IntMap)
import qualified Data.IntMap as IntMap
import Data.Map (Map)
import qualified Data.Map as Map
import Data.Set (Set)
import qualified Data.Set as Set
import Data.Maybe (fromMaybe, listToMaybe)
import Data.Function (fix)
import Control.Applicative (optional)
import Data.Aeson (toJSON)
import Data.Aeson.TH
import qualified Data.Text as T
import Data.Time (getCurrentTime)

import Distribution.Text (display, simpleParse)

import Happstack.Server.Cookie (addCookie, mkCookie, CookieLife(Session))
import Distribution.Server.Framework.DB
import Hasql.Session (SessionError(QueryError))

-- | A feature to allow manipulation of the database of users.
--
-- TODO: clean up mismatched and duplicate functionality (some noted below).
data UserFeature = UserFeature {
    -- | The users `HackageFeature`.
    userFeatureInterface :: HackageFeature,

    -- | User resources.
    userResource :: UserResource,

    -- | Notification that a user has been added. Currently unused.
    userAdded :: Hook () (), --TODO: delete, other status changes?
    -- | The admin user group, including its description, members, and
    -- modification thereof.
    adminGroup :: UserGroup,

    groupChangedHook :: Hook (GroupDescription, Bool, UserId, UserId, String) (),

    -- Authorisation
    -- | Require any of a set of groups, with a friendly error message
    guardAuthorisedWhenInAnyGroup :: [Group.UserGroup] -> ServerPartE User,
    -- | Require any of a set of privileges.
    guardAuthorised_   :: [PrivilegeCondition] -> ServerPartE (),
    -- | Require any of a set of privileges, giving the id of the current user.
    guardAuthorised    :: [PrivilegeCondition] -> ServerPartE User,
    guardAuthorised'    :: [PrivilegeCondition] -> ServerPartE Bool,
    -- | Require being logged in, giving the id of the current user.
    guardAuthenticated :: ServerPartE User,
    -- Gets the authentication if it exists.
    checkAuthenticated :: ServerPartE (Maybe User),
    -- | A hook to override the default authentication error in particular
    -- circumstances.
    authFailHook       :: Hook Auth.AuthError (Maybe ErrorResponse),
    -- | Lookup users by Id
    queryLookupUser    :: forall m t. (MonadIO m, Traversable t) => t UserId -> m (t User),

    -- | Creates a Hackage 2 user credential.
    newUserAuth       :: UserName -> PasswdPlain -> UserAuth,
    -- Adds a user with a fresh name.
    updateAddUser     :: forall m. MonadIO m => UserName -> UserAuth -> m (Either ErrUserNameClash UserId),
    -- Sets the account-enabled status of an existing user to True or False.
    updateSetUserEnabledStatus :: forall m. MonadIO m => UserId -> Bool
                               -> m (Maybe (Either ErrNoSuchUserId ErrDeletedUser)),
    -- Sets the credentials of an existing user.
    updateSetUserAuth :: forall m. MonadIO m => UserId -> UserAuth
                      -> m (Maybe (Either ErrNoSuchUserId ErrDeletedUser)),

    -- Adds a user to a group based on a "user" path component.
    --
    -- Use the UserGroup or GroupResource directly instead, as this is a hack.
    groupAddUser        :: UserGroup -> DynamicPath -> ServerPartE (),
    -- | Likewise, deletes a user, will go away soon.
    groupDeleteUser     :: UserGroup -> DynamicPath -> ServerPartE (),

    -- Get a username from a path.
    userNameInPath      :: forall m. MonadPlus m => DynamicPath -> m UserName,
    -- Lookup a `UserId` from a name, if the name exists.
    lookupUserName      :: UserName -> ServerPartE UserId,
    -- Lookup full `(UsersRow Result)` from a name, if the name exists.
    -- lookupUserNameFull  :: UserName -> ServerPartE (UserId, (UsersRow Result)),
    -- Lookup full `(UsersRow Result)` from an id, if the id exists.
    -- lookupUserInfo      :: UserId -> ServerPartE (UsersRow Result),

    -- | An action to change a password directly, using "password" and
    -- "repeat-password" form fields. Only admins and the user themselves
    -- can do this. This is messy, as it was one of the first things writen
    -- for the users feature.
    --
    -- TODO: update and make more usable.
    changePassword      :: UserName -> ServerPartE (),
    -- | Determine if the first user can change the second user's password,
    -- replicating auth functionality. Avoid using.
    canChangePassword   :: forall m. MonadIO m => UserId -> UserId -> m Bool,
    -- | Action to create a new user with the given credentials. This takes the
    -- desired name, a password, and a repeated password, validating all.
    newUserWithAuth     :: String -> PasswdPlain -> PasswdPlain -> ServerPartE UserName,
    -- | Action for an admin to create a user with "username", "password", and
    -- "repeat-password" username fields.
    adminAddUser        :: ServerPartE Response,

    -- Create a group resource for the given resource path.
    groupResourceAt     :: String -> UserGroup -> IO (UserGroup, GroupResource),
    -- | Create a parameretrized group resource for the given resource path.
    -- The parameter `a` can here be called a group key, and there is
    -- potentially a set of initial values.
    --
    -- This takes functions to create a user group on the fly for the given
    -- key, go from a key to a DynamicPath (for URI generation), as well as
    -- go from a DynamicPath to a key with some possibility of failure. This
    -- should check key membership, as well.
    --
    -- When these parameretrized `UserGroup`s need to be modified, the returned
    -- `a -> UserGroup` function should be used, as it wraps the given
    -- `a -> UserGroup` function to keep user-to-group mappings up-to-date.
    groupResourcesAt    :: forall a. String -> (a -> UserGroup)
                                            -> (a -> DynamicPath)
                                            -> (DynamicPath -> ServerPartE a)
                                            -> [a]
                                            -> IO (a -> UserGroup, GroupResource),
    -- | Look up whether the current user has (add, remove) capabilities for
    -- the given group, erroring out if neither are present.
    lookupGroupEditAuth :: UserGroup -> ServerPartE (Bool, Bool),
    -- | For a given user, return all of the URIs for groups they are in.
    getGroupIndex       :: forall m. (Functor m, MonadIO m) => UserId -> m [String],
    -- | For a given URI, get a GroupDescription for it, if one can be found.
    getIndexDesc        :: forall m. MonadIO m => String -> m GroupDescription,
    userFeatureServerEnv :: ServerEnv
}

instance IsHackageFeature UserFeature where
  getFeatureInterface = userFeatureInterface

data UserResource = UserResource {
    -- | The list of all users.
    userList :: Resource,
    -- | The main page for a given user.
    userPage :: Resource,
    -- | A user's password.
    passwordResource :: Resource,
    -- | A user's package tracking pixels.
    analyticsPixelsResource :: Resource,
    -- | A user's enabled status.
    enabledResource  :: Resource,
    -- | The admin group.
    adminResource :: GroupResource,
    -- | Manage a user
    manageUserResource :: Resource,
    -- | Redirect users to their management page
    redirectUserResource :: Resource,

    -- | URI for `userList` given a format.
    userListUri :: String -> String,
    -- | URI for `userPage` given a format and name.
    userPageUri :: String -> UserName -> String,
    -- | URI for `passwordResource` given a format and name.
    userPasswordUri :: String -> UserName -> String,
    -- | URI for `enabledResource` given a format and name.
    userEnabledUri  :: String -> UserName -> String,
    -- | URI for `adminResource` given a format.
    adminPageUri :: String -> String,
    -- | URI for `manageUserResource` give a format and name
    manageUserUri :: String -> UserName -> String
}

instance FromReqURI UserName where
  fromReqURI = simpleParse

data GroupResource = GroupResource {
    -- | A group, potentially parametetrized over some collection.
    groupResource :: Resource,
    -- | A user's presence in a group.
    groupUserResource :: Resource,
    -- | A `UserGroup` for a group, with a `DynamicPath` for any parameterization.
    getGroup :: DynamicPath -> ServerPartE UserGroup
}

-- This is a mapping of UserId -> group URI and group URI -> description.
-- Like many reverse mappings, it is probably rather volatile. Still, it is
-- a secondary concern, as user groups should be defined by each feature
-- and not globally, to be perfectly modular.
data GroupIndex = GroupIndex {
    usersToGroupUri :: !(IntMap (Set String)),
    groupUrisToDesc :: !(Map String GroupDescription)
}
emptyGroupIndex :: GroupIndex
emptyGroupIndex = GroupIndex IntMap.empty Map.empty

instance MemSize GroupIndex where
    memSize (GroupIndex a b) = memSize2 a b

--  Some types for JSON resources

data UserNameIdResource = UserNameIdResource { ui_username    :: UserName,
                                               ui_userid      :: UserId }
data UserInfoResource   = UserInfoResource   { ui1_username    :: UserName,
                                               ui1_userid      :: UserId,
                                               ui1_groups      :: [T.Text] }
data EnabledResource    = EnabledResource    { ui_enabled     :: Bool }
data UserGroupResource  = UserGroupResource  { ui_title       :: T.Text,
                                               ui_description :: T.Text,
                                               ui_members     :: [UserNameIdResource] }

deriveJSON (compatAesonOptionsDropPrefix "ui_")  ''UserNameIdResource
deriveJSON (compatAesonOptionsDropPrefix "ui1_") ''UserInfoResource
deriveJSON (compatAesonOptionsDropPrefix "ui_")  ''EnabledResource
deriveJSON (compatAesonOptionsDropPrefix "ui_")  ''UserGroupResource

-- TODO: add renaming
initUserFeature :: ServerEnv -> IO (IO UserFeature)
initUserFeature serverEnv@ServerEnv{serverTemplatesDir, serverTemplatesMode} = do
  -- Ephemeral state
  groupIndex   <- newMemStateWHNF emptyGroupIndex

  -- Extension hooks
  userAdded     <- newHook
  authFailHook  <- newHook
  groupChangedHook <- newHook

  -- Load templates
  templates <-
      loadTemplates serverTemplatesMode
      [serverTemplatesDir, serverTemplatesDir </> "Users"]
      [ "manage.html", "token-created.html", "token-revoked.html"
      ]

  return $ do
    -- Slightly tricky: we have an almost recursive knot between the group
    -- resource management functions, and creating the admin group
    -- resource that is part of the user feature.
    --
    -- Instead of trying to pull it apart, we just use a 'do rec'
    --
    rec let (feature@UserFeature{groupResourceAt}, adminGroupDesc)
              = userFeature templates
                            groupIndex
                            userAdded authFailHook groupChangedHook
                            adminG adminR
                            serverEnv

        (adminG, adminR) <- groupResourceAt "/users/admins/" adminGroupDesc

    return feature

userFeature :: Templates
            -> MemState GroupIndex
            -> Hook () ()
            -> Hook Auth.AuthError (Maybe ErrorResponse)
            -> Hook (GroupDescription, Bool, UserId, UserId, String) ()
            -> UserGroup
            -> GroupResource
            -> ServerEnv
            -> (UserFeature, UserGroup)
userFeature templates
             groupIndex userAdded authFailHook groupChangedHook
             adminGroup adminResource userFeatureServerEnv@ServerEnv {serverConnection}
  = (UserFeature {..}, adminGroupDesc)
  where
    userFeatureInterface = (emptyHackageFeature "users") {
        featureDesc = "Manipulate the user database."
      , featureResources =
          map ($ userResource)
            [ userList
            , userPage
            , passwordResource
            , enabledResource
            , manageUserResource
            , redirectUserResource
            ]
          ++ [
              groupResource adminResource
            , groupUserResource adminResource
            ]
      , featureState = [ ]
      , featureCaches = [
            CacheComponent {
              cacheDesc       = "user group index",
              getCacheMemSize = memSize <$> readMemState groupIndex
            }
          ]
      }

    userResource = fix $ \r -> UserResource {
        userList = (resourceAt "/users/.:format") {
            resourceDesc   = [ (GET, "list of users") ]
          , resourceGet    = [ ("json", serveUsersGet) ]
          }
      , userPage = (resourceAt "/user/:username.:format") {
            resourceDesc   = [ (GET,    "user id info")
                             , (PUT,    "create user")
                             , (DELETE, "delete user")
                             ]
          , resourceGet    = [ ("json", serveUserGet) ]
          , resourcePut    = [ ("", serveUserPut) ]
          , resourceDelete = [ ("", serveUserDelete) ]
          }
      , manageUserResource =
              (resourceAt "/user/:username/manage.:format")
              { resourceDesc =
                      [ (GET, "user management page")
                      ]
              , resourceGet  = [ ("", serveUserManagementGet) ]
              , resourcePost = [ ("", serveUserManagementPost) ]
              }
      , redirectUserResource =
              (resourceAt "/users/account-management.:format")
              { resourceDesc =
                      [ (GET, "user's personal account management page")
                      ]
              , resourceGet  = [ ("", const (redirectUserManagement r)) ]
              }
      , passwordResource = resourceAt "/user/:username/password.:format"
      , analyticsPixelsResource = resourceAt "/user/:username/analytics-pixels.:format"
                           --TODO: PUT
      , enabledResource  = (resourceAt "/user/:username/enabled.:format") {
            resourceDesc = [ (GET, "return if the user is enabled")
                           , (PUT, "set if the user is enabled")
                           ]
          , resourceGet  = [("json", serveUserEnabledGet)]
          , resourcePut  = [("json", serveUserEnabledPut)]
          }

      , adminResource = adminResource

      , userListUri = \format ->
          renderResource (userList r) [format]
      , userPageUri = \format uname ->
          renderResource (userPage r) [display uname, format]
      , userPasswordUri = \format uname ->
          renderResource (passwordResource r) [display uname, format]
      , userEnabledUri  = \format uname ->
          renderResource (enabledResource  r) [display uname, format]
      , adminPageUri = \format ->
          renderResource (groupResource adminResource) [format]
      , manageUserUri = \format uname ->
          renderResource (manageUserResource r) [display uname, format]
      }

    -- Queries and updates
    --

    queryLookupUser :: (MonadIO m, Traversable t) => t UserId -> m (t User)
    queryLookupUser = unsafePartsOf $ \case
      [] ->
        -- Avoid a database query if we can help it!
        pure []
      uids -> do
        mres <- liftIO $ doSelect serverConnection $ do
          user <- each usersSchema
          where_ $ userId user `in_` fmap lit uids
          pure user
        case mres of
          Left err -> error $ show err
          Right res -> pure res



    updateAddUser :: MonadIO m => UserName -> UserAuth -> m (Either ErrUserNameClash UserId)
    updateAddUser uname (UserAuth auth) =
      liftIO (registerUser serverConnection uname auth True) >>= \case
        Left _err ->
          -- TODO(sandy): Here we assume that if the insert failed, it's due to
          -- a constraint violation (rather than a more serious DB failure.)
          pure $ Left ErrUserNameClash
        Right uid -> pure $ Right uid

    updateSetUserEnabledStatus :: MonadIO m => UserId -> Bool
                               -> m (Maybe (Either ErrNoSuchUserId ErrDeletedUser))
    updateSetUserEnabledStatus uid isenabled = do
      res <- liftIO $ doUpdate1 serverConnection $ Update
        { target = usersSchema
        , from = pure ()
        , set = \_ user -> user { userStatus = lit $ bool Disabled Enabled isenabled }
        , updateWhere = \_ user -> userId user ==. lit uid &&. userStatus user /=. lit Deleted
        , returning =
            Returning userStatus
        }
      pure $ case res of
        Left _err -> Just $ Left ErrNoSuchUserId
        Right Deleted -> Just $ Right ErrDeletedUser
        Right _ -> Nothing

    updateSetUserAuth :: MonadIO m => UserId -> UserAuth
                      -> m (Maybe (Either ErrNoSuchUserId ErrDeletedUser))
    updateSetUserAuth uid (UserAuth auth) = do
      res <- liftIO $ doUpdate1 serverConnection $ Update
        { target = usersSchema
        , from = pure ()
        , set = \_ user -> user { userAuth = lit auth }
        , updateWhere = \_ user -> userId user ==. lit uid
        , returning =
            Returning userStatus
        }
      pure $ case res of
        Left _err -> Just $ Left ErrNoSuchUserId
        Right Deleted -> Just $ Right ErrDeletedUser
        Right _ -> Nothing

    --
    -- Authorisation: authentication checks and privilege checks
    --

    guardAuthorisedWhenInAnyGroup :: [Group.UserGroup] -> ServerPartE User
    guardAuthorisedWhenInAnyGroup [] =
        fail "Group list is empty, this is not meant to happen"
    guardAuthorisedWhenInAnyGroup groups = do
        user   <- guardAuthenticatedWithErrHook
        Auth.guardInAnyGroup (userId user) groups
        return user

    -- High level, all in one check that the client is authenticated as a
    -- particular user and has an appropriate privilege, but then ignore the
    -- identity of the user.
    guardAuthorised_ :: [PrivilegeCondition] -> ServerPartE ()
    guardAuthorised_ = void . guardAuthorised

    -- As above but also return the identity of the client
    guardAuthorised :: [PrivilegeCondition] -> ServerPartE User
    guardAuthorised privconds = do
        user   <- guardAuthenticatedWithErrHook
        Auth.guardPriviledged (userId user) privconds
        return user

    guardAuthorised' :: [PrivilegeCondition] -> ServerPartE Bool
    guardAuthorised' privconds = do
        user   <- guardAuthenticatedWithErrHook
        valid <- Auth.checkPriviledged (userId user) privconds
        return valid

    -- Simply check if the user is authenticated as some user, without any
    -- check that they have any particular privileges. Only useful as a
    -- building block.
    guardAuthenticated :: ServerPartE User
    guardAuthenticated = do
        guardAuthenticatedWithErrHook

    -- [Note about authentication & `authn` hint cookie]
    --
    -- HTTP clients usually don't perform http authentication eagerly
    -- (especially w/ digest auth). However, 'checkAuthenticated'
    -- needs to a way to detect whether the browser has cached
    -- credentials, and validate them if available.
    --
    -- In order to workaround this HTTP property, we keep a
    -- client-side boolean state /hint/ in the transient `authn`
    -- session cookie, which is supposed to have more or less the same
    -- lifetime as the browser's cached http authentication:
    --
    --  - authn="1"  when the user session is /assumed/ to be authenticated
    --               (i.e. the browser will supply credentials when asked)
    --  - authn="0"  when the user session is /assumed/ to be anonymous
    --
    -- Any other state (and when the `authn` cookie isn't present) is
    -- handled like the authn="0" case
    --
    -- The authn="0" state is the default state.
    --
    -- The authn="1" state will be entered automatically whenever HTTP
    -- authentication succeeds; whenever an authentication error
    -- occurs, the authn="0" state is set.
    --
    -- IMPORTANT: We use the client-side `authn` cookie only as a hint;
    --            it cannot be used to bypass authentication
    --            validation.  If the `authn` cookie gets out of sync it
    --            will be re-synced on the next authentication
    --            attempt.

    -- As above but using the given userdb snapshot
    -- See note about "authn" cookie above
    guardAuthenticatedWithErrHook :: ServerPartE User
    guardAuthenticatedWithErrHook = do
        uid <- Auth.checkAuthenticated realm userFeatureServerEnv
                   >>= either handleAuthError return
        addCookie Session (mkCookie "authn" "1")
        -- Set-Cookie:authn="1";Path=/;Version="1"
        fmap runIdentity $ queryLookupUser $ Identity uid
      where
        realm = Auth.hackageRealm --TODO: should be configurable

        handleAuthError :: Auth.AuthError -> ServerPartE a
        handleAuthError Auth.BadHost { actualHost, oughtToBeHost } =
          errForbidden "Bad Host" [MText $ "Authenticated resources can only be accessed using the regular server host name " <> oughtToBeHost <> ", but was provided host " <> show actualHost]
        handleAuthError err = do
          defaultResponse  <- Auth.authErrorResponse realm err
          overrideResponse <- msum <$> runHook authFailHook err
          let resp' = fromMaybe defaultResponse overrideResponse
              -- reset authn to "0" on auth failures
              resp'' = case resp' of
                r@ErrorResponse{} -> r { errorHeaders = ("Set-Cookie","authn=\"0\";Path=/;Version=\"1\""):errorHeaders r }
                GenericErrorResponse -> GenericErrorResponse
          throwError resp''

    -- Check if there is an authenticated userid, and return info, if so.
    -- See note about "authn" cookie above
    checkAuthenticated :: ServerPartE (Maybe User)
    checkAuthenticated = do
        authn <- optional (lookCookieValue "authn")
        case authn of
          Just "1" -> void guardAuthenticated
          _        -> pure ()
        eAuth <- Auth.checkAuthenticated Auth.hackageRealm userFeatureServerEnv
        case eAuth of
          Left _ -> pure Nothing
          Right uid -> queryLookupUser $ Just uid

    -- | Resources representing the collection of known users.
    --
    -- Features:
    --
    -- * listing the collection of users
    -- * adding and deleting users
    -- * enabling and disabling accounts
    -- * changing user's name and password
    --

    serveUsersGet :: DynamicPath -> ServerPartE Response
    serveUsersGet _ = do
      userlist <- doSelectE serverConnection $ do
        user <- activeUsers
        pure (userId user, userName user)
      let users = [ UserNameIdResource {
                      ui_username = uname,
                      ui_userid   = uid
                    }
                  | (uid, uname) <- userlist ]
      return . toResponse $ toJSON users

    serveUserGet :: DynamicPath -> ServerPartE Response
    serveUserGet dpath = do
      (uid, uinfo)  <- lookupUserNameFull =<< userNameInPath dpath
      groups        <- getGroupIndex uid
      return . toResponse $
        toJSON UserInfoResource {
                 ui1_username = userName uinfo,
                 ui1_userid   = uid,
                 ui1_groups   = map T.pack groups
               }

    serveUserPut :: DynamicPath -> ServerPartE Response
    serveUserPut dpath = do
      guardAuthorised_ [InGroup adminGroup]
      username <- userNameInPath dpath
      -- TODO(sandy): Is it OK to use a blank hash here? It should be
      -- impossible to hash to empty, and the account is not yet enabled. Maybe
      -- the password column should be nullable?
      uid     <- registerUserE serverConnection username (PasswdHash "") False
      return . toResponse $
          toJSON UserNameIdResource {
                   ui_username = username,
                   ui_userid   = uid
                 }

    serveUserDelete :: DynamicPath -> ServerPartE Response
    serveUserDelete dpath = do
      guardAuthorised_ [InGroup adminGroup]
      uid  <- lookupUserName =<< userNameInPath dpath
      merr <- doDeleteE serverConnection $ Delete
        { from = usersSchema
        , using = pure ()
        , deleteWhere = \_ user -> userId user ==. lit uid
        , returning = Returning userId
        }
      case merr of
        [_] -> noContent $ toResponse ()
        --TODO: need to be able to delete user by name to fix this race condition
        [] -> errInternalError [MText "uid does not exist"]
        _ -> errInternalError [MText "too many uids deleted! should be very impossible"]

    serveUserEnabledGet :: DynamicPath -> ServerPartE Response
    serveUserEnabledGet dpath = do
      guardAuthorised_ [InGroup adminGroup]
      (_uid, uinfo) <- lookupUserNameFull =<< userNameInPath dpath
      let enabled = userStatus uinfo == Enabled
      return . toResponse $ toJSON EnabledResource { ui_enabled = enabled }

    serveUserEnabledPut :: DynamicPath -> ServerPartE Response
    serveUserEnabledPut dpath = do
      guardAuthorised_ [InGroup adminGroup]
      uid  <- lookupUserName =<< userNameInPath dpath
      EnabledResource enabled <- expectAesonContent
      res <- updateSetUserEnabledStatus uid enabled
      case res of
        Nothing -> noContent $ toResponse ()
        Just (Left ErrNoSuchUserId) -> errInternalError [MText "uid does not exist"]
        Just (Right ErrDeletedUser) ->
          errBadRequest "User deleted"
            [MText "Cannot disable account, it has already been deleted"]

    redirectUserManagement :: UserResource -> ServerPartE Response
    redirectUserManagement r = do
      user <- guardAuthenticated
      let uid = userId user
      uinfo <- lookupUserInfo uid
      tempRedirect (manageUserUri r "" (userName uinfo)) (toResponse ())

    serveUserManagementGet :: DynamicPath -> ServerPartE Response
    serveUserManagementGet dpath = do
      (uid, uinfo)  <- lookupUserNameFull =<< userNameInPath dpath
      guardAuthorised_ [IsUserId uid, InGroup adminGroup]
      template <- getTemplate templates "manage.html"
      cacheControlWithoutETag [Private]
      tokens <- doSelectE serverConnection $ do
        token <- each userAuthTokensSchema
        where_ $ authTokenUserId token ==. lit uid
        pure (authTokenToken token, authTokenDescription token)
      ok $ toResponse $
        template
          [ "username" $= display (userName uinfo)
          , "tokens"   $=
              [ templateDict
                  [ templateVal "hash" (display authtok)
                  , templateVal "description" $ fromMaybe "" desc
                  ]
              | (authtok, desc) <- tokens ]
          ]

    serveUserManagementPost :: DynamicPath -> ServerPartE Response
    serveUserManagementPost dpath = do
      (uid, uinfo)  <- lookupUserNameFull =<< userNameInPath dpath
      guardAuthorised_ [IsUserId uid, InGroup adminGroup]
      cacheControlWithoutETag [Private]
      action <- look "action"
      case action of
        "new-auth-token" -> do
          desc <- T.pack <$> look "description"
          template <- getTemplate templates "token-created.html"
          origTok  <- liftIO generateOriginalToken
          let storeTok = convertToken origTok
          now <- liftIO getCurrentTime
          mres <- liftIO $ doInsert_ serverConnection $ Insert
            { into = userAuthTokensSchema
            , rows = values $ pure @[] $ lit $ UserAuthTokenRow
                { authTokenUserId = uid
                , authTokenToken = storeTok
                , authTokenDescription = Just desc
                , authTokenCreatedTime = now
                }
            , onConflict = Abort
            , returning = NoReturning
            }
          case mres of
            Right () ->
              ok $ toResponse $
                template
                  [ "username" $= display (userName uinfo)
                  , "token"    $= viewOriginalToken origTok
                  ]
            Left QueryError{} ->
              -- NOTE: here we assume that if the query failed, it's due
              -- to an abort caused by a foreign key violation; which must
              -- occur due to the uid not existing.
              errInternalError [MText "uid does not exist"]
            Left _ ->
              throwError internalServerErrorResponse

        "revoke-auth-token" -> do
          mauthToken <- parseAuthToken . T.pack <$> look "auth-token"
          template <- getTemplate templates "token-revoked.html"
          case mauthToken of
            Left err -> errBadRequest "Bad auth token"
                          [MText "The auth token provided is malformed: "
                          ,MText err]
            Right authToken -> do
              res <-
                doDeleteE serverConnection $ Delete
                  { from = userAuthTokensSchema
                  , using = pure ()
                  , deleteWhere = \_ token ->
                      authTokenUserId token ==. lit uid &&. authTokenToken token ==. lit authToken
                  , returning = Returning authTokenToken
                  }
              case res of
                [] ->
                  errBadRequest "Invalid auth token"
                    [MText "Cannot revoke this token, no such token."]
                _ ->
                  ok $ toResponse $
                    template [ "username" $= display (userName uinfo) ]
        _ -> errBadRequest "Invalid form action" []

    --
    --  Exported utils for looking up user names in URLs\/paths
    --

    userNameInPath :: forall m. MonadPlus m => DynamicPath -> m UserName
    userNameInPath dpath = maybe mzero return (simpleParse =<< lookup "username" dpath)

    lookupUserName :: UserName -> ServerPartE UserId
    lookupUserName = fmap fst . lookupUserNameFull

    lookupUserNameFull :: UserName -> ServerPartE (UserId, (UsersRow Result))
    lookupUserNameFull uname = do
      users <- doSelectE serverConnection $ do
        user <- activeUsers
        where_ $ userName user ==. lit uname
        pure user
      case listToMaybe users of
        Just u -> pure (userId u, u)
        Nothing -> userLost "Could not find user: not presently registered"
      where userLost = errNotFound "User not found" . return . MText
            --FIXME: 404 is only the right error for operating on User resources
            -- not when users are being looked up for other reasons, like setting
            -- ownership of packages. In that case needs errBadRequest

    lookupUserInfo :: UserId -> ServerPartE (UsersRow Result)
    lookupUserInfo uid =
      doSelect1E serverConnection $ do
        user <- activeUsers
        where_ $ userId user ==. lit uid
        pure user

    adminAddUser :: ServerPartE Response
    adminAddUser = do
        -- with this line commented out, self-registration is allowed
        guardAuthorised_ [InGroup adminGroup]
        reqData <- getDataFn lookUserNamePasswords
        case reqData of
            (Left errs) -> errBadRequest "Error registering user"
                       ((MText "Username, password, or repeated password invalid.") : map MText errs)
            (Right (ustr, pwd1, pwd2)) -> do
                uname <- newUserWithAuth ustr (PasswdPlain pwd1) (PasswdPlain pwd2)
                seeOther ("/user/" ++ display uname) (toResponse ())
       where lookUserNamePasswords = do
                 (,,) <$> look "username"
                      <*> look "password"
                      <*> look "repeat-password"

    newUserWithAuth :: String -> PasswdPlain -> PasswdPlain -> ServerPartE UserName
    newUserWithAuth _ pwd1 pwd2 | pwd1 /= pwd2 = errBadRequest "Error registering user" [MText "Entered passwords do not match"]
    newUserWithAuth userNameStr password _ =
      case simpleParse userNameStr of
        Nothing -> errBadRequest "Error registering user" [MText "Not a valid user name!"]
        Just uname -> do
          let UserAuth passwd = newUserAuth uname password
          uname <$ registerUserE serverConnection uname passwd True

    -- Arguments: the auth'd user id, the user path id (derived from the :username)
    canChangePassword :: MonadIO m => UserId -> UserId -> m Bool
    canChangePassword uid userPathId = do
        misAdmin <- liftIO $ doSelect serverConnection $ do
          role <- each userRolesSchema
          where_ $ userRoleUserId role ==. lit uid
               &&. userRoleRole role ==. lit Admin
          pure $ lit True
        let isAdmin = either (const False) (not . null) misAdmin
        return $ uid == userPathId || isAdmin

    --FIXME: this thing is a total mess!
    -- Do admins need to change user's passwords? Why not just reset passwords & (de)activate accounts.
    changePassword :: UserName -> ServerPartE ()
    changePassword username = do
        uid <- lookupUserName username
        guardAuthorised [IsUserId uid, InGroup adminGroup]
        passwd1 <- look "password"        --TODO: fail rather than mzero if missing
        passwd2 <- look "repeat-password"
        when (passwd1 /= passwd2) $
          forbidChange "Copies of new password do not match or is an invalid password (ex: blank)"
        let plainpasswd = PasswdPlain passwd1
            passwd   = newUserAuth username plainpasswd
        res <- liftIO $ updateSetUserAuth uid passwd
        -- 'doUpdateE' with a 'Returning' clause returns a list with one
        -- element for each row updated. We use the returning clause to
        -- exfiltrate whether the user has the deleted status; thus, we can
        -- branch on the number and values of the results.
        case res of
          Nothing -> pure ()
          Just (Left ErrNoSuchUserId) -> errInternalError [MText "user id lookup failure"]
          Just (Right ErrDeletedUser) -> forbidChange "Cannot set passwords for deleted users"
      where
        forbidChange = errForbidden "Error changing password" . return . MText

    newUserAuth :: UserName -> PasswdPlain -> UserAuth
    newUserAuth name pwd = UserAuth (Auth.newPasswdHash Auth.hackageRealm name pwd)

    ------ User group management
    adminGroupDesc :: UserGroup
    adminGroupDesc = UserGroup
      { groupDesc             = nullDescription { groupTitle = "Hackage admins" }
      , queryUserGroup        = fmap (either (error . show) Group.fromList) $ doSelect serverConnection $ do
            role <- each userRolesSchema
            where_ $ userRoleRole role ==. lit Admin
            -- do we need to filter out disabled admins?
            pure $ userRoleUserId role
      , addUserToGroup        = \uid -> do
          now <- getCurrentTime
          fmap (either (error . show) id) $ doInsert_ serverConnection $ Insert
            { into = userRolesSchema
            , rows = values $ pure @[] $ UserRoleRow
              { userRoleId = unsafeDefault
              , userRoleUserId = lit uid
              , userRoleRole = lit Admin
              , userRoleAssignedTime = lit now
                }
            , onConflict = Abort
            , returning = NoReturning
            }
      , removeUserFromGroup = \uid ->
          fmap (either (error . show) id) $ doDelete_ serverConnection $ Delete
            { from = userRolesSchema
            , using = pure ()
            , deleteWhere = \_ role -> userRoleUserId role ==. lit uid
            , returning = NoReturning
            }
      , groupsAllowedToAdd    = [adminGroupDesc]
      , groupsAllowedToDelete = [adminGroupDesc]
      }

    groupAddUser :: UserGroup -> DynamicPath -> ServerPartE ()
    groupAddUser group _ = do
        actor <- guardAuthorised (map InGroup (groupsAllowedToAdd group))
        let actorUid = userId actor
        muser <- optional $ look "user"
        reason <- optional $ look "reason"
        case muser of
            Nothing -> addError "Bad request (could not find 'user' argument)"
            Just ustr -> do
              case simpleParse ustr of
                Nothing ->
                  addError $ "No user with name " ++ show ustr ++ " found"
                Just uname -> do
                  res <- doSelectE serverConnection $ do
                    user <- activeUsers
                    where_ $ userName user ==. lit uname
                    pure $ userId user
                  case listToMaybe res of
                    Nothing      -> addError $ "No user with name " ++ show ustr ++ " found"
                    Just uid -> do
                      liftIO $ addUserToGroup group uid
                      runHook_ groupChangedHook (groupDesc group, True,actorUid,uid,fromMaybe "" reason)
       where addError = errBadRequest "Failed to add user" . return . MText

    groupDeleteUser :: UserGroup -> DynamicPath -> ServerPartE ()
    groupDeleteUser group dpath = do
      actor <- guardAuthorised (map InGroup (groupsAllowedToDelete group))
      let actorUid = userId actor
      uid <- lookupUserName =<< userNameInPath dpath
      reason <- localRq (\req -> req {rqMethod = POST}) . optional $ look "reason"
      liftIO $ removeUserFromGroup group uid
      runHook_ groupChangedHook (groupDesc group, False,actorUid,uid,fromMaybe "" reason)

    lookupGroupEditAuth :: UserGroup -> ServerPartE (Bool, Bool)
    lookupGroupEditAuth group = do
      addList    <- liftIO . Group.queryUserGroups $ groupsAllowedToAdd group
      removeList <- liftIO . Group.queryUserGroups $ groupsAllowedToDelete group
      user <- guardAuthenticated
      let uid = userId user
      let (canAdd, canDelete) = (uid `Group.member` addList, uid `Group.member` removeList)
      if not (canAdd || canDelete)
          then errForbidden "Forbidden" [MText "Can't edit permissions for user group"]
          else return (canAdd, canDelete)

    ------------ Encapsulation of resources related to editing a user group.

    -- | Registers a user group for external display. It takes the index group
    -- mapping (groupIndex from UserFeature), the base uri of the group, and a
    -- UserGroup object with all the necessary hooks. The base uri shouldn't
    -- contain any dynamic or varying components. It returns the GroupResource
    -- object, and also an adapted UserGroup that updates the cache. You should
    -- use this in order to keep the index updated.
    groupResourceAt :: String -> UserGroup -> IO (UserGroup, GroupResource)
    groupResourceAt uri group = do
        let mainr = resourceAt uri
            descr = groupDesc group
            groupUri = renderResource mainr []
            group' = group
              { addUserToGroup = \uid -> do
                    addGroupIndex uid groupUri descr
                    addUserToGroup group uid
              , removeUserFromGroup = \uid -> do
                    removeGroupIndex uid groupUri
                    removeUserFromGroup group uid
              }
        ulist <- queryUserGroup group
        initGroupIndex ulist groupUri descr
        let groupr = GroupResource {
                groupResource = (extendResourcePath "/.:format" mainr) {
                    resourceDesc = [ (GET, "Description of the group and a list of its members (defined in 'users' feature)") ]
                  , resourceGet  = [ ("json", serveUserGroupGet groupr) ]
                  }
              , groupUserResource = (extendResourcePath "/user/:username.:format" mainr) {
                    resourceDesc   = [ (PUT, "Add a user to the group (defined in 'users' feature)")
                                     , (DELETE, "Remove a user from the group (defined in 'users' feature)")
                                     ]
                  , resourcePut    = [ ("", serveUserGroupUserPut groupr) ]
                  , resourceDelete = [ ("", serveUserGroupUserDelete groupr) ]
                  }
              , getGroup = \_ -> return group'
              }
        return (group', groupr)

    -- | Registers a collection of user groups for external display. These groups
    -- are usually backing a separate collection. Like groupResourceAt, it takes the
    -- index group mapping and a base uri The base uri can contain varying path
    -- components, so there should be a group-generating function that, given a
    -- DynamicPath, yields the proper UserGroup. The final argument is the initial
    -- list of DynamicPaths to build the initial group index. Like groupResourceAt,
    -- this function returns an adaptor function that keeps the index updated.
    groupResourcesAt :: String
                     -> (a -> UserGroup)
                     -> (a -> DynamicPath)
                     -> (DynamicPath -> ServerPartE a)
                     -> [a]
                     -> IO (a -> UserGroup, GroupResource)
    groupResourcesAt uri mkGroup mkPath getGroupData initialGroupData = do
        let mainr = resourceAt uri
        sequence_
          [ do let group = mkGroup x
                   dpath = mkPath x
               ulist <- queryUserGroup group
               initGroupIndex ulist (renderResource' mainr dpath) (groupDesc group)
          | x <- initialGroupData ]

        let mkGroup' x =
              let group = mkGroup x
                  dpath = mkPath x
               in group {
                    addUserToGroup = \uid -> do
                        addGroupIndex uid (renderResource' mainr dpath) (groupDesc group)
                        addUserToGroup group uid
                  , removeUserFromGroup = \uid -> do
                        removeGroupIndex uid (renderResource' mainr dpath)
                        removeUserFromGroup group uid
                  }

            groupr = GroupResource {
                groupResource = (extendResourcePath "/.:format" mainr) {
                    resourceDesc = [ (GET, "Description of the group and a list of the members (defined in 'users' feature)") ]
                  , resourceGet  = [ ("json", serveUserGroupGet groupr) ]
                  }
              , groupUserResource = (extendResourcePath "/user/:username.:format" mainr) {
                    resourceDesc   = [ (PUT,    "Add a user to the group (defined in 'users' feature)")
                                     , (DELETE, "Delete a user from the group (defined in 'users' feature)")
                                     ]
                  , resourcePut    = [ ("", serveUserGroupUserPut groupr) ]
                  , resourceDelete = [ ("", serveUserGroupUserDelete groupr) ]
                  }
              , getGroup = \dpath -> mkGroup' <$> getGroupData dpath
              }
        return (mkGroup', groupr)

    serveUserGroupGet groupr dpath = do
      group    <- getGroup groupr dpath
      userlist <- liftIO $ queryUserGroup group
      usernames <- doSelectE serverConnection $ do
        user <- activeUsers
        where_ $ userId user `in_` fmap lit (Group.toList userlist)
        pure (userId user, userName user)
      return . toResponse $ toJSON
          UserGroupResource {
            ui_title       = T.pack $ groupTitle (groupDesc group),
            ui_description = T.pack $ groupPrologue (groupDesc group),
            ui_members     = [ UserNameIdResource {
                                 ui_username = username,
                                 ui_userid   = uid
                               }
                             | (uid, username) <- usernames ]
          }

    --TODO: add serveUserGroupUserPost for the sake of the html frontend
    --      and then remove groupAddUser & groupDeleteUser
    serveUserGroupUserPut groupr dpath = do
      group <- getGroup groupr dpath
      actor <- guardAuthorised (map InGroup (groupsAllowedToAdd group))
      let actorUid = userId actor
      uid <- lookupUserName =<< userNameInPath dpath
      reason <- optional $ look "reason"
      liftIO $ addUserToGroup group uid
      runHook_ groupChangedHook (groupDesc group, True,actorUid,uid,fromMaybe "" reason)
      goToList groupr dpath

    serveUserGroupUserDelete groupr dpath = do
      group <- getGroup groupr dpath
      actor <- guardAuthorised (map InGroup (groupsAllowedToDelete group))
      let actorUid = userId actor
      uid <- lookupUserName =<< userNameInPath dpath
      reason <- optional $ look "reason"
      liftIO $ removeUserFromGroup group uid
      runHook_ groupChangedHook (groupDesc group, False,actorUid,uid,fromMaybe "" reason)
      goToList groupr dpath

    goToList group dpath = seeOther (renderResource' (groupResource group) dpath)
                                    (toResponse ())

    ---------------------------------------------------------------
    addGroupIndex :: MonadIO m => UserId -> String -> GroupDescription -> m ()
    addGroupIndex (UserId uid) uri desc =
        modifyMemState groupIndex $
          adjustGroupIndex
            (IntMap.insertWith Set.union uid (Set.singleton uri))
            (Map.insert uri desc)

    removeGroupIndex :: MonadIO m => UserId -> String -> m ()
    removeGroupIndex (UserId uid) uri =
        modifyMemState groupIndex $
          adjustGroupIndex
            (IntMap.update (keepSet . Set.delete uri) uid)
            id
      where
        keepSet m = if Set.null m then Nothing else Just m

    initGroupIndex :: MonadIO m => UserIdSet -> String -> GroupDescription -> m ()
    initGroupIndex ulist uri desc =
        modifyMemState groupIndex $
          adjustGroupIndex
            (IntMap.unionWith Set.union (IntMap.fromList . map mkEntry $ Group.toList ulist))
            (Map.insert uri desc)
      where
        mkEntry (UserId uid) = (uid, Set.singleton uri)

    getGroupIndex :: (Functor m, MonadIO m) => UserId -> m [String]
    getGroupIndex (UserId uid) =
      liftM (maybe [] Set.toList . IntMap.lookup uid . usersToGroupUri) $ readMemState groupIndex

    getIndexDesc :: MonadIO m => String -> m GroupDescription
    getIndexDesc uri =
      liftM (Map.findWithDefault nullDescription uri . groupUrisToDesc) $ readMemState groupIndex

    -- partitioning index modifications, a cheap combinator
    adjustGroupIndex :: (IntMap (Set String) -> IntMap (Set String))
                     -> (Map String GroupDescription -> Map String GroupDescription)
                     -> GroupIndex -> GroupIndex
    adjustGroupIndex f g (GroupIndex a b) = GroupIndex (f a) (g b)

registerUser
    :: Connection
    -> UserName
    -> Auth.PasswdHash
    -> Bool
    -- ^ Enabled?
    -> IO (Either SessionError UserId)
registerUser conn uname passwd enabled = do
  now <- getCurrentTime
  doInsert1 conn $ Insert
    { into = usersSchema
    , rows = values $ pure @[] $ UsersRow
        { userId = unsafeDefault
        , userName = lit uname
        , userEmail = lit Nothing
        , userRealName = lit Nothing
        , userAuth = lit passwd
        , userStatus =  lit $ bool Disabled Enabled enabled
        , userAccountKind = lit $ Just AccountKindRealUser
        , userAdminNotes = lit ""
        , userCreatedTime = lit now
        }
    , onConflict =
        -- Do nothing, rather than abort, so that we can give a custom error message.
        DoNothing
    , returning = Returning userId
    }

registerUserE
    :: Connection
    -> UserName
    -> Auth.PasswdHash
    -> Bool
    -- ^ Enabled?
    -> ServerPartE UserId
registerUserE conn uname passwd enabled = do
  liftIO (registerUser conn uname passwd enabled) >>= \case
    Left _ -> errForbidden "Error registering user" [MText "A user account with that user name already exists."]
    Right uid -> pure uid
