{-# LANGUAGE DuplicateRecordFields #-}
{-# LANGUAGE FlexibleContexts      #-}
{-# LANGUAGE MonoLocalBinds        #-}
{-# LANGUAGE NamedFieldPuns        #-}
{-# LANGUAGE RankNTypes            #-}

module Distribution.Server.Features.Vouch (VouchFeature(..), initVouchFeature, judgeVouch) where

import Distribution.Server.Database.Schemas.Features (VouchRow(..), vouchesSchema)
import Distribution.Server.Database.Schemas.Users
import Distribution.Server.Features.Vouch.Types
import Control.Monad (when, join)
import Control.Monad.Except (runExceptT, throwError)
import Control.Monad.IO.Class (MonadIO)
import qualified Data.ByteString.Lazy.Char8 as LBS
import qualified Data.Set as Set
import Data.Time (UTCTime(..), addUTCTime, getCurrentTime, nominalDay, secondsToDiffTime)
import Data.Time.Format.ISO8601 (formatShow, iso8601Format)
import Text.XHtml.Strict (prettyHtmlFragment, stringToHtml, li)

import Distribution.Server.Framework ((</>), DynamicPath, HackageFeature, IsHackageFeature, IsHackageFeature(..))
import Distribution.Server.Framework (MessageSpan(MText), Method(..), Response, ServerEnv(..), ServerPartE)
import Distribution.Server.Framework (emptyHackageFeature, errBadRequest)
import Distribution.Server.Framework (featureDesc, featureReloadFiles, featureResources, featureState)
import Distribution.Server.Framework (liftIO, resourceAt, resourceDesc, resourceGet)
import Distribution.Server.Framework (resourcePost, toResponse)
import Distribution.Server.Framework.Templating (($=), TemplateAttr, getTemplate, loadTemplates, reloadTemplates, templateUnescaped)
import qualified Distribution.Server.Users.Group as Group
import Distribution.Server.Users.Types (UserId(..), UserName(..))
import Distribution.Server.Features.Upload(UploadFeature(..))
import Distribution.Server.Features.Users (UserFeature(..))
import Distribution.Simple.Utils (toUTF8LBS)
import Distribution.Server.Framework.DB

data VouchFeature =
  VouchFeature
    { vouchFeatureInterface :: HackageFeature
    , drainQueuedNotifications :: forall m. (MonadIO m, MonadFail m) => m [UserId]
    }

instance IsHackageFeature VouchFeature where
  getFeatureInterface = vouchFeatureInterface

requiredCountOfVouches :: Int
requiredCountOfVouches = 2

isWithinLastMonth :: UTCTime -> (UserId, UTCTime) -> Bool
isWithinLastMonth now (_, vouchTime) =
  addUTCTime (30 * nominalDay) vouchTime >= now

judgeVouch
  :: Group.UserIdSet
  -> UTCTime
  -> UserId
  -> [(UserId, UTCTime)]
  -> [(UserId, UTCTime)]
  -> UserId
  -> Either VouchError VouchSuccess
judgeVouch ugroup now vouchee vouchersForVoucher existingVouchers voucher = join . runExceptT $ do
  when (not (voucher `Group.member` ugroup)) $
    throwError NotAnUploader
  -- You can only vouch for non-uploaders, so if this list has items, the user is uploader because of these vouches.
  -- Make sure none of them are too recent.
  when (length vouchersForVoucher >= requiredCountOfVouches && any (isWithinLastMonth now) vouchersForVoucher) $
    throwError You'reTooNew
  when (vouchee `Group.member` ugroup) $
    throwError VoucheeAlreadyUploader
  when (length existingVouchers >= requiredCountOfVouches) $
    throwError AlreadySufficientlyVouched
  when (voucher `elem` map fst existingVouchers) $
    throwError YouAlreadyVouched
  pure $
    if length existingVouchers == requiredCountOfVouches - 1
       then AddVouchComplete
       else
         let stillRequired = requiredCountOfVouches - length existingVouchers - 1
          in AddVouchIncomplete stillRequired

renderToLBS :: (UserId -> ServerPartE User) -> [(UserId, UTCTime)] -> ServerPartE TemplateAttr
renderToLBS lookupUserInfo vouches = do
  rendered <- traverse (renderVouchers lookupUserInfo) vouches
  pure $
    templateUnescaped "vouches" $
      if null rendered
         then LBS.pack "Nobody has endorsed yet."
         else LBS.intercalate mempty rendered

renderVouchers :: (UserId -> ServerPartE User) -> (UserId, UTCTime) -> ServerPartE LBS.ByteString
renderVouchers lookupUserInfo (uid, timestamp) = do
  info <- lookupUserInfo uid
  let UserName name = userName info
      -- We don't need to show millisecond precision
      -- So we truncate it off here
      truncated = truncate $ utctDayTime timestamp
      newUTCTime = timestamp {utctDayTime = secondsToDiffTime truncated}
  pure . toUTF8LBS . prettyHtmlFragment . li . stringToHtml $ name <> " vouched on " <> formatShow iso8601Format newUTCTime

initVouchFeature :: ServerEnv -> IO (UserFeature -> UploadFeature -> IO VouchFeature)
initVouchFeature ServerEnv{serverConnection = conn, serverTemplatesDir, serverTemplatesMode} = do
  templates <- loadTemplates serverTemplatesMode [ serverTemplatesDir, serverTemplatesDir </> "Html"]
                                                 ["vouch.html"]
  vouchTemplate <- getTemplate templates "vouch.html"
  return $ \UserFeature{userNameInPath, lookupUserName, lookupUserInfo, guardAuthenticated}
            UploadFeature{uploadersGroup} -> do
    let
      handleGetVouches :: DynamicPath -> ServerPartE Response
      handleGetVouches dpath = do
        uid <- lookupUserName =<< userNameInPath dpath
        vouches <- doSelectE conn $ getVouchesFor uid
        param <- renderToLBS lookupUserInfo vouches
        pure . toResponse $ vouchTemplate
          [ "msg" $= ""
          , "requiredNumber" $= show requiredCountOfVouches
          , param
          ]
      handlePostVouch :: DynamicPath -> ServerPartE Response
      handlePostVouch dpath = do
        voucher <- guardAuthenticated
        ugroup <- liftIO $ Group.queryUserGroup uploadersGroup
        now <- liftIO getCurrentTime
        vouchee <- lookupUserName =<< userNameInPath dpath
        vouchersForVoucher <- doSelectE conn $ getVouchesFor voucher
        existingVouchers <- doSelectE conn $ getVouchesFor vouchee
        case judgeVouch ugroup now vouchee vouchersForVoucher existingVouchers voucher of
          Left NotAnUploader ->
            errBadRequest "Not an uploader" [MText "You must be an uploader yourself to endorse other users."]
          Left You'reTooNew ->
            errBadRequest "You're too new" [MText "The latest of the endorsements for your user must be at least 30 days old."]
          Left VoucheeAlreadyUploader ->
            errBadRequest "Endorsee already uploader" [MText "You can't endorse this user, since they are already an uploader."]
          Left AlreadySufficientlyVouched ->
            errBadRequest "Already sufficiently endorsed" [MText "There are already a sufficient number of endorsements for this user."]
          Left YouAlreadyVouched ->
            errBadRequest "Already endorsed" [MText "You have already endorsed this user."]
          Right result -> do
            liftIO $ doInsert_ conn $
              putVouch vouchee voucher now
            param <- renderToLBS lookupUserInfo $ existingVouchers ++ [(voucher, now)]
            case result of
              AddVouchComplete -> do
                liftIO $ Group.addUserToGroup uploadersGroup vouchee
                pure . toResponse $ vouchTemplate
                  [ "msg" $= "Added endorsement. User is now an uploader!"
                  , "requiredNumber" $= show requiredCountOfVouches
                  , param
                  ]
              AddVouchIncomplete stillRequired ->
                pure . toResponse $ vouchTemplate
                  [ "msg" $=
                         "Added endorsement. User still needs "
                      <> show stillRequired
                      <> if stillRequired == 1 then " endorsement" else " endorsements"
                      <> " to become uploader."
                  , param
                  ]
    return $ VouchFeature {
      vouchFeatureInterface =
        (emptyHackageFeature "endorse")
          { featureDesc = "Endorsing users such that they get upload permission."
          , featureResources =
            [(resourceAt "/user/:username/endorse")
              { resourceDesc = [(GET, "list people endorsing")
                               ,(POST, "endorse for user")
                               ]
              , resourceGet = [("html", handleGetVouches)]
              , resourcePost = [("html", handlePostVouch)]
              }
            ]
          , featureState = []
          , featureReloadFiles = reloadTemplates templates
          },
      drainQueuedNotifications = do
        Right notNotified <- liftIO $ doUpdate conn getAndClearUnnotifiedVouchees
        pure $ Set.toList $ Set.fromList notNotified
    }


-- | Insert a new vouch
putVouch
  :: UserId
  -- ^ Vouchee
  -> UserId
  -- ^ Voucher
  -> UTCTime
  -> Insert ()
putVouch vouchee voucher now =
  Insert
  { into = vouchesSchema
  , rows = values
      [ VouchRow
          { vId = unsafeDefault
          , vVouchee = lit vouchee
          , vVoucher = lit voucher
          , vTime = lit now
          , vNotified =
              -- enqueue vouching completed notification
              -- which will be read using drainQueuedNotifications
              lit False
          }
      ]
  , onConflict = Abort
  , returning = NoReturning
  }


-- | Return all vouchers (and times) for a given vouchee.
getVouchesFor :: UserId -> Query (Expr UserId, Expr UTCTime)
getVouchesFor uid = do
  vouch <- each vouchesSchema
  where_ $ vVouchee vouch ==. lit uid
  pure (vVoucher vouch, vTime vouch)


-- | Get all vouchees for whom 'vNotified' is 'False', and atomically set
-- 'vNotified' to 'True'.
getAndClearUnnotifiedVouchees :: Update (Query (Expr UserId))
getAndClearUnnotifiedVouchees = do
  Update
    { target = vouchesSchema
    , from = pure ()
    , set = const $ \vouch ->
        vouch { vNotified = lit True }
    , updateWhere = const $ \vouch -> do
        vNotified vouch ==. lit False
    , returning = Returning vVouchee
    }
