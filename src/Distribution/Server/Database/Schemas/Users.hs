{-# LANGUAGE DeriveAnyClass        #-}
{-# LANGUAGE DeriveGeneric         #-}
{-# LANGUAGE DeriveTraversable     #-}
{-# LANGUAGE DerivingStrategies    #-}
{-# LANGUAGE FlexibleInstances     #-}
{-# LANGUAGE MultiParamTypeClasses #-}
{-# LANGUAGE NamedFieldPuns        #-}
{-# LANGUAGE OverloadedStrings     #-}
{-# LANGUAGE StandaloneDeriving    #-}
{-# LANGUAGE TypeApplications      #-}
{-# LANGUAGE TypeFamilies          #-}

-- | Schema definitions for user-related tables
--
-- CONSOLIDATED TABLES:
-- This module consolidates multiple acid-state types into a single relational design:
--   - Users.Users -> users table (with user enabled status, authentication)
--   - HackageAdmins -> user_roles table (role = 'admin')
--   - HackageUploaders -> user_roles table (role = 'uploader')
--   - HackageTrustees -> user_roles table (role = 'trustee')
--   - MirrorClients -> user_roles table (role = 'mirror_client')
--
-- The acid-state implementation stored these as separate types, but relationally
-- they're all attributes of users. We consolidate them into a single 'users' table
-- with a 'user_roles' junction table for efficient querying of group membership.
--
module Distribution.Server.Database.Schemas.Users
  ( -- * Users table
    UsersRow(..)
  , usersSchema
  , usersTable

    -- * User roles junction table
  , UserRoleRow(..)
  , userRolesSchema
  , userRolesTable

    -- * User auth tokens table
  , UserAuthTokenRow(..)
  , userAuthTokensSchema
  , userAuthTokensTable

    -- * Role type
  , UserRole(..)
  ) where

import Distribution.Server.Users.Types (UserId, UserName)
import Distribution.Server.Features.UserDetails.Types (AccountKind)
import Distribution.Server.Framework.AuthTypes (PasswdHash)
import Distribution.Server.Users.AuthToken (AuthToken)

import Distribution.Server.Database.Schemas.Features ()

import Data.Int (Int64)
import Data.Text (Text)
import Data.Time (UTCTime)
import GHC.Generics (Generic)

import Data.Functor.Contravariant (contramap)
import Rel8
  ( DBType(..)
  , DBEq
  , Name
  , Rel8able
  , TableSchema(..)
  , Column
  , encode
  , decode
  )
import Rel8.CreateTable

-- ============================================================================
-- Users Table
-- ============================================================================

-- | Main users table combining Users, HackageAdmins, HackageTrustees,
-- HackageUploaders, and MirrorClients from acid-state
--
-- Fields map to:
--   - userId: UserId (from acid-state Users)
--   - userName: UserName (from acid-state Users)
--   - userEmail, userRealName: stored separately in acid-state, now normalized
--   - userAuth: PasswdHash (from Users.User record via UserAuth wrapper)
--   - userEnabled: whether user account is active
--   - userCreatedTime: when the account was created
-- PRIMARY KEY (natural): userId
data UsersRow f = UsersRow
  { userId :: Column f UserId
  , userName :: Column f UserName
  , userEmail :: Column f (Maybe Text)
  , userRealName :: Column f (Maybe Text)
  , userAuth :: Column f PasswdHash
  , userEnabled :: Column f Bool
  -- TODO(sandy): Do we need a tombstoned field for "accountdeleted"?
  , userAccountKind :: Column f (Maybe AccountKind)
  , userAdminNotes :: Column f Text
  , userCreatedTime :: Column f UTCTime
  }
  deriving stock (Generic)
  deriving anyclass (Rel8able)

usersSchema :: TableSchema (UsersRow Name)
usersSchema = TableSchema
  { name = "users"
  , columns = UsersRow
      { userId = "user_id"
      , userName = "user_name"
      , userEmail = "user_email"
      , userRealName = "user_real_name"
      , userAuth = "user_auth"
      , userEnabled = "user_enabled"
      , userAccountKind = "user_account_kind"
      , userAdminNotes = "user_admin_notes"
      , userCreatedTime = "user_created_time"
      }
  }

usersTable :: DbTable UsersRow
usersTable = DbTable usersSchema
  [ PK userId
  , AutoInc userId
  ]

-- ============================================================================
-- User Roles Junction Table
-- ============================================================================

-- | Maps users to their roles (admin, trustee, uploader, mirror_client)
--
-- This replaces separate acid-state structures:
--   - HackageAdmins.adminList (role = 'admin')
--   - HackageTrustees.trusteeList (role = 'trustee')
--   - HackageUploaders.uploaderList (role = 'uploader')
--   - MirrorClients.mirrorClients (role = 'mirror_client')
--
-- PRIMARY KEY (synthetic): userRoleId
-- A user can have multiple roles simultaneously, so each role assignment
-- is a separate row. The (user_id, role) pair should be unique to prevent
-- duplicate role assignments.
--
-- Advantages:
--   - Single source of truth for group membership
--   - Easy to add new roles in the future
--   - Efficient querying with proper indexing
--   - Supports time-based audit trails (when was role assigned)
data UserRole
  = Admin
  | Trustee
  | Uploader
  | MirrorClient
  deriving stock (Show, Eq, Ord, Enum, Bounded, Generic)
  deriving anyclass (DBEq)

instance DBType UserRole where
  typeInformation =
    let ti = typeInformation @Int64
    in ti { encode = contramap (fromIntegral . fromEnum) $ encode ti
          , decode = fmap (toEnum . fromIntegral) $ decode ti
          }

data UserRoleRow f = UserRoleRow
  { userRoleId :: Column f Int64
  , userRoleUserId :: Column f UserId
  , userRoleRole :: Column f UserRole
  , userRoleAssignedTime :: Column f UTCTime
  }
  deriving stock (Generic)
  deriving anyclass (Rel8able)

userRolesSchema :: TableSchema (UserRoleRow Name)
userRolesSchema = TableSchema
  { name = "user_roles"
  , columns = UserRoleRow
      { userRoleId = "user_role_id"
      , userRoleUserId = "user_id"
      , userRoleRole = "role"
      , userRoleAssignedTime = "assigned_time"
      }
  }

userRolesTable :: DbTable UserRoleRow
userRolesTable = DbTable userRolesSchema
  [ PK userRoleId
  , AutoInc userRoleId
  , FK userRoleUserId usersSchema userId
  ]

-- ============================================================================
-- User Auth Tokens Table
-- ============================================================================

-- | Authentication tokens for API access
--
-- Maps to: Users.User.userTokens from acid-state
-- Stores user authentication tokens and their metadata
-- PRIMARY KEY (natural): authTokenToken
-- Natural uniqueness by owner should be enforced with UNIQUE (authTokenUserId, authTokenToken).
data UserAuthTokenRow f = UserAuthTokenRow
  { authTokenUserId :: Column f UserId
  , authTokenToken :: Column f AuthToken
  , authTokenDescription :: Column f (Maybe Text)
  , authTokenCreatedTime :: Column f UTCTime
  }
  deriving stock (Generic)
  deriving anyclass (Rel8able)

userAuthTokensSchema :: TableSchema (UserAuthTokenRow Name)
userAuthTokensSchema = TableSchema
  { name = "user_auth_tokens"
  , columns = UserAuthTokenRow
      { authTokenUserId = "user_id"
      , authTokenToken = "token"
      , authTokenDescription = "description"
      , authTokenCreatedTime = "created_time"
      }
  }


userAuthTokensTable :: DbTable UserAuthTokenRow
userAuthTokensTable = DbTable userAuthTokensSchema
  [ PK authTokenToken
  , FK authTokenUserId usersSchema userId
  ]
