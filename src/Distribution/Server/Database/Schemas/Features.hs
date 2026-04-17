{-# LANGUAGE DeriveAnyClass        #-}
{-# LANGUAGE DeriveAnyClass        #-}
{-# LANGUAGE DeriveGeneric         #-}
{-# LANGUAGE DeriveTraversable     #-}
{-# LANGUAGE DerivingStrategies    #-}
{-# LANGUAGE DerivingVia           #-}
{-# LANGUAGE FlexibleInstances     #-}
{-# LANGUAGE MultiParamTypeClasses #-}
{-# LANGUAGE NamedFieldPuns        #-}
{-# LANGUAGE OverloadedStrings     #-}
{-# LANGUAGE StandaloneDeriving    #-}
{-# LANGUAGE TypeApplications      #-}
{-# LANGUAGE TypeFamilies          #-}

-- | Schema definitions for feature-specific tables (votes, tags, build reports, etc.)
--
-- These are relatively straightforward 1:1 mappings from acid-state types
--
module Distribution.Server.Database.Schemas.Features
  ( -- * Votes table
    VoteRow(..)
  , votesSchema

    -- * Build reports table
  , BuildReportRow(..)
  , buildReportsSchema

    -- * Download counts table
  , DownloadCountRow(..)
  , downloadCountsSchema

    -- * User signup/reset table
  , SignupResetRow(..)
  , signupResetSchema

    -- * User notification preferences table
  , UserNotifyPrefRow(..)
  , userNotifyPrefsSchema

    -- * Admin log table
  , AdminLogRow(..)
  , adminLogSchema

    -- * TarIndex cache table
  , TarIndexCacheRow(..)
  , tarIndexCacheSchema

    -- * Analytics pixels table
  , AnalyticsPixelRow(..)
  , analyticsPixelsSchema

    -- * Legacy passwords table
  , LegacyPasswdRow(..)
  , legacyPasswdsSchema

    -- * Haskell Platform packages table
  , HaskellPlatformRow(..)
  , haskellPlatformSchema

    -- * Vouches table
  , VouchRow(..)
  , vouchesSchema

    -- * Distros table
  , DistroRow(..)
  , distrosSchema

    -- * Mirror clients table
  , MirrorClientRow(..)
  , mirrorClientsSchema
  ) where

import Distribution.Package (PackageName)
import Distribution.Types.Version (Version, mkVersion, versionNumbers)
import Distribution.Server.Users.Types (UserId, UserName)
import Distribution.Server.Features.UserNotify.Types
  ( NotifyRevisionRange(..), NotifyTriggerBounds(..) )
import Distribution.Server.Features.UserDetails.Types
  ( AccountKind(..) )
import Distribution.Server.Framework.AuthTypes (PasswdHash)
import Distribution.Server.Framework.BlobStorage (BlobId)

import Data.Int (Int32, Int64)
import Data.Text (Text)
import qualified Data.Text as T
import Data.Time (UTCTime, Day)
import GHC.Generics (Generic)
import Distribution.Server.Framework.DB

import Rel8
  ( Name
  , DBType(..)
  , Rel8able
  , TableSchema(..)
  , Column
  , encode
  , decode
  )
import qualified Rel8

import Data.Coerce (coerce)
import Data.Functor.Contravariant (contramap)
import Distribution.Package (PackageName, mkPackageName)
import qualified Distribution.Package as Pkg
import Distribution.Pretty (prettyShow)
import Distribution.Parsec (simpleParsec)
import Distribution.Server.Framework.BlobStorage (blobMd5, readBlobId)

instance DBType PackageName where
  typeInformation =
    let ti = typeInformation @Text
    in ti { encode = contramap (T.pack . Pkg.unPackageName) $ encode ti
          , decode = fmap (mkPackageName . T.unpack) $ decode ti
          }

instance DBType BlobId where
  typeInformation =
    let ti = typeInformation @Text
    in ti { encode = contramap (T.pack . blobMd5) $ encode ti
          , decode = fmap forceReadBlobId $ decode ti
          }
    where
      forceReadBlobId t = case readBlobId (T.unpack t) of
        Right b  -> b
        Left err -> error $ "DBType BlobId decode: " ++ err

instance DBType Version where
  typeInformation =
    let ti = typeInformation @[Int64]
    in ti { encode = contramap (fmap fromIntegral . versionNumbers) $ encode ti
          , decode = fmap (mkVersion . fmap fromIntegral) $ decode ti
          }

instance DBEq Version
instance DBOrd Version

deriving via ReadShow NotifyRevisionRange instance DBType NotifyRevisionRange
deriving via ReadShow NotifyTriggerBounds instance DBType NotifyTriggerBounds
deriving via ReadShow AccountKind instance DBType AccountKind

-- ============================================================================
-- Votes Table
-- ============================================================================

-- | Package votes for recommendations
--
-- Maps to: Votes.State.VotesState
-- Stores user votes with scores for packages
-- PRIMARY KEY (natural composite): (votePackageName, voteUserId)
-- A user can vote at most once per package, so (package_name, user_id)
-- acts as the natural key.
data VoteRow f = VoteRow
  { votePackageName :: Column f PackageName
  , voteUserId :: Column f UserId
  , voteScore :: Column f Int32
  , voteTime :: Column f UTCTime
  }
  deriving stock (Generic)
  deriving anyclass (Rel8able)

votesSchema :: TableSchema (VoteRow Name)
votesSchema = TableSchema
  { name = "votes"
  , columns = VoteRow
      { votePackageName = "package_name"
      , voteUserId = "user_id"
      , voteScore = "score"
      , voteTime = "vote_time"
      }
  }

-- ============================================================================
-- Build Reports Table
-- ============================================================================

-- | Build reports and logs
--
-- Maps to: BuildReports.State.BuildReports
--
-- PRIMARY KEY (synthetic): brId
-- Each build report is stored as a row. The (package_id, report_id) pair
-- should uniquely identify a report.
data BuildReportRow f = BuildReportRow
  { brId :: Column f Int64
  , brPackageName :: Column f PackageName
  , brPackageVersion :: Column f Version
  , brReportId :: Column f Int64
  , brReport :: Column f Text        -- serialized BuildReport
  , brBuildLog :: Column f (Maybe BlobId)
  , brTestLog :: Column f (Maybe BlobId)
  , brCoverage :: Column f (Maybe BlobId)
  , brReportTime :: Column f UTCTime
  }
  deriving stock (Generic)
  deriving anyclass (Rel8able)

buildReportsSchema :: TableSchema (BuildReportRow Name)
buildReportsSchema = TableSchema
  { name = "build_reports"
  , columns = BuildReportRow
      { brId = "build_report_id"
      , brPackageName = "package_name"
      , brPackageVersion = "package_version"
      , brReportId = "report_id"
      , brReport = "report"
      , brBuildLog = "build_log"
      , brTestLog = "test_log"
      , brCoverage = "coverage"
      , brReportTime = "report_time"
      }
  }

-- ============================================================================
-- Download Counts Table
-- ============================================================================

-- | Download statistics by day
--
-- Maps to: DownloadCount.State.InMemStats and OnDiskStats
--
-- PRIMARY KEY (synthetic): dcId
-- Each (package_id, day) pair represents counts for one day. The pair
-- should be unique to prevent duplicate daily counts.
data DownloadCountRow f = DownloadCountRow
  { dcId :: Column f Int64
  , dcPackageName :: Column f PackageName
  , dcPackageVersion :: Column f Version
  , dcDay :: Column f Day
  , dcCount :: Column f Int64
  }
  deriving stock (Generic)
  deriving anyclass (Rel8able)

downloadCountsSchema :: TableSchema (DownloadCountRow Name)
downloadCountsSchema = TableSchema
  { name = "download_counts"
  , columns = DownloadCountRow
      { dcId = "download_count_id"
      , dcPackageName = "package_name"
      , dcPackageVersion = "package_version"
      , dcDay = "day"
      , dcCount = "count"
      }
  }

-- ============================================================================
-- Signup/Reset Table
-- ============================================================================

-- | User signup and password reset tokens
--
-- Maps to: UserSignup.State.SignupResetTable
--
-- PRIMARY KEY (synthetic): srId
-- Each signup or reset request is stored as a row. The nonce should be unique
-- to serve as a verification code.
data SignupResetRow f = SignupResetRow
  { srId :: Column f Int64
  , srNonce :: Column f Text
  , srUserName :: Column f UserName
  , srRealName :: Column f Text
  , srEmail :: Column f Text
  , srCaptcha :: Column f (Maybe Text)
  , srRequestTime :: Column f UTCTime
  , srExpires :: Column f UTCTime
  , srIsReset :: Column f Bool  -- False for signup, True for password reset
  }
  deriving stock (Generic)
  deriving anyclass (Rel8able)

signupResetSchema :: TableSchema (SignupResetRow Name)
signupResetSchema = TableSchema
  { name = "signup_reset"
  , columns = SignupResetRow
      { srId = "signup_reset_id"
      , srNonce = "nonce"
      , srUserName = "user_name"
      , srRealName = "real_name"
      , srEmail = "email"
      , srCaptcha = "captcha"
      , srRequestTime = "request_time"
      , srExpires = "expires"
      , srIsReset = "is_reset"
      }
  }

-- ============================================================================
-- User Notification Preferences Table
-- ============================================================================

-- | Per-user notification preferences
--
-- Maps to: UserNotify.NotifyData (Map UserId NotifyPref)
--
-- PRIMARY KEY (natural): unpUserId
-- One row per user. Each field corresponds to a NotifyPref record field.
data UserNotifyPrefRow f = UserNotifyPrefRow
  { unpUserId                  :: Column f UserId
  , unpOptOut                  :: Column f Bool
  , unpRevisionRange           :: Column f NotifyRevisionRange
  , unpUpload                  :: Column f Bool
  , unpMaintainerGroup         :: Column f Bool
  , unpDocBuilderReport        :: Column f Bool
  , unpPendingTags             :: Column f Bool
  , unpDependencyForMaintained :: Column f Bool
  , unpDependencyTriggerBounds :: Column f NotifyTriggerBounds
  }
  deriving stock (Generic)
  deriving anyclass (Rel8able)

userNotifyPrefsSchema :: TableSchema (UserNotifyPrefRow Name)
userNotifyPrefsSchema = TableSchema
  { name = "user_notify_prefs"
  , columns = UserNotifyPrefRow
      { unpUserId                  = "user_id"
      , unpOptOut                  = "opt_out"
      , unpRevisionRange           = "revision_range"
      , unpUpload                  = "upload"
      , unpMaintainerGroup         = "maintainer_group"
      , unpDocBuilderReport        = "doc_builder_report"
      , unpPendingTags             = "pending_tags"
      , unpDependencyForMaintained = "dependency_for_maintained"
      , unpDependencyTriggerBounds = "dependency_trigger_bounds"
      }
  }

-- ============================================================================
-- Admin Log Table
-- ============================================================================

-- | Admin action audit log
--
-- Maps to: AdminLog.State.AdminLog
--
-- PRIMARY KEY (synthetic): alId
-- Each admin action is stored as a row for audit trail purposes.
data AdminLogRow f = AdminLogRow
  { alId :: Column f Int64
  , alTime :: Column f UTCTime
  , alUserId :: Column f UserId
  , alAction :: Column f Text  -- serialized AdminAction
  , alReason :: Column f Text
  }
  deriving stock (Generic)
  deriving anyclass (Rel8able)

adminLogSchema :: TableSchema (AdminLogRow Name)
adminLogSchema = TableSchema
  { name = "admin_log"
  , columns = AdminLogRow
      { alId = "admin_log_id"
      , alTime = "time"
      , alUserId = "user_id"
      , alAction = "action"
      , alReason = "reason"
      }
  }

-- ============================================================================
-- TarIndex Cache Table
-- ============================================================================

-- | Cache mapping between tar and index blobs
--
-- Maps to: TarIndexCache.State.TarIndexCache
-- PRIMARY KEY (natural): ticTarBlobId
-- tar_blob_id is the natural key.
data TarIndexCacheRow f = TarIndexCacheRow
  { ticTarBlobId :: Column f BlobId
  , ticIndexBlobId :: Column f BlobId
  }
  deriving stock (Generic)
  deriving anyclass (Rel8able)

tarIndexCacheSchema :: TableSchema (TarIndexCacheRow Name)
tarIndexCacheSchema = TableSchema
  { name = "tar_index_cache"
  , columns = TarIndexCacheRow
      { ticTarBlobId = "tar_blob_id"
      , ticIndexBlobId = "index_blob_id"
      }
  }

-- ============================================================================
-- Analytics Pixels Table
-- ============================================================================

-- | Analytics tracking pixels
--
-- Maps to: AnalyticsPixels.State.AnalyticsPixelsState
-- PRIMARY KEY (natural): apPixelId
-- pixel_id is the natural key.
data AnalyticsPixelRow f = AnalyticsPixelRow
  { apPixelId :: Column f Int64
  , apContent :: Column f Text
  , apAddedTime :: Column f UTCTime
  }
  deriving stock (Generic)
  deriving anyclass (Rel8able)

analyticsPixelsSchema :: TableSchema (AnalyticsPixelRow Name)
analyticsPixelsSchema = TableSchema
  { name = "analytics_pixels"
  , columns = AnalyticsPixelRow
      { apPixelId = "pixel_id"
      , apContent = "content"
      , apAddedTime = "added_time"
      }
  }

-- ============================================================================
-- Legacy Passwords Table
-- ============================================================================

-- | Legacy password hashes for migration
--
-- Maps to: LegacyPasswds.State.LegacyPasswdsTable
--
-- PRIMARY KEY (synthetic): lpId
-- Each user can have one legacy password entry. The user_id should be unique
-- to prevent duplicate legacy password records.
data LegacyPasswdRow f = LegacyPasswdRow
  { lpId :: Column f Int64
  , lpUserId :: Column f UserId
  , lpPasswdHash :: Column f PasswdHash
  }
  deriving stock (Generic)
  deriving anyclass (Rel8able)

legacyPasswdsSchema :: TableSchema (LegacyPasswdRow Name)
legacyPasswdsSchema = TableSchema
  { name = "legacy_passwords"
  , columns = LegacyPasswdRow
      { lpId = "legacy_password_id"
      , lpUserId = "user_id"
      , lpPasswdHash = "passwd_hash"
      }
  }

-- ============================================================================
-- Haskell Platform Table
-- ============================================================================

-- | Haskell Platform included packages
--
-- Maps to: HaskellPlatform.State.PlatformPackages
--
-- PRIMARY KEY (synthetic): hpId
-- Each (package_name, version) pair is stored as a separate row.
-- The pair should be unique.
data HaskellPlatformRow f = HaskellPlatformRow
  { hpId :: Column f Int64
  , hpPackageName :: Column f PackageName
  , hpVersion :: Column f Version
  , hpIncluded :: Column f Bool
  }
  deriving stock (Generic)
  deriving anyclass (Rel8able)

haskellPlatformSchema :: TableSchema (HaskellPlatformRow Name)
haskellPlatformSchema = TableSchema
  { name = "haskell_platform"
  , columns = HaskellPlatformRow
      { hpId = "haskell_platform_id"
      , hpPackageName = "package_name"
      , hpVersion = "version"
      , hpIncluded = "included"
      }
  }

-- ============================================================================
-- Vouches Table
-- ============================================================================

-- | Community vouches for new users
--
-- Maps to: Vouch.State.VouchData
--
-- PRIMARY KEY (synthetic): vId
-- Each vouch is stored as a separate row. A user (vouchee) can receive
-- multiple vouches from different vouchers.
data VouchRow f = VouchRow
  { vId :: Column f Int64
  , vVouchee :: Column f UserId
  , vVoucher :: Column f UserId
  , vTime :: Column f UTCTime
  , vNotified :: Column f Bool
  }
  deriving stock (Generic)
  deriving anyclass (Rel8able)

vouchesSchema :: TableSchema (VouchRow Name)
vouchesSchema = TableSchema
  { name = "vouches"
  , columns = VouchRow
      { vId = "vouch_id"
      , vVouchee = "vouchee"
      , vVoucher = "voucher"
      , vTime = "time"
      , vNotified = "notified"
      }
  }

-- ============================================================================
-- Distros Table
-- ============================================================================

-- | Distribution package information
--
-- Maps to: Distro.State.Distros
--
-- PRIMARY KEY (synthetic): distId
-- Each (dist_name, dist_version, package_name, package_version) tuple
-- is stored as a separate row representing a package in a distro release.
data DistroRow f = DistroRow
  { distId :: Column f Int64
  , distName :: Column f Text
  , distVersion :: Column f Text
  , distPackageName :: Column f PackageName
  , distPackageVersion :: Column f Version
  , distMaintainer :: Column f (Maybe UserId)
  }
  deriving stock (Generic)
  deriving anyclass (Rel8able)

distrosSchema :: TableSchema (DistroRow Name)
distrosSchema = TableSchema
  { name = "distros"
  , columns = DistroRow
      { distId = "distro_id"
      , distName = "dist_name"
      , distVersion = "dist_version"
      , distPackageName = "package_name"
      , distPackageVersion = "package_version"
      , distMaintainer = "maintainer"
      }
  }

-- ============================================================================
-- Mirror Clients Table
-- ============================================================================

-- | Mirror sync client registration
--
-- Maps to: Users.State.MirrorClients (also in user_roles with role='mirror_client')
--
-- PRIMARY KEY (synthetic): mcId
-- Each mirror client is stored as a separate row. The user_id should
-- be unique to prevent duplicate registrations.
data MirrorClientRow f = MirrorClientRow
  { mcId :: Column f Int64
  , mcUserId :: Column f UserId
  , mcRegisteredTime :: Column f UTCTime
  }
  deriving stock (Generic)
  deriving anyclass (Rel8able)

mirrorClientsSchema :: TableSchema (MirrorClientRow Name)
mirrorClientsSchema = TableSchema
  { name = "mirror_clients"
  , columns = MirrorClientRow
      { mcId = "mirror_client_id"
      , mcUserId = "user_id"
      , mcRegisteredTime = "registered_time"
      }
  }
