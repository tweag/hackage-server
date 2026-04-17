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

-- | Schema definitions for package-related tables
--
-- CONSOLIDATED TABLES:
-- This module consolidates multiple acid-state types:
--   - PackagesState (from Core) -> packages + package_versions + package_update_log
--   - CandidatePackages -> candidate_packages + candidate_package_versions
--   - HackageTrustees, HackageUploaders, PackageMaintainers -> package_maintainers
--
module Distribution.Server.Database.Schemas.Packages
  ( -- * Packages table
    PackageRow(..)
  , packagesSchema
  , packageId
  , packageName
  , packageLastUpdated

    -- * Package versions table
  , PackageVersionRow(..)
  , packageVersionsSchema
  , pvId
  , pvPackageId
  , pvVersion
  , pvUploadedBy
  , pvUploadTime
  , pvTarballBlob
  , pvCabalBlob
  , pvIsCandidate
  , pvMigrationFlag

    -- * Package maintainers table (combines maintainers, trustees, uploaders)
  , PackageMaintainerRow(..)
  , packageMaintainersSchema
  , pmId
  , pmPackageName
  , pmUserId
  , pmRole
  , pmAssignedTime

    -- * Package tags table
  , PackageTagRow(..)
  , packageTagsSchema
  , ptId
  , ptPackageName
  , ptTag
  , ptAssignedTime

    -- * Tag aliases table
  , TagAliasRow(..)
  , tagAliasesSchema
  , taId
  , taTag
  , taAlias

    -- * Package preferred versions table
  , PreferredVersionRow(..)
  , preferredVersionsSchema
  , pvPrefPackageName
  , pvPrefVersionRange
  , pvPrefLastUpdated

    -- * Deprecated package versions table
  , DeprecatedVersionRow(..)
  , deprecatedVersionsSchema
  , depId
  , depPackageName
  , depVersion

    -- * Package documentation table
  , DocumentationRow(..)
  , documentationSchema
  , docId
  , docPackageId
  , docBlobId
  , docStoredTime

    -- * Package maintenance role type
  , MaintainerRole(..)
  ) where

import Distribution.Package (PackageName)
import Distribution.Types.Version (Version)
import Distribution.Server.Users.Types (UserId)
import Distribution.Server.Framework.BlobStorage (BlobId)

import Distribution.Server.Database.Schemas.Features ()
import Data.Int (Int32, Int64)
import Data.Text (Text)
import Data.Time (UTCTime)
import GHC.Generics (Generic)
import Data.Functor.Contravariant (contramap)

import Rel8
  ( Name
  , Rel8able
  , TableSchema(..)
  , Column
  , DBType(..)
  , encode
  , decode
  )

-- ============================================================================
-- Packages Table
-- ============================================================================

-- | Packages metadata table
--
-- Maps to: PackagesState.packageIndex (simplified)
-- Stores basic package information
-- PRIMARY KEY (natural): packageId
data PackageRow f = PackageRow
  { packageId :: Column f Int32
  , packageName :: Column f Text
  , packageLastUpdated :: Column f UTCTime
  }
  deriving stock (Generic)
  deriving anyclass (Rel8able)

packagesSchema :: TableSchema (PackageRow Name)
packagesSchema = TableSchema
  { name = "packages"
  , columns = PackageRow
      { packageId = "package_id"
      , packageName = "package_name"
      , packageLastUpdated = "last_updated"
      }
  }

-- ============================================================================
-- Package Versions Table
-- ============================================================================

-- | Package versions and tarballs
--
-- Maps to:
--   - Core.PackagesState.packageIndex -> stored as package_versions rows
--   - CandidatePackages.candidateList -> same table with is_candidate=true
--
-- This combines PackagesState and CandidatePackages into a single table
-- with an is_candidate flag to distinguish them.
--
-- PRIMARY KEY (synthetic): pvId
-- A package can have many versions, so each version is stored as a separate row.
-- The (package_id, version) pair should be unique to prevent duplicate versions.
data PackageVersionRow f = PackageVersionRow
  { pvId :: Column f Int64
  , pvPackageId :: Column f Int32
  , pvVersion :: Column f Version
  , pvUploadedBy :: Column f UserId
  , pvUploadTime :: Column f UTCTime
  , pvTarballBlob :: Column f BlobId
  , pvCabalBlob :: Column f BlobId
  , pvIsCandidate :: Column f Bool
  , pvMigrationFlag :: Column f Bool  -- candidateMigratedPkgTarball equivalent
  }
  deriving stock (Generic)
  deriving anyclass (Rel8able)

packageVersionsSchema :: TableSchema (PackageVersionRow Name)
packageVersionsSchema = TableSchema
  { name = "package_versions"
  , columns = PackageVersionRow
      { pvId = "package_version_id"
      , pvPackageId = "package_id"
      , pvVersion = "version"
      , pvUploadedBy = "uploaded_by"
      , pvUploadTime = "upload_time"
      , pvTarballBlob = "tarball_blob"
      , pvCabalBlob = "cabal_blob"
      , pvIsCandidate = "is_candidate"
      , pvMigrationFlag = "migration_flag"
      }
  }

-- ============================================================================
-- Package Maintainers Table
-- ============================================================================

-- | Package maintainers/trustees/uploaders
--
-- CONSOLIDATION:
-- Combines three acid-state structures:
--   - PackageMaintainers.maintainers (role = 'maintainer')
--   - HackageTrustees (global trustees, but here per-package for consistency)
--   - HackageUploaders (global uploaders, but here per-package for consistency)
--
-- Note: For global roles (all-package trustees/uploaders), these are stored
-- with a special package_id value (e.g., NULL or reserved ID) or use the
-- user_roles table instead.
--
-- PRIMARY KEY (synthetic): pmId
-- A user can have multiple roles for a package, and a package can have
-- multiple maintainers. Each assignment is stored as a separate row.
-- The (package_name, user_id, role) triple should be unique to prevent
-- duplicate role assignments.
data MaintainerRole
  = PackageMaintainer
  | PackageTrustee
  | PackageUploader
  deriving stock (Show, Eq, Ord, Generic, Enum, Bounded)


instance DBType MaintainerRole where
  typeInformation =
    let ti = typeInformation @Int64
    in ti { encode = contramap (fromIntegral . fromEnum) $ encode ti
          , decode = fmap (toEnum . fromIntegral) $ decode ti
          }

data PackageMaintainerRow f = PackageMaintainerRow
  { pmId :: Column f Int64
  , pmPackageName :: Column f PackageName
  , pmUserId :: Column f UserId
  , pmRole :: Column f MaintainerRole
  , pmAssignedTime :: Column f UTCTime
  }
  deriving stock (Generic)
  deriving anyclass (Rel8able)

packageMaintainersSchema :: TableSchema (PackageMaintainerRow Name)
packageMaintainersSchema = TableSchema
  { name = "package_maintainers"
  , columns = PackageMaintainerRow
      { pmId = "package_maintainer_id"
      , pmPackageName = "package_name"
      , pmUserId = "user_id"
      , pmRole = "role"
      , pmAssignedTime = "assigned_time"
      }
  }

-- ============================================================================
-- Package Tags Table
-- ============================================================================

-- | Package tags for categorization
--
-- Maps to: Tags.State.PackageTags and Tags.State.TagAlias
--
-- PRIMARY KEY (synthetic): ptId
-- Each (package_name, tag) pair is stored as a separate row. The pair
-- should be unique to prevent assigning the same tag twice to a package.
data PackageTagRow f = PackageTagRow
  { ptId :: Column f Int64
  , ptPackageName :: Column f PackageName
  , ptTag :: Column f Text
  , ptAssignedTime :: Column f UTCTime
  }
  deriving stock (Generic)
  deriving anyclass (Rel8able)

packageTagsSchema :: TableSchema (PackageTagRow Name)
packageTagsSchema = TableSchema
  { name = "package_tags"
  , columns = PackageTagRow
      { ptId = "package_tag_id"
      , ptPackageName = "package_name"
      , ptTag = "tag"
      , ptAssignedTime = "assigned_time"
      }
  }

-- ============================================================================
-- Tag Aliases Table
-- ============================================================================

-- | Tag aliases for tag normalization
--
-- Maps to: Tags.State.TagAlias
--
-- PRIMARY KEY (synthetic): taId
-- Each (tag, alias) pair is stored as a separate row.
data TagAliasRow f = TagAliasRow
  { taId    :: Column f Int64
  , taTag   :: Column f Text
  , taAlias :: Column f Text
  }
  deriving stock (Generic)
  deriving anyclass (Rel8able)

tagAliasesSchema :: TableSchema (TagAliasRow Name)
tagAliasesSchema = TableSchema
  { name = "tag_aliases"
  , columns = TagAliasRow
      { taId    = "tag_alias_id"
      , taTag   = "tag"
      , taAlias = "alias"
      }
  }

-- ============================================================================
-- Preferred Versions Table
-- ============================================================================

-- | Preferred/deprecated package versions
--
-- Maps to: PreferredVersions.State.PreferredVersions
-- Stores version range preferences.
-- Deprecated versions are stored in 'DeprecatedVersionRow'.
-- PRIMARY KEY (natural): pvPrefPackageName
data PreferredVersionRow f = PreferredVersionRow
  { pvPrefPackageName :: Column f PackageName
  , pvPrefVersionRange :: Column f Text      -- serialized VersionRange
  , pvPrefLastUpdated :: Column f UTCTime
  }
  deriving stock (Generic)
  deriving anyclass (Rel8able)

preferredVersionsSchema :: TableSchema (PreferredVersionRow Name)
preferredVersionsSchema = TableSchema
  { name = "preferred_versions"
  , columns = PreferredVersionRow
      { pvPrefPackageName = "package_name"
      , pvPrefVersionRange = "version_range"
      , pvPrefLastUpdated = "last_updated"
      }
  }

-- ============================================================================
-- Deprecated Versions Table
-- ============================================================================

-- | Deprecated package versions.
--
-- Maps to: PreferredVersions.State.PreferredInfo.deprecatedVersions
-- PRIMARY KEY (synthetic): depId
-- A package can have many deprecated versions, so each deprecated version
-- is a separate row. The (package_name, version) pair should be unique.
data DeprecatedVersionRow f = DeprecatedVersionRow
  { depId :: Column f Int64
  , depPackageName :: Column f PackageName
  , depVersion :: Column f Version
  }
  deriving stock (Generic)
  deriving anyclass (Rel8able)

deprecatedVersionsSchema :: TableSchema (DeprecatedVersionRow Name)
deprecatedVersionsSchema = TableSchema
  { name = "deprecated_versions"
  , columns = DeprecatedVersionRow
      { depId = "deprecated_version_id"
      , depPackageName = "package_name"
      , depVersion = "version"
      }
  }

-- ============================================================================
-- Documentation Table
-- ============================================================================

-- | Package documentation storage
--
-- Maps to: Documentation.State.Documentation
--
-- PRIMARY KEY (synthetic): docId
-- Each package can have one documentation entry. The package_id should
-- be unique to ensure each package has exactly one documentation record.
data DocumentationRow f = DocumentationRow
  { docId :: Column f Int64
  , docPackageId :: Column f Int32
  , docBlobId :: Column f BlobId
  , docStoredTime :: Column f UTCTime
  }
  deriving stock (Generic)
  deriving anyclass (Rel8able)

documentationSchema :: TableSchema (DocumentationRow Name)
documentationSchema = TableSchema
  { name = "documentation"
  , columns = DocumentationRow
      { docId = "documentation_id"
      , docPackageId = "package_id"
      , docBlobId = "blob_id"
      , docStoredTime = "stored_time"
      }
  }
