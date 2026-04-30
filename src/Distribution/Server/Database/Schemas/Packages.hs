{-# LANGUAGE DeriveAnyClass             #-}
{-# LANGUAGE DeriveGeneric              #-}
{-# LANGUAGE DeriveTraversable          #-}
{-# LANGUAGE DerivingStrategies         #-}
{-# LANGUAGE DerivingVia                #-}
{-# LANGUAGE FlexibleInstances          #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE MultiParamTypeClasses      #-}
{-# LANGUAGE NamedFieldPuns             #-}
{-# LANGUAGE OverloadedStrings          #-}
{-# LANGUAGE StandaloneDeriving         #-}
{-# LANGUAGE TypeApplications           #-}
{-# LANGUAGE TypeFamilies               #-}

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
    PkgInfoId(..)
  , PkgInfoRow(..)
  , pkgInfoSchema

  , MetadataRevisionRow(..)
  , metadataRevisionsSchema

  , TarballRevisionRow(..)

    -- * Package versions table
  , PackageVersionRow(..)
  , packageVersionsSchema

    -- * Package maintainers table (combines maintainers, trustees, uploaders)
  , PackageMaintainerRow(..)
  , packageMaintainersSchema

    -- * Package tags table
  , PackageTagRow(..)
  , packageTagsSchema

    -- * Tag aliases table
  , TagAliasRow(..)
  , tagAliasesSchema

    -- * Deprecated package versions table
  , DeprecatedVersionRow(..)
  , deprecatedVersionsSchema

    -- * Package documentation table
  , DocumentationRow(..)
  , documentationSchema

    -- * Package maintenance role type
  , MaintainerRole(..)
  ) where

import Distribution.Server.Features.Security.SHA256
import Distribution.Server.Packages.Types
import Distribution.Package (PackageName)
import Distribution.Types.Version (Version)
import Distribution.Server.Users.Types (UserId(..))
import Distribution.Server.Framework.BlobStorage (BlobId)

import Distribution.Server.Database.Schemas.Features ()
import Data.Int (Int32, Int64)
import Data.Text (Text)
import Data.Time (UTCTime)
import GHC.Generics (Generic)

import Rel8
  ( Rel8able
  , TableSchema(..)
  , Column
  )
import Distribution.Server.Framework.DB

newtype PkgInfoId = PkgInfoId { getPkgInfoId :: Int64 }
  deriving newtype (Eq, Ord, Show, Read, DBEq, DBOrd, DBType)

-- ============================================================================
-- Packages Table
-- ============================================================================

-- | Packages metadata table
--
-- Maps to: PackagesState.packageIndex (simplified)
-- Stores basic package information
-- PRIMARY KEY (natural): packageId
data PkgInfoRow f = PkgInfoRow
  { packageId :: Column f PkgInfoId
  , packageName :: Column f PackageName
  , packageVersion :: Column f Version
  }
  deriving stock (Generic)
  deriving anyclass (Rel8able)

pkgInfoSchema :: TableSchema (PkgInfoRow Name)
pkgInfoSchema = TableSchema
  { name = "pkginfos"
  , columns = PkgInfoRow
      { packageId = "id"
      , packageName = "name"
      , packageVersion = "version"
      }
  }


data MetadataRevisionRow f = MetadataRevisionRow
  { metadataPkgId :: Column f PkgInfoId
  , metadataRevId :: Column f MetadataRevIx
  , metadataTime :: Column f UTCTime
  , metadataUploader :: Column f UserId
  , metadataCabalFile :: Column f Text
  }
  deriving stock (Generic)
  deriving anyclass (Rel8able)


metadataRevisionsSchema :: TableSchema (MetadataRevisionRow Name)
metadataRevisionsSchema = TableSchema
  { name = "metadata_revs"
  , columns = MetadataRevisionRow
      { metadataPkgId = "pkgid"
      , metadataRevId = "rev"
      , metadataTime = "time"
      , metadataUploader = "uploader"
      , metadataCabalFile = "cabal_file"
      }
  }



data TarballRevisionRow f = TarballRevisionRow
  { tarballPkgId :: Column f PkgInfoId
  , tarballRevId :: Column f TarballRevIx
  , tarballTime :: Column f UTCTime
  , tarballUploader :: Column f UserId
  , tarballBlobGz   :: Column f BlobId
  , tarballBlobNoGz :: Column f BlobId
  , tarballLength :: Column f Int64
  , tarballHash :: Column f SHA256Digest
  }
  deriving stock (Generic)
  deriving anyclass (Rel8able)


packageTarballRevisionsSchema :: TableSchema (TarballRevisionRow Name)
packageTarballRevisionsSchema = TableSchema
  { name = "package_tarball_revisions"
  , columns = TarballRevisionRow
      { tarballPkgId = "pkgid"
      , tarballRevId = "rev"
      , tarballTime = "upload_time"
      , tarballUploader = "revised_by"
      , tarballBlobGz   = "blob_gz"
      , tarballBlobNoGz = "blob_nogz"
      , tarballLength = "tarball_length"
      , tarballHash = "tarball_hash"
      }
  }

-- TODO(sandy): works only accidentally; both are implemented as Ints but ought to be Int64s
deriving via UserId instance DBType MetadataRevIx
deriving via UserId instance DBType TarballRevIx


instance DBEq MetadataRevIx
instance DBOrd MetadataRevIx
instance DBEq TarballRevIx
instance DBOrd TarballRevIx

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
  deriving stock (Show, Read, Eq, Ord, Generic, Enum, Bounded)
  deriving (DBType) via ReadShow MaintainerRole
  deriving anyclass (DBEq)

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
