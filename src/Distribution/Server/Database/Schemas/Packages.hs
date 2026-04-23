{-# LANGUAGE DeriveAnyClass             #-}
{-# LANGUAGE DeriveGeneric              #-}
{-# LANGUAGE DeriveTraversable          #-}
{-# LANGUAGE DerivingStrategies         #-}
{-# LANGUAGE DerivingVia                #-}
{-# LANGUAGE FlexibleContexts           #-}
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
  ( PackageId'(..)
  , toPackageIdentifier
  , fromPackageIdentifier
  , eqPackageId

    -- * Package versions table
  , PackageVersionRow(..)
  , packageVersionsSchema

    -- * Package maintainers table (combines maintainers, trustees, uploaders)
  , PackageMaintainerRow(..)
  , packageMaintainersSchema

  , MetadataRevisionId
  , PackageMetadataRevisionsRow(..)
  , packageMetadataRevisionsSchema

  , TarballRevisionId
  , PackageTarballRevisionsRow(..)
  , packageTarballRevisionsSchema

    -- * Package tags table
  , PackageTagRow(..)
  , packageTagsSchema

    -- * Tag aliases table
  , TagAliasRow(..)
  , tagAliasesSchema

    -- * Package preferred versions table
  , PreferredVersionRow(..)
  , preferredVersionsSchema

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
import Data.ByteString (StrictByteString)
import Distribution.Server.Database.Schemas.Users (usersSchema, UsersRow(userId))
import Rel8.CreateTable
import Distribution.Package (PackageName, PackageIdentifier(..))
import Distribution.Version (VersionRange)
import Distribution.Types.Version (Version)
import Distribution.Server.Users.Types (UserId)
import Distribution.Server.Framework.BlobStorage (BlobId)

import Distribution.Server.Database.Schemas.Features ()
import Data.Int (Int32, Int64)
import Data.Text (Text)
import Data.Time (UTCTime)
import GHC.Generics (Generic)
import Data.Functor.Contravariant (contramap)
import Distribution.Server.Framework.DB
import qualified Data.Text as T

import Rel8
  ( Name
  , Rel8able
  , TableSchema(..)
  , Column
  , DBType(..)
  , encode
  , decode
  )

-- | Isomorphic to 'PackageIdentifier', but more amenable to being worked with
-- in Rel8.
data PackageId' f = PackageId'
  { pkgIdName :: Column f PackageName
  , pkgIdVersion :: Column f Version
  }
  deriving stock (Generic)
  deriving anyclass (Rel8able)

deriving via String instance DBEq PackageName
deriving via String instance DBEq Version


toPackageIdentifier :: PackageId' Result -> PackageIdentifier
toPackageIdentifier (PackageId' name version) = PackageIdentifier name version

fromPackageIdentifier :: PackageIdentifier -> PackageId' Result
fromPackageIdentifier (PackageIdentifier name version) = PackageId' name version

eqPackageId
    :: (DBEq PackageName, DBEq Version)
    => PackageId' Expr
    -> PackageIdentifier
    -> Expr Bool
eqPackageId pkgId (PackageIdentifier pkg ver) =
  pkgIdName pkgId ==. lit pkg &&. pkgIdVersion pkgId ==. lit ver


packageIdNames :: PackageId' Name
packageIdNames = PackageId'
  { pkgIdName = "package_id"
  , pkgIdVersion = "package_version"
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
  { pvPackage :: PackageId' f
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
      { pvPackage = packageIdNames
      , pvUploadedBy = "uploaded_by"
      , pvUploadTime = "upload_time"
      , pvTarballBlob = "tarball_blob"
      , pvCabalBlob = "cabal_blob"
      , pvIsCandidate = "is_candidate"
      , pvMigrationFlag = "migration_flag"
      }
  }


packageVersionsTable :: DbTable PackageVersionRow
packageVersionsTable = DbTable packageVersionsSchema
  [ -- PK pvId
  ]

newtype MetadataRevisionId = MetadataRevisionId Int64
  deriving newtype (Eq, Ord, Show, DBType, DBEq, DBOrd, DBAutoInc)

data PackageMetadataRevisionsRow f = PackageMetadataRevisionsRow
  { pmrId :: Column f MetadataRevisionId
  , pmrPackage :: PackageId' f
  , pmrTime :: Column f UTCTime
  , pmrReviser :: Column f UserId
  , pmrCabalFile :: Column f StrictByteString
  }
  deriving stock (Generic)
  deriving anyclass (Rel8able)

packageMetadataRevisionsSchema :: TableSchema (PackageMetadataRevisionsRow Name)
packageMetadataRevisionsSchema = TableSchema
  { name = "package_metadata_revisions"
  , columns = PackageMetadataRevisionsRow
      { pmrId = "metadata_revision_id"
      , pmrPackage = packageIdNames
      , pmrTime = "upload_time"
      , pmrReviser = "revised_by"
      , pmrCabalFile = "cabal_file"
      }
  }


newtype TarballRevisionId = TarballRevisionId Int64
  deriving newtype (Eq, Ord, Show, DBType, DBEq, DBOrd, DBAutoInc)


data PackageTarballRevisionsRow f = PackageTarballRevisionsRow
  { ptrId :: Column f MetadataRevisionId
  , ptrPackage :: PackageId' f
  , ptrTime :: Column f UTCTime
  , ptrReviser :: Column f UserId
  , ptrTarballBlobGz   :: Column f BlobId
  , ptrTarballBlobNoGz :: Column f BlobId
  , ptrTarballLength :: Column f Int64
  , ptrTarballHash :: Column f SHA256Digest
  }
  deriving stock (Generic)
  deriving anyclass (Rel8able)


packageTarballRevisionsSchema :: TableSchema (PackageTarballRevisionsRow Name)
packageTarballRevisionsSchema = TableSchema
  { name = "package_tarball_revisions"
  , columns = PackageTarballRevisionsRow
      { ptrId = "metadata_revision_id"
      , ptrPackage = packageIdNames
      , ptrTime = "upload_time"
      , ptrReviser = "revised_by"
      , ptrTarballBlobGz   = "blob_gz"
      , ptrTarballBlobNoGz = "blob_nogz"
      , ptrTarballLength = "tarball_length"
      , ptrTarballHash = "tarball_hash"
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
  deriving (DBEq, DBType) via ViaEnum MaintainerRole

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


packageMaintainersTable :: DbTable PackageMaintainerRow
packageMaintainersTable = DbTable packageMaintainersSchema
  [ PK pmId
  , FK pmUserId usersSchema userId
  ]

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
  , pvPrefVersionRange :: Column f VersionRange
  , pvPrefLastUpdated :: Column f UTCTime
  }
  deriving stock (Generic)
  deriving anyclass (Rel8able)

instance DBType VersionRange where
  typeInformation =
      let ti = typeInformation @Text
       in ti { encode = contramap (T.pack . show) $ encode ti
             , decode = fmap (read . T.unpack) $ decode ti
             }


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
  { depPkgId :: PackageId' f
  }
  deriving stock (Generic)
  deriving anyclass (Rel8able)

deprecatedVersionsSchema :: TableSchema (DeprecatedVersionRow Name)
deprecatedVersionsSchema = TableSchema
  { name = "deprecated_versions"
  , columns = DeprecatedVersionRow
      { depPkgId = packageIdNames
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
  { docPkgId :: PackageId' f
  , docBlobId :: Column f BlobId
  , docStoredTime :: Column f UTCTime
  }
  deriving stock (Generic)
  deriving anyclass (Rel8able)

documentationSchema :: TableSchema (DocumentationRow Name)
documentationSchema = TableSchema
  { name = "documentation"
  , columns = DocumentationRow
      { docPkgId = packageIdNames
      , docBlobId = "blob_id"
      , docStoredTime = "stored_time"
      }
  }
