{-# LANGUAGE TemplateHaskell #-}

-- | Database schema definitions for Hackage Server PostgreSQL migration
--
-- This module provides rel8-based schema definitions that map from the
-- current acid-state implementation to PostgreSQL tables. This is STEP 1
-- of the acid-state → PostgreSQL migration, focusing on schema design only.
--
-- The schema is organized into three main categories:
--
-- 1. **Users**: Consolidated from 5 acid-state types into 3 tables
--    - Users and their metadata
--    - Role assignments (admin, trustee, uploader, mirror_client)
--    - Authentication tokens
--
-- 2. **Packages**: Consolidated from 7 acid-state types into 4 tables
--    - Package metadata and versions (released and candidates)
--    - Maintenance relationships
--    - Version preferences and documentation
--    - Tags and categorization
--
-- 3. **Features**: Individual tables for feature-specific data
--    - Votes, build reports, download counts
--    - User signup/reset, notifications
--    - Admin logs, analytics, security state
--    - And more (15 feature-specific tables total)
--
-- == Consolidation Strategy
--
-- Where possible, semantically related acid-state types are consolidated
-- into normalized relational tables:
--
-- - User data: @Users.Users@, @HackageAdmins@, @HackageUploaders@, etc.
--   become a single @users@ table with a @user_roles@ junction table
--
-- - Package data: @PackagesState@ and @CandidatePackages@ merge into
--   @package_versions@ with an @is_candidate@ flag
--
-- - Features: Most remain as individual tables due to independence
--
-- == Serialization
--
-- Complex Haskell types that don't naturally decompose into columns are
-- stored as serialized Text values (currently using Haskell Show format,
-- upgradeable to JSON/CBOR in STEP 2). Examples:
--
-- - @UserAuth@ serialized in the users table
-- - @VersionRange@ serialized in preferred_versions
-- - @AdminAction@ serialized in admin_log
--
-- This approach preserves type safety during the initial migration while
-- allowing for gradual normalization in future steps.
--
-- == File Organization
--
-- - "Distribution.Server.Database.Schemas.Users" — User-related tables
-- - "Distribution.Server.Database.Schemas.Packages" — Package-related tables
-- - "Distribution.Server.Database.Schemas.Features" — Feature-specific tables
--
-- See SCHEMA_DESIGN.md for complete documentation of the mapping from
-- acid-state types to relational schemas.
--
module Distribution.Server.Database.Schemas
  ( -- * Re-exports from Users module
    module Distribution.Server.Database.Schemas.Users
    
    -- * Re-exports from Packages module
  , module Distribution.Server.Database.Schemas.Packages
    
    -- * Re-exports from Features module
  , module Distribution.Server.Database.Schemas.Features
  ) where

import Distribution.Server.Database.Schemas.Users
import Distribution.Server.Database.Schemas.Packages
import Distribution.Server.Database.Schemas.Features
