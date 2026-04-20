{-# LANGUAGE DuplicateRecordFields #-}
{-# LANGUAGE GADTs                 #-}
{-# LANGUAGE NamedFieldPuns        #-}
{-# LANGUAGE OverloadedStrings     #-}
{-# LANGUAGE RecordWildCards       #-}

-- | Export tool: reads existing acid-state databases and emits SQL INSERT
-- statements that populate the PostgreSQL tables defined in Database.Schemas.
--
-- Usage:  hackage-export [state-dir]
--   (default state-dir is "state")
--
module Main (main) where

import Control.Exception (bracket)
import Data.Foldable
import Distribution.Server.Database.Schemas.Users
import Distribution.Server.Database.Schemas.Packages
import Distribution.Server.Database.Schemas.Features

import Data.String (fromString)

import Data.Acid (openLocalStateFrom, query)
import Data.Int (Int32)
import Data.Time (UTCTime, Day, getCurrentTime)
import Distribution.Package
import Distribution.Server.Features.AdminLog.Acid
import Distribution.Server.Features.AdminLog.Types
import Distribution.Server.Features.AnalyticsPixels.State
import Distribution.Server.Features.AnalyticsPixels.Types
import Distribution.Server.Features.BuildReports.BuildReports
import Distribution.Server.Features.BuildReports.State
import Distribution.Server.Features.Core.State
import Distribution.Server.Features.Distro.Distributions
import Distribution.Server.Features.Distro.State
import Distribution.Server.Features.Documentation.State
import Distribution.Server.Features.DownloadCount.State
import Distribution.Server.Features.HaskellPlatform.State
import Distribution.Server.Features.LegacyPasswds.Acid
import Distribution.Server.Features.PackageCandidates.State
import Distribution.Server.Features.PackageCandidates.Types
import Distribution.Server.Features.PreferredVersions.State
import Distribution.Server.Features.Tags.State
import Distribution.Server.Features.Tags.Types
import Distribution.Server.Features.TarIndexCache.State
import Distribution.Server.Features.Upload.State
import Distribution.Server.Features.UserDetails.Acid
import Distribution.Server.Features.UserDetails.Types
import Distribution.Server.Features.UserNotify.Acid
import Distribution.Server.Features.UserSignup.Acid
import Distribution.Server.Features.UserSignup.Types
import Distribution.Server.Features.Votes.State
import Distribution.Server.Features.Vouch.State
import Distribution.Server.Framework.BlobStorage (BlobId)
import Distribution.Server.Packages.Types
import Distribution.Server.Users.State
import Distribution.Server.Users.Types
import Distribution.Server.Util.CountingMap
import Distribution.Server.Util.Nonce
import Distribution.Version (Version)

import Hasql.Connection
import qualified Hasql.Connection.Setting as DB
import qualified Hasql.Connection.Setting.Connection as DB


import qualified Data.ByteString.Lazy.Char8 as BS
import qualified Data.ByteString.Char8 as BS8
import qualified Data.IntMap as IntMap
import qualified Data.Map as Map
import qualified Data.Set as Set
import qualified Data.Text as T
import qualified Data.Vector as Vec
import qualified Distribution.Package as Pkg
import qualified Distribution.Pretty as Pretty
import qualified Distribution.Server.Features.BuildReports.BuildReports as BR
import qualified Distribution.Server.Features.LegacyPasswds.Auth as LegacyAuth
import qualified Distribution.Server.Packages.PackageIndex as PackageIndex
import qualified Distribution.Server.Users.UserIdSet as UserIdSet
import qualified Distribution.Server.Users.Users as Users

import Rel8 (Insert(..), OnConflict(..), Returning(..), lit, values, insert, showStatement, QualifiedName(..), TableSchema(..), Name)
import qualified Rel8

import System.Environment (getArgs)
import System.FilePath ((</>))

import Hasql.Session (run, sql, Session)

import Rel8.Table.Verify (showCreateTable)
import Unsafe.Coerce (unsafeCoerce)


withConn :: [DB.Setting] -> (Connection -> IO a) ->  IO a
withConn ss = bracket (acquire ss >>= either (error . show) pure) release



main :: IO ()
main = do
    args <- getArgs
    let stateDir = case args of
          [d] -> d
          _   -> "state"
    withConn (pure $ DB.connection $ DB.string "postgresql://sandy@/sandy") $ \conn -> do

      let create_tables =
            [ showCreateTable usersSchema
            , showCreateTable userRolesSchema
            , showCreateTable userAuthTokensSchema
            , showCreateTable packagesSchema
            , showCreateTable packageVersionsSchema
            , showCreateTable packageMaintainersSchema
            , showCreateTable packageTagsSchema
            , showCreateTable tagAliasesSchema
            , showCreateTable preferredVersionsSchema
            , showCreateTable deprecatedVersionsSchema
            , showCreateTable documentationSchema
            , showCreateTable votesSchema
            , showCreateTable buildReportsSchema
            , showCreateTable downloadCountsSchema
            , showCreateTable signupResetSchema
            , showCreateTable userNotifyPrefsSchema
            , showCreateTable adminLogSchema
            , showCreateTable tarIndexCacheSchema
            , showCreateTable analyticsPixelsSchema
            , showCreateTable legacyPasswdsSchema
            , showCreateTable haskellPlatformSchema
            , showCreateTable vouchesSchema
            , showCreateTable distrosSchema
            , showCreateTable mirrorClientsSchema
            ]

      for_ create_tables $ flip run conn . sql . BS8.pack

      flip run conn $ mkConstraints usersSchema $ PK userId
      flip run conn $ mkConstraints userRolesSchema $ PK userRoleId
      flip run conn $ mkConstraints userRolesSchema $ FK userRoleUserId usersSchema userId
      pure ()


--       sql <- exportAll stateDir
--       putStr sql


exportAll :: FilePath -> IO String
exportAll stateDir = do
    now <- getCurrentTime
    let dbDir = stateDir </> "db"

    usersH     <- openLocalStateFrom (dbDir </> "Users")             Users.emptyUsers
    detailsH   <- openLocalStateFrom (dbDir </> "UserDetails")       (UserDetailsTable IntMap.empty)
    adminsH    <- openLocalStateFrom (dbDir </> "HackageAdmins")     initialHackageAdmins
    trusteesH  <- openLocalStateFrom (dbDir </> "HackageTrustees")   initialHackageTrustees
    uploadersH <- openLocalStateFrom (dbDir </> "HackageUploaders")  initialHackageUploaders
    mirrorH    <- openLocalStateFrom (dbDir </> "MirrorClients")     initialMirrorClients

    packagesH     <- openLocalStateFrom (dbDir </> "PackagesState")      (initialPackagesState False)
    candidatesH   <- openLocalStateFrom (dbDir </> "CandidatePackages")  (initialCandidatePackages False)
    maintainersH  <- openLocalStateFrom (dbDir </> "PackageMaintainers") initialPackageMaintainers
    tagsH         <- openLocalStateFrom (dbDir </> "Tags" </> "Existing") initialPackageTags
    tagAliasH     <- openLocalStateFrom (dbDir </> "Tags" </> "Alias") emptyTagAlias
    prefVersionsH <- openLocalStateFrom (dbDir </> "PreferredVersions")  (initialPreferredVersions False)
    docsH         <- openLocalStateFrom (dbDir </> "Documentation")      initialDocumentation

    votesH        <- openLocalStateFrom (dbDir </> "Votes")              initialVotesState
    buildRepH     <- openLocalStateFrom (dbDir </> "BuildReports")       BR.emptyReports
    downloadH     <- openLocalStateFrom (dbDir </> "DownloadCount" </> "inmem")
                                                                         (initInMemStats (toEnum 0))
    signupH       <- openLocalStateFrom (dbDir </> "UserSignupReset")    (SignupResetTable Map.empty)
    initNotify    <- emptyNotifyData
    notifyH       <- openLocalStateFrom (dbDir </> "UserNotify")         initNotify
    adminLogH     <- openLocalStateFrom (dbDir </> "AdminLog")           initialAdminLog
    tarCacheH     <- openLocalStateFrom (dbDir </> "TarIndexCache")      initialTarIndexCache
    analyticsH    <- openLocalStateFrom (dbDir </> "AnalyticsPixels")    initialAnalyticsPixelsState
    legacyPwH     <- openLocalStateFrom (dbDir </> "LegacyPasswds")      (LegacyPasswdsTable IntMap.empty)
    platformH     <- openLocalStateFrom (dbDir </> "PlatformPackages")   initialPlatformPackages
    vouchH        <- openLocalStateFrom (dbDir </> "Vouch")              (VouchData Map.empty Set.empty)
    distrosH      <- openLocalStateFrom (dbDir </> "Distros")            initialDistros

    users                        <- query usersH     GetUserDb
    UserDetailsTable details     <- query detailsH   GetUserDetailsTable
    HackageAdmins adminSet       <- query adminsH    GetHackageAdmins
    HackageTrustees trusteeSet   <- query trusteesH  GetHackageTrustees
    HackageUploaders uploaderSet <- query uploadersH GetHackageUploaders
    MirrorClients mirrorSet      <- query mirrorH    GetMirrorClients

    packagesState                     <- query packagesH     GetPackagesState
    candidatePkgs                     <- query candidatesH   GetCandidatePackages
    PackageMaintainers mntrs          <- query maintainersH  AllPackageMaintainers
    PackageTags { packageTags = tagMap } <- query tagsH      GetPackageTags
    TagAlias aliasMap                     <- query tagAliasH   GetTagAliasesState
    prefVersions                      <- query prefVersionsH GetPreferredVersions
    Documentation docsMap             <- query docsH         GetDocumentation

    VotesState votesMap               <- query votesH        GetVotesState
    buildReports                      <- query buildRepH     GetBuildReports
    InMemStats dlDay dlCounts         <- query downloadH     GetInMemStats
    SignupResetTable signupMap        <- query signupH       GetSignupResetTable
    NotifyData (notifyMap, _)         <- query notifyH       GetNotifyData
    AdminLog logEntries               <- query adminLogH     GetAdminLog
    TarIndexCache tarCache            <- query tarCacheH     GetTarIndexCache
    AnalyticsPixelsState pixelMap     <- query analyticsH    GetAnalyticsPixelsState
    LegacyPasswdsTable legacyMap      <- query legacyPwH     GetLegacyPasswdsTable
    PlatformPackages platMap          <- query platformH     GetPlatformPackages
    vouchData                         <- query vouchH        GetVouchesData
    Distros{distVersions}             <- query distrosH      GetDistributions

    let allPkgs    = PackageIndex.allPackages (packageIndex packagesState)
        allCands   = map candPkgInfo $ PackageIndex.allPackages (candidateList candidatePkgs)
        migrated   = candidateMigratedPkgTarball candidatePkgs
        pkgNameMap = buildPkgNameMap allPkgs

    let stmts = [ mkInsertUsers users details now
                , mkInsertUserRoles adminSet trusteeSet uploaderSet mirrorSet now
                , mkInsertUserAuthTokens users now
                , mkInsertPackages pkgNameMap now
                , mkInsertPackageVersions pkgNameMap allPkgs allCands migrated
                , mkInsertPackageMaintainers mntrs now
                , mkInsertPackageTags tagMap now
                , mkInsertTagAliases aliasMap
                , mkInsertPreferredVersions prefVersions now
                , mkInsertDeprecatedVersions prefVersions
                , mkInsertDocumentation pkgNameMap docsMap now
                , mkInsertVotes votesMap now
                , mkInsertBuildReports buildReports now
                , mkInsertDownloadCounts dlDay dlCounts
                , mkInsertSignupReset signupMap
                , mkInsertUserNotifications notifyMap
                , mkInsertAdminLog logEntries
                , mkInsertTarIndexCache tarCache
                , mkInsertAnalyticsPixels pixelMap now
                , mkInsertLegacyPasswords legacyMap
                , mkInsertHaskellPlatform platMap
                , mkInsertVouches vouchData
                , mkInsertDistros distVersions
                , mkInsertMirrorClients mirrorSet now
                ]
    pure $ unlines [ showStatement (insert s) ++ ";" | s <- stmts ]


mkInsertUsers :: Users.Users -> IntMap.IntMap AccountDetails -> UTCTime -> Insert ()
mkInsertUsers users details now = Insert
    { into = usersSchema
    , rows = values $ do
        (uid@(UserId rawId), uinfo) <- Users.enumerateAllUsers users
        let UserInfo { userName = uname, userStatus = ustatus, userTokens = _utokens } = uinfo
            acct    = IntMap.lookup rawId details
            email   = fmap accountContactEmail acct
            realNm  = fmap accountName acct
            kind    = acct >>= accountKind
            notes   = maybe T.empty accountAdminNotes acct
            enabled = case ustatus of
                        AccountEnabled{}  -> True
                        AccountDisabled{} -> False
                        AccountDeleted    -> False
            passwd  = case ustatus of
                        AccountEnabled  (UserAuth h)        -> h
                        AccountDisabled (Just (UserAuth h)) -> h
                        _                                   -> PasswdHash ""
        pure $ lit UsersRow
          { userId          = uid
          , userName        = uname
          , userEmail       = email
          , userRealName    = realNm
          , userAuth        = passwd
          , userEnabled     = enabled
          , userAccountKind = kind
          , userAdminNotes  = notes
          , userCreatedTime = now
          }
    , onConflict = Abort
    , returning  = NoReturning
    }


mkInsertUserRoles :: UserIdSet.UserIdSet -> UserIdSet.UserIdSet
                  -> UserIdSet.UserIdSet -> UserIdSet.UserIdSet
                  -> UTCTime -> Insert ()
mkInsertUserRoles adminSet trusteeSet uploaderSet mirrorSet now = Insert
    { into = userRolesSchema
    , rows = values $ zipWith mkRow [1..] allEntries
    , onConflict = Abort
    , returning  = NoReturning
    }
  where
    allEntries :: [(UserId, UserRole)]
    allEntries =
         [ (uid, Admin)        | uid <- UserIdSet.toList adminSet    ]
      ++ [ (uid, Trustee)      | uid <- UserIdSet.toList trusteeSet  ]
      ++ [ (uid, Uploader)     | uid <- UserIdSet.toList uploaderSet ]
      ++ [ (uid, MirrorClient) | uid <- UserIdSet.toList mirrorSet   ]

    mkRow i (uid, role) = lit UserRoleRow
      { userRoleId           = i
      , userRoleUserId       = uid
      , userRoleRole         = role
      , userRoleAssignedTime = now
      }


mkInsertUserAuthTokens :: Users.Users -> UTCTime -> Insert ()
mkInsertUserAuthTokens users now = Insert
    { into = userAuthTokensSchema
    , rows = values $ do
        (uid, uinfo) <- Users.enumerateAllUsers users
        let UserInfo { userTokens = tokens } = uinfo
        (token, desc) <- Map.toList tokens
        pure $ lit UserAuthTokenRow
          { authTokenUserId      = uid
          , authTokenToken       = token
          , authTokenDescription = Just desc
          , authTokenCreatedTime = now
          }
    , onConflict = Abort
    , returning  = NoReturning
    }


-- ---------------------------------------------------------------------------
-- Helper: package name → synthetic Int32 id mapping
-- ---------------------------------------------------------------------------

type PkgNameMap = Map.Map PackageName Int32

buildPkgNameMap :: [PkgInfo] -> PkgNameMap
buildPkgNameMap pkgs =
    Map.fromList $ zip names [1..]
  where
    names = Set.toAscList $ Set.fromList $ map (Pkg.packageName . pkgInfoId) pkgs


-- ---------------------------------------------------------------------------
-- Packages
-- ---------------------------------------------------------------------------

mkInsertPackages :: PkgNameMap -> UTCTime -> Insert ()
mkInsertPackages nameMap now = Insert
    { into = packagesSchema
    , rows = values $ do
        (pn, pid) <- Map.toAscList nameMap
        pure $ lit PackageRow
          { packageId          = pid
          , packageName        = T.pack (Pretty.prettyShow pn)
          , packageLastUpdated = now
          }
    , onConflict = Abort
    , returning  = NoReturning
    }


-- ---------------------------------------------------------------------------
-- Package Versions
-- ---------------------------------------------------------------------------

mkInsertPackageVersions :: PkgNameMap -> [PkgInfo] -> [PkgInfo] -> Bool -> Insert ()
mkInsertPackageVersions nameMap released candidates migrated = Insert
    { into = packageVersionsSchema
    , rows = values $ zipWith mkRow [1..] (relRows ++ candRows)
    , onConflict = Abort
    , returning  = NoReturning
    }
  where
    relRows = do
      pkg <- released
      let pid   = pkgInfoId pkg
          name  = Pkg.packageName pid
          ver   = packageVersion pid
      pkgDbId <- maybe [] pure (Map.lookup name nameMap)
      let (ut, ub) = pkgUploadInfo pkg
          tarBlob  = extractTarBlobId pkg
      pure (pkgDbId, ver, ub, ut, tarBlob, tarBlob, False, False)

    candRows = do
      pkg <- candidates
      let pid   = pkgInfoId pkg
          name  = Pkg.packageName pid
          ver   = packageVersion pid
      pkgDbId <- maybe [] pure (Map.lookup name nameMap)
      let (ut, ub) = pkgUploadInfo pkg
          tarBlob  = extractTarBlobId pkg
      pure (pkgDbId, ver, ub, ut, tarBlob, tarBlob, True, migrated)

    mkRow i (pkgDbId, ver, upBy, upTime, tarBlob, cabBlob, isCand, migFlag) =
      lit PackageVersionRow
        { pvId            = i
        , pvPackageId     = pkgDbId
        , pvVersion       = ver
        , pvUploadedBy    = upBy
        , pvUploadTime    = upTime
        , pvTarballBlob   = tarBlob
        , pvCabalBlob     = cabBlob
        , pvIsCandidate   = isCand
        , pvMigrationFlag = migFlag
        }

pkgUploadInfo :: PkgInfo -> (UTCTime, UserId)
pkgUploadInfo pkg = snd (Vec.last (pkgMetadataRevisions pkg))

extractTarBlobId :: PkgInfo -> BlobId
extractTarBlobId pkg =
    case Vec.toList (pkgTarballRevisions pkg) of
      ((PkgTarball binfo _, _):_) -> blobInfoId binfo
      _                           -> error $ "No tarball for " ++ show (pkgInfoId pkg)


-- ---------------------------------------------------------------------------
-- Package Maintainers
-- ---------------------------------------------------------------------------

mkInsertPackageMaintainers :: Map.Map PackageName UserIdSet.UserIdSet
                           -> UTCTime -> Insert ()
mkInsertPackageMaintainers mntrs now = Insert
    { into = packageMaintainersSchema
    , rows = values $ zipWith mkRow [1..] entries
    , onConflict = Abort
    , returning  = NoReturning
    }
  where
    entries = [ (pn, uid) | (pn, uidSet) <- Map.toList mntrs
                          , uid <- UserIdSet.toList uidSet ]
    mkRow i (pn, uid) = lit PackageMaintainerRow
      { pmId           = i
      , pmPackageName  = pn
      , pmUserId       = uid
      , pmRole         = PackageMaintainer
      , pmAssignedTime = now
      }


-- ---------------------------------------------------------------------------
-- Package Tags
-- ---------------------------------------------------------------------------

mkInsertPackageTags :: Map.Map PackageName (Set.Set Tag) -> UTCTime -> Insert ()
mkInsertPackageTags tagMap now = Insert
    { into = packageTagsSchema
    , rows = values $ zipWith mkRow [1..] entries
    , onConflict = Abort
    , returning  = NoReturning
    }
  where
    entries = [ (pn, tag) | (pn, tags) <- Map.toList tagMap
                          , tag <- Set.toList tags ]
    mkRow i (pn, Tag t) = lit PackageTagRow
      { ptId           = i
      , ptPackageName  = pn
      , ptTag          = T.pack t
      , ptAssignedTime = now
      }


-- ---------------------------------------------------------------------------
-- Tag Aliases
-- ---------------------------------------------------------------------------

mkInsertTagAliases :: Map.Map Tag (Set.Set Tag) -> Insert ()
mkInsertTagAliases aliasMap = Insert
    { into = tagAliasesSchema
    , rows = values $ zipWith mkRow [1..] entries
    , onConflict = Abort
    , returning  = NoReturning
    }
  where
    entries = [ (tag, alias) | (tag, aliases) <- Map.toList aliasMap
                             , alias <- Set.toList aliases ]
    mkRow i (Tag t, Tag a) = lit TagAliasRow
      { taId    = i
      , taTag   = T.pack t
      , taAlias = T.pack a
      }


-- ---------------------------------------------------------------------------
-- Preferred Versions
-- ---------------------------------------------------------------------------

mkInsertPreferredVersions :: PreferredVersions -> UTCTime -> Insert ()
mkInsertPreferredVersions PreferredVersions{preferredMap} now = Insert
    { into = preferredVersionsSchema
    , rows = values $ do
        (pn, info) <- Map.toList preferredMap
        pure $ lit PreferredVersionRow
          { pvPrefPackageName  = pn
          , pvPrefVersionRange = T.pack (show (preferredRanges info))
          , pvPrefLastUpdated  = now
          }
    , onConflict = Abort
    , returning  = NoReturning
    }


-- ---------------------------------------------------------------------------
-- Deprecated Versions
-- ---------------------------------------------------------------------------

mkInsertDeprecatedVersions :: PreferredVersions -> Insert ()
mkInsertDeprecatedVersions PreferredVersions{preferredMap} = Insert
    { into = deprecatedVersionsSchema
    , rows = values $ zipWith mkRow [1..] entries
    , onConflict = Abort
    , returning  = NoReturning
    }
  where
    entries = [ (pn, v) | (pn, info) <- Map.toList preferredMap
                        , v <- deprecatedVersions info ]
    mkRow i (pn, v) = lit DeprecatedVersionRow
      { depId          = i
      , depPackageName = pn
      , depVersion     = v
      }


-- ---------------------------------------------------------------------------
-- Documentation
-- ---------------------------------------------------------------------------

mkInsertDocumentation :: PkgNameMap -> Map.Map PackageIdentifier BlobId
                      -> UTCTime -> Insert ()
mkInsertDocumentation nameMap docsMap now = Insert
    { into = documentationSchema
    , rows = values $ zipWith mkRow [1..] entries
    , onConflict = Abort
    , returning  = NoReturning
    }
  where
    entries = [ (pkgDbId, blob)
              | (pkgIdent, blob) <- Map.toList docsMap
              , pkgDbId <- maybe [] pure (Map.lookup (Pkg.packageName pkgIdent) nameMap) ]
    mkRow i (pkgDbId, blob) = lit DocumentationRow
      { docId         = i
      , docPackageId  = pkgDbId
      , docBlobId     = blob
      , docStoredTime = now
      }


-- ---------------------------------------------------------------------------
-- Votes
-- ---------------------------------------------------------------------------

mkInsertVotes :: Map.Map PackageName (Map.Map UserId Int) -> UTCTime -> Insert ()
mkInsertVotes votesMap now = Insert
    { into = votesSchema
    , rows = values $ do
        (pn, userVotes) <- Map.toList votesMap
        (uid, score) <- Map.toList userVotes
        pure $ lit VoteRow
          { votePackageName = pn
          , voteUserId      = uid
          , voteScore       = fromIntegral score
          , voteTime        = now
          }
    , onConflict = Abort
    , returning  = NoReturning
    }


-- ---------------------------------------------------------------------------
-- Build Reports
-- ---------------------------------------------------------------------------

mkInsertBuildReports :: BuildReports -> UTCTime -> Insert ()
mkInsertBuildReports BuildReports{reportsIndex} now = Insert
    { into = buildReportsSchema
    , rows = values $ zipWith mkRow [1..] entries
    , onConflict = Abort
    , returning  = NoReturning
    }
  where
    entries = [ (pkgId, rid, rpt, mBuildLog, mTestLog, mCovg)
              | (pkgId, pkgRpts) <- Map.toList reportsIndex
              , (BuildReportId rid, (rpt, mBuildLog, mTestLog, mCovg)) <- Map.toList (reports pkgRpts) ]
    mkRow i (pkgId, rid, rpt, mBuildLog, mTestLog, _mCovg) = lit BuildReportRow
      { brId             = i
      , brPackageName    = Pkg.pkgName pkgId
      , brPackageVersion = packageVersion pkgId
      , brReportId       = fromIntegral rid
      , brReport     = T.pack (show rpt)
      , brBuildLog   = fmap (\(BuildLog b) -> b) mBuildLog
      , brTestLog    = fmap (\(TestLog b) -> b) mTestLog
      , brCoverage   = Nothing  -- TODO: BuildCovg is a parsed record, not a BlobId; need to decide how to serialize
      , brReportTime = now
      }


-- ---------------------------------------------------------------------------
-- Download Counts
-- ---------------------------------------------------------------------------

mkInsertDownloadCounts :: Day -> SimpleCountingMap PackageId -> Insert ()
mkInsertDownloadCounts day counts = Insert
    { into = downloadCountsSchema
    , rows = values $ zipWith mkRow [1..] (cmToList counts)
    , onConflict = Abort
    , returning  = NoReturning
    }
  where
    mkRow i (pkgId, count) = lit DownloadCountRow
      { dcId             = i
      , dcPackageName    = Pkg.pkgName pkgId
      , dcPackageVersion = packageVersion pkgId
      , dcDay            = day
      , dcCount          = fromIntegral count
      }


-- ---------------------------------------------------------------------------
-- Signup / Reset
-- ---------------------------------------------------------------------------

mkInsertSignupReset :: Map.Map Nonce SignupResetInfo -> Insert ()
mkInsertSignupReset signupMap = Insert
    { into = signupResetSchema
    , rows = values $ zipWith mkRow [1..] (Map.toList signupMap)
    , onConflict = Abort
    , returning  = NoReturning
    }
  where
    mkRow i (nonce, info) =
      let nonceText = T.pack (renderNonce nonce)
      in case info of
        SignupInfo{..} -> lit SignupResetRow
          { srId          = i
          , srNonce        = nonceText
          , srUserName     = UserName (T.unpack signupUserName)
          , srRealName     = signupRealName
          , srEmail        = signupContactEmail
          , srCaptcha      = Nothing
          , srRequestTime  = nonceTimestamp
          , srExpires      = nonceTimestamp
          , srIsReset      = False
          }
        ResetInfo{..} -> lit SignupResetRow
          { srId          = i
          , srNonce        = nonceText
          , srUserName     = UserName ""
          , srRealName     = T.empty
          , srEmail        = T.empty
          , srCaptcha      = Nothing
          , srRequestTime  = nonceTimestamp
          , srExpires      = nonceTimestamp
          , srIsReset      = True
          }


-- ---------------------------------------------------------------------------
-- User Notifications
-- ---------------------------------------------------------------------------

mkInsertUserNotifications :: Map.Map UserId NotifyPref -> Insert ()
mkInsertUserNotifications notifyMap = Insert
    { into = userNotifyPrefsSchema
    , rows = values $ do
        (uid, NotifyPref{..}) <- Map.toList notifyMap
        pure $ lit UserNotifyPrefRow
          { unpUserId                  = uid
          , unpOptOut                  = notifyOptOut
          , unpRevisionRange           = notifyRevisionRange
          , unpUpload                  = notifyUpload
          , unpMaintainerGroup         = notifyMaintainerGroup
          , unpDocBuilderReport        = notifyDocBuilderReport
          , unpPendingTags             = notifyPendingTags
          , unpDependencyForMaintained = notifyDependencyForMaintained
          , unpDependencyTriggerBounds = notifyDependencyTriggerBounds
          }
    , onConflict = Abort
    , returning  = NoReturning
    }


-- ---------------------------------------------------------------------------
-- Admin Log
-- ---------------------------------------------------------------------------

mkInsertAdminLog :: [(UTCTime, UserId, AdminAction, BS.ByteString)] -> Insert ()
mkInsertAdminLog logEntries = Insert
    { into = adminLogSchema
    , rows = values $ zipWith mkRow [1..] logEntries
    , onConflict = Abort
    , returning  = NoReturning
    }
  where
    mkRow i (time, uid, action, reason) = lit AdminLogRow
      { alId     = i
      , alTime   = time
      , alUserId = uid
      , alAction = T.pack (show action)
      , alReason = T.pack (BS.unpack reason)
      }


-- ---------------------------------------------------------------------------
-- Tar Index Cache
-- ---------------------------------------------------------------------------

mkInsertTarIndexCache :: Map.Map BlobId BlobId -> Insert ()
mkInsertTarIndexCache cacheMap = Insert
    { into = tarIndexCacheSchema
    , rows = values $ do
        (tarBlob, idxBlob) <- Map.toList cacheMap
        pure $ lit TarIndexCacheRow
          { ticTarBlobId   = tarBlob
          , ticIndexBlobId = idxBlob
          }
    , onConflict = Abort
    , returning  = NoReturning
    }


-- ---------------------------------------------------------------------------
-- Analytics Pixels
-- ---------------------------------------------------------------------------

mkInsertAnalyticsPixels :: Map.Map PackageName (Set.Set AnalyticsPixel)
                        -> UTCTime -> Insert ()
mkInsertAnalyticsPixels pixelMap now = Insert
    { into = analyticsPixelsSchema
    , rows = values $ zipWith mkRow [1..] entries
    , onConflict = Abort
    , returning  = NoReturning
    }
  where
    entries = [ px | (_pn, pxs) <- Map.toList pixelMap
                   , px <- Set.toList pxs ]
    mkRow i (AnalyticsPixel url) = lit AnalyticsPixelRow
      { apPixelId   = i
      , apContent   = url
      , apAddedTime = now
      }


-- ---------------------------------------------------------------------------
-- Legacy Passwords
-- ---------------------------------------------------------------------------

mkInsertLegacyPasswords :: IntMap.IntMap LegacyAuth.HtPasswdHash -> Insert ()
mkInsertLegacyPasswords legacyMap = Insert
    { into = legacyPasswdsSchema
    , rows = values $ zipWith mkRow [1..] (IntMap.toList legacyMap)
    , onConflict = Abort
    , returning  = NoReturning
    }
  where
    mkRow i (rawUid, LegacyAuth.HtPasswdHash s) = lit LegacyPasswdRow
      { lpId         = i
      , lpUserId     = UserId rawUid
      , lpPasswdHash = PasswdHash s
      }


-- ---------------------------------------------------------------------------
-- Haskell Platform
-- ---------------------------------------------------------------------------

mkInsertHaskellPlatform :: Map.Map PackageName (Set.Set Version) -> Insert ()
mkInsertHaskellPlatform platMap = Insert
    { into = haskellPlatformSchema
    , rows = values $ zipWith mkRow [1..] entries
    , onConflict = Abort
    , returning  = NoReturning
    }
  where
    entries = [ (pn, v) | (pn, vs) <- Map.toList platMap
                        , v <- Set.toList vs ]
    mkRow i (pn, v) = lit HaskellPlatformRow
      { hpId          = i
      , hpPackageName = pn
      , hpVersion     = v
      , hpIncluded    = True
      }


-- ---------------------------------------------------------------------------
-- Vouches
-- ---------------------------------------------------------------------------

mkInsertVouches :: VouchData -> Insert ()
mkInsertVouches VouchData{vouches=vouchMap, notNotified} = Insert
    { into = vouchesSchema
    , rows = values $ zipWith mkRow [1..] entries
    , onConflict = Abort
    , returning  = NoReturning
    }
  where
    entries = [ (vouchee, voucher, time)
              | (vouchee, vs) <- Map.toList vouchMap
              , (voucher, time) <- vs ]
    mkRow i (vouchee, voucher, time) = lit VouchRow
      { vId       = i
      , vVouchee  = vouchee
      , vVoucher  = voucher
      , vTime     = time
      , vNotified = not (Set.member vouchee notNotified)
      }


-- ---------------------------------------------------------------------------
-- Distros
-- ---------------------------------------------------------------------------

mkInsertDistros :: DistroVersions -> Insert ()
mkInsertDistros DistroVersions{packageDistroMap} = Insert
    { into = distrosSchema
    , rows = values $ zipWith mkRow [1..] entries
    , onConflict = Abort
    , returning  = NoReturning
    }
  where
    entries = [ (pn, dn, dpi) | (pn, dm) <- Map.toList packageDistroMap
                              , (dn, dpi) <- Map.toList dm ]
    mkRow i (pn, DistroName dn, DistroPackageInfo{distroVersion=dv, distroUrl=durl}) =
      lit DistroRow
        { distId             = i
        , distName           = T.pack dn
        , distVersion        = T.pack durl
        , distPackageName    = pn
        , distPackageVersion = dv
        , distMaintainer     = Nothing
        }


-- ---------------------------------------------------------------------------
-- Mirror Clients
-- ---------------------------------------------------------------------------

mkInsertMirrorClients :: UserIdSet.UserIdSet -> UTCTime -> Insert ()
mkInsertMirrorClients mirrorSet now = Insert
    { into = mirrorClientsSchema
    , rows = values $ zipWith mkRow [1..] (UserIdSet.toList mirrorSet)
    , onConflict = Abort
    , returning  = NoReturning
    }
  where
    mkRow i uid = lit MirrorClientRow
      { mcId             = i
      , mcUserId         = uid
      , mcRegisteredTime = now
      }
