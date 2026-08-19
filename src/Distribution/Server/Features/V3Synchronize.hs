{-# LANGUAGE NamedFieldPuns                  #-}
{-# LANGUAGE TypeApplications                #-}
{-# OPTIONS_GHC -Wno-incomplete-uni-patterns #-}

module Distribution.Server.Features.V3Synchronize (
    V3SynchronizeFeature(..),
    initV3SynchronizeFeature,
  ) where

import Data.Foldable
import Data.Proxy (Proxy(..))
import Distribution.Server.Features.Core
import Distribution.Server.Features.Users
import Distribution.Server.Framework
import Distribution.Server.Users.Types (unUserId, unUserName)
import Hackage.SyncAPI.Type
import Hackage.Types
import Network.HTTP.Client (newManager, defaultManagerSettings)
import Servant.API.NamedRoutes
import Servant.Client
import qualified Data.Text as T
import qualified Distribution.Server.Framework.BlobStorage as BlobStorage
import Distribution.Server.Packages.Types (CabalFileText(..), BlobInfo(..), PkgTarball(..), PkgInfo(..), getMetadataRevIx, getTarballRevIx)
import qualified Data.Vector as V


data V3SynchronizeFeature = V3SynchronizeFeature
  { v3SynchronizeFeatureInterface :: HackageFeature
  }

instance IsHackageFeature V3SynchronizeFeature where
  getFeatureInterface = v3SynchronizeFeatureInterface


syncClient :: SyncApi (AsClientT ClientM)
syncClient = client (Proxy @(NamedRoutes SyncApi))


-- | Convert a 'BlobStorage.BlobId' into a 'BlobId'.
toSyncBlobId :: BlobStorage.BlobId -> Either String (BlobId a)
toSyncBlobId = fmap BlobId . parseMD5 . BlobStorage.blobMd5


initV3SynchronizeFeature :: ServerEnv
                         -> IO (CoreFeature -> UserFeature -> IO V3SynchronizeFeature)
initV3SynchronizeFeature ServerEnv{serverV3SyncURI} = do
  pure $ \CoreFeature{packageChangeHook} UserFeature{userAdded} -> do
    for_ serverV3SyncURI  $ \uri -> do
      manager <- newManager defaultManagerSettings
      baseUrl <- parseBaseUrl (show uri)
      let clientEnv = mkClientEnv manager baseUrl


      -- User add hook
      registerHook userAdded
        $ \(UserNameIdResource uname uid) -> do
          res <-
            runClientM
              (sync_api_new_user syncClient $
                NewUserReq
                  (UserName $ T.pack $ unUserName uname)
                  (UserId $ fromIntegral $ unUserId uid)
              ) clientEnv
          print res

      -- New package hook
      registerHookJust packageChangeHook isPackageAdd
        $ \(PkgInfo pid metarevs tarrevs) -> do
          let (CabalFileText cabal, (time, uid)) = V.head metarevs
              (PkgTarball (BlobInfo gz _ _) nogz, _) = V.head tarrevs
          res <-
            runClientM
              (sync_api_new_package syncClient pid $
                NewPackageReq
                  { npr_uploader = UserId $ fromIntegral $ unUserId uid
                  , npr_uploadTime = time
                  , npr_cabalFile = cabal
                  , npr_blobGz = either error id $ toSyncBlobId gz
                  , npr_blobNoGz = either error id $ toSyncBlobId nogz
                  }
              ) clientEnv
          print res

      -- New metaarev hook
      registerHookJust packageChangeHook isPackageChangeMetaRev
        $ \(pid, revix, (CabalFileText cabal, (time, uid))) -> do
          res <-
            runClientM
              (sync_api_revise_meta syncClient pid (MetadataRevIx $ fromIntegral $ getMetadataRevIx $ revix) $
                ReviseMetaReq
                  { rmr_uploader = UserId $ fromIntegral $ unUserId uid
                  , rmr_uploadTime = time
                  , rmr_cabalFile = cabal
                  }
              ) clientEnv
          print res

      -- New tarballrev hook
      registerHookJust packageChangeHook isPackageChangeTarballRev
        $ \(pid, revix, (PkgTarball (BlobInfo gz _ _) nogz, (time, uid))) -> do
          res <-
            runClientM
              (sync_api_revise_tarball syncClient pid (fromIntegral $ getTarballRevIx $ revix) $
                ReviseTarballReq
                  { rtr_uploader = UserId $ fromIntegral $ unUserId uid
                  , rtr_uploadTime = time
                  , rtr_blobGz = either error id $ toSyncBlobId gz
                  , rtr_blobNoGz = either error id $ toSyncBlobId nogz
                  }
              ) clientEnv
          print res

    pure V3SynchronizeFeature {
      v3SynchronizeFeatureInterface = (emptyHackageFeature "v3-synchronize") {
        featureDesc = "Synchronize package changes to the v3 backend"
      }
    }

