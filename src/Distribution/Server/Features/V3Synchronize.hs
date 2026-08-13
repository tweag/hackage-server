{-# LANGUAGE NamedFieldPuns #-}
{-# LANGUAGE TypeApplications #-}
module Distribution.Server.Features.V3Synchronize (
    V3SynchronizeFeature(..),
    initV3SynchronizeFeature,
  ) where

import Data.Foldable
import Data.Proxy (Proxy(..))
import Distribution.Server.Features.Core
import Distribution.Server.Framework
import Distribution.Server.Packages.Types (pkgLatestTarball, pkgTarballNoGz)
import Hackage.SyncAPI.Type
import Hackage.Types
import Network.HTTP.Client (newManager, defaultManagerSettings)
import Servant.API.NamedRoutes
import Servant.Client
import qualified Distribution.Server.Framework.BlobStorage as BlobStorage


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
                         -> IO (CoreFeature -> IO V3SynchronizeFeature)
initV3SynchronizeFeature ServerEnv{serverV3SyncURI} = do
  pure $ \CoreFeature{packageChangeHook} -> do
    for_ serverV3SyncURI  $ \uri -> do
      manager <- newManager defaultManagerSettings
      baseUrl <- parseBaseUrl (show uri)
      let clientEnv = mkClientEnv manager baseUrl

      registerHookJust packageChangeHook isPackageChangeAny $ \(_pkgid, mpkginfo) ->
        for_ (pkgLatestTarball =<< mpkginfo) $ \(tarball, _uploadinfo, _revno) ->
          case toSyncBlobId (pkgTarballNoGz tarball) of
            Left err -> putStrLn $ "v3-synchronize: bad blob id: " ++ err
            Right blobid -> do
              res <- runClientM (sync_api_index_blob syncClient blobid) clientEnv
              print res

    pure V3SynchronizeFeature {
      v3SynchronizeFeatureInterface = (emptyHackageFeature "v3-synchronize") {
        featureDesc = "Synchronize package changes to the v3 backend"
      }
    }

