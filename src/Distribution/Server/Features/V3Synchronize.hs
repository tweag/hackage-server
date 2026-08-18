{-# LANGUAGE NamedFieldPuns #-}
{-# LANGUAGE TypeApplications #-}
module Distribution.Server.Features.V3Synchronize (
    V3SynchronizeFeature(..),
    initV3SynchronizeFeature,
  ) where

import Data.Foldable
import Data.Proxy (Proxy(..))
import Distribution.Server.Features.Core
import Distribution.Server.Features.Users
import Distribution.Server.Framework
import Distribution.Server.Packages.Types (pkgLatestTarball, pkgTarballNoGz)
import Distribution.Server.Users.Types (unUserId, unUserName)
import Hackage.SyncAPI.Type
import Hackage.Types
import Network.HTTP.Client (newManager, defaultManagerSettings)
import Servant.API.NamedRoutes
import Servant.Client
import qualified Data.Text as T
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
                         -> IO (UserFeature -> IO V3SynchronizeFeature)
initV3SynchronizeFeature ServerEnv{serverV3SyncURI} = do
  pure $ \UserFeature{userAdded} -> do
    for_ serverV3SyncURI  $ \uri -> do
      manager <- newManager defaultManagerSettings
      baseUrl <- parseBaseUrl (show uri)
      let clientEnv = mkClientEnv manager baseUrl

      registerHook userAdded $ \(UserNameIdResource uname uid) -> do
        res <-
          runClientM
            (sync_api_new_user syncClient $
              NewUserReq
                (UserName $ T.pack $ unUserName uname)
                (UserId $ fromIntegral $ unUserId uid)
            ) clientEnv
        print res

    pure V3SynchronizeFeature {
      v3SynchronizeFeatureInterface = (emptyHackageFeature "v3-synchronize") {
        featureDesc = "Synchronize package changes to the v3 backend"
      }
    }

