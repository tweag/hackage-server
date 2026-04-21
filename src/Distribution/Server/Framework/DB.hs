{-# LANGUAGE DuplicateRecordFields #-}
{-# LANGUAGE FlexibleContexts      #-}
{-# LANGUAGE MonoLocalBinds        #-}

module Distribution.Server.Framework.DB
    ( module Distribution.Server.Framework.DB
    , Connection
    , (==.)
    , (/=.)
    , (&&.)
    , (||.)
    , Insert(..)
    , Update(..)
    , Upsert(..)
    , Delete(..)
    , Query
    , Name
    , Result
    , Expr
    , Returning(..)
    , OnConflict(..)
    , each
    , values
    , lit
    , where_
    , unsafeDefault
    , DBEq
    , DBOrd
    , DBType(..)
    , TypeInformation(..)
    , (>$<)
    , asc
    , desc
    , orderBy
    ) where

import Data.Functor.Contravariant ((>$<))
import Distribution.Verbosity (normal)
import Distribution.Server.Framework.Error (ServerPartE, internalServerErrorResponse, throwError)
import Distribution.Server.Framework.Logging (lognotice)
import Control.Monad.IO.Class (liftIO)
import Rel8 hiding (null, run)
import qualified Rel8 as Rel8
import           Hasql.Connection (Connection)
import           Hasql.Session (SessionError, statement, run)


doSelect
    :: Serializable exprs (FromExprs exprs)
    => Connection
    -> Query exprs
    -> IO (Either SessionError [FromExprs exprs])
doSelect conn = flip run conn . statement () . Rel8.run . select


doSelect1
    :: Serializable exprs (FromExprs exprs)
    => Connection
    -> Query exprs
    -> IO (Either SessionError (FromExprs exprs))
doSelect1 conn = flip run conn . statement () . Rel8.run1 . select

toE :: IO (Either SessionError a) -> ServerPartE a
toE ma = do
  liftIO ma >>= \case
    Left err -> do
      lognotice normal $ show err
      throwError internalServerErrorResponse
    Right a -> pure a

doSelectE
    :: Serializable exprs (FromExprs exprs)
    => Connection
    -> Query exprs
    -> ServerPartE [FromExprs exprs]
doSelectE conn = toE . doSelect conn


doSelect1E
    :: Serializable exprs (FromExprs exprs)
    => Connection
    -> Query exprs
    -> ServerPartE (FromExprs exprs)
doSelect1E conn = toE . doSelect1 conn

doUpdate
    :: Serializable exprs (FromExprs exprs)
    => Connection
    -> Update (Query exprs)
    -> IO (Either SessionError [FromExprs exprs])
doUpdate conn = flip run conn . statement () . Rel8.run . update

doUpdate1
    :: Serializable exprs (FromExprs exprs)
    => Connection
    -> Update (Query exprs)
    -> IO (Either SessionError (FromExprs exprs))
doUpdate1 conn = flip run conn . statement () . Rel8.run1 . update


doUpdateE
    :: Serializable exprs (FromExprs exprs)
    => Connection
    -> Update (Query exprs)
    -> ServerPartE [FromExprs exprs]
doUpdateE conn = toE . doUpdate conn


doInsert
    :: Serializable exprs (FromExprs exprs)
    => Connection
    -> Insert (Query exprs)
    -> IO (Either SessionError [FromExprs exprs])
doInsert conn = flip run conn . statement () . Rel8.run . insert


doInsert1
    :: Serializable exprs (FromExprs exprs)
    => Connection
    -> Insert (Query exprs)
    -> IO (Either SessionError (FromExprs exprs))
doInsert1 conn = flip run conn . statement () . Rel8.run1 . insert


doInsertE
    :: Serializable exprs (FromExprs exprs)
    => Connection
    -> Insert (Query exprs)
    -> ServerPartE [FromExprs exprs]
doInsertE conn = toE . doInsert conn


doInsert_
    :: Connection
    -> Insert a
    -> IO (Either SessionError ())
doInsert_ conn = flip run conn . statement () . Rel8.run_ . insert


doInsertE_
    :: Connection
    -> Insert a
    -> ServerPartE ()
doInsertE_ conn = toE . doInsert_ conn


doDelete
    :: Serializable exprs (FromExprs exprs)
    => Connection
    -> Delete (Query exprs)
    -> IO (Either SessionError [FromExprs exprs])
doDelete conn = flip run conn . statement () . Rel8.run . delete


doDeleteE
    :: Serializable exprs (FromExprs exprs)
    => Connection
    -> Delete (Query exprs)
    -> ServerPartE [FromExprs exprs]
doDeleteE conn = toE . doDelete conn


doDelete_ :: Connection -> Delete a -> IO (Either SessionError ())
doDelete_ conn = flip run conn . statement () . Rel8.run_ . delete

doDeleteE_ :: Connection -> Delete a -> ServerPartE ()
doDeleteE_ conn = toE . doDelete_ conn
