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


doSelectE
    :: Serializable exprs (FromExprs exprs)
    => Connection
    -> Query exprs
    -> ServerPartE [FromExprs exprs]
doSelectE conn q = do
  liftIO (doSelect conn q) >>= \case
    Left err -> do
      lognotice normal $ show err
      throwError internalServerErrorResponse
    Right a -> pure a

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


doInsert :: Connection -> Insert a -> IO (Either SessionError ())
doInsert conn = flip run conn . statement () . Rel8.run_ . insert
