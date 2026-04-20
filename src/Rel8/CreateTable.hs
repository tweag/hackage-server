{-# LANGUAGE GADTs                    #-}
{-# LANGUAGE StandaloneKindSignatures #-}

module Rel8.CreateTable
  ( DbConstraint (..)
  , DbTable (..)
  , makeTable
  ) where

import qualified Data.ByteString.Char8 as BS8
import           Data.Foldable
import           Data.Kind (Type)
import           Hasql.Session (sql, Session)
import           Rel8 (QualifiedName(QualifiedName), TableSchema(..), Name)
import qualified Rel8 as Rel8
import           Rel8.Table.Verify (showCreateTable)
import           Unsafe.Coerce (unsafeCoerce)


-- | A primary or foreign key constraint on a table.
type DbConstraint :: ((Type -> Type) -> Type) -> Type
data DbConstraint table where
  PK :: (table Name -> Name a) -> DbConstraint table
  FK
    :: (table Name -> Name a)
    -> TableSchema (foreign_table Name)
    -> (foreign_table Name -> Name a)
    -> DbConstraint table


-- | A table schema and its corresponding key constraints. A 'DbTable' can be
-- used to construct a table via 'makeTable'.
data DbTable table where
  DbTable
    :: TableSchema (table Name)
    -> [DbConstraint table]
    -> DbTable table


makeTable :: Rel8.Rel8able table => DbTable table -> Session ()
makeTable (DbTable schema constraints) = do
  sql $ BS8.pack $ showCreateTable schema
  for_ constraints $ mkConstraints schema


nameToString :: Name a -> String
nameToString = unsafeCoerce

mkConstraints :: TableSchema (table Name) -> DbConstraint table -> Session ()
mkConstraints (TableSchema (QualifiedName table_name _) table) (PK f) =
  sql $ BS8.pack $ unwords
    [ "ALTER TABLE"
    , table_name
    , "ADD PRIMARY KEY"
    , "("
    , nameToString $ f table
    , ")"
    ]
mkConstraints (TableSchema (QualifiedName table_name _) table) (FK here (TableSchema (QualifiedName other_name _) other) there) =
  sql $ BS8.pack $ unwords
    [ "ALTER TABLE"
    , table_name
    , "ADD FOREIGN KEY"
    , "("
    , nameToString $ here table
    , ")"
    , "REFERENCES"
    , other_name
    , "("
    , nameToString $ there other
    , ")"
    ]
