{-# LANGUAGE DeriveDataTypeable, GeneralizedNewtypeDeriving, TemplateHaskell #-}
{-# LANGUAGE TypeApplications #-}
module Distribution.Server.Framework.AuthTypes where

import Distribution.Server.Framework.MemSize

import Data.SafeCopy (base, deriveSafeCopy)
import Data.Text (Text, pack, unpack)
import Data.Coerce (coerce)
import Data.Functor.Contravariant (contramap)
import Rel8 (DBType(..), encode, decode)

-- | A plain, unhashed password. Careful what you do with them.
--
newtype PasswdPlain = PasswdPlain String
  deriving Eq

-- | A password hash. It actually contains the hash of the username, passowrd
-- and realm.
--
-- Hashed passwords are stored in the format
-- @md5 (username ++ ":" ++ realm ++ ":" ++ password)@. This format enables
-- us to use either the basic or digest HTTP authentication methods.
--
newtype PasswdHash = PasswdHash String
  deriving (Eq, Ord, Show, MemSize)

newtype RealmName = RealmName String
  deriving (Show, Eq)

$(deriveSafeCopy 0 'base ''PasswdPlain)
$(deriveSafeCopy 0 'base ''PasswdHash)

instance DBType PasswdHash where
  typeInformation =
    let ti = typeInformation @Text
    in ti { encode = contramap (pack . coerce) $ encode ti
          , decode = fmap (PasswdHash . unpack) $ decode ti
          }

