{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}

module Main where

import Control.Exception (bracket)
import Control.Monad (unless, when)
import Data.Acid (closeAcidState, createCheckpoint, openLocalStateFrom, query, update)
import Data.Aeson (Value, eitherDecode, withObject, (.:))
import Data.Aeson.Types (Parser, parseEither)
import qualified Data.ByteString.Lazy as LBS
import qualified Data.Map as Map
import Distribution.Server.Users.State (GetUserDb(..), ReplaceUserDb(..), initialUsers)
import Distribution.Server.Users.Types (UserId(..), UserInfo(..), UserName(..), UserStatus(..), isValidUserNameChar)
import qualified Distribution.Server.Users.Users as Users
import System.Directory (createDirectoryIfMissing)
import System.Environment (getArgs, getProgName)
import System.Exit (die, exitSuccess)
import System.FilePath ((</>))
import System.IO (hPutStrLn, stderr, stdin)

main :: IO ()
main = do
  opts <- parseOptions =<< getArgs
  when (optShowHelp opts) $ do
    printUsage
    exitSuccess

  input <- case optInputFile opts of
    Nothing     -> LBS.hGetContents stdin
    Just "-"    -> LBS.hGetContents stdin
    Just path   -> LBS.readFile path

  values <- either die return (eitherDecode input)
  let (importUsers, parseWarnings) = parseImportUsers values
  let statePath = optStateDir opts </> "db" </> "Users"

  createDirectoryIfMissing True (optStateDir opts </> "db")
  bracket (openLocalStateFrom statePath initialUsers) closeAcidState $ \acid -> do
    users <- query acid GetUserDb
    let (users', insertWarnings, importedCount) = insertUsers users importUsers
        warnings = parseWarnings ++ insertWarnings
    mapM_ warn warnings

    if optDryRun opts
      then putStrLn $ "Validated " ++ show (length values) ++ " JSON entries; " ++ show importedCount ++ " users would be imported; " ++ show (length warnings) ++ " skipped."
      else do
        update acid (ReplaceUserDb users')
        createCheckpoint acid
        putStrLn $ "Imported " ++ show importedCount ++ " users into " ++ statePath ++ "; " ++ show (length warnings) ++ " skipped."

warn :: String -> IO ()
warn = hPutStrLn stderr . ("Warning: " ++)

data Options = Options
  { optInputFile :: Maybe FilePath
  , optStateDir  :: FilePath
  , optDryRun    :: Bool
  , optShowHelp  :: Bool
  }

defaultOptions :: Options
defaultOptions = Options
  { optInputFile = Nothing
  , optStateDir  = "state"
  , optDryRun    = False
  , optShowHelp  = False
  }

parseOptions :: [String] -> IO Options
parseOptions = go defaultOptions
  where
    go opts [] = return opts
    go opts ("--state-dir" : dir : args) = go opts { optStateDir = dir } args
    go _    ["--state-dir"]              = die "--state-dir requires a directory"
    go opts ("--dry-run" : args)         = go opts { optDryRun = True } args
    go opts ("--help" : args)            = go opts { optShowHelp = True } args
    go opts ("-h" : args)                = go opts { optShowHelp = True } args
    go opts (arg : args)
      | "-" <- take 1 arg = die $ "unknown option: " ++ arg
      | Nothing <- optInputFile opts = go opts { optInputFile = Just arg } args
      | otherwise = die $ "unexpected argument: " ++ arg

printUsage :: IO ()
printUsage = do
  prog <- getProgName
  putStrLn $ unlines
    [ "Usage: " ++ prog ++ " [--state-dir DIR] [--dry-run] [USERS.json|-]"
    , ""
    , "Imports a JSON array of users into DIR/db/Users (default DIR: state)."
    , "If USERS.json is omitted or is '-', JSON is read from stdin."
    , "Each user must have the form {\"userid\": 0, \"username\": \"admin\"}."
    , "Imported accounts are created disabled and without passwords."
    ]

data ImportUser = ImportUser
  { importUserId   :: UserId
  , importUserName :: UserName
  }

parseImportUsers :: [Value] -> ([ImportUser], [String])
parseImportUsers values = foldr collect ([], []) (zip [0 :: Int ..] values)
  where
    collect (index, value) (users, warnings) =
      case parseEither (parseImportUser index) value of
        Right importUser -> (importUser : users, warnings)
        Left err         -> (users, err : warnings)

parseImportUser :: Int -> Value -> Parser ImportUser
parseImportUser index = withObject ("import user at array index " ++ show index) $ \obj -> do
    userid@(UserId rawUserId) <- obj .: "userid"
    username@(UserName rawUserName) <- obj .: "username"
    validateUserId index rawUserId
    validateUserName index rawUserId rawUserName
    return ImportUser
      { importUserId = userid
      , importUserName = username
      }

validateUserId :: Int -> Int -> Parser ()
validateUserId index userid =
  when (userid < 0) $ fail $ prefix index userid ++ "userid must be non-negative"

validateUserName :: Int -> Int -> String -> Parser ()
validateUserName index userid username = do
  when (null username) $ fail $ prefix index userid ++ "username must not be empty"
  unless (all isValidUserNameChar username) $
    fail $ prefix index userid ++ "username must contain only ASCII letters, digits, and underscores"

prefix :: Int -> Int -> String
prefix index userid = "array index " ++ show index ++ ", userid " ++ show userid ++ ": "

insertUsers :: Users.Users -> [ImportUser] -> (Users.Users, [String], Int)
insertUsers users = foldl insertUser (users, [], 0)

insertUser :: (Users.Users, [String], Int) -> ImportUser -> (Users.Users, [String], Int)
insertUser (users, warnings, importedCount) ImportUser{..} =
  case Users.insertUserAccount importUserId userInfo users of
    Right users' -> (users', warnings, importedCount + 1)
    Left (Left Users.ErrUserIdClash) ->
      (users, warnings ++ ["duplicate user id: " ++ show importUserId], importedCount)
    Left (Right Users.ErrUserNameClash) ->
      (users, warnings ++ ["duplicate user name: " ++ show importUserName ++ " for " ++ show importUserId], importedCount)
  where
    userInfo = UserInfo
      { userName = importUserName
      , userStatus = AccountDisabled Nothing
      , userTokens = Map.empty
      }
