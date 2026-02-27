{-# LANGUAGE OverloadedStrings #-}

-- |
--    Module: Digg.OIDC.Storage.PostgreSQLStore
--    Copyright: (c) 2024 Digg - Agency for Digital Government
--    License: MIT
--    Maintainer: tomas.stenlund@telia.com
--    Stability: experimental
--
--    Provides functionality for storing OIDC session data in PostgreSQL.
module Digg.OIDC.Client.Storage.PostgreSQLStore (postgreSQLStorage) where

import           Control.Exception               (catch, throwIO)
import           Control.Monad                   (void)
import           Control.Monad.IO.Class          (MonadIO, liftIO)
import qualified Data.Aeson                      as A
import           Data.ByteString                 (toStrict)
import           Database.PostgreSQL.Simple      (ConnectInfo (..), Connection,
                                                  Only (..), close, connect,
                                                  execute, query)
import           Digg.OIDC.Client.Session        (Session, SessionId,
                                                  SessionStorage (..))

import           Control.Concurrent              (getNumCapabilities)
import           Data.Pool                       (Pool, defaultPoolConfig,
                                                  newPool, withResource)
import           Digg.OIDC.Client.Storage.Random (createSystemDRG, generateSystemDRG)

-- | Handles IO errors by rethrowing them as exceptions.
handleIOError :: IOError -> IO a
handleIOError e = do
  throwIO e

-- | 'postgreSQLStorage' initializes a session store using a PostgreSQL connection.
--
-- The database must contain a table named 'sessions' with the following schema:
--
-- CREATE TABLE sessions (
--     session_id TEXT PRIMARY KEY,
--     session_data BYTEA NOT NULL,
--     created_at TIMESTAMPTZ NOT NULL DEFAULT NOW());
--
-- The session data is stored as a JSON-encoded byte array. The 'sessionStoreGenerate' function
--
-- You need to set the sessionStoreGenerate function, it is initialized as 'undefined' in this implementation.
--

-- | Function to create a new database connection
createConn :: ConnectInfo -> IO Connection
createConn conf = connect conf

-- | Function to destroy a database connection
destroyConn :: Connection -> IO ()
destroyConn = close

postgreSQLStorage :: (MonadIO m) => ConnectInfo     -- ^ The PostgreSQL connection info
  -> m (SessionStorage IO)                          -- ^ The initialized session store
postgreSQLStorage connInfo = do
    n <- liftIO $ getNumCapabilities
    liftIO $ putStrLn $ "Creating PostgreSQL connection pool with " ++ show n ++ " connections."
    pool <- liftIO $ catch (newPool $ defaultPoolConfig (createConn connInfo) destroyConn 30 n) handleIOError
    sdrg <- liftIO $ createSystemDRG
    return SessionStorage
      { sessionStoreGenerate = generateSystemDRG sdrg,
        sessionStoreSave = sessionSave pool,
        sessionStoreGet = sessionGet pool,
        sessionStoreDelete = sessionDelete pool,
        sessionStoreCleanup = sessionCleanup pool
      }
  where

    -- | Saves a session in the PostgreSQL store.
    sessionSave :: Pool Connection -> SessionId -> Session -> IO ()
    sessionSave pool sid ses = withResource pool $ \conn -> do
      let sessionData = toStrict (A.encode ses)
      void $ execute conn "INSERT INTO sessions (session_id, session_data) VALUES (?, ?) ON CONFLICT (session_id) DO UPDATE SET session_data = EXCLUDED.session_data" (sid  , sessionData)
      return ()

    -- | Retrieves a session from the PostgreSQL store based on the given session ID.
    sessionGet :: Pool Connection -> SessionId -> IO (Maybe Session)
    sessionGet pool sid = withResource pool $ \conn -> do
        [Only sessionData] <- query conn "SELECT session_data FROM sessions WHERE session_id = ?" (Only { fromOnly = sid })
        case A.decode sessionData of
          Just session -> return (Just session)
          Nothing      -> return Nothing

    -- | Deletes a session from the PostgreSQL store.
    sessionDelete :: Pool Connection -> SessionId -> IO ()
    sessionDelete pool sid = withResource pool $ \conn -> do
      void $ execute conn "DELETE FROM sessions WHERE session_id = ?" (Only sid)

    -- | Clears all sessions from the PostgreSQL store older than the provided age in seconds.
    sessionCleanup :: Pool Connection -> Integer -> IO ()
    sessionCleanup pool age = withResource pool $ \conn -> do
      void $ execute conn "DELETE FROM sessions WHERE EXTRACT(EPOCH FROM (NOW() - created_at)) > ?" (Only age)
