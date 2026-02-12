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

import           Control.Exception          (catch, throwIO)
import           Control.Monad              (void)
import           Control.Monad.IO.Class     (MonadIO, liftIO)
import qualified Data.Aeson                 as A
import           Data.ByteString            (toStrict)
import           Database.PostgreSQL.Simple (ConnectInfo (..), Connection,
                                             Only (..), connect, execute, query)
import           Digg.OIDC.Client.Session   (Session, SessionId,
                                             SessionStorage (..))

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
--     session_data BYTEA NOT NULL);
--
-- The session data is stored as a JSON-encoded byte array. The 'sessionStoreGenerate' function
--
-- You need to set the sessionStoreGenerate function, it is initialized as 'undefined' in this implementation.
--
postgreSQLStorage :: (MonadIO m) => ConnectInfo     -- ^ The PostgreSQL connection info
  -> m (SessionStorage IO)                          -- ^ The initialized session store
postgreSQLStorage connInfo = do

    conn <- liftIO $ catch (connect connInfo) handleIOError
    return SessionStorage
      { sessionStoreGenerate = undefined,
        sessionStoreSave = sessionSave conn,
        sessionStoreGet = sessionGet conn,
        sessionStoreDelete = sessionDelete conn
      }
  where

    -- | Saves a session in the Redis store.
    sessionSave :: Connection -> SessionId -> Session -> IO ()
    sessionSave conn sid ses = do
      let sessionData = toStrict (A.encode ses)
      void $ execute conn "INSERT INTO sessions (session_id, session_data) VALUES (?, ?) ON CONFLICT (session_id) DO UPDATE SET session_data = EXCLUDED.session_data" (sid  , sessionData)
      return ()

    -- | Retrieves a session from the Redis store based on the given session ID.
    sessionGet :: Connection -> SessionId -> IO (Maybe Session)
    sessionGet conn sid = do
        [Only sessionData] <- query conn "SELECT session_data FROM sessions WHERE session_id = ?" (Only { fromOnly = sid })
        case A.decode sessionData of
          Just session -> return (Just session)
          Nothing      -> return Nothing

    -- | Deletes a session from the PostgreSQL store.
    sessionDelete :: Connection -> SessionId -> IO ()
    sessionDelete conn sid = do
      void $ execute conn "DELETE FROM sessions WHERE session_id = ?" (Only sid)


