-- |
--    Module: Digg.OIDC.Storage.RedisStore
--    Copyright: (c) 2024 Digg - Agency for Digital Government
--    License: MIT
--    Maintainer: tomas.stenlund@telia.com
--    Stability: experimental
--
--    Provides functionality for storing OIDC session data in Redis.
module Digg.OIDC.Client.Storage.RedisStore (redisStorage) where

import           Control.Exception        (catch, throwIO)
import           Control.Monad            (void)
import           Control.Monad.IO.Class   (MonadIO, liftIO)
import qualified Data.Aeson               as A
import           Data.ByteString          (fromStrict, toStrict)
import           Database.Redis           (ConnectInfo (..), Connection,
                                           checkedConnect, defaultConnectInfo,
                                           del, expire, get, runRedis, set)
import           Digg.OIDC.Client.Session (Session, SessionId,
                                           SessionStorage (..))

redisConnectInfo :: String -> ConnectInfo
redisConnectInfo host = defaultConnectInfo {connectHost = host}

handleIOError :: IOError -> IO a
handleIOError e = do
  throwIO e

-- | 'redisStore' initializes a session store using a Redis connection.
--
-- This function takes a Redis 'Connection' and returns a 'SessionStore'
-- that operates in the 'IO' monad. The session store can be used to
-- manage user sessions, storing session data in the Redis database.
--
-- You need to set the sessionStoreGenerate function, it is initialized
-- as 'undefined' in this implementation.
redisStorage :: (MonadIO m) => String    -- ^ The Redis connection string
  -> m (SessionStorage IO)    -- ^ The initialized session store
redisStorage redis = do

    conn <- liftIO $ catch (checkedConnect (redisConnectInfo redis)) handleIOError

    return SessionStorage
      { sessionStoreGenerate = undefined,
        sessionStoreSave = sessionSave conn,
        sessionStoreGet = sessionGet conn,
        sessionStoreDelete = sessionDelete conn,
        sessionStoreCleanup = sessionCleanup conn
      }
  where

    -- | Saves a session in the Redis store.
    sessionSave :: Connection -> SessionId -> Session -> IO ()
    sessionSave conn sid ses = do
      _ <- runRedis conn $ do
        _ <- set sid $ toStrict (A.encode ses)
        expire sid 600
      return ()

    -- | Retrieves a session from the Redis store based on the given session ID.
    sessionGet :: Connection -> SessionId -> IO (Maybe Session)
    sessionGet conn sid = do
      res <- runRedis conn $ get sid
      case res of
        Left _         -> return Nothing
        Right (Just v) -> return $ A.decode (fromStrict v)
        Right Nothing  -> return Nothing

    -- | Deletes a session from the Redis store.
    sessionDelete :: Connection -> SessionId -> IO ()
    sessionDelete conn sid = void $ runRedis conn $ del [sid]

    -- | Clears all sessions from the Redis store older than the provided age in seconds.
    sessionCleanup :: Connection -> Integer -> IO ()
    sessionCleanup conn age = do
      return ()

