-- |
--    Module: Digg.OIDC.Storage.RedisStore
--    Copyright: (c) 2024 Digg - Agency for Digital Government
--    License: MIT
--    Maintainer: tomas.stenlund@telia.com
--    Stability: experimental
--
--    Provides functionality for storing OIDC session data in Redis.
module Digg.OIDC.Client.Storage.RedisStore (redisStorage) where

import qualified Data.Aeson as A
import Data.ByteString (fromStrict, toStrict)
import Database.Redis (Connection, del, expire, get, runRedis, set)
import Digg.OIDC.Client.Session (Session, SessionId, SessionStorage (..))

-- | 'redisStore' initializes a session store using a Redis connection.
--
-- This function takes a Redis 'Connection' and returns a 'SessionStore'
-- that operates in the 'IO' monad. The session store can be used to
-- manage user sessions, storing session data in the Redis database.
--
-- You need to set the sessionStoreGenerate function, it is initialized
-- as 'undefined' in this implementation.
redisStorage :: Connection  -- ^ The Redis connection
  -> SessionStorage IO      -- ^ The initialized session store
redisStorage conn =
  SessionStorage
    { sessionStoreGenerate = undefined,
      sessionStoreSave = sessionSave,
      sessionStoreGet = sessionGet,
      sessionStoreDelete = sessionDelete
    }
  where
    sessionSave :: SessionId -> Session -> IO ()
    sessionSave sid ses = do
      _ <- runRedis conn $ do
        _ <- set sid $ toStrict (A.encode ses)
        expire sid 600
      return ()

    sessionGet :: SessionId -> IO (Maybe Session)
    sessionGet sid = do
      res <- runRedis conn $ get sid
      case res of
        Left _ -> return Nothing
        Right (Just v) -> return $ A.decode (fromStrict v)
        Right Nothing -> return Nothing

    sessionDelete :: SessionId -> IO ()
    sessionDelete sid = do
      _ <- runRedis conn $ del [sid]
      return ()