-- |
--    Module: Digg.OIDC.Storage.MemoryStore
--    Copyright: (c) 2024 Digg - Agency for Digital Government
--    License: MIT
--    Maintainer: tomas.stenlund@telia.com
--    Stability: experimental
--
--    Provides functionality for storing OIDC session data in a memory map.
module Digg.OIDC.Client.Storage.MemoryStore (memoryStorage) where

import           Control.Monad.IO.Class   (MonadIO, liftIO)
import           Data.IORef
import           Data.Map                 (Map)
import qualified Data.Map                 as M
import           Digg.OIDC.Client.Session (Session, SessionId,
                                           SessionStorage (..))

type SessionMap = IORef (Map SessionId Session)

createStorage :: IO SessionMap
createStorage = newIORef M.empty

memoryStorage :: (MonadIO m) => m (SessionStorage IO)
memoryStorage = do
    sm <- liftIO createStorage

    return SessionStorage
      { sessionStoreGenerate = undefined,
        sessionStoreSave = sessionSave sm,
        sessionStoreGet = sessionGet sm,
        sessionStoreDelete = sessionDelete sm,
        sessionStoreCleanup = sessionCleanup sm
      }
  where

    -- | Saves a session in the memory store.
    sessionSave :: SessionMap -> SessionId -> Session -> IO ()
    sessionSave smap sid ses = do
        atomicModifyIORef' smap $ \m -> (M.insert sid ses m, ())
        return ()

    -- | Retrieves a session from the memory store based on the given session ID.
    sessionGet :: SessionMap -> SessionId -> IO (Maybe Session)
    sessionGet smap sid = do
        m <- readIORef smap
        return $ M.lookup sid m

    -- | Deletes a session from the memory store.
    sessionDelete :: SessionMap -> SessionId -> IO ()
    sessionDelete smap sid = do
        atomicModifyIORef' smap $ \m -> (M.delete sid m, ())

    -- | Clears all sessions from the memory store older than the provided age in seconds.
    sessionCleanup :: SessionMap -> Integer -> IO ()
    sessionCleanup smap age = do
        return ()
