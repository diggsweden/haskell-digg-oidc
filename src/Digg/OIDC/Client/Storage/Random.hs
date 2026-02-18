-- |
--    Module: Digg.OIDC.Client.Storage.Random
--    Copyright: (c) 2024 Digg - Agency for Digital Government
--    License: MIT
--    Maintainer: tomas.stenlund@telia.com
--    Stability: experimental
--
--    Provides a simple basic random number generator for session IDs and
--    other random values needed in the OIDC client. It should not be used in
--    production, but can be useful for testing and development purposes.
--
module Digg.OIDC.Client.Storage.Random (generatePRNG, createSystemDRG, generateSystemDRG) where

import           Control.Monad.IO.Class (MonadIO, liftIO)
import           Crypto.Random          (SystemDRG, getSystemDRG,
                                         randomBytesGenerate)
import           Data.ByteString        (ByteString)
import qualified Data.ByteString.Base64 as B64
import           Data.ByteString.Random (random)
import           Data.IORef             (IORef, atomicModifyIORef', newIORef)
import           Data.Tuple             (swap)

-- | Generates a random ByteString using the Data.ByteString.Random PRNG.Address
-- The function generates a random ByteString of 64 bytes and encodes it in Base64 format.
generatePRNG:: (MonadIO m) => m ByteString
generatePRNG = liftIO $ B64.encode <$> random 64

-- | Creates a new SystemDRG and wraps it in an IORef for state management. This function is used to
-- initialize the DRG that will be used for generating random values in the OIDC client.
createSystemDRG :: (MonadIO m) => m (IORef SystemDRG)
createSystemDRG = liftIO $ getSystemDRG >>= newIORef

-- | Generates a random ByteString using a SystemDRG. The function takes an IORef to a SystemDRG,
-- updates the DRG state, and returns a Base64-encoded random ByteString of the specified length
-- (64 bytes in this case).
generateSystemDRG :: (MonadIO m) => IORef SystemDRG -> m ByteString
generateSystemDRG rg = liftIO $ B64.encode <$> atomicModifyIORef' rg (swap . randomBytesGenerate 64)
