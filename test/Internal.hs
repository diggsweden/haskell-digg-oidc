{-# LANGUAGE OverloadedStrings #-}
module Internal (handleError) where
    
import           Control.Exception      (SomeException)
import           Control.Exception.Base (Exception (displayException))
import           Control.Monad.IO.Class (MonadIO, liftIO)

-- | Handles exceptions by converting them to an 'Either' type with a 'String' error message.
handleError :: (MonadIO m) => SomeException -> m (Either String a)
handleError e = do
    liftIO $ print $ displayException e
    return $ Left $ displayException e
