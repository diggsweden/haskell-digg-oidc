{-# LANGUAGE OverloadedStrings #-}
module Internal (oidcException, handleError) where

import           Control.Exception      (SomeException)
import           Control.Exception.Base (Exception (displayException))
import           Control.Monad.IO.Class (MonadIO, liftIO)
import           Digg.OIDC.Client       (OIDCException (..))
import           Test.Hspec             (Selector)

-- | A selector function for 'OIDCException' that can be used in exception handling.
oidcException :: OIDCException -> Selector OIDCException
oidcException e a = e == a

-- | Handles exceptions by converting them to an 'Either' type with a 'String' error message.
handleError :: (MonadIO m) => SomeException -> m (Either String a)
handleError e = do
    return $ Left $ displayException e
