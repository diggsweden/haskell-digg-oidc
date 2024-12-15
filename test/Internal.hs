{-# LANGUAGE OverloadedStrings #-}
module Internal (oidcException, handleError, mock) where

import           Control.Exception      (SomeException)
import           Control.Exception.Base (Exception (displayException))
import           Control.Monad.IO.Class (MonadIO, liftIO)
import           Digg.OIDC.Client       (OIDCException (..))
import           Network.HTTP.Client    (Manager)
import           Network.HTTP.Mock      (withMockedManager)
import           Test.Hspec             (Selector)
import           Web.Scotty             (ScottyM, scottyApp)

-- | 'mock' is a function that takes a ScottyM action and a function that
-- | operates on a Manager, and returns an IO action. This can be used to
-- | mock or test Scotty web applications by providing a custom Manager.
mock::ScottyM () -> (Manager->IO a)->IO a
mock a f = do
    application <- liftIO $ scottyApp a
    withMockedManager application f

-- | A selector function for 'OIDCException' that can be used in exception handling.
oidcException :: OIDCException -> Selector OIDCException
oidcException e a = e == a

-- | Handles exceptions by converting them to an 'Either' type with a 'String' error message.
handleError :: (MonadIO m) => SomeException -> m (Either String a)
handleError e = do
    return $ Left $ displayException e
