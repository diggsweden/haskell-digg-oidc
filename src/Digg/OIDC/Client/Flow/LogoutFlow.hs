{-# LANGUAGE OverloadedStrings   #-}
{-# LANGUAGE ScopedTypeVariables #-}

-- |
--    Module: Digg.OIDC.Client.Flow.LogoutFlow
--    Copyright: (c) 2024 Digg - Agency for Digital Government
--    License: MIT
--    Maintainer: tomas.stenlund@telia.com
--    Stability: experimental
--
--    Provides functionality for the RP initiated logout of an ongoing session.
module Digg.OIDC.Client.Flow.LogoutFlow (initiateLogoutRequest, logoutCompleted) where

import           Control.Monad                       (unless, when)
import           Control.Monad.Catch                 (MonadCatch,
                                                      MonadThrow (throwM))
import           Control.Monad.IO.Class              (MonadIO (liftIO))
import           Data.Aeson                          (FromJSON, eitherDecode)
import           Data.ByteString                     (ByteString)
import qualified Data.ByteString.Char8               as B
import           Data.List                           (nub)
import           Data.Maybe                          (fromJust, isJust,
                                                      isNothing)
import           Data.Text                           (pack, unpack)
import           Data.Text.Encoding                  (encodeUtf8)
import           Digg.OIDC.Client                    (OIDC (..),
                                                      OIDCException (InvalidState, UnsupportedOperation, ValidationException))
import           Digg.OIDC.Client.Discovery.Provider (Provider (..),
                                                      ProviderMetadata (..))
import           Digg.OIDC.Client.Internal           (TokensResponse (..),
                                                      isAnElementOf)
import           Digg.OIDC.Client.Session            (Session (..), SessionId,
                                                      SessionStorage (..))
import qualified Digg.OIDC.Client.Tokens             as T
import           Digg.OIDC.Types                     (Address (..), Code, Nonce,
                                                      Parameters, Scope, State)
import           Jose.Jwt                            (Jwt (..))
import           Network.HTTP.Client                 (Manager, Request (..),
                                                      Response (responseBody),
                                                      getUri, httpLbs,
                                                      requestFromURI,
                                                      setQueryString,
                                                      urlEncodedBody)
import           Network.URI                         (URI (..))
import           Prelude                             hiding (exp)

createLogoutRequestURL :: (MonadCatch m) => OIDC -- ^ The OIDC configuration
  -> Maybe State  -- ^ The state
  -> ByteString   -- ^ Id token hint
  -> Parameters   -- ^ Extra parameters
  -> m URI        -- ^ The authorization request URL to redirect to
createLogoutRequestURL oidc state idtoken extra = do
  logoutURL
  where

    logoutURL :: (MonadCatch m) => m URI
    logoutURL = do
        when (isNothing $ oidcLogoutRedirectUri oidc) $ throwM $ UnsupportedOperation "Missing logout redirect URI"
        req <- requestFromURI $ fromJust endpoint
        return $ getUri $ setQueryString query req

    endpoint :: Maybe URI
    endpoint = uri <$> providerEndSessionEndpoint (metadata $ oidcProvider oidc)

    query :: Parameters
    query = base <> maybe [] (\s -> [("state", Just s)]) state <> extra

    base :: Parameters
    base =
      [ ("id_token_hint", Just idtoken),
        ("post_logout_redirect_uri", encodeUtf8 <$> oidcLogoutRedirectUri oidc)
      ]

initiateLogoutRequest :: (MonadIO m, MonadCatch m) => SessionStorage m  -- ^ The session storage
  -> SessionId  -- ^ The session identifier
  -> OIDC       -- ^ The OIDC configuration
  -> Parameters -- ^ Extra parameters
  -> m URI      -- ^ The logout request URL to redirect to
initiateLogoutRequest storage sid oidc extra = do

    -- Verify the session
    session <- sessionStoreGet storage sid
    session' <- verifySession session

    -- Generate a new state and the logout URL
    state <- sessionStoreGenerate storage
    url <- createLogoutRequestURL oidc (Just state) (fromJust (sessionIdToken session')) extra

    -- Update the session with the new state
    sessionStoreSave storage sid $ session' { sessionState = state }

    return url

  where

    verifySession :: (MonadIO m, MonadThrow m) => Maybe Session -> m Session
    verifySession Nothing = do
      throwM $ InvalidState "No session found"
    verifySession (Just s) = do
      when (isNothing (sessionIdToken s)) $ throwM $ InvalidState "Missing ID token"
      return s


logoutCompleted :: (MonadIO m, MonadCatch m) => SessionStorage m -- ^ The session storage
  -> SessionId  -- ^ The session identifier
  -> State      -- ^ The state
  -> m ()
logoutCompleted storage sid state = do

  -- Verify the session
  session <- sessionStoreGet storage sid
  _ <- verifySession session

  -- Update the session
  sessionStoreDelete storage sid

  return ()

  where

    verifySession :: (MonadIO m, MonadThrow m) => Maybe Session -> m Session
    verifySession Nothing = do
      throwM $ InvalidState "No session found"
    verifySession (Just s) = do
      when (sessionState s /= state) $ throwM $ InvalidState "State mismatch"
      when (isNothing (sessionAccessToken s)) $ throwM $ InvalidState "Missing access token"
      when (isNothing (sessionIdToken s)) $ throwM $ InvalidState "Missing ID token"
      when (isNothing (sessionRefreshToken s)) $ throwM $ InvalidState "Missing refresh token"
      when (isJust (sessionNonce s)) $ throwM $ InvalidState "Invalid state, nonce should be empty"
      when (isNothing (sessionCode s)) $ throwM $ InvalidState "Missing authorization code"
      return s
