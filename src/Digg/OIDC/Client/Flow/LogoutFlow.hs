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

import           Control.Monad                       (when)
import           Control.Monad.Catch                 (MonadCatch,
                                                      MonadThrow (throwM))
import           Control.Monad.IO.Class              (MonadIO)
import           Data.ByteString                     (ByteString)
import           Data.Maybe                          (fromJust, isJust,
                                                      isNothing)
import           Data.Text.Encoding                  (encodeUtf8)
import           Digg.OIDC.Client                    (OIDC (..),
                                                      OIDCException (InvalidState, UnsupportedOperation))
import           Digg.OIDC.Client.Discovery.Provider (Provider (..),
                                                      ProviderMetadata (..))

import           Digg.OIDC.Client.Session            (Session (..), SessionId,
                                                      SessionStorage (..))

import           Digg.OIDC.Types                     (Address (..), Parameters,
                                                      State)
import           Network.HTTP.Client                 (getUri, requestFromURI,
                                                      setQueryString)

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

    -- | Generates the logout URL for the OIDC client.
    -- This function may throw exceptions, hence it operates within a MonadCatch context.
    logoutURL :: (MonadCatch m) => m URI
    logoutURL = do
        when (isNothing $ oidcLogoutRedirectUri oidc) $ throwM $ UnsupportedOperation "Missing logout redirect URI"
        req <- requestFromURI $ fromJust endpoint
        return $ getUri $ setQueryString query req

    -- | The 'endpoint' represents an optional URI for the logout endpoint.
    -- It is used in the context of the OIDC (OpenID Connect) client flow
    -- to specify where the logout request should be sent.
    -- If 'Nothing', it indicates that no specific logout endpoint is provided.
    endpoint :: Maybe URI
    endpoint = uri <$> providerEndSessionEndpoint (metadata $ oidcProvider oidc)

    -- | 'query' represents the parameters required for the logout flow in the OIDC client.
    -- It is used to construct the query string for the logout request.
    query :: Parameters
    query = base <> maybe [] (\s -> [("state", Just s)]) state <> extra

    -- | The 'base' function represents the parameters required for the logout flow.
    -- It is part of the 'Parameters' type, which encapsulates all necessary data
    -- for handling the logout process in the OIDC client.
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
    session <- sessionStoreGet storage sid >>= verifySession

    -- Generate a new state and the logout URL
    state <- sessionStoreGenerate storage
    url <- createLogoutRequestURL oidc (Just state) (fromJust (sessionIdToken session)) extra

    -- Update the session with the new state
    sessionStoreSave storage sid $ session { sessionState = state }

    return url

  where

    -- | Verifies the given session. If the session is 'Nothing', it throws an error.
    -- If the session is 'Just', it returns the session.
    verifySession :: (MonadIO m, MonadThrow m) => Maybe Session -> m Session
    verifySession Nothing = do
      throwM $ InvalidState "No session found"
    verifySession (Just s) = do
      when (isNothing (sessionIdToken s)) $ throwM $ InvalidState "Missing ID token"
      return s


-- | This function handles the completion of the logout flow.
-- | It takes a 'SessionStorage' as an argument, which is used to manage the session state.
-- | The function operates within a monadic context that supports IO operations and exception handling.
logoutCompleted :: (MonadIO m, MonadCatch m) => SessionStorage m -- ^ The session storage
  -> SessionId  -- ^ The session identifier
  -> State      -- ^ The state
  -> m ()
logoutCompleted storage sid state = do

  -- Verify the session
  _ <- sessionStoreGet storage sid >>= verifySession

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
