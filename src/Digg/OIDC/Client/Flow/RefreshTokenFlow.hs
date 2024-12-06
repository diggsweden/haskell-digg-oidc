{-# LANGUAGE OverloadedStrings   #-}
{-# LANGUAGE ScopedTypeVariables #-}

-- |
--    Module: Digg.OIDC.Client.Flow.RefreshTokenFlow
--    Copyright: Copyright (c) 2024 Digg - Agency for Digital Government
--    License: MIT
--    Maintainer: tomas.stenlund@telia.com
--    Stability: experimental
--
--    Provides functionality for refreshing a token in an ongoing session.
module Digg.OIDC.Client.Flow.RefreshTokenFlow (refreshToken) where

import           Control.Monad                       (when, unless)
import           Control.Monad.Catch                 (MonadCatch,
                                                      MonadThrow (throwM))
import           Control.Monad.IO.Class              (MonadIO (liftIO))
import           Data.Aeson                          (FromJSON, eitherDecode)
import qualified Data.ByteString.Char8               as B
import           Data.Maybe                          (fromJust, isJust,
                                                      isNothing)
import           Data.Text                           (pack)
import           Data.Text.Encoding                  (encodeUtf8)
import           Digg.OIDC.Client                    (OIDC (..),
                                                      OIDCException (InvalidState, ValidationException, UnsupportedOperation))
import           Digg.OIDC.Client.Discovery.Provider (Provider (..),
                                                      ProviderMetadata (..))
import           Digg.OIDC.Client.Internal           (TokensResponse (..), isAnElementOf)
import           Digg.OIDC.Client.Session            (Session (..), SessionId,
                                                      SessionStorage (..))
import           Digg.OIDC.Client.Tokens             (NoExtraClaims,
                                                      TokenClaims (..),
                                                      validateAccessClaims,
                                                      validateIdClaims,
                                                      validateToken)
import           Digg.OIDC.Types                     (Address (..), Code)
import           Jose.Jwt                            (Jwt (..))
import           Network.HTTP.Client                 (Manager, Request (..),
                                                      Response (responseBody),
                                                      httpLbs, requestFromURI,
                                                      urlEncodedBody)
import           Prelude                             hiding (exp)
import Data.Void (vacuous)

-- | Refreshes the token using the refresh token flow.
--
-- This function takes a session storage, session ID, HTTP manager, OIDC configuration
-- to refresh the token and return the token claims.
refreshToken :: (MonadIO m, MonadCatch m, FromJSON a) => SessionStorage m   -- ^ The session storage
  -> SessionId -- ^ The session identifier to refresh
  -> Manager   -- ^ The HTTP manager
  -> OIDC      -- ^ The OIDC configuration
  -> m (TokenClaims a) -- ^ The token claims
refreshToken storage sid mgr oidc = do

  -- Verify that the provider supports authorization code grant type
  unless (isAnElementOf "refresh_token" (providerGrantTypesSupported (metadata $ oidcProvider oidc))) $ throwM $ UnsupportedOperation "Refresh token grant type not supported"

  -- Get the session from the storage and verify it
  session <- sessionStoreGet storage sid >>= verifySession

  -- Call the token endpoint to refresh the tokens
  tr <- liftIO $ callTokenEndpoint (sessionCode session) (sessionRefreshToken session)

  -- Validate the ID token
  claims <- validateToken oidc $ tokensResponseIdToken tr
  liftIO $ validateIdClaims (providerIssuer . metadata $ oidcProvider oidc) (oidcClientId oidc) (sessionNonce session) claims

  -- Validate the access token
  claimsA :: (TokenClaims NoExtraClaims) <- validateToken oidc $ tokensResponseAccessToken tr
  liftIO $ validateAccessClaims (providerIssuer . metadata $ oidcProvider oidc) claimsA

  -- Update the session with the new tokens
  sessionStoreSave storage sid $
    session
      { sessionNonce = Nothing,
        sessionState = "",
        sessionAccessToken = Just $ unJwt $ tokensResponseAccessToken tr,
        sessionIdToken = Just $ unJwt $ tokensResponseIdToken tr,
        sessionRefreshToken = unJwt <$> tokensResponseRefreshToken tr
      }

  return claims

  where

    verifySession :: (MonadIO m, MonadThrow m) => Maybe Session -> m Session
    verifySession Nothing = do
      throwM $ InvalidState "No session found in storage"
    verifySession (Just s) = do
      when (sessionState s /= "") $ throwM $ InvalidState "State should be empty"
      when (isNothing (sessionAccessToken s)) $ throwM $ InvalidState "No access token, wrong state"
      when (isNothing (sessionRefreshToken s)) $ throwM $ InvalidState "No refreshtoken, wrong state"
      when (isJust (sessionNonce s)) $ throwM $ InvalidState "Nonce should be empty, wrong state"
      when (isNothing (sessionCode s)) $ throwM $ InvalidState "Missing code, wrong state"
      return s

    callTokenEndpoint :: Maybe Code -> Maybe B.ByteString -> IO TokensResponse
    callTokenEndpoint code rt = do
      req <- requestFromURI endpoint
      res <- httpLbs (urlEncodedBody (base code rt) $ req {method = "POST"}) mgr
      case eitherDecode (responseBody res) of
        Left err -> throwM $ ValidationException $ "Failed to parse token refresh response " <> pack err
        Right tr -> do
          when (tokensResponseTokenType tr /= "Bearer") $ throwM $ ValidationException $ "Invalid token type " <> tokensResponseTokenType tr
          return tr

    endpoint = uri $ providerTokenEndpoint $ metadata $ oidcProvider oidc

    base code rt =
      [ ("grant_type", "refresh_token"),
        ("code", fromJust code),
        ("client_id", encodeUtf8 $ oidcClientId oidc),
        ("client_secret", encodeUtf8 $ oidcClientSecret oidc),
        ("redirect_uri", encodeUtf8 $ oidcRedirectUri oidc),
        ("refresh_token", fromJust rt)
      ]

