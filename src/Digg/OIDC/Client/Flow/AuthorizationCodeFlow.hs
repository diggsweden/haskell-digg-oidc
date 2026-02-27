{-# LANGUAGE OverloadedStrings   #-}
{-# LANGUAGE ScopedTypeVariables #-}

-- |
--    Module: Digg.OIDC.Client.Flow.AuthorizationCodeFlow
--    Copyright: (c) 2024 Digg - Agency for Digital Government
--    License: MIT
--    Maintainer: tomas.stenlund@telia.com
--    Stability: experimental
--
--    Provides functionality for the authorization flow and initiate an ongoing session.
module Digg.OIDC.Client.Flow.AuthorizationCodeFlow (initiateAuthorizationRequest, authorizationGranted) where

import           Control.Monad                       (unless, when)
import           Control.Monad.Catch                 (MonadCatch,
                                                      MonadThrow (throwM))
import           Control.Monad.IO.Class              (MonadIO (liftIO))
import           Data.Aeson                          (FromJSON, eitherDecode)
import qualified Data.ByteString.Char8               as B
import           Data.List                           (nub)
import           Data.Maybe                          (isJust, isNothing)
import           Data.Text                           (pack, unpack)
import           Data.Text.Encoding                  (encodeUtf8)
import           Digg.OIDC.Client                    (OIDC (..),
                                                      OIDCException (InvalidState, UnsupportedOperation, ValidationException))
import           Digg.OIDC.Client.Claims             (AccessTokenClaims, IdTokenClaims, NoExtraClaims)
import           Digg.OIDC.Client.Discovery.Provider (Provider (..),
                                                      ProviderMetadata (..))
import           Digg.OIDC.Client.Internal           (TokensResponse (..),
                                                      isAnElementOf)
import           Digg.OIDC.Client.Session            (Session (..), SessionId,
                                                      SessionStorage (..))
import qualified Digg.OIDC.Client.Tokens             as T
import           Digg.OIDC.Types                     (Address (..), Code, Nonce,
                                                      Parameters, Scope, State)
import           Network.HTTP.Client                 (Manager, Request (..),
                                                      Response (responseBody),
                                                      getUri, httpLbs,
                                                      requestFromURI,
                                                      setQueryString,
                                                      urlEncodedBody)
import           Network.URI                         (URI (..))
import           Prelude                             hiding (exp)

-- |  Creates the URL for the authorization request.
--    This function constructs the URL that the client needs to redirect the user to in order to
--    start the authorization code flow.
createAuthorizationRequestURL :: (MonadCatch m) => OIDC -- ^ The OIDC configuration
  -> Scope        -- ^ The scope
  -> Maybe State  -- ^ The state
  -> Maybe Nonce  -- ^ The nonce
  -> Parameters   -- ^ Extra parameters
  -> m URI        -- ^ The authorization request URL to redirect to
createAuthorizationRequestURL oidc scope state nonce extra = do
    authenticationURL
  where

    -- | Generates the authentication URL for the authorization code flow.
    -- This URL is used to redirect the user to the authorization server
    -- where they can authenticate and authorize the client application.
    authenticationURL :: (MonadCatch m) => m URI
    authenticationURL = do
      req <- requestFromURI endpoint
      return $ getUri $ setQueryString query req

    -- | The endpoint URI for the authorization code flow.
    endpoint :: URI
    endpoint = uri $ providerAuthorizationEndpoint $ metadata $ oidcProvider oidc

    -- | 'query' represents the parameters used in the authorization code flow
    query :: Parameters
    query = base <> maybe [] (\s -> [("state", Just s)]) state <> maybe [] (\n -> [("nonce", Just n)]) nonce <> extra

    -- | 'base' represents the base parameters used in the Authorization Code Flow
    --   for the OIDC (OpenID Connect) client. These parameters are essential for
    --   initiating the authorization request and handling the response.
    base :: Parameters
    base =
      [ ("response_type", Just "code"),
        ("client_id", Just $ encodeUtf8 $ oidcClientId oidc),
        ("redirect_uri", Just $ encodeUtf8 $ oidcRedirectUri oidc),
        ("scope", Just $ B.pack $ unwords $ nub $ map unpack scope <> [unpack "openid"])
      ]

-- | Initiates an authorization request in the Authorization Code Flow.
--
-- This function constructs the authorization request URI that the user
-- should be redirected to in order to initiate the OAuth 2.0 Authorization
-- Code Flow. It takes care of storing the session information and generating
-- the appropriate request parameters and the state and nonce values.
initiateAuthorizationRequest :: (MonadCatch m) => SessionStorage m  -- ^ The session storage
  -> SessionId  -- ^ The session identifier
  -> OIDC       -- ^ The OIDC configuration
  -> Scope      -- ^ The scope
  -> Parameters -- ^ Extra parameters
  -> m URI      -- ^ The authorization request URL to redirect to
initiateAuthorizationRequest storage sid oidc scope extra = do

  -- Verify that the provider supports the response type
  unless ("code" `elem` providerResponseTypesSupported (metadata $ oidcProvider oidc)) $ throwM $ UnsupportedOperation "Response type code not supported by OP"

  -- Create a new session
  s <- sessionStoreGenerate storage
  n <- sessionStoreGenerate storage
  sessionStoreSave storage sid $
    Session
      { sessionState = Just s,
        sessionNonce = Just n,
        sessionAccessToken = Nothing,
        sessionIdToken = Nothing,
        sessionRefreshToken = Nothing,
        sessionCode = Nothing
      }
  createAuthorizationRequestURL oidc scope (Just s) (Just n) extra

-- |  Handles the authorization code flow when the authorization is granted it
--    exchanges the authorization code for tokens and retrieves the token claims
--    from the response. It also validates the identity and access tokens.
authorizationGranted :: (MonadIO m, MonadCatch m, FromJSON a) => SessionStorage m -- ^ The session storage
  -> SessionId  -- ^ The session identifier
  -> Manager    -- ^ The HTTP manager for making requests
  -> OIDC       -- ^ The OIDC configuration
  -> State      -- ^ The state
  -> Code       -- ^ The authorization code
  -> m (IdTokenClaims a)
authorizationGranted storage sid mgr oidc state code = do

    -- Verify that the provider supports authorization code grant type
    unless (isAnElementOf "authorization_code" (providerGrantTypesSupported (metadata $ oidcProvider oidc))) $ throwM $ UnsupportedOperation "Authorization code grant not supported by OP"

    -- Verify the session
    session <- sessionStoreGet storage sid >>= verifySession

    -- Exchange code with tokens
    tr <- liftIO callTokenEndpoint

    -- Validate the ID token
    claims <- T.validateToken oidc $ tokensResponseIdToken tr
    liftIO $ T.validateIdClaims (providerIssuer . metadata $ oidcProvider oidc) (oidcClientId oidc) (sessionNonce session) claims

    -- Validate the Access token
    claimsA::(AccessTokenClaims NoExtraClaims) <- T.validateToken oidc $ tokensResponseAccessToken tr
    liftIO $ T.validateAccessClaims (providerIssuer . metadata $ oidcProvider oidc) (oidcAudience oidc) claimsA

    -- Update the session
    sessionStoreSave storage sid $
      session
        {
          sessionNonce = Nothing,
          sessionState = Nothing,
          sessionAccessToken = Just $ tokensResponseAccessToken tr,
          sessionIdToken = Just $ tokensResponseIdToken tr,
          sessionRefreshToken = tokensResponseRefreshToken tr,
          sessionCode = Just code
        }

    return claims

  where

    -- | Verifies the given session. If the session is 'Nothing', it throws an error.
    -- If the session is 'Just', it returns the session.
    verifySession :: (MonadIO m, MonadThrow m) => Maybe Session -> m Session
    verifySession Nothing = do
      throwM $ InvalidState "No session found"
    verifySession (Just s) = do
      when (sessionState s /= Just state) $ throwM $ InvalidState "Invalid state"
      when (isJust (sessionAccessToken s)) $ throwM $ InvalidState "Access token already exists"
      when (isJust (sessionIdToken s)) $ throwM $ InvalidState "ID token already exists"
      when (isJust (sessionRefreshToken s)) $ throwM $ InvalidState "Refresh token already exists"
      when (isNothing (sessionNonce s)) $ throwM $ InvalidState "Missing nonce"
      when (isJust (sessionCode s)) $ throwM $ InvalidState "Code already exists"
      return s

    -- | Calls the token endpoint to exchange an authorization code for tokens.
    -- This function performs an HTTP request to the token endpoint and returns
    -- the response containing the tokens.
    callTokenEndpoint :: IO TokensResponse
    callTokenEndpoint = do
        req <- requestFromURI endpoint
        res <- httpLbs (urlEncodedBody base $ req { method = "POST" }) mgr
        case eitherDecode (responseBody res) of
          Left err -> throwM $ ValidationException $ "Failed to parse token exchange response " <> pack err
          Right tr -> do
            when (tokensResponseTokenType tr /= "Bearer") $ throwM $ ValidationException $ "Invalid token type " <> tokensResponseTokenType tr
            return tr

    -- | Retrieves the token endpoint URI from the OIDC provider metadata.
    -- This endpoint is used to exchange the authorization code for an access token.
    endpoint = uri $ providerTokenEndpoint $ metadata $ oidcProvider oidc

    -- | The base parameters for the authorization code flow.
    base     =
      [ ("grant_type",    "authorization_code")
      , ("code",          code)
      , ("client_id",     encodeUtf8 $ oidcClientId oidc)
      , ("client_secret", encodeUtf8 $ oidcClientSecret oidc)
      , ("redirect_uri",  encodeUtf8 $ oidcRedirectUri oidc)
      ]

