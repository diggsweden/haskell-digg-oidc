{-# LANGUAGE OverloadedStrings #-}

-- |
--    Module: Digg.OIDC.Client.Discovery
--    Copyright: (c) 2024 Digg - Agency for Digital Government
--    License: MIT
--    Maintainer: tomas.stenlund@telia.com
--    Stability: experimental
--
--    The module defines functions for the OpenID Provider Configuration Request according to
--    OpenID Connect Discovery 1.0
module Digg.OIDC.Client.Discovery (discover) where

import           Control.Monad.Catch                 (MonadThrow (throwM),
                                                      catch)
import           Data.Aeson                          (eitherDecode)
import           Data.Text                           (Text, pack, unpack)
import           Digg.OIDC.Client                    (OIDCException (..))
import           Digg.OIDC.Client.Discovery.Provider (Provider (..),
                                                      ProviderMetadata (..))
import           Digg.OIDC.Types                     (Address (..), Endpoint,
                                                      Issuer)
import           Jose.Jwk                            (Jwk, keys)
import           Network.HTTP.Client                 (HttpException, Manager,
                                                      Request, httpLbs,
                                                      parseRequest,
                                                      requestFromURI,
                                                      responseBody,
                                                      responseStatus)
import           Network.HTTP.Types.Status           (Status (..))

import           Control.Monad                       (when)

-- | The URI for the well-known OpenID Connect discovery endpoint.
wellKnownURI :: Text
wellKnownURI = "/.well-known/openid-configuration"

-- | Creates a discovery request for the given OIDC issuer.
createDiscoveryRequest :: (MonadThrow m) => Issuer -> m Request
createDiscoveryRequest location = do
  parseRequest $ unpack $ location <> wellKnownURI

-- | Creates a JSON Web Key Set (JWKS) request for the given endpoint.
createJWKSRequest :: (MonadThrow m) => Endpoint -> m Request
createJWKSRequest location = do
  requestFromURI $ uri location

-- | Discover the OpenID Connect provider configuration for a given issuer location.
--
-- This function takes an 'IssuerLocation' and an HTTP 'Manager' and performs
-- the HTTP requests to retrieve the provider's configuration.
discover :: Issuer  -- ^ The issuer location, the well-known openid configuration path is appended to this location
  -> Manager                -- ^ The HTTP manager to use for the requests
  -> IO Provider            -- ^ The discovered provider configuration
discover issuer manager = do
  catch discoverCall discoverError >>= validateProvider
  where

    -- | Makes a discovery call to the OIDC provider to retrieve its configuration.
    -- This function performs an IO action that returns a 'Provider' containing
    -- the provider's metadata.
    discoverCall :: IO Provider
    discoverCall = do
      md <- getMetadata issuer
      p <- getJWKS $ providerJWKSUri md
      return $ Provider md p

    -- | Handles HTTP exceptions that occur during the discovery process.
    discoverError :: (MonadThrow m) => HttpException -> m Provider
    discoverError e = do
      throwM $ BackendHTTPException e

    -- | Retrieves the OpenID Connect provider metadata for a given issuer.
    getMetadata :: Issuer -> IO ProviderMetadata
    getMetadata loc = do
      res <- createDiscoveryRequest loc >>= flip httpLbs manager
      case statusCode (responseStatus res) of
        200 -> do
          case eitherDecode $ responseBody res of
            Right md -> do
              return md
            Left err -> do
              throwM $ DiscoveryException $ "Failed to parse JSON response, error: " <> pack err
        n -> do
          throwM $ DiscoveryException $ "Well-known endpoint retuned HTTP Code " <> pack (show n)

    -- | Fetches the JSON Web Key Set (JWKS) from the given endpoint.
    getJWKS :: Endpoint -> IO [Jwk]
    getJWKS ep = do
      res <- createJWKSRequest ep >>= flip httpLbs manager
      case keys <$> eitherDecode (responseBody res) of
        Right ks -> return ks
        Left err -> throwM $ DiscoveryException $ "Failed to parse JWKS JSON response, error: " <> pack err

    -- | Validates the given OIDC provider.
    validateProvider :: Provider -> IO Provider
    validateProvider provider = do
      let md = metadata provider
      when (providerIssuer md /= issuer) $ throwM $ DiscoveryException "Issuer value do not match configuration"
      return provider
