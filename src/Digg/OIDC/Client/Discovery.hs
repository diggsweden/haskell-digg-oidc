{-# LANGUAGE OverloadedStrings #-}

-- |
--    Module: Digg.OIDC.Client.Discovery
--    Copyright: (c) 2024 Digg - Agency for Digital Government
--    License: MIT
--    Maintainer: tomas.stenlund@telia.com
--    Stability: experimental
--
--    The module defines functions to discover OIDC providers.
module Digg.OIDC.Client.Discovery (discover) where

import           Control.Monad.Catch                 (MonadThrow (throwM),
                                                      catch)
import           Data.Aeson                          (eitherDecode)
import           Data.Text                           (pack)
import           Digg.OIDC.Client                    (OIDCException (..))
import           Digg.OIDC.Client.Discovery.Provider (Provider (..),
                                                      ProviderMetadata (..))
import           Digg.OIDC.Types                     (Address (..), Endpoint,
                                                      IssuerLocation)
import           Jose.Jwk                            (Jwk, keys)
import           Network.HTTP.Client                 (HttpException, Manager,
                                                      Request, httpLbs,
                                                      requestFromURI,
                                                      responseBody,
                                                      responseStatus)
import           Network.HTTP.Types.Status           (Status (..))
import           Network.URI                         (URI (..), nullURI,
                                                      relativeTo)

wellKnownURI :: URI
wellKnownURI = nullURI {uriPath = ".well-known/openid-configuration"}

createDiscoveryRequest :: (MonadThrow m) => IssuerLocation -> m Request
createDiscoveryRequest location = do
  requestFromURI $ relativeTo wellKnownURI $ uri location

createJWKSRequest :: (MonadThrow m) => Endpoint -> m Request
createJWKSRequest location = do
  requestFromURI $ uri location

-- | Discover the OpenID Connect provider configuration for a given issuer location.
--
-- This function takes an 'IssuerLocation' and an HTTP 'Manager' and performs
-- the HTTP requests to retrieve the provider's configuration.
discover :: IssuerLocation  -- ^ The issuer location, the well-known openid configuration path is appended to this location
  -> Manager                -- ^ The HTTP manager to use for the requests
  -> IO Provider            -- ^ The discovered provider configuration
discover location manager =
  catch discoverCall discoverError
  where
    discoverCall :: IO Provider
    discoverCall = do
      md <- getMetadata location
      p <- getJWKS $ providerJWKSUri md
      return $ Provider md p

    discoverError :: (MonadThrow m) => HttpException -> m Provider
    discoverError e = do
      throwM $ BackendHTTPException e

    getMetadata :: IssuerLocation -> IO ProviderMetadata
    getMetadata loc = do
      req <- createDiscoveryRequest loc
      res <- httpLbs req manager
      case statusCode (responseStatus res) of
        200 -> do
          case eitherDecode $ responseBody res of
            Right md -> do
              return md
            Left err -> do
              throwM $ DiscoveryException $ "Failed to parse JSON response, error: " <> pack err
        n -> do
          throwM $ DiscoveryException $ "Well-known endpoint retuned HTTP Code " <> pack (show n)

    getJWKS :: Endpoint -> IO [Jwk]
    getJWKS ep = do
      req <- createJWKSRequest ep
      res <- httpLbs req manager
      case keys <$> eitherDecode (responseBody res) of
        Right ks -> return ks
        Left err -> throwM $ DiscoveryException $ "Failed to parse JWKS JSON response, error: " <> pack err
