-- |
--    Module: Digg.OIDC.Client
--    Copyright: (c) 2024 Digg - Agency for Digital Government
--    License: MIT
--    Maintainer: tomas.stenlund@telia.com
--    Stability: experimental
--
--    The module defines types and functions to handle client configuration and creations.
module Digg.OIDC.Client (OIDC (..), createOIDC, OIDCException (..)) where

import           Control.Exception                   (Exception)
import           Data.ByteString                     (ByteString)
import           Data.Text                           (Text)
import           Digg.OIDC.Client.Discovery.Provider (Provider)
import           Jose.Jwt                            (JwtError)
import           Network.HTTP.Client                 (HttpException)

-- | This data type represents information needed in the OpenID flow.
data OIDC = OIDC
  { oidcClientId     :: Text,     -- ^ The client id as defined by the OIDC provider.
    oidcClientSecret :: Text,     -- ^ The client secret as defined by the OIDC provider.
    oidcRedirectUri  :: Text,     -- ^ The redirect URI.
    oidcProvider     :: Provider  -- ^ The OIDC provider configuration.
  }

-- | Creates an OIDC (OpenID Connect) client configuration with the given parameters.
createOIDC :: Text  -- ^ The client id as defined by the OIDC provider.
  -> Text           -- ^ The client secret as defined by the OIDC provider.
  -> Text           -- ^ The redirect URI.
  -> Provider       -- ^ The OIDC provider configuration.
  -> OIDC           -- ^ The OIDC client configuration.
createOIDC clientId clientSecret redirectURI provider =
  OIDC
    { oidcClientId = clientId,
      oidcClientSecret = clientSecret,
      oidcRedirectUri = redirectURI,
      oidcProvider = provider
    }

-- | The 'OIDCException' data type represents exceptions that can occur
--   within the OpenID Connect (OIDC) process. These exceptions are used
--   to handle various error scenarios that may arise during OIDC
--   authentication and authorization flows.
data OIDCException
  = DiscoveryException Text             -- ^ Represents an exception that occurred during the OIDC provider discovery process
  | BackendHTTPException HttpException  -- ^ Represents an HTTP exception that occurred in the backend call
  | InvalidState Text                   -- ^ Represents an invalid state exception during any of the OIDC flows
  | ValidationException Text            -- ^ Represents a validation exception during any of the OIDC flows
  | UnsecuredJWT ByteString             -- ^ Represents an unsecured JWT error, during login or refresh flows
  | JWTException JwtError               -- ^ Represents a JWT error, during login or refresh flows
  deriving (Show)

instance Exception OIDCException
