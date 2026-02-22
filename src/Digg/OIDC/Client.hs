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

-- | This data type represents information needed in the OpenID flows.
data OIDC = OIDC
  { oidcClientId          :: Text,     -- ^ The client id as defined by the OIDC provider.
    oidcClientSecret      :: Text,     -- ^ The client secret as defined by the OIDC provider.
    oidcRedirectUri       :: Text,     -- ^ The redirect URI.
    oidcLogoutRedirectUri :: Maybe Text, -- ^ The logout redirect URI.
    oidcProvider          :: Provider,  -- ^ The OIDC provider configuration.
    oidcAudience          :: Maybe Text -- ^ The audience to verify in the Access Token.  
  }

-- | Creates an OIDC (OpenID Connect) client configuration with the given parameters.
createOIDC :: Text  -- ^ The client id as defined by the OIDC provider.
  -> Text           -- ^ The client secret as defined by the OIDC provider.
  -> Text           -- ^ The redirect URI.
  -> Maybe Text     -- ^ The logout redirect URI.
  -> Maybe Text     -- ^ The audience to verify in the Access Token.
  -> Provider       -- ^ The OIDC provider configuration.
  -> OIDC           -- ^ The OIDC client configuration.
createOIDC clientId clientSecret redirectURI logoutRedirectURI audience provider =
  OIDC
    { oidcClientId = clientId,
      oidcClientSecret = clientSecret,
      oidcRedirectUri = redirectURI,
      oidcLogoutRedirectUri = logoutRedirectURI,
      oidcProvider = provider,
      oidcAudience = audience
    }

-- | The 'OIDCException' data type represents exceptions that can occur
--   within the OpenID Connect (OIDC) process. These exceptions are used
--   to handle various error scenarios that may arise during OIDC
--   authentication and authorization flows.
data OIDCException
  = DiscoveryException Text             -- ^ Represents an exception that occurred during the OIDC provider discovery process
  | BackendHTTPException Text           -- ^ Represents an HTTP exception that occurred in a backend call
  | InvalidState Text                   -- ^ Represents an invalid state exception during any of the OIDC flows
  | ValidationException Text            -- ^ Represents a validation exception during any of the OIDC flows
  | UnsecuredJWT ByteString             -- ^ Represents an unsecured JWT error, during login or refresh flows
  | JWTException JwtError               -- ^ Represents a JWT error, during login or refresh flows
  | UnsupportedOperation Text           -- ^ Represents an unsupported operation by the OpenID Provider
  deriving (Show, Eq)

instance Exception OIDCException
