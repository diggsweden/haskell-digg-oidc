{-# LANGUAGE InstanceSigs      #-}
{-# LANGUAGE LambdaCase        #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE TemplateHaskell   #-}
-- |
--    Module: Digg.OIDC.Client.Discovery.Provider
--    Copyright: 2024 Digg - Agency for Digital Government
--    License: MIT
--    Maintainer: tomas.stenlund@telia.com
--    Stability: experimental
--
--    The module defines the 'ProviderMetadata' and 'Provider' types for representing OIDC providers
--    configurations.
module Digg.OIDC.Client.Discovery.Provider (ProviderMetadata (..), Provider (..), Algorithm (..)) where

import           Data.Aeson       (FromJSON (..), Value (..), withText)
import           Data.Aeson.TH    (Options (..), defaultOptions, deriveFromJSON)
import           Data.Aeson.Types (Parser, camelTo2)
import           Data.Text        (Text)
import           Digg.OIDC.Types  (Endpoint, Scope)
import           Jose.Jwa         (JwsAlg (..))
import           Jose.Jwk         (Jwk)

-- | Represents the JWS (JSON Web Signature) algorithm used in the OIDC (OpenID Connect) context.
data Algorithm
  = Algorithm JwsAlg
  | Unsupported Text
  deriving (Show, Eq)

instance FromJSON Algorithm where
  parseJSON :: Value -> Parser Algorithm
  parseJSON = withText "Algorithm as id" $ \case
    "HS256" -> pure $ Algorithm HS256
    "HS384" -> pure $ Algorithm HS384
    "HS512" -> pure $ Algorithm HS512
    "RS256" -> pure $ Algorithm RS256
    "RS384" -> pure $ Algorithm RS384
    "RS512" -> pure $ Algorithm RS512
    "ES256" -> pure $ Algorithm ES256
    "ES384" -> pure $ Algorithm ES384
    "ES512" -> pure $ Algorithm ES512
    "EdDSA" -> pure $ Algorithm EdDSA
    "None" -> pure $ Algorithm None
    alg -> pure $ Unsupported alg

-- | The 'Provider' data type represents an OpenID Connect (OIDC) provider.
-- This type is used to encapsulate the details of an OIDC provider, which
-- can be discovered and utilized for authentication and authorization purposes.
data Provider = Provider
  { metadata :: ProviderMetadata,
    jwkSet   :: [Jwk]
  }
  deriving (Show)

-- | 'ProviderMetadata' represents the metadata associated with an OpenID Connect (OIDC) provider.
-- This data structure is used to store and manage the information retrieved from the provider's
-- discovery endpoint, which typically includes details such as the authorization endpoint, token
-- endpoint, userinfo endpoint, and supported scopes and claims. It is by no means the complete
-- set of metadata that can be retrieved from the discovery endpoint, but it is a good starting point.
data ProviderMetadata = ProviderMetadata
  { providerIssuer                            :: Text,              -- ^ The issuer value of the provider
    providerAuthorizationEndpoint             :: Endpoint,          -- ^ The authorization endpoint
    providerTokenEndpoint                     :: Endpoint,          -- ^ The token endpoint
    providerRegistrationEndpoint              :: Maybe Endpoint,    -- ^ The registration endpoint
    providerScopesSupported                   :: Maybe Scope,       -- ^ The supported scopes
    providerResponseModesSupported            :: Maybe [Text],      -- ^ The supported response modes
    providerGrantTypesSupported               :: Maybe [Text],      -- ^ The supported grant types
    providerACRValuesSupported                :: Maybe [Text],      -- ^ The supported ACR values
    providerUserinfoEndpoint                  :: Maybe Endpoint,    -- ^ The userinfo endpoint
    providerRevocationEndpoint                :: Maybe Endpoint,    -- ^ The revocation endpoint
    providerEndSessionEndpoint                :: Maybe Endpoint,    -- ^ The end session endpoint
    providerJWKSUri                           :: Endpoint,          -- ^ The JWKS URI
    providerResponseTypesSupported            :: [Text],            -- ^ The supported response types
    providerSubjectTypesSupported             :: [Text],            -- ^ The supported subject types
    providerIdTokenSigningAlgValuesSupported  :: [Algorithm],       -- ^ The supported signing algorithms for ID tokens
    providerTokenEndpointAuthMethodsSupported :: Maybe [Text],      -- ^ The supported token endpoint authentication methods
    providerClaimsSupported                   :: Maybe [Text]       -- ^ The supported claims
  }
  deriving (Show)

$(deriveFromJSON defaultOptions {fieldLabelModifier = camelTo2 '_' . drop 8} ''ProviderMetadata)
