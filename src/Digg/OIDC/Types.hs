{-# LANGUAGE InstanceSigs      #-}
{-# LANGUAGE OverloadedStrings #-}
-- |
--    Module      : Digg.OIDC.Types
--    Copyright   : (c) 2024 Digg - Agency for Digital Government
--    License     : MIT
--    Maintainer  : tomas.stenlund@telia.com
--    Stability   : experimental
--
--    The module defines various types used in the OIDC client library, such as 'Nonce', 'State', 'IssuerLocation', 'Endpoint', 'Scope', 'ScopeValue', 'Code', 'Address', and 'Parameters'.
module Digg.OIDC.Types
  ( Nonce,
    State,
    IssuerLocation,
    Endpoint,
    Scope,
    ScopeValue,
    Code,
    Address (..),
    Parameters,
  )
where

import           Data.Aeson       (FromJSON (..), ToJSON (..), Value (..))
import           Data.Aeson.Types (Parser, prependFailure, typeMismatch)
import           Data.ByteString  (ByteString)
import           Data.Text        (Text, unpack)
import           Network.URI      (URI, parseAbsoluteURI)

-- | The 'Address' data type represents an address with a single field 'uri'.
-- The 'uri' field is of type 'URI' and is used to store the address URI.
--
-- This is a workaround to be able to handle URI in JSON format.
newtype Address = Address {
    uri :: URI -- ^ The URI value of the address
  } deriving (Show)

instance ToJSON Address where
  toJSON :: Address -> Value
  toJSON v = toJSON $ show $ uri v

instance FromJSON Address where
  parseJSON :: Value -> Parser Address
  parseJSON (String v) = case parseAbsoluteURI (unpack v) of
    Just u  -> return $ Address {uri = u}
    Nothing -> aesonError (String v)
  parseJSON invalid = aesonError invalid

-- | Represents an URI type in JSON format used in the OIDC (OpenID Connect) context
--   for various purposes, such as endpoints, issuer locations, etc.
aesonError :: Value -> Parser a
aesonError v = prependFailure "Parsing URI failed, " (typeMismatch "String" v)

-- | Type alias for Nonce, representing a cryptographic nonce used in
--   OpenID Connect sessions.
--
--   This type alias uses 'ByteString' to store the nonce value.
type Nonce = ByteString

-- | Represents the state parameter used in OAuth2 authentication flows.
-- The state is a unique string that is used to maintain state between the
-- request and the callback.
type State = ByteString

-- | 'Code' represents an authorization code in the OpenID Connect flow.
-- It is typically a short-lived token used to obtain an access token.
-- The type alias 'Code' is defined as 'ByteString' for efficient handling
-- of binary data.
type Code = ByteString

-- | 'ScopeValue' represents a scope value in the context of OpenID Connect (OIDC).
-- It is used to define the permissions or access levels that a client application
-- is requesting from the OIDC provider.
--
-- For example, a client might request access to the user's email address or profile
-- information by including the appropriate scope values in the authentication request.
type ScopeValue = Text

-- | 'Scope' represents a list of 'ScopeValue's, which are used to define
-- the permissions or access levels requested by an OpenID Connect client.
type Scope = [ScopeValue]

-- | 'IssuerLocation' is a type alias for 'Address', representing the location of the OpenID Connect (OIDC) issuer.
-- This type is used to store the URI of the OIDC issuer
-- and used mainly during discovery.
type IssuerLocation = Address

-- | 'Endpoint' is a type alias for 'Address', representing an OpenID Connect (OIDC) endpoint.
-- This type is used to define the various endpoints involved in the OIDC flows.
type Endpoint = Address

-- | 'Parameters' is a type alias for a list of key-value pairs, to be used
-- for setting various parameters for calls to the OP.
type Parameters = [(ByteString, Maybe ByteString)]

