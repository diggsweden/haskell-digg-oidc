{-# LANGUAGE DeriveGeneric     #-}
{-# LANGUAGE LambdaCase        #-}
{-# LANGUAGE OverloadedStrings #-}
{-# OPTIONS_GHC -Wno-unrecognised-pragmas #-}
{-# HLINT ignore "Use lambda-case" #-}

-- |
--    Module: Digg.OIDC.Client.Tokens
--    Copyright: (c) 2024 Digg - Agency for Digital Government
--    License: MIT
--    Maintainer: tomas.stenlund@telia.com
--    Stability: experimental
--
--    The module defines types and functions for handling OIDC tokens and validations of standard claims as well
--    as custom claims.
module Digg.OIDC.Client.Claims
  ( Claims (..),
    IdClaims (..),
    AccessClaims (..),
    RolesClaims (..),
    ResourceAccessClaims (..),
    NoExtraClaims (..),
    IdTokenClaims,
    AccessTokenClaims
  )
where

import           Control.Applicative                 (optional, (<|>))
import           Data.Aeson                          (FromJSON (parseJSON),
                                                      Value (..), 
                                                      withObject, (.:), (.:?))
import           Data.ByteString                     (ByteString)
import           Data.Map.Strict                     (Map)
import           Data.Text                           (Text)
import           Data.Text.Encoding                  (encodeUtf8)
import           GHC.Generics                        (Generic)
import           Jose.Jwt                            (IntDate (..))
import           Prelude                             hiding (exp)

-- | Type aliases for the 'Claims' data type with specific additional claims for the ID token.
type IdTokenClaims a = Claims (IdClaims a)

-- | Type aliases for the 'Claims' data type with specific additional claims for the access token.
type AccessTokenClaims a = Claims (AccessClaims a)

-- | The 'Claims' data type represents the claims contained within a token and specific for any JWT.
-- The type parameter 'a' allows for flexibility in specifying additional claims.
-- This can be used to define different kinds of tokens with varying claim structures.
data Claims a = Claims
  { iss          :: !Text,     -- ^ The issuer of the token
    sub          :: !Text,     -- ^ The subject of the token
    aud          :: ![Text],   -- ^ The audience of the token
    exp          :: !IntDate,  -- ^ The expiration time of the token
    iat          :: !IntDate,  -- ^ The time the token was issued
    jti          :: !Text,     -- ^ The JWT ID of the token

    other_claims :: !a     -- ^ Additional claims of the token, defined by the user of this library
  }
  deriving (Show, Eq, Generic)

instance (FromJSON a) => FromJSON (Claims a) where
  parseJSON = withObject "Claims" $ \o -> do
    Claims
      <$> o .: "iss"
      <*> o .: "sub"
      <*> ((o .: "aud") <|> ((:[]) <$> (o .: "aud")))
      <*> o .: "exp"
      <*> o .: "iat"
      <*> o .: "jti"
      <*> parseJSON (Object o)

-- | 'IdClaims' represents the claims contained in an ID token.
-- The type parameter 'a' allows for flexibility in the type of the claims.
data IdClaims a = IdClaims
  {
    id_nonce        :: !(Maybe ByteString),   -- ^ The nonce value of the token
    id_auth_time    :: !(Maybe IntDate),      -- ^ The time the user authenticated
    id_acr          :: !(Maybe Text),         -- ^ The authentication context class reference
    id_amr          :: !(Maybe Text),         -- ^ The authentication methods used
    id_azp          :: !(Maybe Text),         -- ^ The authorized party

    id_other_claims :: !(Maybe a)           -- ^ Additional claims of the id token, defined by the user of this library

  } deriving (Show, Eq, Generic)

instance (FromJSON a) => FromJSON (IdClaims a) where
  parseJSON = withObject "IdClaims" $ \o ->
    (IdClaims . fmap encodeUtf8 <$> (o .:? "nonce"))
      <*> (fmap IntDate <$> (o .:? "auth_time"))
      <*> o .:? "acr"
      <*> o .:? "amr"
      <*> o .:? "azp"
      <*> optional (parseJSON (Object o))

-- | 'AccessClaims' represents the claims contained in an access token.
-- The type parameter 'a' allows for flexibility in specifying the type of the claims.
data AccessClaims a = AccessClaims
  {
    a_scope        :: !(Maybe Text),  -- ^ The scope of the token
    a_auth_time    :: !(Maybe IntDate), -- ^ The time the user authenticated
    a_acr          :: !(Maybe Text),    -- ^ The authentication context class reference
    a_amr          :: !(Maybe Text),    -- ^ The authentication methods used
    a_other_claims :: !(Maybe a)        -- ^ Additional claims of the id token, defined by the user of this library
  } deriving (Show, Eq, Generic)

instance (FromJSON a) => FromJSON (AccessClaims a) where
  parseJSON = withObject "AccessClaims" $ \o ->
    AccessClaims
      <$> o .:? "scope"
      <*> (fmap IntDate <$> (o .:? "auth_time"))
      <*> o .:? "acr"
      <*> o .:? "amr"
      <*> optional (parseJSON (Object o))


-- | 'RolesClaim' is a type for the "roles" claim in the access tokens resource_access,
-- which is a list of strings.
data RolesClaims = RolesClaims
  { r_roles :: ![Text]  -- ^ The list of roles in the claim
  } deriving (Show, Generic)

instance FromJSON RolesClaims where
  parseJSON = withObject "RolesClaims" $ \v ->
    RolesClaims <$> v .: "roles"

-- | 'ResourceAccessClaims' is a type for the "resource_access" claim in the access tokens,
-- which is a map of resource names to their corresponding 'RolesClaims'.
data ResourceAccessClaims a = ResourceAccessClaims
  { ra_resource_access :: Map Text RolesClaims,   -- ^ The map of resource access in the claim
    ra_other_claims :: !(Maybe a)                 -- ^ Additional claims of the resource access claim, defined by the user of this library
  } deriving (Show)

instance (FromJSON a) => FromJSON (ResourceAccessClaims a) where
  parseJSON = withObject "ResourceAccessClaims" $ \v ->
    ResourceAccessClaims <$> v .: "resource_access" <*> optional (parseJSON (Object v)) 

-- | 'NoExtraClaims' is a data type representing the absence of additional claims.
--   It is used when no extra claims are needed in the context of the claims.
data NoExtraClaims = NoClaims
  deriving (Show, Eq, Generic)

instance FromJSON NoExtraClaims
