{-# LANGUAGE DeriveGeneric         #-}
{-# LANGUAGE LambdaCase            #-}
{-# LANGUAGE OverloadedStrings     #-}
{-# OPTIONS_GHC -Wno-unrecognised-pragmas #-}
{-# HLINT ignore "Use lambda-case" #-}

{-# LANGUAGE DuplicateRecordFields #-}
{-# LANGUAGE NoFieldSelectors      #-}
{-# LANGUAGE OverloadedRecordDot   #-}

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
    ProfileClaims (..),
    ResourceAccessClaims (..),
    NoExtraClaims (..),
    IdTokenClaims,
    AccessTokenClaims
  )
where

import           Control.Applicative ((<|>))
import           Data.Aeson          (FromJSON (parseJSON), Value (..),
                                      withObject, (.:), (.:?))
import           Data.ByteString     (ByteString)
import           Data.Map.Strict     (Map)
import           Data.Maybe          (fromMaybe)
import           Data.Text           (Text)
import           Data.Text.Encoding  (encodeUtf8)
import           GHC.Generics        (Generic)
import           Jose.Jwt            (IntDate (..))
import           Prelude             hiding (exp)

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
      <*> (fromMaybe [] <$> ((o .:? "aud") <|> (fmap (:[]) <$> (o .:? "aud"))))
      <*> o .: "exp"
      <*> o .: "iat"
      <*> o .: "jti"
      <*> parseJSON (Object o)

-- | 'IdClaims' represents the claims contained in an ID token.
-- The type parameter 'a' allows for flexibility in the type of the claims.
data IdClaims a = IdClaims
  {
    nonce        :: !(Maybe ByteString),   -- ^ The nonce value of the token
    auth_time    :: !(Maybe IntDate),      -- ^ The time the user authenticated
    acr          :: !(Maybe Text),         -- ^ The authentication context class reference
    amr          :: !(Maybe Text),         -- ^ The authentication methods used
    azp          :: !(Maybe Text),         -- ^ The authorized party
    other_claims :: !a           -- ^ Additional claims of the id token, defined by the user of this library

  } deriving (Show, Eq, Generic)

instance (FromJSON a) => FromJSON (IdClaims a) where
  parseJSON = withObject "IdClaims" $ \o ->
    (IdClaims . fmap encodeUtf8 <$> (o .:? "nonce"))
      <*> (fmap IntDate <$> (o .:? "auth_time"))
      <*> o .:? "acr"
      <*> o .:? "amr"
      <*> o .:? "azp"
      <*> parseJSON (Object o)

-- | 'AccessClaims' represents the claims contained in an access token.
-- The type parameter 'a' allows for flexibility in specifying the type of the claims.
data AccessClaims a = AccessClaims
  {
    scope        :: !(Maybe Text),  -- ^ The scope of the token
    auth_time    :: !(Maybe IntDate), -- ^ The time the user authenticated
    acr          :: !(Maybe Text),    -- ^ The authentication context class reference
    amr          :: !(Maybe Text),    -- ^ The authentication methods used
    other_claims :: !a        -- ^ Additional claims of the id token, defined by the user of this library
  } deriving (Show, Eq, Generic)

instance (FromJSON a) => FromJSON (AccessClaims a) where
  parseJSON = withObject "AccessClaims" $ \o ->
    AccessClaims
      <$> o .:? "scope"
      <*> (fmap IntDate <$> (o .:? "auth_time"))
      <*> o .:? "acr"
      <*> o .:? "amr"
      <*> parseJSON (Object o)

-- | 'RolesClaim' is a type for the "roles" claim in the access tokens resource_access,
-- which is a list of strings.
data RolesClaims = RolesClaims
  { roles :: ![Text]  -- ^ The list of roles in the claim
  } deriving (Show, Generic)

instance FromJSON RolesClaims where
  parseJSON = withObject "RolesClaims" $ \v ->
    RolesClaims <$> v .: "roles"

-- | 'ResourceAccessClaims' is a type for the "resource_access" claim in the access tokens,
-- which is a map of resource names to their corresponding 'RolesClaims'.
data ResourceAccessClaims a = ResourceAccessClaims
  { resource_access :: Map Text RolesClaims,   -- ^ The map of resource access in the claim
    other_claims    :: !a                 -- ^ Additional claims of the resource access claim, defined by the user of this library
  } deriving (Show, Generic)

instance (FromJSON a) => FromJSON (ResourceAccessClaims a) where
  parseJSON = withObject "ResourceAccessClaims" $ \v ->
    ResourceAccessClaims <$> v .: "resource_access" <*> parseJSON (Object v)

-- | 'ProfileClaims' is a type for the standard profile claims in the ID token,
-- which includes various user attributes. 
data ProfileClaims a = ProfileClaims
  { name :: !(Maybe Text),
    family_name :: !(Maybe Text),
    given_name :: !(Maybe Text),
    middle_name :: !(Maybe Text),
    nickname :: !(Maybe Text),
    preferred_username :: !(Maybe Text),
    profile :: !(Maybe Text),
    picture :: !(Maybe Text),
    website :: !(Maybe Text),
    gender :: !(Maybe Text),
    birthdate :: !(Maybe Text),
    zoneinfo :: !(Maybe Text),
    locale :: !(Maybe Text),
    updated_at :: !(Maybe IntDate),
    other_claims :: !a
  } deriving (Show, Generic)

instance (FromJSON a) => FromJSON (ProfileClaims a) where
  parseJSON = withObject "ProfileClaims" $ \v ->
    ProfileClaims
      <$> v .:? "name"
      <*> v .:? "family_name"
      <*> v .:? "given_name"
      <*> v .:? "middle_name"
      <*> v .:? "nickname"
      <*> v .:? "preferred_username"
      <*> v .:? "profile"
      <*> v .:? "picture"
      <*> v .:? "website"
      <*> v .:? "gender"
      <*> v .:? "birthdate"
      <*> v .:? "zoneinfo"
      <*> v .:? "locale"
      <*> (fmap IntDate <$> v .:? "updated_at")
      <*> parseJSON (Object v)

-- | 'NoExtraClaims' is a data type representing the absence of additional claims.
--   It is used when no extra claims are needed in the context of the claims.
data NoExtraClaims = NoExtraClaims
  { dummy :: ()  -- ^ A dummy field to satisfy the JSON parsing requirements, as the type needs to be an object for the FromJSON instance.
  } deriving (Show, Eq, Generic)

instance FromJSON NoExtraClaims
