{-# LANGUAGE DeriveGeneric     #-}
{-# LANGUAGE LambdaCase        #-}
{-# LANGUAGE OverloadedStrings #-}
-- |
--    Module: Digg.OIDC.Client.Tokens
--    Copyright: (c) 2024 Digg - Agency for Digital Government
--    License: MIT
--    Maintainer: tomas.stenlund@telia.com
--    Stability: experimental
--
--    The module defines types and functions for handling OIDC tokens and validations of standard claims as well
--    as custom claims.
module Digg.OIDC.Client.Tokens
  ( Tokens (..),
    Claims (..),
    IdClaims (..),
    AccessClaims (..),
    NoExtraClaims (..),
    validateToken,
    validateAccessClaims,
    validateIdClaims,
    IdTokenClaims,
    AccessTokenClaims,
  )
where

import           Control.Applicative                 (optional, (<|>))
import           Control.Exception                   (throwIO)
import           Control.Monad.Except                (catchError)
import           Control.Monad.IO.Class              (MonadIO, liftIO)
import           Data.Aeson                          (FromJSON (parseJSON),
                                                      Value (Object),
                                                      eitherDecode, withObject,
                                                      (.:), (.:?))
import           Data.ByteString                     (ByteString)
import qualified Data.ByteString.Lazy.Char8          as BL
import           Data.Either                         (partitionEithers)
import           Data.Text                           (Text, pack)
import           Data.Text.Encoding                  (encodeUtf8)
import           Digg.OIDC.Client                    (OIDC (..),
                                                      OIDCException (..))
import           Digg.OIDC.Client.Discovery.Provider (Algorithm (..),
                                                      Provider (..),
                                                      ProviderMetadata (..))
import           GHC.Generics                        (Generic)
import           Jose.Jwt                            (IntDate (..), Jwt,
                                                      JwtContent (Jwe, Jws, Unsecured))
import qualified Jose.Jwt                            as Jwt
import           Prelude                             hiding (exp)
import Digg.OIDC.Types (Nonce)
import Control.Monad (unless)
import Control.Monad.Catch (MonadThrow(throwM))
import Data.Time.Clock.POSIX (getPOSIXTime)

-- | The 'TokenClaims' data type represents the claims contained within a token.
-- The type parameter 'a' allows for flexibility in specifying additional claims.
-- This can be used to define different kinds of tokens with varying claim structures.
data Claims a = Claims
  { iss         :: !Text,     -- ^ The issuer of the token
    sub         :: !Text,     -- ^ The subject of the token
    aud         :: ![Text],   -- ^ The audience of the token
    exp         :: !IntDate,  -- ^ The expiration time of the token
    iat         :: !IntDate,  -- ^ The time the token was issued
    jti         :: !Text,     -- ^ The JWT ID of the token

    other_claims :: !a     -- ^ Additional claims of the token, defined by the user of this library
  }
  deriving (Show, Eq, Generic)

instance (FromJSON a) => FromJSON (Claims a) where
  parseJSON = withObject "Claims" $ \o ->
    Claims
      <$> o .: "iss"
      <*> o .: "sub"
      <*> (o .: "aud" <|> ((: []) <$> (o .: "aud")))
      <*> o .: "exp"
      <*> o .: "iat"
      <*> o .: "jti"
      <*> parseJSON (Object o)

-- | 'IdTokenClaims' represents the claims contained in an ID token.
-- The type parameter 'a' allows for flexibility in the type of the claims.
-- This data type is typically used in the context of OpenID Connect (OIDC)
-- to hold the information about the authenticated user.
data IdClaims a = IdClaims
  {
    id_nonce       :: !(Maybe ByteString),   -- ^ The nonce value of the token
    id_auth_time   :: !(Maybe IntDate),      -- ^ The time the user authenticated
    id_acr         :: !(Maybe Text),         -- ^ The authentication context class reference
    id_amr         :: !(Maybe Text),         -- ^ The authentication methods used
    id_azp         :: !(Maybe Text),         -- ^ The authorized party

    id_other_claims :: !(Maybe a)           -- ^ Additional claims of the id token, defined by the user of this library

  } deriving (Show, Eq, Generic)

instance (FromJSON a) => FromJSON (IdClaims a) where
  parseJSON = withObject "IdTokenClaims" $ \o ->
    (IdClaims . fmap encodeUtf8 <$> (o .:? "nonce"))
      <*> (fmap IntDate <$> (o .:? "auth_time"))
      <*> o .:? "acr"
      <*> o .:? "amr"
      <*> o .:? "azp"
      <*> optional (parseJSON (Object o))

-- | 'AccessTokenClaims' represents the claims contained in an access token.
-- The type parameter 'a' allows for flexibility in specifying the type of the claims.
-- This data type is typically used in the context of OpenID Connect (OIDC) to
-- handle and validate access tokens issued by an OIDC provider.
data AccessClaims a = AccessClaims
  {
    a_scope             :: !(Maybe [Text]), -- ^ The scope of the token
    a_auth_time   :: !(Maybe IntDate),      -- ^ The time the user authenticated
    a_acr         :: !(Maybe Text),         -- ^ The authentication context class reference
    a_amr         :: !(Maybe Text),         -- ^ The authentication methods used
    a_other_claims :: !(Maybe a)     -- ^ Additional claims of the id token, defined by the user of this library
  } deriving (Show, Eq, Generic)

instance (FromJSON a) => FromJSON (AccessClaims a) where
  parseJSON = withObject "IdTokenClaims" $ \o ->
    AccessClaims
      <$> optional (o .: "scope" <|> ((: []) <$> (o .: "scope")))
      <*> (fmap IntDate <$> (o .:? "auth_time"))
      <*> o .:? "acr"
      <*> o .:? "amr"
      <*> optional (parseJSON (Object o))

-- | 'NoExtraClaims' is a data type representing the absence of additional claims.
--   It is used when no extra claims are needed in the context of OIDC (OpenID Connect) tokens.
--   The only constructor, 'NoClaims', signifies that there are no extra claims.
data NoExtraClaims = NoClaims
  deriving (Show, Eq, Generic)

instance FromJSON NoExtraClaims

type IdTokenClaims a = Claims (IdClaims a)
type AccessTokenClaims a = Claims (AccessClaims a)

-- | The 'Tokens' data type represents a collection of tokens.
-- The type parameter 'a' allows for flexibility for the identity token stored.
data Tokens a = Tokens
  { accessToken  :: Text,           -- ^ The access token
    tokenType    :: Text,           -- ^ The token type, should always be Bearer
    idToken      :: Claims a,       -- ^ The identity tokens claims and its additional claims
    idTokenJwt   :: Jwt,            -- ^ The identity token as a JWT
    expiresIn    :: Maybe Integer,  -- ^ The expiration time of the token
    refreshToken :: Maybe Text      -- ^ The refresh token
  }
  deriving (Show, Eq)

-- | Validates a given JWT token using the provided OIDC configuration and returns
-- the token claims if the token is valid.
--
-- The function operates within a MonadIO context and expects the token
-- claims to be JSON-decodable.
validateToken :: (MonadIO m, FromJSON a) => OIDC -- ^ The OIDC configuration
  -> Jwt -- ^ The JWT token to validate
  -> m (Claims a) -- ^ The token claims
validateToken oidc jwt' = do
  let jwks = jwkSet . oidcProvider $ oidc
      token = Jwt.unJwt jwt'
      algs = providerIdTokenSigningAlgValuesSupported . metadata $ oidcProvider oidc
  liftIO $ print algs
  decoded <- selectDecodedResult <$> traverse (tryDecode jwks token) algs
  case decoded of
    Right (Unsecured payload)      -> liftIO . throwIO $ UnsecuredJWT payload
    Right (Jws (_header, payload)) -> parsePayload payload
    Right (Jwe (_header, payload)) -> parsePayload payload
    Left err                       -> liftIO . throwIO $ JWTException err
  where

    tryDecode jwks token = \case
      Algorithm alg -> do
        liftIO $ catchError (Jwt.decode jwks (Just $ Jwt.JwsEncoding alg) token) handleDecodeError
      Unsupported alg -> return $ Left $ Jwt.BadAlgorithm ("Unsupported algorithm: " <> alg)

    handleDecodeError e = return $ Left $ Jwt.BadAlgorithm ("Decode error: " <> pack (show e))

    selectDecodedResult xs = case partitionEithers xs of
      (_, k : _) -> Right k
      (e : _, _) -> Left e
      ([], [])   -> Left $ Jwt.KeyError "No Keys available for decoding"

    parsePayload payload = case eitherDecode $ BL.fromStrict payload of
      Right x  -> return x
      Left err -> liftIO . throwIO . ValidationException $ pack err

-- | Validates the ID token claims.
-- 
-- This function checks the validity of the ID token claims based on the provided
-- issuer, audience, and optional nonce. It performs necessary checks to ensure
-- that the token is valid and has not been tampered with.
--
-- If not it throws a 'ValidationException'.
validateIdClaims :: Text -- ^ The expected issuer
  -> Text         -- ^ The client ID (audience)
  -> Maybe Nonce  -- ^ The nonce value
  -> IdTokenClaims a  -- ^ The token claims
  -> IO ()            -- ^ Everything went well if we return, maybe we should return the claims for continuation purposes
validateIdClaims issuer client n claims = do

    now <- getCurrentIntDate

    unless (iss claims == issuer)
        $ throwM $ ValidationException $ "Issuer in token \"" <> iss claims <> "\" is different than expected issuer \"" <> issuer <> "\""

    unless (client `elem` aud claims)
        $ throwM $ ValidationException $ "Our client \"" <> client <> "\" isn't contained in the token's audience " <> (pack . show) (aud claims)

    unless (now < exp claims)
        $ throwM $ ValidationException "Received idtoken has expired"

    unless (id_nonce (other_claims claims) == n)
        $ throwM $ ValidationException "Nonce mismatch"

-- | Validates the access token claims.
-- 
-- This function takes a 'Text' value representing the expected issuer
-- and a 'TokenClaims' value containing the claims to be validated.
-- It performs the necessary checks to ensure that the claims are valid
-- and belong to the expected audience.
--
-- Maybe this is not really needed.
--
-- If not it throws a 'ValidationException'.
validateAccessClaims :: Text  -- ^ The expected issuer
  -> Text                    -- ^ The expected audience
  -> AccessTokenClaims a            -- ^ The token claims
  -> IO ()                    -- ^ Everything went well if we return, maybe we should return the claims for continuation purposes
validateAccessClaims issuer audience claims = do

    now <- getCurrentIntDate

    unless (iss claims == issuer)
        $ throwM $ ValidationException $ "Issuer from token \"" <> iss claims <> "\" is different than expected issuer \"" <> issuer <> "\""

    unless (audience `elem` aud claims)
      $ throwM $ ValidationException $ "our audience \"" <> audience <> "\" isn't contained in the token's audience " <> (pack . show) (aud claims)

    unless (now < exp claims)
        $ throwM $ ValidationException "Received accesstoken has expired"

getCurrentIntDate :: IO IntDate
getCurrentIntDate = IntDate <$> getPOSIXTime