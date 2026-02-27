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
module Digg.OIDC.Client.Tokens
  ( Claims (..),
    IdClaims (..),
    AccessClaims (..),
    RolesClaims (..),
    ResourceAccessClaims (..),
    NoExtraClaims (..),
    validateToken,
    validateAccessClaims,
    validateIdClaims,
    IdTokenClaims,
    AccessTokenClaims,
    IdTokenJWT,
    AccessTokenJWT,
    RefreshTokenJWT
  )
where

import           Control.Exception                   (throwIO)
import           Control.Monad                       (unless)
import           Control.Monad.Catch                 (MonadThrow (throwM))
import           Control.Monad.Except                (catchError)
import           Control.Monad.IO.Class              (MonadIO, liftIO)
import           Data.Aeson                          (FromJSON, eitherDecode)
import           Data.ByteString                     (ByteString)
import qualified Data.ByteString.Lazy.Char8          as BL
import           Data.Either                         (partitionEithers)
import           Data.Maybe                          (fromMaybe)
import           Data.Text                           (Text, pack)
import           Data.Time.Clock.POSIX               (getPOSIXTime)
import           Digg.OIDC.Client                    (OIDC (..),
                                                      OIDCException (..))
import           Digg.OIDC.Client.Claims             (AccessClaims (..),
                                                      AccessTokenClaims,
                                                      Claims (..),
                                                      IdClaims (..),
                                                      IdTokenClaims,
                                                      NoExtraClaims (..),
                                                      ResourceAccessClaims (..),
                                                      RolesClaims (..))
import           Digg.OIDC.Client.Discovery.Provider (Algorithm (..),
                                                      Provider (..),
                                                      ProviderMetadata (..))
import           Digg.OIDC.Types                     (Nonce)
import           Jose.Jwt                            (IntDate (..), Jwt,
                                                      JwtContent (Jwe, Jws, Unsecured))
import qualified Jose.Jwt                            as Jwt
import           Prelude                             hiding (exp)

-- | Type alias for representing an ID Token as a JSON Web Token (JWT).
type IdTokenJWT = Jwt

-- | Type alias for representing an access token in JWT (JSON Web Token) format.
type AccessTokenJWT = Jwt

-- | Type alias for representing the refresh token in JWT (JSON Web Token) format.
type RefreshTokenJWT = Jwt

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

    parsePayload:: (MonadIO m, FromJSON a) => ByteString -> m (Claims a)
    parsePayload payload = do
      case eitherDecode $ BL.fromStrict payload of
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
        $ throwM $ ValidationException $ "Issuer in identity token \"" <> iss claims <> "\" is different than expected issuer \"" <> issuer <> "\""

    unless (client `elem` aud claims)
        $ throwM $ ValidationException $ "Our client identity \"" <> client <> "\" isn't contained in the identity token's audience " <> (pack . show) (aud claims)

    unless (now < exp claims)
        $ throwM $ ValidationException "Received identity token has expired"

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
  -> Maybe Text                     -- ^ The expected audience
  -> AccessTokenClaims a            -- ^ The token claims
  -> IO ()                    -- ^ Everything went well if we return, maybe we should return the claims for continuation purposes
validateAccessClaims issuer audience claims = do

    now <- getCurrentIntDate

    unless (iss claims == issuer)
        $ throwM $ ValidationException $ "Issuer from token \"" <> iss claims <> "\" is different than expected issuer \"" <> issuer <> "\""

    unless (maybe True (`elem` aud claims) audience)
        $ throwM $ ValidationException $ "our audience \"" <> fromMaybe "" audience <> "\" isn't contained in the token's audience " <> (pack . show) (aud claims)

    unless (now < exp claims)
        $ throwM $ ValidationException "Received accesstoken has expired"

-- | Current time as 'IntDate' for validating token expiration and issued at times.
getCurrentIntDate :: IO IntDate
getCurrentIntDate = IntDate <$> getPOSIXTime
