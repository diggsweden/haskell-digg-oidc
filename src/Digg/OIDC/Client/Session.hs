{-# LANGUAGE DeriveGeneric     #-}
{-# LANGUAGE InstanceSigs      #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards   #-}

-- |
--    Module: Digg.OIDC.Client.Session
--    Copyright: (c) 2024 Digg - Agency for Digital Government
--    License: MIT
--    Maintainer: tomas.stenlund@telia.com
--    Stability: experimental
--
--   Defines the Session, SessionId, and SessionStore types for managing OIDC sessions.
module Digg.OIDC.Client.Session (Session (..), SessionId, SessionStorage (..), getAccessToken,
  getAccessClaims, getIdToken, getIdClaims, getRefreshToken) where

import           Control.Monad           (when)
import           Control.Monad.Catch     (MonadCatch, MonadThrow (throwM))
import           Control.Monad.IO.Class  (MonadIO)
import           Data.Aeson              (FromJSON (..), ToJSON (..),
                                          Value (..), object, (.:?), (.=))
import           Data.Aeson.Types        (Parser, prependFailure, typeMismatch)
import           Data.ByteString         (ByteString)
import           Data.Maybe              (isJust, isNothing)
import           Data.Text               (Text)
import           Data.Text.Encoding      (decodeUtf8, encodeUtf8)
import           Digg.OIDC.Client        (OIDC(..), OIDCException (InvalidState))
import           Digg.OIDC.Client.Claims (AccessTokenClaims, IdTokenClaims)
import           Digg.OIDC.Client.Tokens (AccessTokenJWT, IdTokenJWT,
                                          validateToken, validateAccessClaims, validateIdClaims)
import           Digg.OIDC.Types         (Code, Nonce, State)
import           GHC.Generics            (Generic)
import Control.Monad.IO.Class (liftIO)
import Digg.OIDC.Client.Discovery.Provider (Provider (..), ProviderMetadata (..))

-- | The 'Session' data type represents a user session in the OIDC (OpenID Connect) context.
-- It is used to store and manage session-related information for authenticated users or users
-- undergoing authentication.
data Session = Session
  { sessionState        :: Maybe State,       -- ^ The state of the session, used during login and logout flows
    sessionNonce        :: Maybe Nonce,       -- ^ The nonce value of the session
    sessionAccessToken  :: Maybe AccessTokenJWT,  -- ^ The access token of the session
    sessionIdToken      :: Maybe IdTokenJWT,  -- ^ The ID token of the session
    sessionRefreshToken :: Maybe Text,        -- ^ The refresh token of the session, it is opaque and should not be parsed, it is only used to refresh the session
    sessionCode         :: Maybe Code         -- ^ The authorization code of the session
  }
  deriving (Generic, Show)

instance ToJSON Session where
  toJSON :: Session -> Value
  toJSON Session {..} =
    object
      [ "state" .= (decodeUtf8 <$> sessionState),
        "nonce" .= (decodeUtf8 <$> sessionNonce),
        "accessToken" .= sessionAccessToken,
        "idToken" .= sessionIdToken,
        "refreshToken" .= sessionRefreshToken,
        "code" .= (decodeUtf8 <$> sessionCode)
      ]

textToByteString :: Maybe Text -> Maybe ByteString
textToByteString t = encodeUtf8 <$> t

instance FromJSON Session where
  parseJSON :: Value -> Parser Session
  parseJSON (Object v) =
    (Session . textToByteString <$> (v .:? "state"))
      <*> (textToByteString <$> (v .:? "nonce"))
      <*> (v .:? "accessToken")
      <*> (v .:? "idToken")
      <*> (v .:? "refreshToken")
      <*> (textToByteString <$> (v .:? "code"))
  parseJSON invalid =
    prependFailure "Parsing Session failed, " (typeMismatch "Object" invalid)

-- | 'SessionId' represents a unique identifier for a user session and is
-- used to manage and track user sessions within the OIDC (OpenID Connect) context.
type SessionId = ByteString

-- | 'SessionStore' is a data type that represents a store for managing sessions.
data SessionStorage m = SessionStorage
  { sessionStoreGenerate :: m ByteString,                     -- ^ Generates a new unique identifier, for a session and a nonce
    sessionStoreSave     :: SessionId -> Session -> m (),     -- ^ Saves a session with the given identifier
    sessionStoreGet      :: SessionId -> m (Maybe Session),   -- ^ Retrieves a session with the given identifier
    sessionStoreDelete   :: SessionId -> m (),                -- ^ Deletes a session with the given identifier
    sessionStoreCleanup  :: Integer -> m ()                   -- ^ Clears all sessions from the store older than the provided age in seconds
  }

-- | Retrieves the access token from the session storage.
getAccessToken :: (MonadIO m, MonadCatch m) => SessionStorage m  -- ^ The session storage
  -> SessionId      -- ^ The session identifier
  -> m (Maybe AccessTokenJWT)   -- ^ The logout request URL to redirect to
getAccessToken storage sid = do

    -- Verify the session
    session <- sessionStoreGet storage sid >>= verifySession

    return $ sessionAccessToken session

  where

    -- | Verifies the given session. If the session is 'Nothing', it throws an error.
    -- If the session is 'Just', it returns the session if it is valid for this operation.
    verifySession :: (MonadIO m, MonadThrow m) => Maybe Session -> m Session
    verifySession Nothing = do
      throwM $ InvalidState "No session found"
    verifySession (Just s) = do
      when (isJust (sessionState s)) $ throwM $ InvalidState "State should be empty"
      when (isJust (sessionNonce s)) $ throwM $ InvalidState "Nonce should be empty"
      when (isNothing (sessionAccessToken s)) $ throwM $ InvalidState "Missing access token"
      return s

-- | Retrieves the ID token from the session storage.
getIdToken :: (MonadIO m, MonadCatch m) => SessionStorage m  -- ^ The session storage
  -> SessionId      -- ^ The session identifier
  -> m (Maybe IdTokenJWT)   -- ^ The ID token
getIdToken storage sid = do

    -- Verify the session
    session <- sessionStoreGet storage sid >>= verifySession

    return $ sessionIdToken session

  where

    -- | Verifies the given session. If the session is 'Nothing', it throws an error.
    -- If the session is 'Just', it returns the session if it is valid for this operation.
    verifySession :: (MonadIO m, MonadThrow m) => Maybe Session -> m Session
    verifySession Nothing = do
      throwM $ InvalidState "No session found"
    verifySession (Just s) = do
      when (isJust (sessionState s)) $ throwM $ InvalidState "State should be empty"
      when (isJust (sessionNonce s)) $ throwM $ InvalidState "Nonce should be empty"
      when (isNothing (sessionIdToken s)) $ throwM $ InvalidState "Missing ID token"
      return s

-- | Retrieves the refresh token from the session storage.
getRefreshToken :: (MonadIO m, MonadCatch m) => SessionStorage m  -- ^ The session storage
  -> SessionId                    -- ^ The session identifier
  -> m (Maybe Text)    -- ^ The refresh token
getRefreshToken storage sid = do

    -- Verify the session
    session <- sessionStoreGet storage sid >>= verifySession

    return $ sessionRefreshToken session

  where

    -- | Verifies the given session. If the session is 'Nothing', it throws an error.
    -- If the session is 'Just', it returns the session if it is valid for this operation.
    verifySession :: (MonadIO m, MonadThrow m) => Maybe Session -> m Session
    verifySession Nothing = do
      throwM $ InvalidState "No session found"
    verifySession (Just s) = do
      when (isJust (sessionState s)) $ throwM $ InvalidState "State should be empty"
      when (isJust (sessionNonce s)) $ throwM $ InvalidState "Nonce should be empty"
      when (isNothing (sessionRefreshToken s)) $ throwM $ InvalidState "Missing refresh token"
      return s

-- | Retrieves the ID token claims from the session storage and validates them.
-- This function checks the validity of the ID token claims based on the provided
-- issuer, audience, and optional nonce. It performs necessary checks to ensure that the token is valid
-- and has not been tampered with. If the claims are valid, it returns them; otherwise, it throws a 'ValidationException'.
getIdClaims :: (MonadIO m, MonadCatch m, FromJSON a) => OIDC
  -> SessionStorage m  -- ^ The session storage
  -> SessionId -- ^ The session identifier
  -> m (Maybe (IdTokenClaims a))
getIdClaims oidc storage sid = do

    -- Verify the session
    session <- sessionStoreGet storage sid >>= verifySession

    -- Validate the ID token and extract the claims
    let jwt = sessionIdToken session
    mapM (validateToken oidc) jwt

  where

    -- | Verifies the given session. If the session is 'Nothing', it throws an error.
    -- If the session is 'Just', it returns the session if it is valid for this operation.
    verifySession :: (MonadIO m, MonadThrow m) => Maybe Session -> m Session
    verifySession Nothing = do
      throwM $ InvalidState "No session found"
    verifySession (Just s) = do
      when (isJust (sessionState s)) $ throwM $ InvalidState "State should be empty"
      when (isJust (sessionNonce s)) $ throwM $ InvalidState "Nonce should be empty"
      when (isNothing (sessionIdToken s)) $ throwM $ InvalidState "Missing ID token"
      return s

-- | Retrieves the access token claims from the session storage and validates them.
-- This function checks the validity of the access token claims based on the provided
-- issuer and audience. It performs necessary checks to ensure that the token is valid
-- and has not been tampered with. If the claims are valid, it returns them; otherwise, it throws a 'ValidationException'.
getAccessClaims :: (MonadIO m, MonadCatch m, FromJSON a) => OIDC
  -> SessionStorage m  -- ^ The session storage
  -> SessionId -- ^ The session identifier
  -> m (Maybe (AccessTokenClaims a))
getAccessClaims oidc storage sid = do

    -- Verify the session
    session <- sessionStoreGet storage sid >>= verifySession

    -- Validate the Access token and extract the claims
    mapM (validateToken oidc) (sessionAccessToken session)

  where

    -- | Verifies the given session. If the session is 'Nothing', it throws an error.
    -- If the session is 'Just', it returns the session if it is valid for this operation.
    verifySession :: (MonadIO m, MonadThrow m) => Maybe Session -> m Session
    verifySession Nothing = do
      throwM $ InvalidState "No session found"
    verifySession (Just s) = do
      when (isJust (sessionState s)) $ throwM $ InvalidState "State should be empty"
      when (isJust (sessionNonce s)) $ throwM $ InvalidState "Nonce should be empty"
      when (isNothing (sessionAccessToken s)) $ throwM $ InvalidState "Missing Access token"
      return s
