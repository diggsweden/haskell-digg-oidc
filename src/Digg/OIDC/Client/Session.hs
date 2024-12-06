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
module Digg.OIDC.Client.Session (Session (..), SessionId, SessionStorage (..)) where

import           Data.Aeson         (FromJSON (..), ToJSON (..), Value (..),
                                     object, (.:?), (.=))
import           Data.Aeson.Types   (Parser, prependFailure, typeMismatch)
import           Data.ByteString    (ByteString)
import           Data.Text          (Text)
import           Data.Text.Encoding (decodeUtf8, encodeUtf8)
import           Digg.OIDC.Types    (Code, Nonce, State)
import           GHC.Generics       (Generic)

-- | The 'Session' data type represents a user session in the OIDC (OpenID Connect) context.
-- It is used to store and manage session-related information for authenticated users or users
-- undergoing authentication.
data Session = Session
  { sessionState        :: Maybe State,       -- ^ The state of the session, used during login and logout flows
    sessionNonce        :: Maybe Nonce,       -- ^ The nonce value of the session
    sessionAccessToken  :: Maybe ByteString,  -- ^ The access token of the session
    sessionIdToken      :: Maybe ByteString,  -- ^ The ID token of the session
    sessionRefreshToken :: Maybe ByteString,  -- ^ The refresh token of the session
    sessionCode         :: Maybe Code         -- ^ The authorization code of the session
  }
  deriving (Generic, Show)

instance ToJSON Session where
  toJSON :: Session -> Value
  toJSON Session {..} =
    object
      [ "state" .= (decodeUtf8 <$> sessionState),
        "nonce" .= (decodeUtf8 <$> sessionNonce),
        "accessToken" .= (decodeUtf8 <$> sessionAccessToken),
        "idToken" .= (decodeUtf8 <$> sessionIdToken),
        "refreshToken" .= (decodeUtf8 <$> sessionRefreshToken),
        "code" .= (decodeUtf8 <$> sessionCode)
      ]

textToByteString :: Maybe Text -> Maybe ByteString
textToByteString t = encodeUtf8 <$> t

instance FromJSON Session where
  parseJSON :: Value -> Parser Session
  parseJSON (Object v) =
    (Session . textToByteString <$> (v .:? "state"))
      <*> (textToByteString <$> (v .:? "nonce"))
      <*> (textToByteString <$> (v .:? "accessToken"))
      <*> (textToByteString <$> (v .:? "idToken"))
      <*> (textToByteString <$> (v .:? "refreshToken"))
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
    sessionStoreDelete   :: SessionId -> m ()                 -- ^ Deletes a session with the given identifier
  }
