{-# LANGUAGE OverloadedStrings #-}

-- |
--    Module: Digg.OIDC.Client.Internal
--    Copyright: (c) 2024 Digg - Agency for Digital Government
--    License: MIT
--    Maintainer: tomas.stenlund@telia.com
--    Stability: experimental
--
--    Defines internal types and functions for the OIDC client library. Not to besued outside the
--    library.
module Digg.OIDC.Client.Internal (TokensResponse (..), isAnElementOf) where

import           Control.Applicative ((<|>))
import           Control.Monad       (mzero)
import           Data.Aeson          (FromJSON, Value (..), parseJSON, (.:),
                                      (.:?))
import           Data.Aeson.Types    (Parser)
import           Data.Text           (Text)
import           Data.Text.Read      (decimal)
import           Jose.Jwt            (Jwt)
import           Prelude             hiding (exp)

data TokensResponse = TokensResponse
  { tokensResponseAccessToken  :: !Jwt,               -- ^ The access token
    tokensResponseTokenType    :: !Text,              -- ^ The token type
    tokensResponseIdToken      :: !Jwt,               -- ^ The ID token
    tokensResponseScope        :: !(Maybe Text),      -- ^ The scopes
    tokensResponseExpiresIn    :: !(Maybe Integer),   -- ^ The expiration time
    tokensResponseRefreshToken :: !(Maybe Jwt)        -- ^ The refresh token
  }
  deriving (Show, Eq)

instance FromJSON TokensResponse where
  parseJSON (Object o) =
    TokensResponse
      <$> o .: "access_token"
      <*> o .: "token_type"
      <*> o .: "id_token"
      <*> o .:? "scope"
      <*> ((o .:? "expires_in") <|> (textToInt =<< (o .:? "expires_in")))
      <*> o .:? "refresh_token"
    where

      textToInt :: Maybe Text -> Parser (Maybe Integer)
      textToInt (Just t) =
        case decimal t of
          Right (i, _) -> pure $ Just i
          Left _ -> fail "expires_in: expected a decimal text, encountered a non decimal text"
      textToInt _ = pure Nothing

  parseJSON _ = mzero

-- | Checks if an element is present in a given list wrapped in a 'Maybe' context.
isAnElementOf :: Eq a => a -> Maybe [a] -> Bool
isAnElementOf _ Nothing = False
isAnElementOf a (Just as) = a `elem` as
