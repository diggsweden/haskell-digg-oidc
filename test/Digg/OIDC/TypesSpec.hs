{-# LANGUAGE OverloadedStrings #-}
module Digg.OIDC.TypesSpec (spec) where

import           Data.Aeson      (encode, decode)
import           Data.Maybe      (fromJust, Maybe(..))
import           Digg.OIDC.Types
import           Network.URI     (URI, parseAbsoluteURI)
import           Test.Hspec

spec :: Spec
spec = do
  describe "Address JSON" $ do

    it "Address JSON encode verification" $ do
        let uri1 = fromJust $ parseAbsoluteURI "https://localhost:3000/hello"
        encode (Address {uri = uri1}) `shouldBe` "\"https://localhost:3000/hello\""

    it "Address JSON decode verification" $ do
        let uri2 = fromJust $ parseAbsoluteURI "https://localhost:3000/hello"
        (decode "\"https://localhost:3000/hello\"") `shouldBe` (Just $ Address {uri = uri2})
