{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE QuasiQuotes       #-}

module Digg.OIDC.Client.DiscoverySpec (spec) where

import           Control.Exception                   (catch)
import           Control.Monad.IO.Class
import           Data.String.Interpolation
import           Digg.OIDC.Client
import           Digg.OIDC.Client.Discovery          (discover)
import           Digg.OIDC.Client.Discovery.Provider (Provider (..),
                                                      ProviderMetadata (..))
import           Digg.OIDC.Types                     (Address (..))
import           Internal
import           Network.HTTP.Types
import           Test.Hspec
import           Text.ParserCombinators.ReadPrec     (lift)
import           Web.Scotty
import           Jose.Jwk         (Jwk(..))
import  Crypto.PubKey.RSA

-- | Specification for testing the OIDC Client Discovery functionality.
-- This spec contains tests to ensure that the OIDC client discovery
-- process works as expected.
spec :: Spec
spec = do

  around (mock app) $ do

    describe "OIDC Discovery" $ do

      it "Non existant discovery endpoint" $ \mgr -> do
        shouldThrow (discover "http://localhost/donotexists" mgr)
          (oidcException (DiscoveryException "Well-known endpoint retuned HTTP Code 404"))

      it "Fetch the discovery endpoint" $ \mgr -> do
        m <- catch (Right <$> discover "http://localhost/auth/realms/verify" mgr) handleError
        case m of
          Left e -> expectationFailure $ "Failed to fetch the discovery endpoint: " <> e
          Right provider -> do
            show provider `shouldBe` "Provider {metadata = ProviderMetadata {providerIssuer = \"http://localhost/auth/realms/verify\", providerAuthorizationEndpoint = Address {uri = http://localhost/auth/realms/verify/protocol/openid-connect/auth}, providerUserinfoEndpoint = Just (Address {uri = http://localhost/auth/realms/verify/protocol/openid-connect/userinfo}), providerEndSessionEndpoint = Just (Address {uri = http://localhost/auth/realms/verify/protocol/openid-connect/logout}), providerScopesSupported = Just [\"openid\",\"phone\",\"basic\",\"web-origins\",\"profile\",\"acr\",\"testbed\",\"email\",\"address\",\"offline_access\",\"microprofile-jwt\",\"roles\"], providerResponseModesSupported = Nothing, providerGrantTypesSupported = Just [\"authorization_code\",\"implicit\",\"refresh_token\",\"password\",\"client_credentials\",\"urn:openid:params:grant-type:ciba\",\"urn:ietf:params:oauth:grant-type:device_code\"], providerACRValuesSupported = Just [\"0\",\"1\"], providerResponseTypesSupported = [\"code\",\"none\",\"id_token\",\"token\",\"id_token token\",\"code id_token\",\"code token\",\"code id_token token\"], providerSubjectTypesSupported = [\"public\",\"pairwise\"], providerClaimsSupported = Just [\"aud\",\"sub\",\"iss\",\"auth_time\",\"name\",\"given_name\",\"family_name\",\"preferred_username\",\"email\",\"acr\"], providerJWKSUri = Address {uri = http://localhost/auth/realms/verify/protocol/openid-connect/certs}, providerIdTokenSigningAlgValuesSupported = [Unsupported \"PS384\",Algorithm RS384,Algorithm EdDSA,Algorithm ES384,Algorithm HS256,Algorithm HS512,Algorithm ES256,Algorithm RS256,Algorithm HS384,Algorithm ES512,Unsupported \"PS256\",Unsupported \"PS512\",Algorithm RS512], providerTokenEndpoint = Address {uri = http://localhost/auth/realms/verify/protocol/openid-connect/token}, providerTokenEndpointAuthSigningAlgValuesSupported = [Unsupported \"PS384\",Algorithm RS384,Algorithm EdDSA,Algorithm ES384,Algorithm HS256,Algorithm HS512,Algorithm ES256,Algorithm RS256,Algorithm HS384,Algorithm ES512,Unsupported \"PS256\",Unsupported \"PS512\",Algorithm RS512], providerTokenEndpointAuthMethodsSupported = Just [\"private_key_jwt\",\"client_secret_basic\",\"client_secret_post\",\"tls_client_auth\",\"client_secret_jwt\"]}, jwkSet = [RsaPublicJwk (PublicKey {public_size = 256, public_n = 20987703012223672814501884882171848248078334386279410275261150449915502707026124168461124362292627924029791881494820950916016213318406304354022058655706486944057048442046235856407543085047361820202074465022398898735449768038168692685151706577474208670020756607418759506176497243171110135623610378722668173383103760061442594487007612500595845653382857714674350946965257542295144682551433761126372199912652840663821360622409887408739747622059189819397216237275856866800035151396806145450484348280804232343633760308842253646993806520936880286567085374980574096767225549080769319581689218892523386222739277230390957383991, public_e = 65537}) (Just (KeyId \"bIbln6kFW7fNARAXgFyZWN5kvRS6goTJELJT1Tdm_mw\")) (Just Sig) (Just (Signed RS256))]}"

      it "Lack of required data in discovery endpoint" $ \mgr -> do
        shouldThrow (discover "http://localhost/auth/realms/missing1" mgr)
          (oidcException (DiscoveryException "Failed to parse JSON response, error: Error in $: When parsing the record ProviderMetadata of type Digg.OIDC.Client.Discovery.Provider.ProviderMetadata the key authorization_endpoint was not present."))

      it "Other error from discovery endpoint" $ \mgr -> do
          shouldThrow (discover "http://localhost/auth/realms/other" mgr)
            (oidcException (DiscoveryException "Well-known endpoint retuned HTTP Code 500"))

      it "Cannot fetch jwksuri" $ \mgr -> do
          shouldThrow (discover "http://localhost/auth/realms/missing2" mgr)
            (oidcException (DiscoveryException "Fetch JWKS endpoint returned HTTP Code 500"))

-- | The 'app' function defines the Scotty application.
-- This function sets up the routes and handlers for the web application.
app :: ScottyM ()
app = do

  get "/auth/realms/other/.well-known/openid-configuration" $ do
    status internalServerError500

  get "/auth/realms/missing2/protocol/openid-connect/certs" $ do
    status internalServerError500

  get "/auth/realms/verify/protocol/openid-connect/certs" $ do
    text [str|
{
    "keys": [
        {
            "kid": "bIbln6kFW7fNARAXgFyZWN5kvRS6goTJELJT1Tdm_mw",
            "kty": "RSA",
            "alg": "RS256",
            "use": "sig",
            "n": "pkEvmiMFZH29C4b9H8bGwO6qnv94SWZEw-0xswK1nyDXfSKjGRunItpOtDrEmj4bqKwhMBVzMILZBwnHqoMNp6He-JXZQ5P97lQeaVRuqkRl40b8Uu_I6Dm1O6VfcMLjqcwrxLvcBggjGobUdGUSMDFYWkDcVEN_cH0UeOPuO60LvgC9l4Y7S30jE47aA4OHtKdQOLb_iEt5nDcSELmStJCWVg_v_hTEixDNK0BKaMGpXwA1_SheVtAPhdcvisn_rYWq677bsni10zrNAahqCvpjPCmgvAZsK4URTjKQqI7G--lyU7zqrli6yM8oPeoqxHiMhCbEj0mnaqnLXGEhNw",
            "e": "AQAB",
            "x5c": [
                "MIICmzCCAYMCBgGTO0C4ODANBgkqhkiG9w0BAQsFADARMQ8wDQYDVQQDDAZ2ZXJpZnkwHhcNMjQxMTE3MTc1MDE3WhcNMzQxMTE3MTc1MTU3WjARMQ8wDQYDVQQDDAZ2ZXJpZnkwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCmQS+aIwVkfb0Lhv0fxsbA7qqe/3hJZkTD7TGzArWfINd9IqMZG6ci2k60OsSaPhuorCEwFXMwgtkHCceqgw2nod74ldlDk/3uVB5pVG6qRGXjRvxS78joObU7pV9wwuOpzCvEu9wGCCMahtR0ZRIwMVhaQNxUQ39wfRR44+47rQu+AL2XhjtLfSMTjtoDg4e0p1A4tv+IS3mcNxIQuZK0kJZWD+/+FMSLEM0rQEpowalfADX9KF5W0A+F1y+Kyf+tharrvtuyeLXTOs0BqGoK+mM8KaC8BmwrhRFOMpCojsb76XJTvOquWLrIzyg96irEeIyEJsSPSadqqctcYSE3AgMBAAEwDQYJKoZIhvcNAQELBQADggEBAIobDVj3w4zMO5N+zeNpQZCZuiF26FlVRTdFNqcF9pVtCY36ZRBzGpg0KpANF0d/YsFXH0QkmhOXcVzHCjhG2Tbj9Z27O1l7OPrR2XjvLIs1Q+F/o0IUrHkJeSkeFz0M/eHrgdbkNYg4AR5mcOtdQA4baWbDRv24eM0BLZodM6BkMxT5c+FcoBULyclqRKs3pROFMDsC+9YF13FyShTtPUMnd7hcVuD6g/csdf+ck1vxXSvWaGctXkwC/pPMpDBJaMKdSJyHVtz7kDb86GM8PetvVzpHSBKidZnKnUay/rUpBIFjDBv8F6fDvKf+oodv7UPCHDEqzu/mugRTxRgGsGM="
            ],
            "x5t": "5n9_NRIgJZNa_l-OJrnuGrJzg3s",
            "x5t##S256": "wcR61MbVNibWwt0Q8L2skp5Ml_g0bNoUICL9zDU-kUI"
        }
    ]
}
    |]

  get "/auth/realms/missing1/.well-known/openid-configuration" $ do
    text [str|
{
    "issuer": "http://localhost/auth/realms/verify"
}
    |]

  get "/auth/realms/verify/.well-known/openid-configuration" $ do
    text [str|
{
    "issuer": "http://localhost/auth/realms/verify",
    "authorization_endpoint": "http://localhost/auth/realms/verify/protocol/openid-connect/auth",
    "token_endpoint": "http://localhost/auth/realms/verify/protocol/openid-connect/token",
    "registration_endpoint": "http://localhost/auth/realms/verify/clients-registrations/openid-connect",
    "userinfo_endpoint": "http://localhost/auth/realms/verify/protocol/openid-connect/userinfo",
    "end_session_endpoint": "http://localhost/auth/realms/verify/protocol/openid-connect/logout",
    "jwks_uri": "http://localhost/auth/realms/verify/protocol/openid-connect/certs",
    "scopes_supported": [
        "openid",
        "phone",
        "basic",
        "web-origins",
        "profile",
        "acr",
        "testbed",
        "email",
        "address",
        "offline_access",
        "microprofile-jwt",
        "roles"
    ],
    "grant_types_supported": [
        "authorization_code",
        "implicit",
        "refresh_token",
        "password",
        "client_credentials",
        "urn:openid:params:grant-type:ciba",
        "urn:ietf:params:oauth:grant-type:device_code"
    ],
    "acr_values_supported": [
        "0",
        "1"
    ],
    "response_types_supported": [
        "code",
        "none",
        "id_token",
        "token",
        "id_token token",
        "code id_token",
        "code token",
        "code id_token token"
    ],
    "subject_types_supported": [
        "public",
        "pairwise"
    ],
    "id_token_signing_alg_values_supported": [
        "PS384",
        "RS384",
        "EdDSA",
        "ES384",
        "HS256",
        "HS512",
        "ES256",
        "RS256",
        "HS384",
        "ES512",
        "PS256",
        "PS512",
        "RS512"
    ],
    "token_endpoint_auth_methods_supported": [
        "private_key_jwt",
        "client_secret_basic",
        "client_secret_post",
        "tls_client_auth",
        "client_secret_jwt"
    ],
    "claims_supported": [
        "aud",
        "sub",
        "iss",
        "auth_time",
        "name",
        "given_name",
        "family_name",
        "preferred_username",
        "email",
        "acr"
    ],
    "token_endpoint_auth_signing_alg_values_supported": [
        "PS384",
        "RS384",
        "EdDSA",
        "ES384",
        "HS256",
        "HS512",
        "ES256",
        "RS256",
        "HS384",
        "ES512",
        "PS256",
        "PS512",
        "RS512"
    ]
}
  |]


  get "/auth/realms/missing2/.well-known/openid-configuration" $ do
    text [str|
{
    "issuer": "http://localhost/auth/realms/missing2",
    "authorization_endpoint": "http://localhost/auth/realms/missing2/protocol/openid-connect/auth",
    "token_endpoint": "http://localhost/auth/realms/missing2/protocol/openid-connect/token",
    "registration_endpoint": "http://localhost/auth/realms/missing2/clients-registrations/openid-connect",
    "jwks_uri": "http://localhost/auth/realms/missing2/protocol/openid-connect/certs",
    "id_token_signing_alg_values_supported": [
        "PS384",
        "RS384",
        "EdDSA",
        "ES384",
        "HS256",
        "HS512",
        "ES256",
        "RS256",
        "HS384",
        "ES512",
        "PS256",
        "PS512",
        "RS512"
    ],
    "token_endpoint_auth_methods_supported": [
        "private_key_jwt",
        "client_secret_basic",
        "client_secret_post",
        "tls_client_auth",
        "client_secret_jwt"
    ],
    "claims_supported": [
        "aud",
        "sub",
        "iss",
        "auth_time",
        "name",
        "given_name",
        "family_name",
        "preferred_username",
        "email",
        "acr"
    ],
        "response_types_supported": [
        "code",
        "none",
        "id_token",
        "token",
        "id_token token",
        "code id_token",
        "code token",
        "code id_token token"
    ],
    "subject_types_supported": [
      "public",
      "pairwise"
    ],
    "token_endpoint_auth_signing_alg_values_supported": [
        "PS384",
        "RS384",
        "EdDSA",
        "ES384",
        "HS256",
        "HS512",
        "ES256",
        "RS256",
        "HS384",
        "ES512",
        "PS256",
        "PS512",
        "RS512"
    ]
}
  |]
