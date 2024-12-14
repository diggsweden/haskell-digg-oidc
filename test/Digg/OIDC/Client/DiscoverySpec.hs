{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE QuasiQuotes       #-}

module Digg.OIDC.Client.DiscoverySpec (spec) where

import           Control.Exception                   (catch)
import           Data.String.Interpolation
import           Digg.OIDC.Client
import           Digg.OIDC.Client.Discovery          (discover)
import           Digg.OIDC.Client.Discovery.Provider (Provider (..),
                                                      ProviderMetadata (..))
import           Internal
import           Network.HTTP.Mock
import           Network.HTTP.Types
import           Test.Hspec
import           Web.Scotty

spec :: Spec
spec = do
  describe "OIDC Discovery" $ do

    it "Non existant discovery endpoint" $ do
      application <- scottyApp app
      shouldThrow (withMockedManager application (discover "http://localhost/donotexists"))
        (oidcException (DiscoveryException "Well-known endpoint retuned HTTP Code 404"))

    it "Fetch the discovery endpoint" $ do
      application <- scottyApp app
      m <- catch (Right <$> withMockedManager application (discover "http://localhost/auth/realms/verify")) handleError
      case m of
        Left e -> expectationFailure $ "Failed to fetch the discovery endpoint: " <> e
        Right provider -> do
          providerIssuer (metadata provider) `shouldBe` "http://localhost/auth/realms/verify"

    it "Lack of required data in discovery endpoint" $ do
      application <- scottyApp app
      shouldThrow (withMockedManager application (discover "http://localhost/auth/realms/missing1"))
        (oidcException (DiscoveryException "Failed to parse JSON response, error: Error in $: When parsing the record ProviderMetadata of type Digg.OIDC.Client.Discovery.Provider.ProviderMetadata the key authorization_endpoint was not present."))

    it "Other error from discovery endpoint" $ do
        application <- scottyApp app
        shouldThrow (withMockedManager application (discover "http://localhost/auth/realms/other"))
          (oidcException (DiscoveryException "Well-known endpoint retuned HTTP Code 500"))

    it "Cannot fetch jwksuri" $ do
        application <- scottyApp app
        shouldThrow (withMockedManager application (discover "http://localhost/auth/realms/missing2"))
          (oidcException (DiscoveryException "Fetch JWKS endpoint returned HTTP Code 500"))

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
