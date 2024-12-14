{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE QuasiQuotes       #-}

module Digg.OIDC.Client.DiscoverySpec (spec) where

import           Control.Exception                   (catch)
import           Data.String.Interpolation
import           Digg.OIDC.Client
import           Digg.OIDC.Client.Discovery          (discover)
import           Digg.OIDC.Client.Discovery.Provider (Provider (..),
                                                      ProviderMetadata (..))
import           Internal                            (handleError)
import           Network.HTTP.Mock
import           Test.Hspec
import           Web.Scotty


oidc404Exception :: Selector OIDCException
oidc404Exception a = case a of
  DiscoveryException "Well-known endpoint retuned HTTP Code 404" -> True
  _                                                              -> False

oidcJSONException :: Selector OIDCException
oidcJSONException a = case a of
  DiscoveryException "Failed to parse JSON response, error: Error in $: When parsing the record ProviderMetadata of type Digg.OIDC.Client.Discovery.Provider.ProviderMetadata the key authorization_endpoint was not present." -> True
  _ -> False

spec :: Spec
spec = do
  describe "OIDC Discovery" $ do

    it "Non existant discovery endpoint" $ do
      application <- scottyApp app
      shouldThrow (withMockedManager application (discover "http://localhost/donotexists")) oidc404Exception

    it "Fetch the discovery endpoint" $ do
      application <- scottyApp app
      m <- catch (Right <$> withMockedManager application (discover "http://localhost/auth/realms/verify")) handleError
      case m of
        Left e -> expectationFailure $ "Failed to fetch the discovery endpoint: " <> e
        Right provider -> do
          providerIssuer (metadata provider) `shouldBe` "http://localhost/auth/realms/verify"

    it "Missing data in discovery endpoint" $ do
      application <- scottyApp app
      shouldThrow (withMockedManager application (discover "http://localhost/auth/realms/missing1")) oidcJSONException


app :: ScottyM ()
app = do
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
        },
        {
            "kid": "qt39O5pPJXOsjJ5UYDimotj28dVMNMhiGbDeJzexiv0",
            "kty": "RSA",
            "alg": "RSA-OAEP",
            "use": "enc",
            "n": "qfv3WLhE8-qOGyTgfvDS4x8Pmi8SNdhjlCROQZ2HFqd-dcOxXgoswrpHXgr0tvAnDwGHspofVdb0tTgJEHme2WnV4wsjumFqbCRAFyU2QMhF9YLxxbIeclhxgIOU_rUUCy4RL1qz9WqWz3DLfDomn0M2SbY6B38Ex2i7Jv6JnZtoHMMGx176AFwbWWyHlWCR2bMdF_01kNnc70vqk5IpWXwLb-njhTfiTU2Z5KFaTvhqu8_I_9Ei0tDOqpI5YLTG9Q-TR1EBhwzwadmFBTZd0Tpbf8cERQZkPUMZqcP8DGbtrZgsW8N-txRVgOIyJtAPnRLlPmENw0tIhVAeykhipw",
            "e": "AQAB",
            "x5c": [
                "MIICmzCCAYMCBgGOuXSgETANBgkqhkiG9w0BAQsFADARMQ8wDQYDVQQDDAZ2ZXJpZnkwHhcNMjQwNDA3MTY0NTExWhcNMzQwNDA3MTY0NjUxWjARMQ8wDQYDVQQDDAZ2ZXJpZnkwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCp+/dYuETz6o4bJOB+8NLjHw+aLxI12GOUJE5BnYcWp351w7FeCizCukdeCvS28CcPAYeymh9V1vS1OAkQeZ7ZadXjCyO6YWpsJEAXJTZAyEX1gvHFsh5yWHGAg5T+tRQLLhEvWrP1apbPcMt8OiafQzZJtjoHfwTHaLsm/omdm2gcwwbHXvoAXBtZbIeVYJHZsx0X/TWQ2dzvS+qTkilZfAtv6eOFN+JNTZnkoVpO+Gq7z8j/0SLS0M6qkjlgtMb1D5NHUQGHDPBp2YUFNl3ROlt/xwRFBmQ9Qxmpw/wMZu2tmCxbw363FFWA4jIm0A+dEuU+YQ3DS0iFUB7KSGKnAgMBAAEwDQYJKoZIhvcNAQELBQADggEBAHB4y4eSYG9SUET7NltNwbEwDrzI/X45oTRy8iVLeXwYgyCQLN2j9HFHRxk6XVfXTQhS/7bt04+ISrVX9JC3eDF/n/ucjo5eSFV6OF2VCdIbmw6crx4Xc6XQyRKacY0QXzg3XZjT1D9Mnui2eoNKtTGlyM5XN2nmmAyHXiwIUY2uWk2kWGTZU2OsVvxgdS1htR/hWYW1YLPFFvVrjJ8FnU+SSKaz+Cv4fckjtF9IbdOX+I9WMIV974NZJne4AkxRpgJocuxuycaTNyNM+1H16bE2zqGSJL/nf2cJQYVgvBnnECFZfs2ANPgihyOf/rEfYZN8Ib1yqDqA4ENVNaZuP9M="
            ],
            "x5t": "Kt-KxF2EiJzI9wXok1V8OwoN1CI",
            "x5t##S256": "DqJWwYBlWmE3q6-cBGNXziBkI7iDBAHLe6dYo_yg1AM"
        },
        {
            "kid": "AcyArIyElE7t_mIzLq-lk2BUTFuwTKTiVqlFXWNAnwU",
            "kty": "RSA",
            "alg": "RS256",
            "use": "sig",
            "n": "rvBT7mP3IPreFkl8QRNyXgyDCbwo91Fy85KyRm5HlVL5-dgoagD7AnuXk7ecpUn55wKD3qVrGQ1FNoCFezwZ3IaNvaEUvcer6uJ1WZmumuTXejO27ehQjlOgRFhrk8PFxF_uB2c627NDGE9BAcBmdELp5xGQdDv1dWzv-sbYpbabAuP54VJAYxraDhhKrMZk41sqNrsB6dEbbndWpx8QgunnOVI2aa4eqQrNTs1jIeyIxbhSRJODt-0oWBzsnh5-uA05zl_8-kBYdBgQgwzcK01sbU2-IJJaXEGmi192bD3G2lQQKrfw31DJEVw-AxxDkm9rHtXzoIYsF3gLg1Lr3w",
            "e": "AQAB",
            "x5c": [
                "MIICmzCCAYMCBgGOuXSeZzANBgkqhkiG9w0BAQsFADARMQ8wDQYDVQQDDAZ2ZXJpZnkwHhcNMjQwNDA3MTY0NTExWhcNMzQwNDA3MTY0NjUxWjARMQ8wDQYDVQQDDAZ2ZXJpZnkwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCu8FPuY/cg+t4WSXxBE3JeDIMJvCj3UXLzkrJGbkeVUvn52ChqAPsCe5eTt5ylSfnnAoPepWsZDUU2gIV7PBncho29oRS9x6vq4nVZma6a5Nd6M7bt6FCOU6BEWGuTw8XEX+4HZzrbs0MYT0EBwGZ0QunnEZB0O/V1bO/6xtiltpsC4/nhUkBjGtoOGEqsxmTjWyo2uwHp0Rtud1anHxCC6ec5UjZprh6pCs1OzWMh7IjFuFJEk4O37ShYHOyeHn64DTnOX/z6QFh0GBCDDNwrTWxtTb4gklpcQaaLX3ZsPcbaVBAqt/DfUMkRXD4DHEOSb2se1fOghiwXeAuDUuvfAgMBAAEwDQYJKoZIhvcNAQELBQADggEBAIliKYedWTtYubz8YGXCNywjBcELU51aP/ALxVl+SpgqXyb3ES1utAb13qj8H1eQ6dvXT/Gvq575fY47aVyKDRz8TrMNYcu1bdYD8pk4Y+bVFMzyKn4ijVX4M8bjykgT35QWrusm/vrkR4NilNxxyzs7Q3gAoDaf1B3Z2waNbQmNGLra6d8VzHO8O2WCb4/sC3uGSL3UikLNVJ19i0PciQK12XgBMvWiiMYoZ0R1Vcn4ANu4vSuG8pOt9p9nAlTPVCQ26IsTgKhNdvD+zbRbjjNUw9etCYaM3EtomQN/e4mySIGT5DjOD0EkdLRlw0iM9jZtlWQgtD1VYek6tklnQ5k="
            ],
            "x5t": "hpzP_j13CxRWP07VVC9muM8IVis",
            "x5t##S256": "ROO2SPW1QAVQOQ2OqampomjLIorady-tT62kyspmlUg"
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

