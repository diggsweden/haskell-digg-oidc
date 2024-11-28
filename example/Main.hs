{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}

-- |  Module: Main
--    Maintainer: tomas.stenlund@telia.com
--    Stability: experimental
--
--    The module is a simple web server that uses the OIDC and OIDF client modules to authenticate users with an OpenID Connect provider.
module Main (main) where

import Control.Monad.Catch (Exception (displayException), catch)
import Control.Monad.IO.Class (MonadIO, liftIO)
import Control.Monad.Reader (ReaderT, ask, lift, runReaderT)
import Crypto.Random (SystemDRG, getSystemDRG, randomBytesGenerate)
import Data.Aeson (FromJSON)
import Data.ByteString (ByteString)
import qualified Data.ByteString.Base64 as B64
import qualified Data.ByteString.Char8 as B
import Data.IORef (IORef, atomicModifyIORef', newIORef)
import qualified Data.List as L
import Data.Maybe (fromMaybe)
import Data.Text (Text)
import Data.Text.Encoding (encodeUtf8, decodeUtf8)
import Data.Text.Lazy (fromStrict, pack, toStrict)
import Data.Time.Clock (secondsToDiffTime)
import Data.Tuple (swap)
import Database.Redis (ConnectInfo (..), checkedConnect, defaultConnectInfo)
import Digg.OIDC.Client (OIDC, createOIDC)
import Digg.OIDC.Client.Discovery (discover)
import Digg.OIDC.Client.Flow.AuthorizationCodeFlow (authorizationGranted, initiateAuthorizationRequest)
import Digg.OIDC.Client.Flow.RefreshTokenFlow (refreshToken)
import Digg.OIDC.Client.Session (SessionStorage (..))
import Digg.OIDC.Client.Storage.RedisStore (redisStorage)
import Digg.OIDC.Client.Tokens (TokenClaims (..))
import Digg.OIDC.Types (Address (..), IssuerLocation)
import GHC.Exception.Type (SomeException)
import GHC.Generics (Generic)
import Network.HTTP.Client (Manager, newManager)
import Network.HTTP.Client.TLS (tlsManagerSettings)
import Network.HTTP.Types (badRequest400, notFound404, unauthorized401)
import Network.URI (nullURI, parseAbsoluteURI)
import Network.Wai.Middleware.RequestLogger (logStdoutDev)
import System.Environment (lookupEnv)
import Text.Blaze.Html (Html)
import Text.Blaze.Html.Renderer.Text (renderHtml)
import Text.Blaze.Html5 ((!))
import qualified Text.Blaze.Html5 as H
import qualified Text.Blaze.Html5.Attributes as A
import Web.Scotty.Cookie (SetCookie (..), defaultSetCookie, getCookie, sameSiteLax, setCookie)
import Web.Scotty.Trans (ScottyT, get, html, middleware, post, queryParam, redirect, scottyT, status, text)

--
-- Redis connection information
--
redisConnectInfo :: String -> ConnectInfo
redisConnectInfo host = defaultConnectInfo {connectHost = host}

--
-- Authorization server environment
--

-- | 'AuthServerEnv' represents the environment configuration for the authentication server.
-- This data type is used to encapsulate all necessary settings and parameters required
-- for the example to operate correctly.
data AuthServerEnv = AuthServerEnv
  { issuer :: IssuerLocation,     -- ^ The OIDC provider issuer location.
    oidc :: OIDC,                 -- ^ The OIDC client configuration.
    storage :: SessionStorage IO, -- ^ The session storage.
    sdrg :: IORef SystemDRG,      -- ^ The system DRG.
    mgr :: Manager                -- ^ The HTTP client manager.
  }

-- | Type alias for the authentication server monad stack.
-- 
-- This type alias represents a ScottyT monad transformer stack
-- with a ReaderT transformer that carries an 'AuthServerEnv' environment
-- and runs in the 'IO' monad.
-- 
-- @type AuthServer a = ScottyT (ReaderT AuthServerEnv IO) a@
type AuthServer a = ScottyT (ReaderT AuthServerEnv IO) a

-- | 'ProfileClaims' represents the claims that we want in the IdToken returned from the OP when the user logs in
-- or refreshes the tokens.
newtype ProfileClaims = ProfileClaims
  { 
    name :: Text  -- ^ The name of the user.
  }
  deriving (Show, Generic)

instance FromJSON ProfileClaims

-- | The 'main' entrypoint for the example.
main :: IO ()
main = do

  -- Load the environment variables
  baseUrl <- B.pack . fromMaybe "http://localhost:3000" <$> lookupEnv "EXAMPLE_CLIENT_BASE_URL"
  issuer <- (\i -> Address {uri = fromMaybe nullURI i}) . parseAbsoluteURI . fromMaybe "https://change.me" <$> lookupEnv "EXAMPLE_ISSUER_URL"
  client <- toStrict . pack . fromMaybe "ChangeToYourClientId" <$> lookupEnv "EXAMPLE_CLIENT_ID"
  secret <- toStrict . pack . fromMaybe "ChangeToYourClientsSecret" <$> lookupEnv "EXAMPLE_CLIENT_SECRET"
  redis <- fromMaybe "localhost" <$> lookupEnv "EXAMPLE_REDIS_HOST"

  -- Create the system DRG and the session storage
  sdrg <- getSystemDRG >>= newIORef
  storage <- redisStorage <$> checkedConnect (redisConnectInfo redis)

  -- Create the HTTP client manager and the OIDC client
  mgr <- newManager tlsManagerSettings
  provider <- liftIO $ discover issuer mgr
  let oidc = createOIDC client secret (toStrict (fromStrict (decodeUtf8 baseUrl) <> "/login/callback")) provider

  -- Start the server
  let port = getPort baseUrl
  run
    port
    AuthServerEnv
      { issuer = issuer,
        oidc = oidc,
        storage = storage {sessionStoreGenerate = gen sdrg},
        sdrg = sdrg,
        mgr = mgr
      }

getPort :: ByteString -> Int
getPort bs = fromMaybe 3000 port
  where
    port = case B.split ':' bs of
      [] -> Nothing
      [_] -> Nothing
      xs ->
        let p = (!! 0) . L.reverse $ xs
         in fst <$> B.readInt p

run :: Int -> AuthServerEnv -> IO ()
run port env = scottyT port runReader run'
  where
    runReader a = runReaderT a env

-- logRequestHeaders :: Application -> Application
-- logRequestHeaders incoming request outgoing = do
--  let headerList = requestHeaders request
--  liftIO $ mapM_ print headerList
--  incoming request outgoing

run' :: AuthServer ()
run' = do
  middleware logStdoutDev
  -- middleware logRequestHeaders

  -- \| Route handler for the "/login" endpoint.
  -- This handler will display a simple "login" form.
  get "/login" $
    blaze htmlLogin

  -- \| Handles the POST request to the "/login" endpoint.
  -- This route is responsible for processing user login requests and will generate
  -- an authorization request to the OP.
  post "/login" $ do
    AuthServerEnv {..} <- lift ask
    sid <- genSessionId sdrg
    setCookie $ createCookie sid
    muri <- liftIO $ catch (Right <$> initiateAuthorizationRequest storage sid oidc [] []) handleError
    either
      (status400 . pack)
      (redirect . pack . show)
      muri

  -- \| Handler for the "/refresh" route.
  -- This route is used to refresh the tokens with the OP.
  get "/refresh" $ do
    sid <- getCookie cookieName
    case sid of
      Just s -> do
        AuthServerEnv {..} <- lift ask
        tokens <- liftIO $ catch (Right <$> refreshToken storage (encodeUtf8 s) mgr oidc) handleError
        blaze $ htmlSuccess tokens
      Nothing -> status404 "No current ongoing session found"

  -- \| Handler for the "/login/callback" route.
  -- This route is used as the callback URL for the OIDC login flow and will process
  -- the login response from the provider.
  get "/login/callback" $ do
    err <- catch (Just <$> queryParam "error") noValue
    case err of
      Just e -> status401 $ fromStrict e
      Nothing -> do
        getCookie cookieName >>= doCallback
  where
    createCookie sid =
      defaultSetCookie
        { setCookieName = encodeUtf8 cookieName,
          setCookieValue = sid,
          setCookiePath = Just "/",
--          setCookieDomain = Just "localhost",
          setCookieHttpOnly = True,
          setCookieSecure = True,
          setCookieSameSite = Just sameSiteLax,
          setCookieMaxAge = Just $ secondsToDiffTime 600
        }

    doCallback cookie =
      case cookie of
        Just sid -> do
          AuthServerEnv {..} <- lift ask
          state <- queryParam "state"
          code <- queryParam "code"
          tokens <- liftIO $ catch (Right <$> authorizationGranted storage (encodeUtf8 sid) mgr oidc state code) handleError
          blaze $ htmlSuccess tokens
        Nothing -> status400 "Missing session information"

    htmlSuccess :: Either String (TokenClaims ProfileClaims) -> Html
    htmlSuccess bool = do
      H.h1 "Result"
      H.pre . H.toHtml . show $ bool

    htmlLogin = do
      H.h1 "Login"
      H.form ! A.method "post" ! A.action "/login" $
        H.button ! A.type_ "submit" $
          "login"

    genSessionId sdrg = liftIO $ gen sdrg

    noValue :: (MonadIO m) => SomeException -> m (Maybe a)
    noValue e = do
      liftIO $ print $ displayException e
      return Nothing

    handleError :: (MonadIO m) => SomeException -> m (Either String a)
    handleError e = do
      liftIO $ print $ displayException e
      return $ Left $ displayException e

    cookieName = "session"

    blaze = html . renderHtml

    status400 m = status badRequest400 >> text m

    status401 m = status unauthorized401 >> text m

    status404 m = status notFound404 >> text m

-- | Generates a random session ID using the provided 'SystemDRG'.
gen :: IORef SystemDRG -> IO ByteString
gen sdrg = B64.encode <$> atomicModifyIORef' sdrg (swap . randomBytesGenerate 64)
