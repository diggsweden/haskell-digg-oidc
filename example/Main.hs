{-# LANGUAGE DeriveGeneric     #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards   #-}

-- |  Module: Main
--    Maintainer: tomas.stenlund@telia.com
--    Stability: experimental
--
--    The module is a simple web server that uses the OIDC and OIDF client modules to authenticate users with an OpenID Connect provider.
module Main (main) where

import           Control.Exception                           (throwIO)
import           Control.Monad.Catch                         (Exception (displayException),
                                                              catch)
import           Control.Monad.IO.Class                      (MonadIO, liftIO)
import           Control.Monad.Reader                        (ReaderT, ask,
                                                              lift, runReaderT)
import           Crypto.Random                               (SystemDRG,
                                                              getSystemDRG,
                                                              randomBytesGenerate)

import           Data.Aeson                                  (FromJSON)
import           Data.ByteString                             (ByteString)
import qualified Data.ByteString.Base64                      as B64
import qualified Data.ByteString.Char8                       as B
import           Data.IORef                                  (IORef,
                                                              atomicModifyIORef',
                                                              newIORef)
import qualified Data.List                                   as L
import           Data.Maybe                                  (fromMaybe)
import           Data.Text                                   (Text)
import           Data.Text.Encoding                          (decodeUtf8,
                                                              encodeUtf8)
import           Data.Text.Lazy                              (fromStrict, pack,
                                                              toStrict)
import           Data.Time.Clock                             (secondsToDiffTime)
import           Data.Tuple                                  (swap)

import           Digg.OIDC.Client                            (OIDC, createOIDC)
import           Digg.OIDC.Client.Discovery                  (discover)
import           Digg.OIDC.Client.Discovery.Provider         (metadata)
import           Digg.OIDC.Client.Flow.AuthorizationCodeFlow (authorizationGranted,
                                                              initiateAuthorizationRequest)
import           Digg.OIDC.Client.Flow.LogoutFlow            (initiateLogoutRequest,
                                                              logoutCompleted)
import           Digg.OIDC.Client.Flow.RefreshTokenFlow      (refreshToken)
import           Digg.OIDC.Client.Session                    (SessionStorage (..),
                                                              getAccessClaims,
                                                              getAccessToken,
                                                              getIdClaims,
                                                              getIdToken)
-- import           Digg.OIDC.Client.Storage.MemoryStore        (memoryStorage)
import           Digg.OIDC.Client.Storage.RedisStore         (redisStorage)
import           Digg.OIDC.Client.Tokens                     (AccessTokenClaims,
                                                              AccessTokenJWT,
                                                              IdTokenClaims,
                                                              IdTokenJWT,
                                                              NoExtraClaims)
import           Digg.OIDC.Types                             (Issuer)
import           GHC.Exception.Type                          (SomeException)
import           GHC.Generics                                (Generic)
import           Network.HTTP.Client                         (Manager,
                                                              newManager)
import           Network.HTTP.Client.TLS                     (tlsManagerSettings)
import           Network.HTTP.Types                          (badRequest400,
                                                              notFound404,
                                                              unauthorized401)
import           Network.Wai.Middleware.RequestLogger        (logStdoutDev)
import           System.Environment                          (lookupEnv)
import           Text.Blaze.Html                             (Html)
import           Text.Blaze.Html.Renderer.Text               (renderHtml)
import qualified Text.Blaze.Html5                            as H
import           Text.Blaze.Html5                            ((!))
import qualified Text.Blaze.Html5.Attributes                 as A
import           Text.Pretty.Simple                          (pPrint)
import           Web.Scotty.Cookie                           (SetCookie (..),
                                                              defaultSetCookie,
                                                              getCookie,
                                                              sameSiteLax,
                                                              setCookie)
import           Web.Scotty.Trans                            (ActionT, ScottyT,
                                                              finish, get, html,
                                                              middleware, post,
                                                              queryParam,
                                                              redirect, scottyT,
                                                              status, text)

--
-- Authorization server environment
--

-- | 'AuthServerEnv' represents the environment configuration for the authentication server.
-- This data type is used to encapsulate all necessary settings and parameters required
-- for the example to operate correctly.
data AuthServerEnv = AuthServerEnv
  { issuer  :: Issuer,     -- ^ The OIDC provider issuer location.
    oidc    :: OIDC,                 -- ^ The OIDC client configuration.
    storage :: SessionStorage IO, -- ^ The session storage.
    sdrg    :: IORef SystemDRG,      -- ^ The system DRG.
    mgr     :: Manager                -- ^ The HTTP client manager.
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
  issuer <- toStrict . pack . fromMaybe "https://change.me" <$> lookupEnv "EXAMPLE_ISSUER_URL"
  client <- toStrict . pack . fromMaybe "ChangeToYourClientId" <$> lookupEnv "EXAMPLE_CLIENT_ID"
  secret <- toStrict . pack . fromMaybe "ChangeToYourClientsSecret" <$> lookupEnv "EXAMPLE_CLIENT_SECRET"
  redis <- fromMaybe "localhost" <$> lookupEnv "EXAMPLE_REDIS_HOST"

  -- Create the system DRG and the session storage
  sdrg <- getSystemDRG >>= newIORef
  storage <- catch (redisStorage redis 600) (handleIOError "Failed to connect to redis")
  -- storage <- catch (memoryStorage) (handleIOError "Failed to create the memory storage")

  -- Create the HTTP client manager and the OIDC client
  mgr <- newManager tlsManagerSettings
  provider <- liftIO $ discover issuer mgr
  pPrint $ metadata provider
  let oidc = createOIDC client secret (toStrict (fromStrict (decodeUtf8 baseUrl) <> "/login/callback")) (Just (toStrict (fromStrict (decodeUtf8 baseUrl) <> "/logout/callback"))) provider

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

  where

    handleIOError :: String -> IOError -> IO a
    handleIOError msg e = do
      liftIO $ print $ msg <> ": " <> displayException e
      throwIO e

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

  -- | Route handler for the "/login" endpoint.
  -- This handler will display a simple "login" form.
  get "/login" $
    blaze htmlLogin

  -- | Handles the POST request to the "/login" endpoint.
  -- This route is responsible for processing user login requests and will generate
  -- an authorization request to the OP.
  post "/login" $ do
    redirectToLogin

  -- | Handler for the "/login/callback" route.
  -- This route is used as the callback URL for the OIDC login flow and will process
  -- the login response from the provider.
  get "/login/callback" $ do
    err <- catch (Just <$> queryParam "error") noValue
    case err of
      Just e -> status401 $ fromStrict e
      Nothing -> do
        getCookie cookieName >>= doLoginCallback

  -- | Handler for the logout route. It initiates the RP initiated logout flow.
  get "/logout" $ do
    sid <- getCookie cookieName
    case sid of
      Nothing -> status404 "No current ongoing session found"
      Just s -> do
        AuthServerEnv {..} <- lift ask
        muri <- liftIO $ catch (Right <$> initiateLogoutRequest storage (encodeUtf8 s) oidc []) handleError
        either
          (status400 . pack)
          (redirect . pack . show)
          muri

  -- | Handler for the logout callback endpoint.
  -- This route is triggered after a user logs out and the OIDC provider
  -- redirects back to the application. It processes the logout callback
  -- and performs any necessary cleanup or redirection.
  get "/logout/callback" $ do
    err <- catch (Just <$> queryParam "error") noValue
    case err of
      Just e -> status401 $ fromStrict e
      Nothing -> do
        getCookie cookieName >>= doLogoutCallback
        setCookie deleteCookie

  -- | Handler for the "/refresh" route.
  -- This route is used to refresh the tokens with the OP.
  get "/refresh" $ do
    sid <- getCookie cookieName
    case sid of
      Just s -> do
        AuthServerEnv {..} <- lift ask
        tokens <- liftIO $ catch (Right <$> refreshToken storage (encodeUtf8 s) mgr oidc) handleError
        blaze $ htmlSuccess tokens
      Nothing -> status404 "No current ongoing session found"

  -- | Handler for the "/fetch" route. It returns the id and access tokens and their claims
  get "/fetch" $ do
    sid <- getCookie cookieName
    case sid of
      Just s -> do
        AuthServerEnv {..} <- lift ask
        token <- liftIO $ catch (getAccessToken storage (encodeUtf8 s)) noValue
        idtoken <- liftIO $ catch (getIdToken storage (encodeUtf8 s)) noValue
        idClaims <- liftIO $ catch (getIdClaims oidc storage (encodeUtf8 s)) noValue
        accessClaims <- liftIO $ catch (getAccessClaims oidc storage (encodeUtf8 s)) noValue
        blaze $ htmlFetch token idtoken idClaims accessClaims
      Nothing -> status404 "No current ongoing session found"

  -- | Handler for the "/protected" route.
  -- This route is protected and requires the user to be authenticated.
  get "/protected" $ do
    protect
    blaze $ htmlPage "This is a protected route which you have access to."

  where

    -- | Redirects the user to the login page.
    redirectToLogin :: ActionT (ReaderT AuthServerEnv IO) ()
    redirectToLogin = do
      AuthServerEnv {..} <- lift ask
      sid <- genSessionId sdrg
      setCookie $ createCookie sid
      muri <- liftIO $ catch (Right <$> initiateAuthorizationRequest storage sid oidc ["testbed"] []) handleError
      either
        (status400 . pack)
        (redirect . pack . show)
        muri

    -- | The 'protect' function is an Action Transformer that ensures the
    --   protected route can only be accessed by authenticated users.
    protect:: ActionT (ReaderT AuthServerEnv IO) ()
    protect = do
      AuthServerEnv {..} <- lift ask
      sid <- getCookie cookieName
      case sid of
        Just s -> do
          token <- liftIO $ catch (getAccessToken storage (encodeUtf8 s)) noValue
          case token of
            Just _ -> return ()
            Nothing -> do
              redirectToLogin
              finish
        Nothing -> do
          redirectToLogin
          finish

    cookieName = "session"

    -- | Creates a cookie with the given session ID.
    createCookie sid =
      defaultSetCookie
        { setCookieName = encodeUtf8 cookieName,
          setCookieValue = sid,
          setCookiePath = Just "/",
          setCookieHttpOnly = True,
          setCookieSecure = True,
          setCookieSameSite = Just sameSiteLax,
          setCookieMaxAge = Just $ secondsToDiffTime 600
        }

    -- | Deletes a cookie from the client's browser.
    deleteCookie =
      defaultSetCookie
        { setCookieName = encodeUtf8 cookieName,
          setCookieValue = "",
          setCookiePath = Just "/",
          setCookieMaxAge = Just $ secondsToDiffTime 0
        }

    -- | Handles the login callback, session, state and code.
    doLoginCallback cookie =
      case cookie of
        Just sid -> do
          AuthServerEnv {..} <- lift ask
          state <- queryParam "state"
          code <- queryParam "code"
          tokens <- liftIO $ catch (Right <$> authorizationGranted storage (encodeUtf8 sid) mgr oidc state code) handleError
          blaze $ htmlSuccess tokens
        Nothing -> status400 "Missing session information"

    -- | Handles the logout callback, session and state.
    doLogoutCallback cookie =
      case cookie of
        Just sid -> do
          AuthServerEnv {..} <- lift ask
          state <- queryParam "state"
          result <- liftIO $ catch (Right <$> logoutCompleted storage (encodeUtf8 sid) state) handleError
          blaze $ htmlLoggedOut result
        Nothing -> status400 "Missing session information"

    -- Various html pages

    htmlPage :: String -> Html
    htmlPage s = do
      H.h1 "Result:"
      H.pre . H.toHtml $ s

    htmlLoggedOut :: Either String () -> Html
    htmlLoggedOut result = do
      H.h1 "Result:"
      H.p $ H.text "This page contains the result of the logout flow."
      H.pre . H.toHtml . show $ result


    htmlSuccess :: Either String (IdTokenClaims ProfileClaims) -> Html
    htmlSuccess bool = do
      H.h1 "Result:"
      H.p $ H.text "This page contains the result of the login or refresh flow. For now it only displays the ID token claims or any errors."
      H.pre . H.toHtml . show $ bool

    htmlFetch :: Maybe AccessTokenJWT -> Maybe IdTokenJWT
      -> Maybe (IdTokenClaims ProfileClaims)
      -> Maybe (AccessTokenClaims NoExtraClaims)
      -> Html
    htmlFetch t idt ic ac = do
      H.h1 "Result:"
      H.p $ H.text "This page contains the access and id token and their claims."
      H.p $ H.text "Access token:"
      H.pre . H.toHtml . show $ t
      H.p $ H.text "Access token claims:"
      H.pre . H.toHtml . show $ ac
      H.p $ H.text "ID token:"
      H.pre . H.toHtml . show $ idt
      H.p $ H.text "ID token claims:"
      H.pre . H.toHtml . show $ ic

    htmlLogin = do
      H.h1 "Login"
      H.p $ H.text "This page will contain more stuff later on, when we develop the testbed further. For now it only initiates the login flow."
      H.form ! A.method "post" ! A.action "/login" $
        H.button ! A.type_ "submit" $
          "login"

    blaze = html . renderHtml

    status400 m = status badRequest400 >> text m

    status401 m = status unauthorized401 >> text m

    status404 m = status notFound404 >> text m

    -- | Generates a random session ID using the provided 'SystemDRG'.
    genSessionId sdrg = liftIO $ gen sdrg

    -- | A function that handles exceptions by returning 'Nothing'.
    noValue :: (MonadIO m) => SomeException -> m (Maybe a)
    noValue _ = do
      return Nothing

    -- | Handles exceptions by converting them to an 'Either' type with a 'String' error message.
    handleError :: (MonadIO m) => SomeException -> m (Either String a)
    handleError e = do
      return $ Left $ displayException e

-- | Generates a random session ID using the provided 'SystemDRG'.
gen :: IORef SystemDRG -> IO ByteString
gen sdrg = B64.encode <$> atomicModifyIORef' sdrg (swap . randomBytesGenerate 64)
