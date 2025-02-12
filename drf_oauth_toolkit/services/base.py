import base64
import hashlib
import hmac
import logging
import time
from random import SystemRandom
from typing import Any
from urllib.parse import parse_qsl
from urllib.parse import quote
from urllib.parse import urlencode

import requests
from oauthlib.common import UNICODE_ASCII_CHARACTER_SET
from oauthlib.common import generate_token

from drf_oauth_toolkit.exceptions import OAuthException
from drf_oauth_toolkit.exceptions import TokenValidationError
from drf_oauth_toolkit.models import OAuth1Token
from drf_oauth_toolkit.utils.types import OAuth1Credentials
from drf_oauth_toolkit.utils.types import OAuth1Tokens
from drf_oauth_toolkit.utils.types import OAuth2Tokens
from drf_oauth_toolkit.utils.types import OAuthBase

logger = logging.getLogger(__name__)


class OAuth2ServiceBase(OAuthBase):
    """
    Base class for implementing OAuth2 authentication flows.
    This class provides the core functionality for OAuth2
    authorization code grant type with optional PKCE support.

    Required Class Attributes:
        TOKEN_URL (str): The OAuth2 token endpoint URL
        SCOPES (list): List of permission scopes to request
        AUTHORIZATION_URL (str): The OAuth2 authorization endpoint URL
        USER_INFO_URL (str): Endpoint for retrieving user information

    Usage:
        Subclass this base class and implement the required methods to create a specific
        OAuth2 provider integration (e.g., Google, Twitter OAuth2).

    Example:
        class GoogleOAuth2Service(OAuth2ServiceBase):
            TOKEN_URL = "https://oauth2.googleapis.com/token"
            SCOPES = ["profile", "email"]
            # ... implement required methods
    """

    TOKEN_URL: str
    SCOPES: list

    def __init__(self):
        self._credentials = self.get_credentials()

    def get_authorization_url(self, request) -> tuple[str, str]:
        """
        Generates the OAuth2 authorization URL and state parameter.

        Args:
            request: The HTTP request object

        Returns:
            tuple: (authorization_url, state)
                - authorization_url: Full URL for redirecting user to OAuth provider
                - state: Random state token for CSRF protection
        """
        redirect_uri = self._get_redirect_uri()
        state = self._generate_state_session_token()
        params = self.get_authorization_params(redirect_uri, state, request)
        query_params = urlencode(params)
        authorization_url = f"{self.AUTHORIZATION_URL}?{query_params}"
        return authorization_url, state

    def _generate_state_session_token(
        self, length: int = 30, chars=UNICODE_ASCII_CHARACTER_SET
    ) -> str:
        rand = SystemRandom()
        return "".join(rand.choice(chars) for _ in range(length))

    def get_tokens(self, *, code: str, state, request) -> OAuth2Tokens:
        """
        Exchanges an authorization code for access and refresh tokens.

        Args:
            code: Authorization code received from OAuth provider
            state: State parameter to verify against CSRF attacks
            request: The HTTP request object

        Returns:
            OAuth2Tokens: Object containing access_token, refresh_token, and id_token

        Raises:
            OAuthException: If token request fails
        """
        redirect_uri = self._get_redirect_uri()
        data = self.get_token_request_data(code, redirect_uri, state, request)
        headers = self.get_authorization_headers()
        response = requests.post(self.TOKEN_URL, data=data, headers=headers)
        self._validate_response(response)
        return self._parse_token_response(response.json())

    def get_authorization_headers(self) -> dict[str, str]:
        return {"Content-Type": "application/x-www-form-urlencoded"}

    def _validate_response(self, response):
        if not response.ok:
            logger.error(f"Token request failed: {response.text}")
            raise OAuthException(f"Error during token request: {response.text}")

    def _parse_token_response(self, response_data: dict[str, Any]) -> OAuth2Tokens:
        return OAuth2Tokens(
            access_token=response_data["access_token"],
            refresh_token=response_data.get("refresh_token"),
            id_token=response_data.get("id_token"),
        )

    def _refresh_access_token(self, oauth_tokens: OAuth2Tokens) -> None:
        if not oauth_tokens.refresh_token:
            raise TokenValidationError("Refresh token is missing.")

        data = self._get_refresh_token_data(oauth_tokens.refresh_token)
        headers = self.get_authorization_headers()
        response = requests.post(self.TOKEN_URL, data=data, headers=headers)
        self._validate_response(response)
        tokens_data = response.json()
        oauth_tokens.access_token = tokens_data.get("access_token")

    def _get_refresh_token_data(self, refresh_token: str) -> dict[str, Any]:
        return {
            "client_id": self._credentials.client_id,
            "client_secret": self._credentials.client_secret,
            "refresh_token": refresh_token,
            "grant_type": "refresh_token",
        }

    def get_user_info(
        self,
        *,
        oauth_tokens: OAuth1Tokens | OAuth2Tokens,
        parameters: dict | None = None,
    ) -> dict[str, Any]:
        """
        Retrieves user information from the OAuth provider's userinfo endpoint.

        Args:
            oauth_tokens: OAuth2Tokens object containing valid access token
            parameters: Optional additional parameters for the userinfo request

        Returns:
            dict: User information from the provider

        Raises:
            OAuthException: If userinfo request fails or URL not configured
            TokenValidationError: If invalid token type provided
        """
        if not parameters:
            parameters = {}
        if not self.USER_INFO_URL:
            raise OAuthException("USER_INFO_URL is not defined.")
        if not isinstance(oauth_tokens, OAuth2Tokens):
            raise TokenValidationError
        headers = {"Authorization": f"Bearer {oauth_tokens.access_token}"}
        response = requests.get(self.USER_INFO_URL, headers=headers, params=parameters)
        self._validate_response(response)
        return response.json()

    @staticmethod
    def store_in_session(request, key: str, value: Any) -> None:
        request.session[key] = value
        request.session.modified = True
        request.session.save()

    @staticmethod
    def retrieve_from_session(request, key: str) -> Any:
        value = request.session.pop(key, None)
        if not value:
            raise OAuthException(f"Missing session value for key: {key}")
        return value

    def get_token_request_data(
        self, code: str, redirect_uri: str, state: str, request
    ) -> dict[str, Any]:
        raise NotImplementedError("Subclasses must implement this method.")


class OAuth1ServiceBase(OAuthBase):
    """
    Base class for implementing OAuth1.0a authentication flows.
    Provides core functionality for the three-legged
    OAuth1 authentication process.

    Required Class Attributes:
        REQUEST_TOKEN_URL (str): URL for obtaining request tokens
        ACCESS_TOKEN_URL (str): URL for exchanging request tokens for access tokens
        AUTHORIZATION_URL (str): URL for user authorization

    Usage:
        Subclass this base class and implement the required methods to create a specific
        OAuth1.0a provider integration (e.g., Twitter OAuth1.0a).

    Example:
        class TwitterOAuth1Service(OAuth1ServiceBase):
            REQUEST_TOKEN_URL = "https://api.twitter.com/oauth/request_token"
            # ... implement required methods
    """

    REQUEST_TOKEN_URL: str
    ACCESS_TOKEN_URL: str
    AUTHORIZATION_URL: str

    def __init__(self):
        self._credentials = self.get_credentials()

    def get_request_token(self, request) -> dict[str, str]:
        """
        Obtains OAuth1 request token from the provider.

        Args:
            request: The HTTP request object

        Returns:
            dict: Contains oauth_token and oauth_token_secret

        Raises:
            OAuthException: If request token retrieval fails
        """
        oauth_params = self._get_oauth1_params(callback_url=self._get_redirect_uri())
        oauth_params["oauth_signature"] = self._generate_oauth_signature(
            method="POST",
            url=self.REQUEST_TOKEN_URL,
            params=oauth_params,
        )
        headers = {"Authorization": f"OAuth {self._format_oauth_header(oauth_params)}"}
        response = requests.post(self.REQUEST_TOKEN_URL, headers=headers)
        if not response.ok:
            raise OAuthException(f"Failed to obtain request token: {response.text}")

        token_data = dict(parse_qsl(response.text))
        self._save_request_token(request, token_data)
        return token_data

    def get_access_token(self, oauth_token: str, oauth_verifier: str) -> OAuth1Tokens:
        """
        Exchanges request token for access token after user authorization.

        Args:
            oauth_token: OAuth token from callback
            oauth_verifier: OAuth verifier from callback

        Returns:
            OAuth1Tokens: Object containing oauth_token and oauth_token_secret

        Raises:
            OAuthException: If token exchange fails or token not found
        """
        try:
            token_obj = OAuth1Token.objects.get(request_token=oauth_token)
        except OAuth1Token.DoesNotExist as e:
            raise OAuthException("Invalid or expired request token.") from e

        token_secret = token_obj.request_token_secret

        oauth_params = {
            "oauth_consumer_key": self._credentials["client_key"],
            "oauth_token": oauth_token,
            "oauth_verifier": oauth_verifier,
            "oauth_nonce": generate_token(length=32),
            "oauth_signature_method": "HMAC-SHA1",
            "oauth_timestamp": str(int(time.time())),
            "oauth_version": "1.0",
        }
        oauth_params["oauth_signature"] = self._generate_oauth_signature(
            method="POST",
            url=self.ACCESS_TOKEN_URL,
            params=oauth_params,
            token_secret=token_secret,
        )
        headers = {"Authorization": f"OAuth {self._format_oauth_header(oauth_params)}"}
        response = requests.post(self.ACCESS_TOKEN_URL, headers=headers)
        if not response.ok:
            raise OAuthException(f"Failed to obtain access token: {response.text}")

        return OAuth1Tokens(**dict(parse_qsl(response.text)))

    def _generate_oauth_signature(
        self, method: str, url: str, params: dict[str, str], token_secret: str = ""
    ) -> str:
        """
        Generates OAuth1.0a signature for requests.

        Args:
            method: HTTP method (GET, POST, etc.)
            url: Request URL
            params: OAuth parameters
            token_secret: Token secret for signature (empty for request token)

        Returns:
            str: Base64 encoded HMAC-SHA1 signature
        """
        assert isinstance(self._credentials, OAuth1Credentials), (
            "Credentials must be of type OAuth1Credentials"
        )
        sorted_params = "&".join(
            f"{quote(k)}={quote(v)}" for k, v in sorted(params.items())
        )
        base_string = f"{method.upper()}&{quote(url)}&{quote(sorted_params)}"
        signing_key = f"{self._credentials.consumer_secret}&{token_secret}"
        signature = hmac.new(
            signing_key.encode(), base_string.encode(), hashlib.sha1
        ).digest()
        return base64.b64encode(signature).decode()

    def _get_oauth1_params(self, callback_url: str = "") -> dict[str, str]:
        assert isinstance(self._credentials, OAuth1Credentials), (
            "Credentials must be of type OAuth1Credentials"
        )

        return {
            "oauth_consumer_key": self._credentials.consumer_key,
            "oauth_nonce": base64.b64encode(SystemRandom().randbytes(16)).decode(),
            "oauth_signature_method": "HMAC-SHA1",
            "oauth_timestamp": str(int(time.time())),
            "oauth_version": "1.0",
            "oauth_callback": callback_url,
        }

    def _format_oauth_header(self, params: dict[str, str]) -> str:
        return ", ".join(f'{k}="{quote(v, safe="")}"' for k, v in params.items())

    def _generate_nonce(self) -> str:
        """
        Generate a random nonce for OAuth1 requests.
        """
        # Generate 16 random bytes (128 bits) and encode them in base64
        return base64.b64encode(SystemRandom().randbytes(16)).decode()

    def _save_request_token(self, request, token_data: dict[str, str]):
        """Optional hook for subclasses to save tokens (e.g., to a database)."""

    def get_user(self, request):
        raise NotImplementedError("Subclasses must implement this method.")
