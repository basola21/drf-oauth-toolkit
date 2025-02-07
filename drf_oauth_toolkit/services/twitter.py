import base64
import hashlib
import logging
import time
from typing import Any
from urllib.parse import parse_qsl

import requests
from django.conf import settings
from django.core.exceptions import ImproperlyConfigured
from django.utils.crypto import get_random_string

from drf_oauth_toolkit.exceptions import OAuthException
from drf_oauth_toolkit.models import OAuthRequestToken
from drf_oauth_toolkit.services.base import OAuth1ServiceBase
from drf_oauth_toolkit.services.base import OAuth2ServiceBase
from drf_oauth_toolkit.utils.settings_loader import get_nested_setting
from drf_oauth_toolkit.utils.types import OAuth1Credentials
from drf_oauth_toolkit.utils.types import OAuth1Tokens
from drf_oauth_toolkit.utils.types import OAuth2Credentials
from drf_oauth_toolkit.utils.types import OAuth2Tokens

logger = logging.getLogger(__name__)


class TwitterOAuth2Service(OAuth2ServiceBase):
    """
    Twitter oauth2 service handles auth with twitter
    Handles PKCE, user info, etc.
    """

    API_URI_NAME = get_nested_setting(["OAUTH_CREDENTIALS", "twitter", "callback_url"])
    AUTHORIZATION_URL = "https://twitter.com/i/oauth2/authorize"
    TOKEN_URL = "https://api.twitter.com/2/oauth2/token"
    USER_INFO_URL = "https://api.twitter.com/2/users/me"
    SCOPES = ["tweet.read", "users.read", "offline.access"]

    def get_credentials(self) -> OAuth2Credentials:
        """
        Retrieve Twitter API client_id and client_secret from your settings
        and return an OAuth2Credentials object.
        """
        client_id = get_nested_setting(["OAUTH_CREDENTIALS", "twitter", "client_id"])
        client_secret = get_nested_setting(
            ["OAUTH_CREDENTIALS", "twitter", "client_secret"]
        )

        if not client_id or not client_secret:
            raise ImproperlyConfigured("Twitter client ID or secret not set.")
        return OAuth2Credentials(client_id=client_id, client_secret=client_secret)

    def get_authorization_params(
        self, redirect_uri: str, state: str, request
    ) -> dict[str, Any]:
        """
        Build the OAuth 2 authorization parameters, including PKCE.
        Stores the code_verifier in the session so we can use it
        during the token exchange.
        """

        assert isinstance(self._credentials, OAuth2Credentials)

        # Generate code_verifier and code_challenge
        code_verifier = get_random_string(128)
        code_challenge = (
            base64.urlsafe_b64encode(hashlib.sha256(code_verifier.encode()).digest())
            .decode()
            .rstrip("=")
        )

        self.store_in_session(request, f"{state}_code_verifier", code_verifier)

        return {
            "response_type": "code",
            "client_id": self._credentials.client_id,
            "redirect_uri": redirect_uri,
            "scope": " ".join(self.SCOPES),
            "state": state,
            "code_challenge_method": "S256",
            "code_challenge": code_challenge,
        }

    def get_authorization_headers(self) -> dict[str, str]:
        """
        Twitter's OAuth2 token endpoint requires Basic Authorization header
        with the client_id and client_secret.
        """

        assert isinstance(self._credentials, OAuth2Credentials)
        creds = f"{self._credentials.client_id}:{self._credentials.client_secret}"
        basic_credentials = base64.b64encode(creds.encode()).decode()
        return {
            "Content-Type": "application/x-www-form-urlencoded",
            "Authorization": f"Basic {basic_credentials}",
        }

    def get_token_request_data(
        self, code: str, redirect_uri: str, state: str, request
    ) -> dict[str, Any]:
        """
        Prepare the payload to exchange the authorization code for the tokens.
        Retrieve the PKCE code_verifier from the session, stored previously.
        """
        assert isinstance(self._credentials, OAuth2Credentials)
        code_verifier = self.retrieve_from_session(request, f"{state}_code_verifier")
        return {
            "grant_type": "authorization_code",
            "client_id": self._credentials.client_id,
            "code": code,
            "redirect_uri": redirect_uri,
            "code_verifier": code_verifier,
        }


class TwitterOAuth1aService(OAuth1ServiceBase):
    REQUEST_TOKEN_URL = "https://api.twitter.com/oauth/request_token"
    AUTHORIZATION_URL = "https://api.twitter.com/oauth/authorize"
    ACCESS_TOKEN_URL = "https://api.twitter.com/oauth/access_token"
    USER_INFO_URL = "https://api.twitter.com/1.1/account/verify_credentials.json"
    USER_ADS_ACCOUNTS_URL = "https://ads-api.twitter.com/12/accounts"
    API_URI_NAME = "twitter-oauth1a-callback"

    def get_credentials(self) -> OAuth1Credentials:
        consumer_key = settings.TWITTER_API_KEY
        consumer_secret = settings.TWITTER_API_SECRET
        if not consumer_key or not consumer_secret:
            raise ImproperlyConfigured("Twitter API key/secret not configured.")
        return OAuth1Credentials(
            consumer_key=consumer_key, consumer_secret=consumer_secret
        )

    def get_user(self, request):
        return request.user  # Or custom logic (e.g., session-based user)

    def _save_request_token(self, request, token_data: dict[str, str]):
        user = self.get_user(request)
        OAuthRequestToken.objects.create(
            user=user,
            request_token=token_data["oauth_token"],
            request_token_secret=token_data["oauth_token_secret"],
        )

    def get_access_token(self, oauth_token: str, oauth_verifier: str) -> OAuth1Tokens:
        token_obj = OAuthRequestToken.objects.get(request_token=oauth_token)
        token_secret = token_obj.request_token_secret

        oauth_params = self._get_oauth1_params()
        oauth_params.update(
            {"oauth_token": oauth_token, "oauth_verifier": oauth_verifier}
        )

        oauth_params["oauth_signature"] = self._generate_oauth_signature(
            method="POST",
            url=self.ACCESS_TOKEN_URL,
            params=oauth_params,
            token_secret=token_secret,
        )

        headers = {"Authorization": f"OAuth {self._format_oauth_header(oauth_params)}"}
        response = requests.post(self.ACCESS_TOKEN_URL, headers=headers)
        if not response.ok:
            raise OAuthException(f"Failed to get access token: {response.text}")

        token_data = dict(parse_qsl(response.text))
        return OAuth1Tokens(
            oauth_token=token_data["oauth_token"],
            oauth_token_secret=token_data["oauth_token_secret"],
            user_id=token_data.get("user_id"),
            screen_name=token_data.get("screen_name"),
        )

    def get_user_info(
        self, *, oauth_tokens: OAuth1Tokens | OAuth2Tokens
    ) -> dict[str, Any]:
        # Twitter-specific API call (not part of the base class)
        assert isinstance(self._credentials, OAuth1Credentials)
        assert isinstance(oauth_tokens, OAuth1Tokens)
        params = {
            "oauth_consumer_key": self._credentials.consumer_key,
            "oauth_token": oauth_tokens.oauth_token,
            "oauth_nonce": self._generate_nonce(),
            "oauth_signature_method": "HMAC-SHA1",
            "oauth_timestamp": str(int(time.time())),
            "oauth_version": "1.0",
        }
        params["oauth_signature"] = self._generate_oauth_signature(
            method="GET",
            url=self.USER_INFO_URL,
            params=params,
            token_secret=oauth_tokens.oauth_token_secret,
        )
        headers = {"Authorization": f"OAuth {self._format_oauth_header(params)}"}
        response = requests.get(self.USER_INFO_URL, headers=headers)
        return response.json()
