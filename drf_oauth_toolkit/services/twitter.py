import base64
import hashlib
import hmac
import logging
import time
from typing import Any, Dict
from urllib.parse import quote

import requests
from django.conf import settings
from django.core.exceptions import ImproperlyConfigured
from django.utils.crypto import get_random_string

from drf_oauth_toolkit.exceptions import OAuthException, TokenValidationError
from drf_oauth_toolkit.services.base import OAuth1ServiceBase, OAuth2ServiceBase
from drf_oauth_toolkit.utils.settings_loader import get_nested_setting
from drf_oauth_toolkit.utils.types import (
    OAuth1Credentials,
    OAuth1Tokens,
    OAuth2Credentials,
    OAuth2Tokens,
)

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
        client_secret = get_nested_setting(["OAUTH_CREDENTIALS", "twitter", "client_secret"])

        if not client_id or not client_secret:
            raise ImproperlyConfigured("Twitter client ID or secret not set.")
        return OAuth2Credentials(client_id=client_id, client_secret=client_secret)

    def get_authorization_params(self, redirect_uri: str, state: str, request) -> Dict[str, Any]:
        """
        Build the OAuth 2 authorization parameters, including PKCE.
        Stores the code_verifier in the session so we can use it
        during the token exchange.
        """
        # Generate code_verifier and code_challenge
        code_verifier = get_random_string(128)
        code_challenge = (
            base64.urlsafe_b64encode(hashlib.sha256(code_verifier.encode()).digest())
            .decode()
            .rstrip("=")
        )

        self._store_in_session(request, f"{state}_code_verifier", code_verifier)

        return {
            "response_type": "code",
            "client_id": self._credentials.client_id,
            "redirect_uri": redirect_uri,
            "scope": " ".join(self.SCOPES),
            "state": state,
            "code_challenge_method": "S256",
            "code_challenge": code_challenge,
        }

    def get_authorization_headers(self) -> Dict[str, str]:
        """
        Twitter's OAuth2 token endpoint requires Basic Authorization header
        with the client_id and client_secret.
        """
        creds = f"{self._credentials.client_id}:{self._credentials.client_secret}"
        basic_credentials = base64.b64encode(creds.encode()).decode()
        return {
            "Content-Type": "application/x-www-form-urlencoded",
            "Authorization": f"Basic {basic_credentials}",
        }

    def get_token_request_data(
        self, code: str, redirect_uri: str, state: str, request
    ) -> Dict[str, Any]:
        """
        Prepare the payload to exchange the authorization code for the tokens.
        Retrieve the PKCE code_verifier from the session, stored previously.
        """
        code_verifier = self._retrieve_from_session(request, f"{state}_code_verifier")
        return {
            "grant_type": "authorization_code",
            "client_id": self._credentials.client_id,
            "code": code,
            "redirect_uri": redirect_uri,
            "code_verifier": code_verifier,
        }


class TwitterOAuth1aService(OAuth1ServiceBase):
    """
    Refactored version of your old TwitterOAuth1aService, now using OAuth1ServiceBase.
    """

    REQUEST_TOKEN_URL = "https://api.twitter.com/oauth/request_token"
    AUTHORIZATION_URL = "https://api.twitter.com/oauth/authorize"
    ACCESS_TOKEN_URL = "https://api.twitter.com/oauth/access_token"
    USER_INFO_URL = "https://api.twitter.com/1.1/account/verify_credentials.json"
    API_URI_NAME = "twitter-oauth1a-callback"

    def get_credentials(self) -> OAuth1Credentials:
        """
        Load the consumer_key and consumer_secret from settings.
        Return as an OAuth1Credentials object.
        """
        consumer_key = getattr(settings, "TWITTER_API_KEY", None)
        consumer_secret = getattr(settings, "TWITTER_API_SECRET", None)
        if not consumer_key or not consumer_secret:
            raise ImproperlyConfigured("Twitter consumer_key or consumer_secret not set.")
        return OAuth1Credentials(consumer_key=consumer_key, consumer_secret=consumer_secret)

    def get_request_token(self, request) -> Dict[str, str]:
        """
        Request a temporary oauth_token and oauth_token_secret from Twitter.
        You can store them in DB or session as needed.
        """
        # The parent class implements the logic for signing, but it expects
        # self._credentials.client_id / client_secret. We’ll override _get_oauth1_params.
        # Then call super().get_request_token().
        return super().get_request_token(request)

    def get_access_token(self, oauth_token: str, oauth_verifier: str) -> OAuth1Tokens:
        """
        Exchange the request token + verifier for an access token.
        Returns an OAuth1Tokens object containing oauth_token, oauth_token_secret, etc.
        """
        return super().get_access_token(oauth_token, oauth_verifier)

    def get_user_info(self, *, oauth_tokens: OAuth1Tokens | OAuth2Tokens) -> Dict[str, Any]:
        """
        Calls verify_credentials with the user's access_token and access_token_secret
        to retrieve user info from Twitter.
        """
        # Build OAuth params for a GET request. We'll replicate the parent's approach
        # but handle the signed request ourselves if we want to do custom logic:
        method = "GET"
        url = self.USER_INFO_URL
        if not isinstance(oauth_tokens, OAuth1Tokens):
            raise TokenValidationError()

        oauth_params = {
            "oauth_consumer_key": self._credentials.consumer_key,
            "oauth_token": oauth_tokens.oauth_token,
            "oauth_nonce": base64.b64encode(get_random_string(32).encode()).decode(),
            "oauth_signature_method": "HMAC-SHA1",
            "oauth_timestamp": str(int(time.time())),
            "oauth_version": "1.0",
        }
        # Build signature using the user's access_token_secret
        signature = self._generate_oauth_signature(
            method, url, oauth_params, oauth_tokens.oauth_token_secret
        )
        oauth_params["oauth_signature"] = signature

        headers = {"Authorization": f"OAuth {self._format_oauth_header(oauth_params)}"}
        response = requests.get(url, headers=headers)
        if not response.ok:
            raise OAuthException(f"Failed to obtain user info: {response.text}")

        return response.json()

    # Optional method if you need Ads Accounts:
    def get_user_ads_accounts(self, oauth_tokens: OAuth1Tokens) -> Dict[str, Any]:
        """
        Example of an additional call to Twitter Ads API (v12).
        """
        ads_url = "https://ads-api.twitter.com/12/accounts"
        method = "GET"

        oauth_params = {
            "oauth_consumer_key": self._credentials.consumer_key,
            "oauth_token": oauth_tokens.oauth_token,
            "oauth_nonce": base64.b64encode(get_random_string(32).encode()).decode(),
            "oauth_signature_method": "HMAC-SHA1",
            "oauth_timestamp": str(int(time.time())),
            "oauth_version": "1.0",
        }
        signature = self._generate_oauth_signature(
            method, ads_url, oauth_params, oauth_tokens.oauth_token_secret
        )
        oauth_params["oauth_signature"] = signature

        headers = {"Authorization": f"OAuth {self._format_oauth_header(oauth_params)}"}
        response = requests.get(ads_url, headers=headers)
        if not response.ok:
            raise OAuthException(f"Failed to obtain user ads accounts: {response.text}")

        return response.json()

    def _get_oauth1_params(self, callback_url: str = "") -> Dict[str, str]:
        """
        Override the parent's method to return the correct dict keys for consumer_key/secret.
        Notice the base expects self._credentials.client_id, but we have consumer_key.
        """
        return {
            "oauth_consumer_key": self._credentials.consumer_key,
            "oauth_nonce": base64.b64encode(get_random_string(32).encode()).decode(),
            "oauth_signature_method": "HMAC-SHA1",
            "oauth_timestamp": str(int(time.time())),
            "oauth_version": "1.0",
            "oauth_callback": callback_url,
        }

    def _generate_oauth_signature(
        self,
        method: str,
        url: str,
        params: Dict[str, str],
        token_secret: str = "",
    ) -> str:
        """
        Override if you need to incorporate the token_secret when signing the request.
        The parent class only uses self._credentials.consumer_secret + '&'.
        We append the token_secret if available.
        """
        sorted_params = "&".join(
            f"{quote(k, safe='')}={quote(v, safe='')}" for k, v in sorted(params.items())
        )
        base_string = f"{method.upper()}&{quote(url, safe='')}&{quote(sorted_params, safe='')}"
        signing_key = f"{self._credentials.consumer_secret}&{token_secret}"

        signature = hmac.new(
            signing_key.encode("utf-8"), base_string.encode("utf-8"), hashlib.sha1
        ).digest()
        return base64.b64encode(signature).decode("utf-8")

    def _format_oauth_header(self, params: Dict[str, str]) -> str:
        """
        Typically the same as the parent's approach, but you can override for custom encoding.
        """
        return ", ".join(f'{k}="{quote(v, safe="")}"' for k, v in params.items())
