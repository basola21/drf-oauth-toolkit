import base64
import hashlib
import hmac
import logging
import time
from dataclasses import dataclass
from random import SystemRandom
from typing import Any, Dict, Optional, Tuple
from urllib.parse import parse_qsl, quote, urlencode

import jwt
import requests
from django.urls import reverse_lazy
from oauthlib.common import UNICODE_ASCII_CHARACTER_SET

from drf_oauth_toolkit.exceptions import OAuthException, TokenValidationError
from drf_oauth_toolkit.utils.settings_loader import get_nested_setting

logger = logging.getLogger(__name__)


@dataclass
class OAuth1Credentials:
    consumer_key: str
    consumer_secret: str


@dataclass
class OAuth2Credentials:
    client_id: str
    client_secret: str


@dataclass
class OAuth1Tokens:
    oauth_token: str
    oauth_token_secret: str
    user_id: Optional[str] = None
    screen_name: Optional[str] = None


@dataclass
class OAuth2Tokens:
    access_token: str
    refresh_token: Optional[str] = None
    id_token: Optional[str] = None
    expires_in: Optional[int] = 90

    def decode_id_token(self) -> Dict[str, Any]:
        if not self.id_token:
            return {}
        decoded_token = jwt.decode(jwt=self.id_token, options={"verify_signature": False})
        return decoded_token


class OAuthBase:
    """
    Abstract base class for both OAuth 1.0a and OAuth 2.0 strategies.
    """

    API_URI_NAME: str
    AUTHORIZATION_URL: str
    USER_INFO_URL: str

    def _get_redirect_uri(self) -> str:
        domain = get_nested_setting(["OAUTH_CREDENTIALS", "host"])
        return f"{domain}{reverse_lazy(self.API_URI_NAME)}"

    def get_authorization_params(self, redirect_uri: str, state: str, request) -> Dict[str, Any]:
        raise NotImplementedError("Subclasses must implement this method.")

    def get_credentials(self) -> OAuth1Credentials | OAuth2Credentials:
        raise NotImplementedError("Subclasses must implement this method.")

    def get_tokens(self, *, code: str, state, request) -> OAuth1Tokens | OAuth2Tokens:
        raise NotImplementedError

    def get_user_info(self, *, oauth_tokens: OAuth1Tokens | OAuth2Tokens) -> Dict[str, Any]:
        raise NotImplementedError


class OAuth2ServiceBase(OAuthBase):
    TOKEN_URL: str
    SCOPES: list

    def __init__(self):
        self._credentials = self.get_credentials()

    def get_authorization_url(self, request) -> Tuple[str, str]:
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
        redirect_uri = self._get_redirect_uri()
        data = self.get_token_request_data(code, redirect_uri, state, request)
        headers = self.get_authorization_headers()
        response = requests.post(self.TOKEN_URL, data=data, headers=headers)
        self._validate_response(response)
        return self._parse_token_response(response.json())

    def get_authorization_headers(self) -> Dict[str, str]:
        return {"Content-Type": "application/x-www-form-urlencoded"}

    def _validate_response(self, response):
        if not response.ok:
            logger.error(f"Token request failed: {response.text}")
            raise OAuthException(f"Error during token request: {response.text}")

    def _parse_token_response(self, response_data: Dict[str, Any]) -> OAuth2Tokens:
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

    def _get_refresh_token_data(self, refresh_token: str) -> Dict[str, Any]:
        return {
            "client_id": self._credentials.client_id,
            "client_secret": self._credentials.client_secret,
            "refresh_token": refresh_token,
            "grant_type": "refresh_token",
        }

    def get_user_info(self, *, oauth_tokens: OAuth1Tokens | OAuth2Tokens) -> Dict[str, Any]:
        if not self.USER_INFO_URL:
            raise OAuthException("USER_INFO_URL is not defined.")
        if not isinstance(oauth_tokens, OAuth2Tokens):
            raise TokenValidationError()
        headers = {"Authorization": f"Bearer {oauth_tokens.access_token}"}
        response = requests.get(self.USER_INFO_URL, headers=headers)
        self._validate_response(response)
        return response.json()

    @staticmethod
    def _store_in_session(request, key: str, value: Any) -> None:
        request.session[key] = value
        request.session.modified = True
        request.session.save()

    @staticmethod
    def _retrieve_from_session(request, key: str) -> Any:
        value = request.session.pop(key, None)
        if not value:
            raise OAuthException(f"Missing session value for key: {key}")
        return value

    def get_token_request_data(
        self, code: str, redirect_uri: str, state: str, request
    ) -> Dict[str, Any]:
        raise NotImplementedError("Subclasses must implement this method.")


class OAuth1ServiceBase(OAuthBase):
    REQUEST_TOKEN_URL: str
    ACCESS_TOKEN_URL: str

    def __init__(self):
        self._credentials = self.get_credentials()

    def get_request_token(self, request) -> Dict[str, str]:
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

        return dict(parse_qsl(response.text))

    def get_access_token(self, oauth_token: str, oauth_verifier: str) -> OAuth1Tokens:
        oauth_params = self._get_oauth1_params()
        oauth_params.update(
            {
                "oauth_token": oauth_token,
                "oauth_verifier": oauth_verifier,
            }
        )
        oauth_params["oauth_signature"] = self._generate_oauth_signature(
            method="POST",
            url=self.ACCESS_TOKEN_URL,
            params=oauth_params,
        )
        headers = {"Authorization": f"OAuth {self._format_oauth_header(oauth_params)}"}
        response = requests.post(self.ACCESS_TOKEN_URL, headers=headers)

        if not response.ok:
            raise OAuthException(f"Failed to obtain access token: {response.text}")

        # Parse the response; typically you’ll get oauth_token and oauth_token_secret
        token_data = dict(parse_qsl(response.text))

        return OAuth1Tokens(
            oauth_token=token_data["oauth_token"],
            oauth_token_secret=token_data["oauth_token_secret"],
            user_id=token_data.get("user_id"),
            screen_name=token_data.get("screen_name"),
        )

    def _get_oauth1_params(self, callback_url: str = "") -> Dict[str, str]:
        return {
            "oauth_consumer_key": self._credentials.client_id,
            "oauth_nonce": base64.b64encode(SystemRandom().randbytes(16)).decode(),
            "oauth_signature_method": "HMAC-SHA1",
            "oauth_timestamp": str(int(time.time())),
            "oauth_version": "1.0",
            "oauth_callback": callback_url,
        }

    def _generate_oauth_signature(self, method: str, url: str, params: Dict[str, str]) -> str:
        sorted_params = "&".join(f"{k}={v}" for k, v in sorted(params.items()))
        base_string = f"{method.upper()}&{quote(url, safe='')}" f"&{quote(sorted_params, safe='')}"
        signing_key = f"{self._credentials.client_secret}&"
        signature = hmac.new(signing_key.encode(), base_string.encode(), hashlib.sha1).digest()
        return base64.b64encode(signature).decode()

    def _format_oauth_header(self, params: Dict[str, str]) -> str:
        return ", ".join(f'{k}="{v}"' for k, v in params.items())
