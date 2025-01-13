import logging
from random import SystemRandom
from typing import Any, Dict, Optional, Tuple
from urllib.parse import urlencode

import jwt
import requests
from django.urls import reverse_lazy
from oauthlib.common import UNICODE_ASCII_CHARACTER_SET

from drf_oauth_toolkit.exceptions import OAuthException, TokenValidationError
from drf_oauth_toolkit.utils.settings_loader import get_nested_setting

logger = logging.getLogger(__name__)


class OAuthCredentials:
    def __init__(self, client_id: str, client_secret: str) -> None:
        self.client_id = client_id
        self.client_secret = client_secret


class OAuthTokens:
    def __init__(
        self,
        access_token: str,
        refresh_token: Optional[str] = None,
        id_token: Optional[str] = None,
        expires_in: Optional[int] = 90,
    ) -> None:
        self.access_token = access_token
        self.refresh_token = refresh_token
        self.id_token = id_token
        self.expires_in = expires_in

    def decode_id_token(self) -> Dict[str, Any]:
        if not self.id_token:
            return {}
        decoded_token = jwt.decode(jwt=self.id_token, options={"verify_signature": False})
        return decoded_token


class OAuthServiceBase:
    API_URI_NAME: str
    AUTHORIZATION_URL: str
    TOKEN_URL: str
    USER_INFO_URL: str
    SCOPES: list

    def __init__(self):
        self._credentials = self.get_credentials()
        self.API_URI = reverse_lazy(self.API_URI_NAME)

    def get_credentials(self) -> OAuthCredentials:
        raise NotImplementedError("Subclasses must implement this method.")

    @staticmethod
    def _generate_state_session_token(length: int = 30, chars=UNICODE_ASCII_CHARACTER_SET) -> str:
        rand = SystemRandom()
        return "".join(rand.choice(chars) for _ in range(length))

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

    def _get_redirect_uri(self) -> str:
        domain = get_nested_setting(["OAUTH_CREDENTIALS", "host"])
        return f"{domain}{self.API_URI}"

    def get_authorization_url(self, request) -> Tuple[str, str]:
        redirect_uri = self._get_redirect_uri()
        state = self._generate_state_session_token()
        params = self.get_authorization_params(redirect_uri, state, request)
        query_params = urlencode(params)
        authorization_url = f"{self.AUTHORIZATION_URL}?{query_params}"
        return authorization_url, state

    def get_authorization_params(self, redirect_uri: str, state: str, request) -> Dict[str, Any]:
        raise NotImplementedError("Subclasses must implement this method.")

    def get_authorization_headers(self) -> Dict[str, str]:
        return {"Content-Type": "application/x-www-form-urlencoded"}

    def get_tokens(self, *, code: str, state, request) -> OAuthTokens:
        redirect_uri = self._get_redirect_uri()
        data = self.get_token_request_data(code, redirect_uri, state, request)
        headers = self.get_authorization_headers()
        response = requests.post(self.TOKEN_URL, data=data, headers=headers)
        self._validate_response(response)
        return self._parse_token_response(response.json())

    def _parse_token_response(self, response_data: Dict[str, Any]) -> OAuthTokens:
        return OAuthTokens(
            access_token=response_data["access_token"],
            refresh_token=response_data.get("refresh_token"),
            id_token=response_data.get("id_token"),
        )

    def _validate_response(self, response):
        if not response.ok:
            logger.error(f"Token request failed: {response.text}")
            raise OAuthException(f"Error during token request: {response.text}")

    def get_token_request_data(
        self, code: str, redirect_uri: str, state: str, request
    ) -> Dict[str, Any]:
        raise NotImplementedError("Subclasses must implement this method.")

    def _refresh_access_token(self, oauth_tokens: OAuthTokens) -> None:
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

    def get_user_info(self, *, oauth_tokens: OAuthTokens) -> Dict[str, Any]:
        if not self.USER_INFO_URL:
            raise OAuthException("USER_INFO_URL is not defined.")
        headers = {"Authorization": f"Bearer {oauth_tokens.access_token}"}
        response = requests.get(self.USER_INFO_URL, headers=headers)
        self._validate_response(response)
        return response.json()
