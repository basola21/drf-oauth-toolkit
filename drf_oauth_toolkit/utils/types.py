from dataclasses import dataclass
from typing import Any, Dict, Optional

import jwt
from django.urls import reverse_lazy

from drf_oauth_toolkit.utils.settings_loader import get_nested_setting


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
