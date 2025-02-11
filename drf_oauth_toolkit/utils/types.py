from dataclasses import dataclass
from typing import Any

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
    user_id: str | None = None
    screen_name: str | None = None


@dataclass
class OAuth2Tokens:
    access_token: str
    refresh_token: str | None = None
    id_token: str | None = None
    expires_in: int | None = 90

    def decode_id_token(self) -> dict[str, Any]:
        if not self.id_token:
            return {}
        return jwt.decode(jwt=self.id_token, options={"verify_signature": False})


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

    def get_authorization_params(
        self, redirect_uri: str, state: str, request
    ) -> dict[str, Any]:
        raise NotImplementedError("Subclasses must implement this method.")

    def get_credentials(self):
        raise NotImplementedError("Subclasses must implement this method.")

    def get_tokens(self, *, code: str, state, request):
        raise NotImplementedError

    def get_user_info(
        self, *, oauth_tokens: OAuth1Tokens | OAuth2Tokens
    ) -> dict[str, Any]:
        raise NotImplementedError
