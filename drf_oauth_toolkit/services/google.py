from typing import Any

from drf_oauth_toolkit.services.base import OAuth2ServiceBase
from drf_oauth_toolkit.utils.settings_loader import get_nested_setting
from drf_oauth_toolkit.utils.types import OAuth2Credentials


class GoogleOAuth2Service(OAuth2ServiceBase):
    API_URI_NAME = get_nested_setting(["OAUTH_CREDENTIALS", "google", "callback_url"])
    AUTHORIZATION_URL = "https://accounts.google.com/o/oauth2/auth"
    TOKEN_URL = "https://oauth2.googleapis.com/token"
    USER_INFO_URL = "https://www.googleapis.com/oauth2/v3/userinfo"
    SCOPES = [
        "https://www.googleapis.com/auth/userinfo.email",
        "https://www.googleapis.com/auth/userinfo.profile",
    ]

    def get_credentials(self) -> OAuth2Credentials:
        return OAuth2Credentials(
            client_id=get_nested_setting(["OAUTH_CREDENTIALS", "google", "client_id"]),
            client_secret=get_nested_setting(
                ["OAUTH_CREDENTIALS", "google", "client_secret"]
            ),
        )

    def get_authorization_params(
        self, redirect_uri: str, state: str, request
    ) -> dict[str, Any]:
        return {
            "client_id": self._credentials.client_id,
            "redirect_uri": redirect_uri,
            "response_type": "code",
            "scope": " ".join(self.SCOPES),
            "state": state,
            "access_type": "offline",
            "prompt": "consent",
        }

    def get_token_request_data(
        self, code: str, redirect_uri: str, state: str, request
    ) -> dict[str, Any]:
        return {
            "code": code,
            "client_id": self._credentials.client_id,
            "client_secret": self._credentials.client_secret,
            "redirect_uri": redirect_uri,
            "grant_type": "authorization_code",
        }
