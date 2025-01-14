from unittest.mock import Mock, patch

import pytest
from django.http import HttpRequest

from drf_oauth_toolkit.exceptions import OAuthException
from drf_oauth_toolkit.services.base import OAuth2Credentials, OAuth2ServiceBase, OAuth2Tokens


class TestOAuth2ServiceBase:
    @pytest.fixture
    def oauth_service(self):
        class TestOAuthService(OAuth2ServiceBase):
            API_URI_NAME = "test_redirect_uri"
            AUTHORIZATION_URL = "https://example.com/auth"
            TOKEN_URL = "https://example.com/token"

            def get_authorization_url(self, request):
                return self.AUTHORIZATION_URL, "test_state"

            def get_credentials(self):
                return OAuth2Credentials(
                    client_id="test_client_id", client_secret="test_client_secret"
                )

            def get_token_request_data(self, code, redirect_uri, state, request):
                return {"code": code, "redirect_uri": redirect_uri, "state": state}

            def _get_redirect_uri(self) -> str:
                return "https://example.com/test-redirect-uri"

        return TestOAuthService()

    @patch("requests.post")
    @patch(
        "drf_oauth_toolkit.services.base.reverse_lazy",
        return_value="/test-redirect-uri/",
    )
    def test_get_authorization_url(self, mock_post, mock_reverse, oauth_service):
        request = HttpRequest()
        url, state = oauth_service.get_authorization_url(request)

        assert url.startswith("https://example.com/auth")
        assert state

    @patch("requests.post")
    @patch(
        "drf_oauth_toolkit.services.base.reverse_lazy",
        return_value="/test-redirect-uri/",
    )
    def test_get_tokens_success(self, mock_reverse, mock_post, oauth_service):
        mock_post.return_value = Mock(
            ok=True,
            json=lambda: {
                "access_token": "test_access_token",
                "refresh_token": "test_refresh_token",
                "id_token": "test_id_token",
            },
        )
        request = HttpRequest()
        tokens = oauth_service.get_tokens(code="test_code", state="test_state", request=request)
        assert tokens.access_token == "test_access_token"
        assert tokens.refresh_token == "test_refresh_token"
        assert tokens.id_token == "test_id_token"

    @patch("requests.post")
    @patch(
        "drf_oauth_toolkit.services.base.reverse_lazy",
        return_value="/test-redirect-uri/",
    )
    def test_get_tokens_failure(self, mock_reverse, mock_post, oauth_service):
        mock_post.return_value = Mock(ok=False, text="Error occurred")
        request = HttpRequest()
        with pytest.raises(OAuthException):
            oauth_service.get_tokens(code="invalid_code", state="test_state", request=request)

    @patch("requests.post")
    def test_refresh_access_token_success(self, mock_post, oauth_service):
        mock_post.return_value = Mock(ok=True, json=lambda: {"access_token": "new_access_token"})
        tokens = OAuth2Tokens(access_token="expired", refresh_token="valid_refresh_token")
        oauth_service._refresh_access_token(tokens)
        assert tokens.access_token == "new_access_token"

    @patch("requests.post")
    def test_refresh_access_token_failure(self, mock_post, oauth_service):
        mock_post.return_value = Mock(ok=False, text="Error occurred")
        tokens = OAuth2Tokens(access_token="expired", refresh_token="valid_refresh_token")
        with pytest.raises(OAuthException):
            oauth_service._refresh_access_token(tokens)
