from unittest.mock import Mock, patch

import pytest
from django.http import HttpRequest

from drf_oauth_toolkit.exceptions import OAuthException
from drf_oauth_toolkit.services.base import OAuth1ServiceBase, OAuth2ServiceBase
from drf_oauth_toolkit.utils.types import OAuth2Credentials, OAuth2Tokens


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
        "drf_oauth_toolkit.utils.types.reverse_lazy",
        return_value="/test-redirect-uri/",
    )
    def test_get_authorization_url(self, mock_post, mock_reverse, oauth_service):
        request = HttpRequest()
        url, state = oauth_service.get_authorization_url(request)

        assert url.startswith("https://example.com/auth")
        assert state

    @patch("requests.post")
    @patch(
        "drf_oauth_toolkit.utils.types.reverse_lazy",
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
        "drf_oauth_toolkit.utils.types.reverse_lazy",
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


class TestOAuth1ServiceBase:
    @pytest.fixture
    def oauth1_service(self):
        """
        Example subclass for testing OAuth1ServiceBase.
        You can adapt the credentials, URLs, etc. to match your real implementation.
        """

        class TestOAuth1Service(OAuth1ServiceBase):
            REQUEST_TOKEN_URL = "https://example.com/oauth/request_token"
            ACCESS_TOKEN_URL = "https://example.com/oauth/access_token"

            def get_credentials(self):
                # Return OAuth1-specific credentials
                # e.g. consumer_key, consumer_secret
                # If your actual code uses a specialized class like OAuth1Credentials,
                # return an instance of that instead.
                mock_credentials = Mock()
                mock_credentials.consumer_key = "test_consumer_key"
                mock_credentials.consumer_secret = "test_consumer_secret"
                return mock_credentials

            def _get_redirect_uri(self) -> str:
                # For testing, we'll return a fake callback URI.
                return "https://testserver/callback"

        return TestOAuth1Service()

    @patch("requests.post")
    def test_get_request_token_success(self, mock_post, oauth1_service):
        """
        Test a successful retrieval of request tokens.
        """
        # Mock the response from the OAuth provider
        mock_post.return_value = Mock(
            ok=True,
            text="oauth_token=test_request_token&oauth_token_secret=test_secret&callback_confirmed=true",
        )

        # We assume get_request_token needs a request (like a Django HttpRequest).
        request = HttpRequest()

        token_data = oauth1_service.get_request_token(request)

        assert "oauth_token" in token_data
        assert "oauth_token_secret" in token_data
        assert token_data["oauth_token"] == "test_request_token"
        assert token_data["oauth_token_secret"] == "test_secret"

    @patch("requests.post")
    def test_get_request_token_failure(self, mock_post, oauth1_service):
        """
        Test an error scenario retrieving request tokens.
        """
        mock_post.return_value = Mock(ok=False, text="Error occurred")
        request = HttpRequest()

        with pytest.raises(OAuthException, match="Failed to obtain request token"):
            oauth1_service.get_request_token(request)

    @patch("requests.post")
    def test_get_access_token_success(self, mock_post, oauth1_service):
        """
        Test successfully exchanging a request token + verifier for an access token.
        """
        # Suppose the provider responds with an access token and secret
        mock_post.return_value = Mock(
            ok=True,
            text="oauth_token=test_access_token&oauth_token_secret=test_access_secret&screen_name=TestUser",
        )

        # Typically you'd get 'oauth_token' and 'oauth_verifier' from callback params
        oauth_token = "test_request_token"
        oauth_verifier = "test_verifier"

        access_data = oauth1_service.get_access_token(oauth_token, oauth_verifier)

        assert access_data.oauth_token == "test_access_token"
        assert access_data.oauth_token_secret == "test_access_secret"
        assert access_data.screen_name == "TestUser"

    @patch("requests.post")
    def test_get_access_token_failure(self, mock_post, oauth1_service):
        """
        Test a failure scenario when requesting an access token.
        """
        mock_post.return_value = Mock(ok=False, text="Error occurred")

        with pytest.raises(OAuthException, match="Failed to obtain access token"):
            oauth1_service.get_access_token("invalid_token", "invalid_verifier")
