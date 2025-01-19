from unittest.mock import MagicMock, patch

import pytest
from django.contrib.auth import get_user_model
from django.test import RequestFactory, override_settings
from rest_framework.test import APIClient, APIRequestFactory
from rest_framework_simplejwt.tokens import RefreshToken

from drf_oauth_toolkit.models import OAuth2Token, ServiceChoices
from drf_oauth_toolkit.services.google import GoogleOAuth2Service
from drf_oauth_toolkit.views.google_views import GoogleOAuth2CallbackApi, GoogleOAuth2RedirectApi

User = get_user_model()


@pytest.fixture
def api_rf():
    """Provides an instance of DRF's APIRequestFactory for building requests."""
    return APIRequestFactory()


@pytest.fixture
def http_rf():
    """Provides an instance of DRF's APIRequestFactory for building requests."""
    return RequestFactory()


@pytest.fixture
def api_client():
    """Provides an instance of DRF's APIClient for making requests at a higher level."""
    return APIClient()


class TestGoogleOAuth2Service:
    @pytest.fixture
    def google_service(self):
        with override_settings(
            OAUTH_CREDENTIALS={
                "host": "https://example.com",
                "google": {
                    "client_id": "test-client-id",
                    "client_secret": "test-client-secret",
                    "callback_url": "https://example.com/callback",
                },
            }
        ):
            yield GoogleOAuth2Service()

    def test_get_authorization_params(self, google_service):
        service = google_service
        redirect_uri = "https://example.com/callback"
        state = "test_state"
        params = service.get_authorization_params(redirect_uri, state, request=None)
        assert params["client_id"] == service.get_credentials().client_id
        assert params["redirect_uri"] == redirect_uri
        assert " ".join(service.SCOPES) in params["scope"]
        assert params["state"] == state
        assert params["access_type"] == "offline"
        assert params["prompt"] == "consent"

    def test_get_token_request_data(self, google_service):
        service = google_service
        code = "sample_code"
        redirect_uri = "https://example.com/callback"
        data = service.get_token_request_data(code, redirect_uri, state="some_state", request=None)
        assert data["code"] == code
        assert data["client_id"] == service.get_credentials().client_id
        assert data["client_secret"] == service.get_credentials().client_secret
        assert data["redirect_uri"] == redirect_uri
        assert data["grant_type"] == "authorization_code"

    def test_service_constants(self, google_service):
        service = google_service
        assert service.AUTHORIZATION_URL == "https://accounts.google.com/o/oauth2/auth"
        assert service.TOKEN_URL == "https://oauth2.googleapis.com/token"
        assert service.USER_INFO_URL == "https://www.googleapis.com/oauth2/v3/userinfo"
        assert "https://www.googleapis.com/auth/userinfo.email" in service.SCOPES
        assert "https://www.googleapis.com/auth/userinfo.profile" in service.SCOPES


@pytest.mark.django_db
class TestGoogleOAuthRedirectApi:
    @pytest.fixture
    def mock_oauth_service(self):
        """Patch the GoogleOAuth2Service for network isolation."""
        with patch.object(
            GoogleOAuth2RedirectApi, "oauth_service_class", autospec=True
        ) as mock_class:
            instance = mock_class.return_value
            instance.get_authorization_url.return_value = (
                "https://accounts.google.com/o/oauth2/auth",
                "mocked_state",
            )
            yield instance

    def test_authenticated_user_redirect(self, api_rf, mock_oauth_service):
        """Authenticated user should receive a redirect URL with a JWT."""
        user = User.objects.create_user(
            username="testuser", email="testuser@example.com", password="testpass"
        )
        request = api_rf.get("/google-redirect/")
        request.user = user

        view = GoogleOAuth2RedirectApi.as_view()
        response = view(request)

        assert response.status_code == 200
        assert "authorization_url" in response.data
        assert response.data["authorization_url"] == "https://accounts.google.com/o/oauth2/auth"
        mock_oauth_service._store_in_session.assert_called_once()

    def test_unauthenticated_user_redirect(self, api_rf, mock_oauth_service):
        """Unauthenticated user should receive a redirect with `unauthenticated` in state."""
        request = api_rf.get("/google-redirect/")
        request.user = MagicMock(is_authenticated=False)

        view = GoogleOAuth2RedirectApi.as_view()
        response = view(request)

        assert response.status_code == 200
        assert "authorization_url" in response.data
        assert response.data["authorization_url"] == "https://accounts.google.com/o/oauth2/auth"
        mock_oauth_service._store_in_session.assert_called_once()


@pytest.mark.django_db
class TestGoogleOAuth2CallbackApi:
    @pytest.fixture
    def mock_oauth_service(self):
        """Patch the GoogleOAuth2Service for the callback view."""
        with patch.object(
            GoogleOAuth2CallbackApi, "oauth_service_class", autospec=True
        ) as mock_class:
            instance = mock_class.return_value
            instance.get_tokens.return_value = MagicMock(
                access_token="mock_access_token", refresh_token="mock_refresh_token", expires_in=90
            )
            instance.get_user_info.return_value = {
                "email": "newuser@example.com",
                "given_name": "New",
                "family_name": "User",
            }

            instance._retrieve_from_session.return_value = "mocked_state:jwt_token"
            yield instance

    @patch("drf_oauth_toolkit.views.google_views.GoogleOAuth2CallbackApi._validate_state_token")
    @patch("drf_oauth_toolkit.views.google_views.GoogleOAuth2CallbackApi._get_user_from_token")
    def test_callback_success_existing_user(
        self, mock_get_user_from_token, mock_validate_state_token, http_rf, mock_oauth_service
    ):
        """If the user exists, their tokens should be updated."""
        user = User.objects.create_user(username="testuser", email="testuser@example.com")
        access_token = str(RefreshToken.for_user(user).access_token)

        mock_validate_state_token.return_value = access_token
        mock_get_user_from_token.return_value = user

        request = http_rf.get(
            "/google-callback/", {"code": "mock_code", "state": f"mocked_state:{access_token}"}
        )
        request.session = {"google_oauth_state": f"mocked_state:{access_token}"}

        view = GoogleOAuth2CallbackApi.as_view()
        response = view(request)

        assert response.status_code == 200
        mock_oauth_service.get_user_info.assert_not_called()

    @patch("drf_oauth_toolkit.views.google_views.GoogleOAuth2CallbackApi._validate_state_token")
    def test_callback_creates_new_user(
        self,
        mock_validate_state_token,
        api_rf,
        mock_oauth_service,
    ):
        """A new user should be created if they don't exist."""

        mock_validate_state_token.return_value = "unauthenticated"
        request = api_rf.get(
            "/google-callback/", {"code": "mock_code", "state": "mocked_state:unauthenticated"}
        )
        request.session = {"google_oauth_state": "mocked_state:unauthenticated"}
        view = GoogleOAuth2CallbackApi.as_view()
        response = view(request)

        assert response.status_code == 200

        user = User.objects.get(email="newuser@example.com")
        assert user.first_name == "New"
        assert user.last_name == "User"
        assert OAuth2Token.objects.filter(user=user, service_name=ServiceChoices.GOOGLE).exists()

    def test_callback_provider_error(self, api_rf):
        """If Google returns an error, return a 400."""
        request = api_rf.get("/google-callback/", {"error": "access_denied"})
        view = GoogleOAuth2CallbackApi.as_view()
        response = view(request)

        assert response.status_code == 400
        assert response.data["error"] == "access_denied"

    def test_callback_invalid_jwt(self, api_rf, mock_oauth_service):
        """Invalid JWT should return a 401."""
        with patch.object(
            GoogleOAuth2CallbackApi.oauth_service_class,
            "_retrieve_from_session",
            return_value="mocked_state:BAD_JWT_TOKEN",
        ):
            request = api_rf.get(
                "/google-callback/", {"code": "mock_code", "state": "mocked_state"}
            )
            response = GoogleOAuth2CallbackApi.as_view()(request)

        assert response.status_code == 401
        assert "Could not validate JWT token" in response.data["error"]

    def test_callback_unauthenticated_flow_creates_user(self, api_rf, mock_oauth_service):
        """When unauthenticated, a new user should be created."""
        with patch.object(
            GoogleOAuth2CallbackApi.oauth_service_class,
            "_retrieve_from_session",
            return_value="mocked_state:unauthenticated",
        ):
            request = api_rf.get(
                "/google-callback/", {"code": "mock_code", "state": "mocked_state"}
            )
            response = GoogleOAuth2CallbackApi.as_view()(request)

        assert response.status_code == 200
        assert User.objects.filter(email="newuser@example.com").exists()
