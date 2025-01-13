from unittest.mock import MagicMock, patch

import pytest
from django.contrib.auth import get_user_model
from rest_framework.test import APIClient, APIRequestFactory
from rest_framework_simplejwt.tokens import RefreshToken

from drf_oauth_toolkit.views.base import OAuthCallbackApiBase, OAuthRedirectApiBase

User = get_user_model()


@pytest.fixture
def api_rf():
    """
    Provides an instance of DRF's APIRequestFactory for building requests.
    """
    return APIRequestFactory()


@pytest.fixture
def api_client():
    """
    Provides an instance of DRF's APIClient for making requests at a higher level.
    """
    return APIClient()


@pytest.mark.django_db
class TestOAuthRedirectApiBase:
    @pytest.fixture
    def mock_oauth_service(self):
        """
        Patch the oauth_service_class so we don't do real network calls.
        """
        with patch.object(
            OAuthRedirectApiBase, 'oauth_service_class', autospec=True
        ) as mock_class:
            instance = mock_class.return_value
            instance.get_authorization_url.return_value = (
                "https://provider.com/oauth/authorize",  # Mocked provider URL
                "mocked_state",
            )
            yield instance

    def test_authenticated_user_redirect(self, api_rf, mock_oauth_service):
        """
        If the user is authenticated, the redirect flow should include
        a valid JWT in the combined state.
        """

        class MyRedirectView(OAuthRedirectApiBase):
            session_state_key = "test_redirect_state"

        # Create a user and authenticate the request
        user = User.objects.create_user(
            username="testuser", email="test@example.com", password="pass"
        )

        request = api_rf.get("/fake-redirect/")
        request.user = user  # Simulate authenticated user

        view = MyRedirectView.as_view()
        response = view(request)

        assert response.status_code == 200
        data = response.data
        assert "authorization_url" in data
        assert data["authorization_url"] == "https://provider.com/oauth/authorize"

        # Check that state was stored in session (the base class uses
        # _store_in_session, but to test thoroughly you might need
        # to mock session or see if the call was made).
        mock_oauth_service._store_in_session.assert_called_once()

        # Extract the state we passed to _store_in_session
        args, kwargs = mock_oauth_service._store_in_session.call_args
        request_arg, key_arg, combined_state_arg = args
        assert key_arg == "test_redirect_state"
        assert ":" in combined_state_arg  # e.g. "mocked_state:<JWT>"

    def test_unauthenticated_user_redirect(self, api_rf, mock_oauth_service):
        """
        If the user is not authenticated, we store `unauthenticated` in place of the JWT.
        """

        class MyRedirectView(OAuthRedirectApiBase):
            session_state_key = "test_redirect_state"

        request = api_rf.get("/fake-redirect/")
        request.user = MagicMock(is_authenticated=False)  # Unauthenticated

        view = MyRedirectView.as_view()
        response = view(request)

        assert response.status_code == 200
        data = response.data
        assert "authorization_url" in data
        assert data["authorization_url"] == "https://provider.com/oauth/authorize"

        # Check state storage
        mock_oauth_service._store_in_session.assert_called_once()
        args, kwargs = mock_oauth_service._store_in_session.call_args
        _, _, combined_state_arg = args
        # Should end with "unauthenticated" if the user isn't logged in
        assert combined_state_arg == "mocked_state:unauthenticated"


@pytest.mark.django_db
class TestOAuthCallbackApiBase:
    @pytest.fixture
    def mock_oauth_service(self):
        """
        Patch the oauth_service_class on the Callback Base.
        """
        with patch.object(
            OAuthCallbackApiBase, 'oauth_service_class', autospec=True
        ) as mock_class:
            instance = mock_class.return_value
            instance.get_tokens.return_value = MagicMock(
                access_token="mock_access_token", refresh_token="mock_refresh_token"
            )
            yield instance

    def test_callback_no_error_and_valid_state(self, api_rf, mock_oauth_service):
        """
        If no error, a valid code/state is provided, and the user
        can be retrieved from the JWT => success.
        """

        class MyCallbackView(OAuthCallbackApiBase):
            session_state_key = "test_callback_state"

            def update_account(self, user, oauth_tokens):
                user.oauth_access_token = oauth_tokens.access_token
                user.save()

        # Create a user and a valid JWT
        user = User.objects.create_user(username="testuser")
        refresh = RefreshToken.for_user(user)
        combined_state = f"mocked_state:{refresh.access_token}"

        # Mock session data retrieval
        with patch.object(
            MyCallbackView.oauth_service_class,
            '_retrieve_from_session',
            return_value=combined_state,
        ):
            request = api_rf.get(
                "/fake-callback/",
                {"code": "mocked_code", "state": "mocked_state"},
            )

            response = MyCallbackView.as_view()(request)

        assert response.status_code == 200
        assert response.data["access_token"] == "mock_access_token"
        assert response.data["refresh_token"] == "mock_refresh_token"
        assert response.data["user_id"] == user.id

    def test_callback_provider_error(self, api_rf, mock_oauth_service):
        """
        If the provider returns an error param in the callback, we immediately
        return a 400 error.
        """

        class MyCallbackView(OAuthCallbackApiBase):
            def update_account(self, user, oauth_tokens):
                pass  # Not reached in this scenario

        request = api_rf.get("/fake-callback/", {"error": "some_oauth_error"})
        response = MyCallbackView.as_view()(request)
        assert response.status_code == 400
        assert response.data["error"] == "some_oauth_error"

    def test_callback_invalid_csrf_state(self, api_rf, mock_oauth_service):
        """
        If the stored state doesn't match the one from the query, we raise CSRFValidationError.
        """

        class MyCallbackView(OAuthCallbackApiBase):
            session_state_key = "test_callback_state"

            def update_account(self, user, oauth_tokens):
                pass

        # We'll store a different state in session than the one provided
        with patch.object(
            MyCallbackView.oauth_service_class,
            '_retrieve_from_session',
            return_value="other_state:some_jwt",
        ):
            request = api_rf.get(
                "/fake-callback/", {"code": "mocked_code", "state": "mismatch_state"}
            )
            response = MyCallbackView.as_view()(request)
            # We expect a 403 or similar
            assert response.status_code == 403
            assert "Invalid CSRF token" in response.data["error"]

    def test_callback_invalid_jwt(self, api_rf, mock_oauth_service):
        """
        If the JWT in the combined state is invalid (or user doesn't exist),
        we raise a TokenValidationError => 401 by default in the example code.
        """

        class MyCallbackView(OAuthCallbackApiBase):
            session_state_key = "test_callback_state"

            def update_account(self, user, oauth_tokens):
                pass

        # Combined state has a bogus JWT
        with patch.object(
            MyCallbackView.oauth_service_class,
            '_retrieve_from_session',
            return_value="mocked_state:BAD_JWT_TOKEN",
        ):
            request = api_rf.get(
                "/fake-callback/", {"code": "mocked_code", "state": "mocked_state"}
            )
            response = MyCallbackView.as_view()(request)

        assert response.status_code == 401
        assert "Could not validate JWT token" in response.data["error"]

    def test_callback_unauthenticated_jwt_creates_none_user(self, api_rf, mock_oauth_service):
        """
        If the combined state says `unauthenticated`, the retrieved user is None,
        and we can handle that in update_account (e.g., create a new user).
        """

        class MyCallbackView(OAuthCallbackApiBase):
            session_state_key = "test_callback_state"

            def update_account(self, user, oauth_tokens):
                # In real usage, you might create a new user or do something else
                assert user is None, "Expected user=None for unauthenticated flow"

        with patch.object(
            MyCallbackView.oauth_service_class,
            '_retrieve_from_session',
            return_value="mocked_state:unauthenticated",
        ):
            request = api_rf.get(
                "/fake-callback/", {"code": "mocked_code", "state": "mocked_state"}
            )
            response = MyCallbackView.as_view()(request)

        # We still respond 200 if everything else is good
        assert response.status_code == 200
        data = response.data
        assert data["access_token"] == "mock_access_token"
        assert data["refresh_token"] == "mock_refresh_token"
        # user_id should be None because user is None
        assert data["user_id"] is None
