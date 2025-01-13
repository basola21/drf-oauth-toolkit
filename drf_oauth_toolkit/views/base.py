import logging
from typing import Dict

from django.contrib.auth import get_user_model
from rest_framework import serializers, status
from rest_framework.response import Response
from rest_framework_simplejwt.tokens import AccessToken, RefreshToken

from drf_oauth_toolkit.exceptions import CSRFValidationError, OAuthException, TokenValidationError
from drf_oauth_toolkit.services.base import OAuthServiceBase
from drf_oauth_toolkit.utils.commons import PublicApi

logger = logging.getLogger(__name__)

User = get_user_model()


class OAuthRedirectApiBase(PublicApi):
    """
    Handles the 'redirect' part of the OAuth flow:
      1. Get the authorization URL from the OAuth provider
      2. Store state in the session
      3. Return the URL for the front-end to redirect the user
    """

    oauth_service_class = OAuthServiceBase
    session_state_key = ""

    def get_authorization_url(self, request):
        """
        Subclass can override if it needs special parameters.
        By default, calls the service's get_authorization_url.
        """
        oauth_service = self.oauth_service_class()
        return oauth_service.get_authorization_url(request)

    def store_state_in_session(self, request, state):
        """
        Subclass can override to customize how state is stored in session.
        """
        oauth_service = self.oauth_service_class()
        oauth_service._store_in_session(request, self.session_state_key, state)

    def build_state_value(self, request, state: str) -> str:
        """
        By default, we generate a JWT token from the current user (if any)
        and combine it with the state so we can later verify it on callback.
        """
        if request.user.is_authenticated:
            refresh = RefreshToken.for_user(request.user)
            jwt_token = str(refresh.access_token)
        else:
            # For example, if no user is logged in, we store some placeholder.
            jwt_token = "unauthenticated"
        return f"{state}:{jwt_token}"

    def get(self, request, *args, **kwargs):
        """
        Main GET handler:
          1. Get (authorization_url, state)
          2. Build new combined_state
          3. Store in session
          4. Return the authorization URL
        """
        authorization_url, state = self.get_authorization_url(request)
        combined_state = self.build_state_value(request, state)

        self.store_state_in_session(request, combined_state)

        return Response({"authorization_url": authorization_url}, status=status.HTTP_200_OK)


class OAuthCallbackApiBase(PublicApi):
    """
    Handles the 'callback' part of the OAuth flow:
      1. Receives provider's callback (with code & state or possibly an error).
      2. Verifies the state from session & extracts a JWT to identify the user.
      3. Exchanges the code for tokens.
      4. Calls `update_account` so subclass can do something with these tokens.
      5. Returns a success response (with tokens, user data, etc.)
    """

    oauth_service_class = OAuthServiceBase
    session_state_key = ""

    class InputSerializer(serializers.Serializer):
        code = serializers.CharField(required=False)
        state = serializers.CharField(required=False)
        error = serializers.CharField(required=False)

    def update_account(self, user, oauth_tokens):
        """
        Subclasses must override:
          - Possibly link this OAuth account to the user
          - Or create a new user if not already authenticated
        """
        raise NotImplementedError("Subclasses must implement this method.")

    def handle_callback_error(self, error):
        """
        Subclass hook if you want custom error handling or logging.
        """
        logger.error(f"OAuth error: {error}")
        return Response({"error": error}, status=status.HTTP_400_BAD_REQUEST)

    def get(self, request, *args, **kwargs):
        """
        Main GET handler for OAuth callback.
        """
        input_serializer = self.InputSerializer(data=request.GET)
        input_serializer.is_valid(raise_exception=True)
        validated_data: Dict = input_serializer.validated_data

        error_response = self._handle_initial_errors(validated_data)
        if error_response:
            return error_response

        state, code = validated_data.get("state"), validated_data.get("code")

        try:
            jwt_token = self._validate_state_token(request, state)
            user = self._get_user_from_token(jwt_token)
        except (CSRFValidationError, TokenValidationError) as e:
            return Response({"error": str(e)}, status=e.status_code)

        oauth_service = self.oauth_service_class()
        try:
            oauth_tokens = oauth_service.get_tokens(code=code, state=state, request=request)
        except Exception as e:
            logger.exception(f"OAuth flow failed: {e}")
            raise OAuthException()

        user = self.update_account(user, oauth_tokens)

        return self.generate_success_response(user, oauth_tokens)

    def _handle_initial_errors(self, validated_data):
        """
        Check if the provider returned an error, e.g. user denied permission.
        """
        error = validated_data.get("error")
        if error:
            return self.handle_callback_error(error)
        return None

    def _validate_state_token(self, request, state):
        """
        Retrieve the combined state from session, then compare & extract the JWT.
        """
        session_state = self.oauth_service_class._retrieve_from_session(
            request, self.session_state_key
        )
        state_value, jwt_token = session_state.split(":")
        if state != state_value:
            raise CSRFValidationError("Invalid CSRF token in state parameter.")
        return jwt_token

    def _get_user_from_token(self, jwt_token):
        """
        If the stored JWT was "unauthenticated" or is invalid, handle that case.
        Otherwise decode the token and retrieve the user.
        """
        if jwt_token == "unauthenticated":
            # Means no user was logged in at the time of redirect.
            return None
        try:
            decoded_token = AccessToken(jwt_token)
            user_id = decoded_token["user_id"]
            return User.objects.get(id=user_id)
        except (User.DoesNotExist, Exception):
            raise TokenValidationError("Could not validate JWT token to retrieve user.")

    def generate_success_response(self, user, oauth_tokens, **kwargs):
        """
        Construct your own success payload for the front-end.
        """
        return Response(
            {
                "access_token": oauth_tokens.access_token,
                "refresh_token": oauth_tokens.refresh_token,
                "user_id": user.id if user else None,
                **kwargs,
            },
            status=status.HTTP_200_OK,
        )
