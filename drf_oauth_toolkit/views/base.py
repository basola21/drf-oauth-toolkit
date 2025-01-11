import logging
from typing import Dict

from django.contrib.auth import get_user_model
from rest_framework import serializers, status
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework_simplejwt.tokens import AccessToken, RefreshToken
from services.base import OAuthServiceBase

from drf_oauth_toolkit.exceptions import CSRFValidationError, OAuthException, TokenValidationError
from drf_oauth_toolkit.utils.commons import PublicApi

logger = logging.getLogger(__name__)

User = get_user_model()


class OAuthRedirectApiBase(APIView):
    oauth_service_class = OAuthServiceBase
    session_state_key = ""
    permission_classes = [IsAuthenticated]

    def get(self, request, *args, **kwargs):
        oauth_service = self.oauth_service_class()
        authorization_url, state = oauth_service.get_authorization_url(request)

        refresh = RefreshToken.for_user(request.user)
        jwt_token = str(refresh.access_token)
        combined_state = self._generate_combined_state(state, jwt_token)

        oauth_service._store_in_session(request, self.session_state_key, combined_state)

        return Response({"authorization_url": authorization_url}, status=status.HTTP_200_OK)

    @staticmethod
    def _generate_combined_state(state, jwt_token):
        return f"{state}:{jwt_token}"


class OAuthCallbackApiBase(PublicApi):
    oauth_service_class = OAuthServiceBase
    session_state_key = ""

    class InputSerializer(serializers.Serializer):
        code = serializers.CharField(required=False)
        state = serializers.CharField(required=False)
        error = serializers.CharField(required=False)

    def update_account(self, user, oauth_tokens):
        raise NotImplementedError("Subclasses must implement this method.")

    def get(self, request, *args, **kwargs):
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
            logger.exception(f"OAuth flow failed.{e}")
            raise OAuthException()

        self.update_account(user, oauth_tokens)

        return self.generate_success_response(user, oauth_tokens)

    def _handle_initial_errors(self, validated_data):
        error = validated_data.get("error")
        if error:
            logger.error(f"OAuth error: {error}")
            return Response({"error": error}, status=status.HTTP_400_BAD_REQUEST)
        return None

    def _validate_state_token(self, request, state):
        session_state = self.oauth_service_class._retrieve_from_session(
            request, self.session_state_key
        )
        state_value, jwt_token = session_state.split(":")
        if state != state_value:
            raise CSRFValidationError()
        return jwt_token

    def _get_user_from_token(self, jwt_token):
        try:
            decoded_token = AccessToken(jwt_token)
            user_id = decoded_token["user_id"]
            return User.objects.get(id=user_id)
        except (User.DoesNotExist, Exception):
            raise TokenValidationError()

    def generate_success_response(self, user, oauth_tokens, **kwargs):
        return Response(
            {
                "access_token": oauth_tokens.access_token,
                "refresh_token": oauth_tokens.refresh_token,
                "user_id": user.id,
                **kwargs,
            },
            status=status.HTTP_200_OK,
        )
