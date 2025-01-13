from drf_oauth_toolkit.models import OAuth2Token, ServiceChoices
from drf_oauth_toolkit.services.google import GoogleOAuthService
from drf_oauth_toolkit.views.base import OAuthCallbackApiBase, OAuthRedirectApiBase


class GoogleOAuthRedirectApi(OAuthRedirectApiBase):
    oauth_service_class = GoogleOAuthService
    session_state_key = "google_oauth_state"


class GoogleOAuthCallbackApi(OAuthCallbackApiBase):
    oauth_service_class = GoogleOAuthService
    session_state_key = "google_oauth_state"
    user_info_email_field = "email"
    user_info_first_name_field = "given_name"
    user_info_last_name_field = "family_name"

    def update_account(self, user, oauth_tokens):
        """
        Delegate token update to the manager for better separation of concerns.
        """
        OAuth2Token.objects.update_or_create_token(
            user=user, service_name=ServiceChoices.GOOGLE, oauth_tokens=oauth_tokens
        )
