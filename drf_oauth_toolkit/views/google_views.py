from django.contrib.auth import get_user_model

from drf_oauth_toolkit.models import OAuth2Token, ServiceChoices
from drf_oauth_toolkit.services.google import GoogleOAuthService
from drf_oauth_toolkit.views.base import OAuthCallbackApiBase, OAuthRedirectApiBase

User = get_user_model()


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
        Update or create a user account with the given OAuth tokens.
        """
        if user is None:
            user_info = self.oauth_service_class().get_user_info(oauth_tokens=oauth_tokens)

            user = self.create_user_from_oauth(user_info)

        OAuth2Token.objects.update_or_create_token(
            user=user, service_name=ServiceChoices.GOOGLE, oauth_tokens=oauth_tokens
        )

    def create_user_from_oauth(self, user_info):
        """
        Create a new user based on the information retrieved from the OAuth service.
        """
        email = user_info.get(self.user_info_email_field)
        first_name = user_info.get(self.user_info_first_name_field, "")
        last_name = user_info.get(self.user_info_last_name_field, "")

        user, _ = User.objects.get_or_create(
            email=email,
            defaults={
                "first_name": first_name,
                "last_name": last_name,
                "username": email.split("@")[0],
            },
        )
        return user
