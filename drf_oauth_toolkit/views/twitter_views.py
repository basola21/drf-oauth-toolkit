from django.contrib.auth import get_user_model

from drf_oauth_toolkit.models import OAuth2Token, ServiceChoices
from drf_oauth_toolkit.services.twitter import TwitterOAuth2Service
from drf_oauth_toolkit.views.base import OAuth2CallbackApiBase, OAuth2RedirectApiBase

User = get_user_model()


class TwitterOAuth2RedirectApi(OAuth2RedirectApiBase):
    oauth_service_class = TwitterOAuth2Service
    session_state_key = 'twitter_oauth2_state'


class TwitterOAuth2CallbackApi(OAuth2CallbackApiBase):
    oauth_service_class = TwitterOAuth2Service
    session_state_key = "twitter_oauth2_state"

    user_info_first_name_field = "name"
    user_info_email_field = "email"

    def update_account(self, user, oauth_tokens):
        """
        Update or create a user account with the given OAuth tokens.
        """
        user_info = self.oauth_service_class().get_user_info(oauth_tokens=oauth_tokens)["data"]

        if user is None:
            user = self.create_user_from_oauth(user_info)
        else:
            user.name = user_info.get("name", user.name)
            user.username = user_info.get("username", user.username)
            user.save()

        OAuth2Token.objects.update_or_create_token(
            user=user, service_name=ServiceChoices.TWITTER, oauth_tokens=oauth_tokens
        )
        return user

    def create_user_from_oauth(self, user_info):
        """
        Create a new user based on the information retrieved from the OAuth service.
        """

        name = user_info.get("name", "").split(" ", 1)
        first_name = name[0] if name else ""
        last_name = name[1] if len(name) > 1 else ""
        username = user_info.get("username", None)
        id = user_info.get("id")

        # Fallback email logic since Twitter requires oauth1a for email
        email = f"{id}@twitter.com"

        user, _ = User.objects.get_or_create(
            username=username,
            defaults={
                "first_name": first_name,
                "last_name": last_name,
                "email": email,
            },
        )
        return user
