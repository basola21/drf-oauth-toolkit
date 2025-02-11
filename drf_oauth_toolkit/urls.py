from typing import Any

from django.urls import path

from drf_oauth_toolkit.views import google_views
from drf_oauth_toolkit.views import twitter_views

# Google OAuth2 URLs
google_urls: list[Any] = [
    path(
        "auth/oauth2/google/redirect/",
        google_views.GoogleOAuth2RedirectApi.as_view(),
        name="google_redirect",
    ),
    path(
        "auth/oauth2/google/callback/",
        google_views.GoogleOAuth2CallbackApi.as_view(),
        name="google_callback",
    ),
]

# Twitter OAuth2 URLs
twitter_urls: list[Any] = [
    path(
        "auth/oauth2/twitter/redirect/",
        twitter_views.TwitterOAuth2RedirectApi.as_view(),
        name="twitter_redirect",
    ),
    path(
        "auth/oauth2/twitter/callback/",
        twitter_views.TwitterOAuth2CallbackApi.as_view(),
        name="twitter_callback",
    ),
]

urlpatterns: list[Any] = google_urls + twitter_urls
