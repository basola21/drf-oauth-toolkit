# DRF OAuth Toolkit

[![CI Tests](https://github.com/basola21/drf-oauth-toolkit/actions/workflows/test.yml/badge.svg)](https://github.com/basola21/drf-oauth-toolkit/actions/workflows/test.yml)
[![PyPI](https://img.shields.io/pypi/v/drf-oauth-toolkit)](https://pypi.org/project/drf-oauth-toolkit/)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![Python Version](https://img.shields.io/pypi/pyversions/drf-oauth-toolkit)](https://pypi.org/project/drf-oauth-toolkit/)

<p align="center">
  <img src="https://github.com/user-attachments/assets/81bcbcfb-c723-4930-9e20-04073498f7d5" alt="DRF OAuth Toolkit Logo" style="width:100%; max-width:600px;">
</p>

`drf-oauth-toolkit` is a flexible and lightweight OAuth2 integration library for Django Rest Framework (DRF), designed to simplify the process of adding OAuth2 support to your DRF projects.

## 🚀 Features

- ✅ **Plug-and-play OAuth2 integration for DRF**
- ✅ **Supports multiple OAuth providers (Google, Facebook, etc.)**
- ✅ **Built-in token management and CSRF protection**
- ✅ **Customizable and extensible service classes**

---

## 📦 Installation

```bash
pip install drf-oauth-toolkit
```

Add `drf_oauth_toolkit` to your `settings.py`:

```python
INSTALLED_APPS = [
    ...
    "drf_oauth_toolkit",
]
```

---

## 📖 Usage

1. **Configure OAuth credentials** in your Django settings:

```python
OAUTH_CREDENTIALS = {
    "host": "http://127.0.0.1:8000",
    "encryption_key": "Xcub4xIr71H3VR_PxDQdXAT39H9lM9nE2A0GQBg38Xo=",
    "google": {
        "client_id": "your google client id",
        "client_secret": "your google client secert",
        "callback_url": "google-callback",
    },
}
```

2. **Extend the base service class** to integrate a provider:

```python
from drf_oauth_toolkit.views.google_views import GoogleOAuthCallbackApi, GoogleOAuthRedirectApi

urlpatterns = [
    ...
    path("oauth2/google/login", GoogleOAuthRedirectApi.as_view(), name="google-login"),
    path("oauth2/google/callback", GoogleOAuthCallbackApi.as_view(), name="google-callback"), # sure the url name matches the one in the settings
]
```
---

## 🎯 Inspiration

In my experience, OAuth integration has become a standard requirement across modern software projects. Whether you're integrating with Google, Facebook, or other OAuth providers, there are already some outstanding libraries available for Django and Django Rest Framework, such as:

- **[django-oauth-toolkit](https://github.com/jazzband/django-oauth-toolkit)** – A full-featured OAuth2 provider for Django.
- **[social-auth-app-django](https://github.com/python-social-auth/social-app-django)** – A powerful social authentication library supporting multiple providers.
- **[dj-rest-auth](https://github.com/iMerica/dj-rest-auth)** – A drop-in solution for user registration and social authentication.

However, the challenge I aim to solve with **`drf-oauth-toolkit`** is the ease of use and flexibility. Many existing solutions assume a rigid workflow for how you should handle tokens and user management, often leading to challenges when working with DRF or when the library doesn’t align with your token handling requirements.

### ✅ Key Problems Addressed:
- **Complex Setup**: Some libraries require extensive setup with limited flexibility.
- **Token Management Assumptions**: Many solutions assume how tokens should be stored and used, which may not fit every project.
- **DRF Integration**: Some packages aren't well-optimized for Django Rest Framework out of the box.

---

## 🌟 Solution and Design Philosophy

`drf-oauth-toolkit` aims to simplify the OAuth integration process while maintaining full control and flexibility over how tokens are stored, validated, and extended. The core design principle is **customizability** — you can override and extend methods according to your project’s needs.

### Example: Overriding Token Storage Logic

If you simply want to store tokens after a successful OAuth flow, you should not need to do anything, but in case you have a custom user model
you can use something like below example:

```python
from django.contrib.auth import get_user_model

from drf_oauth_toolkit.models import OAuth2Token, ServiceChoices
from drf_oauth_toolkit.services.google import GoogleOAuthService
from drf_oauth_toolkit.views.base import OAuthCallbackApiBase

User = get_user_model()

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
```

---

## 🎯 Extending for Specialized Use Cases

You can easily extend the base service for different OAuth providers. For example, handling **YouTube** OAuth integration:

```python
class YouTubeOAuthService(GoogleOAuthService):
    API_URI_NAME = "youtube_callback"
    SCOPES = [
        "https://www.googleapis.com/auth/youtube.readonly",
        "https://www.googleapis.com/auth/userinfo.email",
    ]

    def fetch_channel_info(self, oauth_tokens: OAuthTokens) -> Dict[str, Any]:
        self._ensure_valid_token(oauth_tokens)
        headers = {"Authorization": f"Bearer {oauth_tokens.access_token}"}
        response = requests.get(
            "https://www.googleapis.com/youtube/v3/channels",
            headers=headers,
            params={"part": "snippet,contentDetails,statistics", "mine": "true"},
        )
        response.raise_for_status()
        return response.json()
```

---

## 🎯 Next Steps and Enhancements
- **Improved Documentation**: Adding more inline code documentation and examples for clarity.
- **Expanded Provider Support**: Adding support for additional OAuth providers like Facebook and Microsoft.
- **Enhanced Token Management**: Providing built-in support for token rotation and expiration handling.


---

## ✅ Running Tests

Run tests using `pytest`:

```bash
pytest
```

---

## 🤝 Contributing

Contributions are welcome! If you'd like to contribute:
- Fork the repository
- Create a feature branch (`git checkout -b feature-branch`)
- Commit your changes (`git commit -m 'Add feature'`)
- Push the branch (`git push origin feature-branch`)
- Open a pull request

For major changes, please open an issue first to discuss your ideas.

---

## 📄 License

This project is licensed under the MIT License. See the [`LICENSE`](./LICENSE) file for more details.

---


## 📫 Contact

For questions and suggestions, feel free to reach out via [GitHub Issues](https://github.com/basola21/drf-oauth-toolkit/issues).

