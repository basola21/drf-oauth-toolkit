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
    "google": {
        "client_id": "your-client-id",
        "client_secret": "your-client-secret",
        "redirect_uri": "https://yourapp.com/callback",
    }
}
```

2. **Extend the base service class** to integrate a provider:

```python
from drf_oauth_toolkit.services.base import OAuthServiceBase

class GoogleOAuthService(OAuthServiceBase):
    API_URI_NAME = "google_redirect"
    AUTHORIZATION_URL = "https://accounts.google.com/o/oauth2/auth"
    TOKEN_URL = "https://oauth2.googleapis.com/token"
    USER_INFO_URL = "https://www.googleapis.com/oauth2/v3/userinfo"
    SCOPES = ["openid", "email", "profile"]
```

3. **Use the service in your views:**

```python
from drf_oauth_toolkit.services.google import GoogleOAuthService

def google_login(request):
    service = GoogleOAuthService()
    redirect_url = service.get_authorization_url()
    return redirect(redirect_url)
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

If you simply want to store tokens after a successful OAuth flow, you can override the base methods like this:

```python
from typing import Any, Dict
import requests
from django.conf import settings
from utils.base_oauth import OAuthCredentials, OAuthServiceBase, OAuthTokens

class GoogleOAuthService(OAuthServiceBase):
    API_URI_NAME = "google_oauth_callback"
    AUTHORIZATION_URL = "https://accounts.google.com/o/oauth2/auth"
    TOKEN_URL = "https://oauth2.googleapis.com/token"
    SCOPES = ["https://www.googleapis.com/auth/userinfo.email"]

    def get_credentials(self) -> OAuthCredentials:
        return OAuthCredentials(
            client_id=settings.GOOGLE_CLIENT_ID,
            client_secret=settings.GOOGLE_CLIENT_SECRET
        )

    def get_token_request_data(self, code: str, redirect_uri: str, state: str, request) -> Dict[str, Any]:
        return {
            "code": code,
            "client_id": self._credentials.client_id,
            "client_secret": self._credentials.client_secret,
            "redirect_uri": redirect_uri,
            "grant_type": "authorization_code"
        }
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

## 📊 Flexible View Example

The flexibility extends to how views handle token management and user updates. Here's a `GoogleOAuthCallbackApi` class that handles token saving after authentication:

```python
from rest_framework.viewsets import GenericViewSet
from utils.base_oath_view import OAuthCallbackApiBase
from .models import OAuth2Token
from .services import GoogleOAuthService

class GoogleOAuthCallbackApi(OAuthCallbackApiBase):
    oauth_service_class = GoogleOAuthService
    session_state_key = "google_oauth_state"

    def update_account(self, user, user_info, oauth_tokens):
        OAuth2Token.objects.update_or_create(
            user=user,
            service_name="google",
            defaults={
                "access_token": oauth_tokens.access_token,
                "refresh_token": oauth_tokens.refresh_token,
            },
        )
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

