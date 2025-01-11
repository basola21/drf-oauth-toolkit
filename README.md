
# DRF OAuth Toolkit

`drf-oauth-toolkit` is a flexible OAuth2 integration library for Django Rest Framework (DRF).

## Features
- Plug-and-play OAuth2 integration for DRF
- Supports multiple OAuth providers
- Built-in token management and CSRF protection

## Installation
```bash
pip install drf-oauth-toolkit
```

## Usage
1. Add `drf_oauth_toolkit` to `INSTALLED_APPS` in your `settings.py`.
2. Configure OAuth credentials in your Django settings.
3. Import and extend the base `OAuthServiceBase` class for your desired OAuth provider.

```python
from drf_oauth_toolkit.services.base import OAuthServiceBase

class GoogleOAuthService(OAuthServiceBase):
    API_URI_NAME = "google_redirect"
    AUTHORIZATION_URL = "https://accounts.google.com/o/oauth2/auth"
    TOKEN_URL = "https://oauth2.googleapis.com/token"
    USER_INFO_URL = "https://www.googleapis.com/oauth2/v3/userinfo"
    SCOPES = ["openid", "email", "profile"]
```

## Running Tests
```bash
pytest
```

## Contributing
Pull requests are welcome. For major changes, please open an issue first.

## License
MIT License. See `LICENSE` for more information.

