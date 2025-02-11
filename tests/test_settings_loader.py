import pytest
from django.test import override_settings

from drf_oauth_toolkit.utils.settings_loader import SettingNotFoundError
from drf_oauth_toolkit.utils.settings_loader import get_nested_setting


def test_get_nested_setting_success():
    """Test successful retrieval of a nested setting."""
    with override_settings(
        OAUTH_CREDENTIALS={
            "host": "https://example.com",
            "google": {
                "client_id": "test-client-id",
                "client_secret": "test-client-secret",
                "redirect_uri": "https://example.com/callback",
            },
        }
    ):
        assert (
            get_nested_setting(["OAUTH_CREDENTIALS", "google", "client_id"])
            == "test-client-id"
        )


def test_get_nested_setting_error():
    """Test exception when a nested setting is missing."""
    with override_settings(OAUTH_CREDENTIALS={}):
        with pytest.raises(SettingNotFoundError):
            get_nested_setting(["OAUTH_CREDENTIALS", "google", "client_id"])


def test_get_nested_setting_default():
    """Test retrieval with a default fallback."""
    with override_settings(OAUTH_CREDENTIALS={}):
        assert (
            get_nested_setting(
                ["OAUTH_CREDENTIALS", "google", "client_id"], default="default-value"
            )
            == "default-value"
        )


def test_get_nested_setting_missing_key():
    """Test missing key returns default."""
    with override_settings(OAUTH_CREDENTIALS={}):
        assert (
            get_nested_setting(
                ["OAUTH_CREDENTIALS", "invalid_key"], default="not-found"
            )
            == "not-found"
        )
