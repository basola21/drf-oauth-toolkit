import secrets
from datetime import timedelta

import pytest
from django.db import models
from django.db.utils import IntegrityError
from django.utils.timezone import now
from model_bakery import baker

from drf_oauth_toolkit.models import OAuth2Token
from drf_oauth_toolkit.models import ServiceChoices
from drf_oauth_toolkit.utils.types import OAuth2Tokens


def gen_random_access_token():
    """
    Generates a secure random access token.
    """
    return secrets.token_urlsafe(32)


baker.generators.add(
    "drf_oauth_toolkit.utils.fields.EncryptedField", gen_random_access_token
)


@pytest.mark.django_db
class TestModelOauth2Token:
    @pytest.fixture
    def instance(self) -> OAuth2Token:
        """Fixture to create a test instance of OAuth2Token."""
        return baker.make(OAuth2Token)

    def test_issubclass_model(self) -> None:
        """Ensure the model is a subclass of Django's base model."""
        assert issubclass(OAuth2Token, models.Model)

    def test_has_all_attributes(self, instance):
        """Check all model attributes exist."""
        assert hasattr(instance, "user")
        assert hasattr(instance, "service_name")
        assert hasattr(instance, "access_token")
        assert hasattr(instance, "refresh_token")
        assert hasattr(instance, "token_expires_at")
        assert hasattr(instance, "created_at")
        assert hasattr(instance, "updated_at")

    def test_token_creation(self):
        token = baker.make(OAuth2Token, token_expires_at=now() + timedelta(days=1))
        assert token.is_token_valid() is True

    def test_token_expiry(self):
        token = baker.make(OAuth2Token, token_expires_at=now() - timedelta(days=1))
        assert token.is_token_valid() is False

    def test_update_or_create_token(self):
        user = baker.make("auth.User")
        token_data = OAuth2Tokens(
            gen_random_access_token(), gen_random_access_token(), expires_in=80
        )
        token = OAuth2Token.objects.update_or_create_token(
            user=user, service_name=ServiceChoices.GOOGLE, oauth_tokens=token_data
        )
        assert token[0].user == user
        assert token[0].service_name == ServiceChoices.GOOGLE

    def test_unique_together_constraint(self):
        user = baker.make("auth.User")
        baker.make(OAuth2Token, user=user, service_name="google")
        with pytest.raises(IntegrityError):
            baker.make(OAuth2Token, user=user, service_name="google")

    def test_encrypted_field(self):
        token = baker.make(OAuth2Token, access_token="sensitive_data")
        token.refresh_from_db()
        assert token.access_token == "sensitive_data"

    def test_expired_queryset(self):
        baker.make(OAuth2Token, token_expires_at=now() - timedelta(days=1))
        assert OAuth2Token.objects.get_queryset().expired().count() == 1

    def test_active_queryset(self):
        baker.make(OAuth2Token, token_expires_at=now() + timedelta(days=1))
        assert OAuth2Token.objects.get_queryset().active().count() == 1
