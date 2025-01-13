from datetime import timedelta

from django.conf import settings
from django.db import models
from django.utils.timezone import now

from drf_oauth_toolkit.utils.fields import EncryptedField


class OAuth2TokenQuerySet(models.QuerySet):
    def active(self):
        return self.filter(token_expires_at__gt=now())

    def expired(self):
        return self.filter(token_expires_at__lte=now())


class OAuth2TokenManager(models.Manager):
    def get_queryset(self):
        return OAuth2TokenQuerySet(self.model, using=self._db)

    def update_or_create_token(self, user, service_name, oauth_tokens):
        """
        Centralized method to update or create a token with expiration handling.
        """
        token_expires_at = now() + timedelta(seconds=oauth_tokens.expires_in)
        return self.update_or_create(
            user=user,
            service_name=service_name,
            defaults={
                "access_token": oauth_tokens.access_token,
                "refresh_token": oauth_tokens.refresh_token,
                "token_expires_at": token_expires_at,
            },
        )


class ServiceChoices(models.TextChoices):
    GOOGLE = "google", "Google"


class OAuth2Token(models.Model):
    """
    A unified token model that can store OAuth2 tokens for multiple services,
    using extendable choices.
    """

    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="oauth2_tokens",
    )
    service_name = models.CharField(max_length=50, choices=ServiceChoices.choices)
    access_token = EncryptedField(max_length=500)
    refresh_token = EncryptedField(max_length=500, null=True, blank=True)
    token_expires_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    objects = OAuth2TokenManager()

    class Meta:
        unique_together = ("user", "service_name")

    def save(self, *args, **kwargs):
        """
        Automatically set token expiration if we have a refresh_token.
        """
        if self.refresh_token and not self.token_expires_at:
            self.token_expires_at = now() + timedelta(days=90)
        super().save(*args, **kwargs)

    def is_token_valid(self) -> bool:
        """Check if the token is still valid."""
        return now() < self.token_expires_at

    def __str__(self):
        return f"{self.user} - {self.service_name} Token"
