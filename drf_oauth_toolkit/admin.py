from django.contrib import admin

from drf_oauth_toolkit.models import OAuth2Token


@admin.register(OAuth2Token)
class OAuth2TokenAdmin(admin.ModelAdmin):
    """
    Admin panel for managing OAuth2 tokens. For security, you may wish
    to exclude tokens from being directly editable and only display them
    for debugging or development environments.
    """

    list_display = (
        "user",
        "service_name",
        "is_token_valid",
        "token_expires_at",
        "created_at",
        "updated_at",
    )
    list_filter = ("service_name", "created_at", "updated_at")
    search_fields = ("user__email",)

    readonly_fields = ("access_token", "refresh_token")

    @admin.display(boolean=True, description="Is Token Valid?")
    def is_token_valid(self, obj):
        return obj.is_token_valid()
