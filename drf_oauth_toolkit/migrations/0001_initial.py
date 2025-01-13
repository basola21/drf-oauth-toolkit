import django.db.models.deletion
from django.conf import settings
from django.db import migrations, models

import drf_oauth_toolkit.utils.fields


class Migration(migrations.Migration):
    initial = True

    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.CreateModel(
            name='OAuth2Token',
            fields=[
                (
                    'id',
                    models.BigAutoField(
                        auto_created=True, primary_key=True, serialize=False, verbose_name='ID'
                    ),
                ),
                ('service_name', models.CharField(choices=[('google', 'Google')], max_length=50)),
                ('access_token', drf_oauth_toolkit.utils.fields.EncryptedField(max_length=500)),
                (
                    'refresh_token',
                    drf_oauth_toolkit.utils.fields.EncryptedField(
                        blank=True, max_length=500, null=True
                    ),
                ),
                ('token_expires_at', models.DateTimeField(blank=True, null=True)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('updated_at', models.DateTimeField(auto_now=True)),
                (
                    'user',
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name='oauth2_tokens',
                        to=settings.AUTH_USER_MODEL,
                    ),
                ),
            ],
            options={
                'unique_together': {('user', 'service_name')},
            },
        ),
    ]
