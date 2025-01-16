Usage
=====

1. Configure OAuth2 Credentials
-------------------------------

Add your OAuth provider credentials in `settings.py`:

.. code-block:: python

    OAUTH_PROVIDERS = {
        'google': {
            'client_id': '<your-client-id>',
            'client_secret': '<your-client-secret>',
            'redirect_uri': 'https://your-app.com/oauth2/callback',
        },
    }

2. Integrate OAuth2 with Your API
---------------------------------

Use the provided views and serializers to set up OAuth endpoints:

.. code-block:: python

    from drf_oauth_toolkit.views import OAuth2TokenView

    urlpatterns = [
        ...
        path('oauth2/token/', OAuth2TokenView.as_view(), name='oauth2_token'),
    ]
