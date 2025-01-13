from cryptography.fernet import Fernet
from django.db import models

from drf_oauth_toolkit.utils.settings_loader import get_nested_setting

ENCRYPTION_KEY = get_nested_setting(["OAUTH_CREDENTIALS", "encryption_key"])

fernet = Fernet(ENCRYPTION_KEY)


class EncryptedField(models.TextField):
    """
    A custom TextField that transparently encrypts and decrypts data using Fernet.
    Compatible with existing unencrypted values for backward compatibility.
    """

    def __init__(self, *args, **kwargs):
        self.fernet = fernet
        super().__init__(*args, **kwargs)

    def get_prep_value(self, value):
        """
        Encrypt the value before saving to the database.
        If the value is already encrypted, do not re-encrypt.
        """
        if value is None:
            return value

        try:
            self.fernet.decrypt(value.encode())
            return value
        except Exception:
            return self.fernet.encrypt(value.encode()).decode()

    def from_db_value(self, value, expression, connection):
        """
        Decrypt the value when loading from the database.
        If the value is unencrypted, return it as-is for backward compatibility.
        """
        if value is None:
            return value

        try:
            # Decrypt the value
            return self.fernet.decrypt(value.encode()).decode()
        except Exception:
            # Return unencrypted value as-is (for backward compatibility)
            return value

    def to_python(self, value):
        """
        Ensure the field is always returned in a decrypted form.
        """
        return self.from_db_value(value, None, None)
