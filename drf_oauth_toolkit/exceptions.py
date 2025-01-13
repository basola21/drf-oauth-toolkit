from rest_framework.exceptions import APIException


class SettingNotFoundError(Exception):
    """
    Exception raised when a required setting is not found.

    Attributes:
        setting_key (str): The missing setting key.
        message (str): Explanation of the error.
    """

    def __init__(self, setting_key: str, message: str = "setting not found"):
        """
        Initialize the SettingNotFoundError with the missing key and optional message.

        Args:
            setting_key (str): The key that was not found in the settings.
            message (str, optional): Custom error message. Defaults to a standard message.
        """
        self.setting_key = setting_key
        self.message = message or f"Required setting '{setting_key}' not found."
        super().__init__(self.message)

    def __str__(self):
        """
        String representation of the error message.
        """
        return f"{self.message} (Key: {self.setting_key})"


class OAuthException(APIException):
    status_code = 400
    default_detail = "An OAuth error occurred."
    default_code = "oauth_error"


class CSRFValidationError(OAuthException):
    status_code = 403
    default_detail = "CSRF validation failed."
    default_code = "csrf_error"


class TokenValidationError(OAuthException):
    status_code = 401
    default_detail = "Invalid or expired token."
    default_code = "token_error"
