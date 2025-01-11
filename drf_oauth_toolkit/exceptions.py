from rest_framework.exceptions import APIException


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
