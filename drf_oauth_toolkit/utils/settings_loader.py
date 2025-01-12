from typing import Any, Optional

from django.conf import settings

from drf_oauth_toolkit.exceptions import SettingNotFoundError


def get_nested_setting(keys: list[str], default: Optional[Any] = None) -> Any:
    """
    Retrieve a nested setting value from Django settings.

    Args:
        keys (list[str]): A list of keys representing the nested path in the settings dictionary.
        default (Any, optional): A fallback value if the key path is not present.

    Returns:
        Any: The value of the nested setting or the default value.

    Raises:
        SettingNotFoundError: If the setting is not found and no default is provided.
    """
    # Ensure the retrieved value is treated as a dictionary or raises an error early
    value = getattr(settings, keys[0], None)

    if not isinstance(value, (dict, list)):
        raise SettingNotFoundError(
            f"The top-level setting '{keys[0]}' is not a valid nested structure."
        )

    try:
        for key in keys[1:]:
            if isinstance(value, dict):
                value = value[key]
            elif isinstance(value, list) and key.isdigit():
                value = value[int(key)]
            else:
                raise SettingNotFoundError(
                    f"Invalid key '{key}' for the current nested structure."
                )
    except (KeyError, IndexError, TypeError, ValueError):
        if default is None:
            raise SettingNotFoundError(f"Setting path '{' -> '.join(keys)}' not found.")
        return default

    return value
