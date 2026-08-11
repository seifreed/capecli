"""Exceptions raised by capecli."""


class CapeError(Exception):
    """Base error for capecli."""


class ConfigError(CapeError):
    """Raised when configuration is missing or invalid."""


class ApiError(CapeError):
    """Raised when the CAPE API returns an error response."""

    def __init__(self, message: str, status_code: int | None = None) -> None:
        super().__init__(message)
        self.status_code = status_code
