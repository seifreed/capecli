"""Tests for capecli.errors."""

from capecli.errors import ApiError, CapeError, ConfigError


def test_api_error_carries_status_code() -> None:
    error = ApiError("boom", status_code=503)
    assert str(error) == "boom"
    assert error.status_code == 503
    assert isinstance(error, CapeError)


def test_api_error_status_code_defaults_to_none() -> None:
    assert ApiError("boom").status_code is None


def test_config_error_is_cape_error() -> None:
    assert isinstance(ConfigError("bad"), CapeError)
