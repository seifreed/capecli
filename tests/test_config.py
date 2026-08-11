"""Tests for capecli.config."""

import os
from pathlib import Path

import pytest

from capecli.config import (
    DEFAULT_TIMEOUT,
    Config,
    default_search_paths,
    load_config,
)
from capecli.errors import ConfigError

ENV_OVERRIDES = {
    "CAPECLI_URL": "http://env",
    "CAPECLI_TOKEN": "env-token",
    "CAPECLI_TIMEOUT": "15",
}


def write_config(path: Path, content: str) -> Path:
    path.write_text(content, encoding="utf-8")
    return path


@pytest.fixture
def no_config_file(tmp_path: Path) -> list[Path]:
    """Search paths that resolve to no config file at all."""
    return [tmp_path / "missing.toml"]


def test_load_from_file(tmp_path: Path) -> None:
    config_file = write_config(
        tmp_path / "capecli.toml",
        'url = "http://cape.local/"\ntoken = "abc"\ntimeout = 30\n',
    )
    config = load_config(env={}, search_paths=[config_file])
    assert config == Config(url="http://cape.local", token="abc", timeout=30.0)


def test_first_existing_file_wins(tmp_path: Path) -> None:
    missing = tmp_path / "missing.toml"
    second = write_config(tmp_path / "second.toml", 'url = "http://second"\n')
    config = load_config(env={}, search_paths=[missing, second])
    assert config.url == "http://second"


def test_env_overrides_file(tmp_path: Path) -> None:
    config_file = write_config(
        tmp_path / "capecli.toml",
        'url = "http://file"\ntoken = "file-token"\ntimeout = 30\n',
    )
    config = load_config(env=ENV_OVERRIDES, search_paths=[config_file])
    assert config == Config(url="http://env", token="env-token", timeout=15.0)


def test_explicit_arguments_override_env(no_config_file: list[Path]) -> None:
    config = load_config(
        url="http://arg",
        token="arg-token",
        timeout=5.0,
        env=ENV_OVERRIDES,
        search_paths=no_config_file,
    )
    assert config == Config(url="http://arg", token="arg-token", timeout=5.0)


def test_defaults_without_token_and_timeout(no_config_file: list[Path]) -> None:
    config = load_config(
        env={"CAPECLI_URL": "http://cape"}, search_paths=no_config_file
    )
    assert config.token is None
    assert config.timeout == DEFAULT_TIMEOUT


def test_missing_url_raises(no_config_file: list[Path]) -> None:
    with pytest.raises(ConfigError, match="CAPE URL not configured"):
        load_config(env={}, search_paths=no_config_file)


@pytest.mark.parametrize("raw_timeout", ["-5", "0", "nan", "inf"])
def test_unusable_timeout_raises(no_config_file: list[Path], raw_timeout: str) -> None:
    """Zero, negative and non-finite timeouts are all rejected up front."""
    with pytest.raises(ConfigError, match="Timeout must be a finite number"):
        load_config(
            env={"CAPECLI_URL": "http://cape", "CAPECLI_TIMEOUT": raw_timeout},
            search_paths=no_config_file,
        )


@pytest.mark.parametrize("raw_timeout", ["0.5", "1", "0.001"])
def test_timeouts_just_above_zero_are_accepted(
    no_config_file: list[Path], raw_timeout: str
) -> None:
    """Only zero and below are unusable; a sub-second timeout is a real choice."""
    config = load_config(
        env={"CAPECLI_URL": "http://cape", "CAPECLI_TIMEOUT": raw_timeout},
        search_paths=no_config_file,
    )
    assert config.timeout == float(raw_timeout)


def test_explicit_timeout_argument_is_validated(no_config_file: list[Path]) -> None:
    """The CLI passes --timeout through as a float, bypassing the env parser."""
    with pytest.raises(ConfigError, match="Timeout must be a finite number"):
        load_config(
            url="http://cape", timeout=-5.0, env={}, search_paths=no_config_file
        )


def test_invalid_env_timeout_raises(no_config_file: list[Path]) -> None:
    env = {"CAPECLI_URL": "http://cape", "CAPECLI_TIMEOUT": "soon"}
    with pytest.raises(ConfigError, match="Invalid timeout"):
        load_config(env=env, search_paths=no_config_file)


@pytest.mark.parametrize("blank", ["", "   "])
def test_blank_env_timeout_falls_through_to_file(tmp_path: Path, blank: str) -> None:
    """A blank CAPECLI_TIMEOUT is unset, like a blank URL or token, so it defers
    to the config file rather than aborting the command."""
    config_file = write_config(tmp_path / "capecli.toml", "timeout = 30\n")
    config = load_config(
        env={"CAPECLI_URL": "http://cape", "CAPECLI_TIMEOUT": blank},
        search_paths=[config_file],
    )
    assert config.timeout == 30.0


def test_blank_env_timeout_falls_through_to_default(
    no_config_file: list[Path],
) -> None:
    config = load_config(
        env={"CAPECLI_URL": "http://cape", "CAPECLI_TIMEOUT": ""},
        search_paths=no_config_file,
    )
    assert config.timeout == DEFAULT_TIMEOUT


@pytest.mark.parametrize(
    ("content", "message"),
    [
        ('url = "http://cape"\ntimeout = "soon"\n', "Invalid timeout"),
        ("url = [broken\n", "Unusable config file"),
        ("url = 123\n", "Invalid url"),
    ],
)
def test_malformed_config_file_raises(
    tmp_path: Path, content: str, message: str
) -> None:
    """Unparsable TOML and wrongly typed values alike surface as ConfigError."""
    config_file = write_config(tmp_path / "capecli.toml", content)
    with pytest.raises(ConfigError, match=message):
        load_config(env={}, search_paths=[config_file])


def test_a_config_file_that_is_not_utf8_names_the_file(tmp_path: Path) -> None:
    """Decoding failures are as much "this file is unusable" as syntax errors,
    and only ConfigError carries the path that says which file to fix."""
    config_file = tmp_path / "capecli.toml"
    config_file.write_bytes(b'url = "http://\xff\xfe"\n')
    with pytest.raises(ConfigError, match="Unusable config file"):
        load_config(env={}, search_paths=[config_file])


def test_a_config_file_carrying_a_byte_order_mark_is_read(tmp_path: Path) -> None:
    """A byte order mark is not part of a TOML document, but the editors that
    ship with Windows write one anyway, and the text after it is entirely
    valid. Refusing the file sends the user looking for a syntax error that
    their editor put there and does not show them."""
    config_file = tmp_path / "capecli.toml"
    config_file.write_bytes(b'\xef\xbb\xbfurl = "http://cape.example.tld"\n')
    assert load_config(env={}, search_paths=[config_file]).url == (
        "http://cape.example.tld"
    )


def test_a_config_file_that_cannot_be_read_names_the_file(tmp_path: Path) -> None:
    """A file the process may not open is as unusable as a malformed one, and a
    caller handling configuration failures should not have to catch OSError."""
    config_file = write_config(tmp_path / "capecli.toml", 'url = "http://cape"\n')
    config_file.chmod(0o000)
    if os.access(config_file, os.R_OK):
        pytest.skip("this platform does not enforce the mode that was just set")
    with pytest.raises(ConfigError, match="Unusable config file"):
        load_config(env={}, search_paths=[config_file])


def test_resolved_settings_cannot_be_mutated_afterwards() -> None:
    """A client keeps the Config it was built from; letting callers edit it
    afterwards would mean the settings in force stopped matching it."""
    config = Config(url="http://cape")
    attribute = "url"  # named indirectly so this stays a runtime check
    with pytest.raises(AttributeError):
        setattr(config, attribute, "http://elsewhere")


def test_default_search_paths() -> None:
    paths = default_search_paths()
    assert paths[0] == Path("capecli.toml")
    assert paths[1].name == "config.toml"


def test_defaults_read_process_environment(isolated_env: Path) -> None:
    os.environ["CAPECLI_URL"] = "http://process-env"
    os.environ["CAPECLI_TOKEN"] = "process-token"
    os.environ["CAPECLI_TIMEOUT"] = "45"
    config = load_config()
    assert config == Config(
        url="http://process-env", token="process-token", timeout=45.0
    )


def test_dist_url_from_flag(no_config_file: list[Path]) -> None:
    config = load_config(
        url="http://cape",
        dist_url="http://d:9003/",
        env={},
        search_paths=no_config_file,
    )
    assert config.dist_url == "http://d:9003"


def test_dist_url_from_env(no_config_file: list[Path]) -> None:
    config = load_config(
        env={"CAPECLI_URL": "http://cape", "CAPECLI_DIST_URL": "http://d:9003"},
        search_paths=no_config_file,
    )
    assert config.dist_url == "http://d:9003"


def test_dist_url_from_file(tmp_path: Path) -> None:
    config_file = write_config(
        tmp_path / "capecli.toml", 'url = "http://cape"\ndist_url = "http://d:9003"\n'
    )
    assert load_config(env={}, search_paths=[config_file]).dist_url == "http://d:9003"


def test_dist_url_absent_is_none(no_config_file: list[Path]) -> None:
    config = load_config(url="http://cape", env={}, search_paths=no_config_file)
    assert config.dist_url is None


def test_dist_only_config_needs_no_main_url(no_config_file: list[Path]) -> None:
    config = load_config(
        dist_url="http://d:9003",
        require_url=False,
        env={},
        search_paths=no_config_file,
    )
    assert config.url == ""
    assert config.dist_url == "http://d:9003"
