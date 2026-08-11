"""Configuration loading for capecli."""

import math
import os
import tomllib
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path

from capecli.errors import ConfigError

DEFAULT_TIMEOUT = 60.0


@dataclass(frozen=True)
class Config:
    """Resolved settings needed to talk to a CAPE instance."""

    url: str
    token: str | None = None
    timeout: float = DEFAULT_TIMEOUT
    dist_url: str | None = None


def default_search_paths() -> tuple[Path, ...]:
    """Return the config file locations checked by default, in order.

    Uses os.path.expanduser rather than Path.home() because the latter raises
    when no home directory can be resolved, which happens in containers and
    service accounts even when the URL and token come from flags or the
    environment.
    """
    return (
        Path("capecli.toml"),
        Path(os.path.expanduser("~")) / ".config" / "capecli" / "config.toml",
    )


def _read_first_config_file(paths: Sequence[Path]) -> Mapping[str, object]:
    for path in paths:
        if path.is_file():
            try:
                # utf-8-sig rather than utf-8: a TOML document is UTF-8, and a
                # byte order mark is not part of one, but the editors that ship
                # with Windows write it anyway. Reading it as the nothing it
                # encodes beats refusing a file whose text is entirely valid.
                return tomllib.loads(path.read_text(encoding="utf-8-sig"))
            except (OSError, tomllib.TOMLDecodeError, UnicodeDecodeError) as exc:
                # Unreadable, undecodable and unparsable all mean the same thing
                # to the caller: this file is unusable. Only ConfigError carries
                # the path that says which one, and callers handling a
                # configuration failure should not have to catch OSError too.
                raise ConfigError(f"Unusable config file {path}: {exc}") from exc
    return {}


def _optional_str(data: Mapping[str, object], key: str) -> str | None:
    value = data.get(key)
    if value is None:
        return None
    if not isinstance(value, str):
        raise ConfigError(f"Invalid {key} in config file: {value!r}")
    return value


def _parse_timeout(raw: object, source: str) -> float:
    try:
        return float(str(raw))
    except ValueError as exc:
        raise ConfigError(f"Invalid timeout in {source}: {raw!r}") from exc


def _validated_timeout(timeout: float) -> float:
    if not math.isfinite(timeout) or timeout <= 0:
        raise ConfigError(
            f"Timeout must be a finite number greater than zero, got {timeout}"
        )
    return timeout


def load_config(
    *,
    url: str | None = None,
    token: str | None = None,
    timeout: float | None = None,
    dist_url: str | None = None,
    require_url: bool = True,
    env: Mapping[str, str] | None = None,
    search_paths: Sequence[Path] | None = None,
) -> Config:
    """Resolve configuration from explicit values, environment, and config files.

    Precedence: explicit arguments, then CAPECLI_* environment variables,
    then the first config file found in ``search_paths``.

    ``require_url`` is False for commands that reach only the distributed
    service, which needs ``dist_url`` but not the main CAPE URL.
    """
    environ: Mapping[str, str] = os.environ if env is None else env
    paths = default_search_paths() if search_paths is None else search_paths
    file_data = _read_first_config_file(paths)

    resolved_url = url or environ.get("CAPECLI_URL") or _optional_str(file_data, "url")
    if not resolved_url:
        if require_url:
            raise ConfigError(
                "CAPE URL not configured. Set it via --url, the CAPECLI_URL "
                "environment variable, or a capecli.toml config file."
            )
        resolved_url = ""

    resolved_token = (
        token or environ.get("CAPECLI_TOKEN") or _optional_str(file_data, "token")
    )

    resolved_dist_url = (
        dist_url
        or environ.get("CAPECLI_DIST_URL")
        or _optional_str(file_data, "dist_url")
    )

    resolved_timeout = DEFAULT_TIMEOUT
    if timeout is not None:
        resolved_timeout = timeout
    elif environ.get("CAPECLI_TIMEOUT", "").strip():
        # Presence alone would make an empty CAPECLI_TIMEOUT="" abort every
        # command, where the same empty CAPECLI_URL and CAPECLI_TOKEN fall
        # through to the config file. A blank value is unset here too, so the
        # three variables agree on what "empty" means.
        resolved_timeout = _parse_timeout(
            environ["CAPECLI_TIMEOUT"], "$CAPECLI_TIMEOUT"
        )
    elif "timeout" in file_data:
        resolved_timeout = _parse_timeout(file_data["timeout"], "config file")

    return Config(
        url=resolved_url.rstrip("/"),
        token=resolved_token,
        timeout=_validated_timeout(resolved_timeout),
        dist_url=resolved_dist_url.rstrip("/") if resolved_dist_url else None,
    )
