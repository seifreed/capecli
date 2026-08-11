"""HTTP client for CAPE's distributed API (utils/dist.py).

This is a separate Flask service from the ``/apiv2/`` REST API -- a different
base URL (default port 9003), no ``/apiv2/`` prefix, and no token authentication
-- so it has its own client rather than another method on CapeClient. The HTTP
plumbing is shared with the main client; only the envelope shapes differ.
"""

from collections.abc import Mapping
from types import TracebackType
from typing import Self

import httpx

from capecli.client import (
    FormValue,
    JsonDict,
    _build_http,
    _envelope_detail,
    _fields,
    _json_payload,
    _raise_for_html,
    _raise_for_status,
    _segment,
)
from capecli.config import Config
from capecli.errors import ApiError, ConfigError


def _dist_path(*parts: object) -> str:
    """Join path segments without a trailing slash.

    The distributed routes are registered without one (``/node``, not
    ``/node/``), so a trailing slash would answer 404.
    """
    return "/".join(_segment(part) for part in parts if part is not None)


def _flag(value: bool | None) -> int | None:
    """Render an optional bool as the 1/0 the node parser reads, or leave it unset."""
    if value is None:
        return None
    return 1 if value else 0


def _raise_for_dist_envelope(payload: object, status_code: int) -> None:
    """Report the error a distributed response carries.

    The service reports failure two ways: an ``error`` flag, like the main API,
    and a ``success: False`` with a ``message`` on a 200 when a node already
    exists. Either one is a failure the caller has to hear about.
    """
    if not isinstance(payload, dict):
        return
    if payload.get("error") or payload.get("Error") or payload.get("success") is False:
        detail = _envelope_detail(payload) or "Unknown CAPE distributed API error"
        raise ApiError(detail, status_code=status_code)


def _parse_dist_json_body(response: httpx.Response, path: str) -> JsonDict:
    _raise_for_status(response, path)
    _raise_for_html(response, path, "JSON")
    payload = _json_payload(response, path)
    _raise_for_dist_envelope(payload, response.status_code)
    if not isinstance(payload, dict):
        raise ApiError(
            f"Unexpected JSON response for {path}", status_code=response.status_code
        )
    return payload


class DistClient:
    """Client for CAPE's distributed node-management API."""

    def __init__(self, config: Config) -> None:
        if not config.dist_url:
            raise ConfigError(
                "CAPE distributed URL not configured. Set it via --dist-url, the "
                "CAPECLI_DIST_URL environment variable, or dist_url in a config file."
            )
        self._http = _build_http(
            f"{config.dist_url.rstrip('/')}/",
            {},
            config.timeout,
            url_label="CAPE distributed URL",
            url_value=config.dist_url,
        )

    def close(self) -> None:
        self._http.close()

    def __enter__(self) -> Self:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        self.close()

    def _json(
        self, method: str, path: str, *, data: Mapping[str, FormValue] | None = None
    ) -> JsonDict:
        try:
            response = self._http.request(method, path, data=data)
        except httpx.HTTPError as exc:
            raise ApiError(f"Request failed for {path}: {exc}") from exc
        return _parse_dist_json_body(response, path)

    # Nodes

    def nodes_list(self) -> JsonDict:
        return self._json("GET", "node")

    def node_view(self, name: str) -> JsonDict:
        return self._json("GET", _dist_path("node", name))

    def node_add(
        self,
        name: str,
        url: str,
        *,
        apikey: str | None = None,
        exitnodes: bool | None = None,
        enabled: bool | None = None,
    ) -> JsonDict:
        """Register a worker node by name and its apiv2 base URL."""
        return self._json(
            "POST",
            "node",
            data=_fields(
                name=name,
                url=url,
                apikey=apikey,
                exitnodes=_flag(exitnodes),
                enabled=_flag(enabled),
            ),
        )

    def node_update(
        self,
        name: str,
        *,
        url: str | None = None,
        apikey: str | None = None,
        exitnodes: bool | None = None,
        enabled: bool | None = None,
    ) -> JsonDict:
        """Modify a node; only the fields given are sent."""
        return self._json(
            "PUT",
            _dist_path("node", name),
            data=_fields(
                url=url,
                apikey=apikey,
                exitnodes=_flag(exitnodes),
                enabled=_flag(enabled),
            ),
        )

    def node_delete(self, name: str) -> JsonDict:
        return self._json("DELETE", _dist_path("node", name))

    # Status and tasks

    def dist_status(self) -> JsonDict:
        """Return the distributed cluster status: nodes and task counts."""
        return self._json("GET", "status")

    def dist_task(self, main_task_id: int) -> JsonDict:
        """Return the distributed record for a submitted (main) task id."""
        return self._json("GET", _dist_path("task", main_task_id))
