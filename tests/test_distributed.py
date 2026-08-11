"""Tests for capecli.distributed against a real in-process distributed server."""

import socket

import pytest

from capecli.config import Config
from capecli.distributed import DistClient
from capecli.errors import ApiError, ConfigError


def _closed_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.bind(("127.0.0.1", 0))
        return int(probe.getsockname()[1])


def test_nodes_list(dist_client: DistClient) -> None:
    assert "main" in dist_client.nodes_list()["nodes"]


def test_node_view(dist_client: DistClient) -> None:
    assert dist_client.node_view("main") == {"name": "main", "url": "http://n1"}


def test_node_add(dist_client: DistClient) -> None:
    result = dist_client.node_add(
        "worker", "http://w1", apikey="k", enabled=True, exitnodes=False
    )
    assert result["name"] == "worker"


def test_node_add_conflict_raises(dist_client: DistClient) -> None:
    with pytest.raises(ApiError, match="already exists"):
        dist_client.node_add("existing", "http://w1")


def test_node_update(dist_client: DistClient) -> None:
    result = dist_client.node_update("main", url="http://new", enabled=False)
    assert result["error"] is False


def test_node_update_missing_raises(dist_client: DistClient) -> None:
    with pytest.raises(ApiError, match="doesn't exist"):
        dist_client.node_update("ghost")


def test_node_delete(dist_client: DistClient) -> None:
    assert dist_client.node_delete("main")["error"] is False


def test_dist_status(dist_client: DistClient) -> None:
    assert dist_client.dist_status()["tasks"] == {"pending": 0}


def test_dist_task(dist_client: DistClient) -> None:
    assert dist_client.dist_task(5)["Tasks"][0]["id"] == 5


def test_dist_task_missing_raises(dist_client: DistClient) -> None:
    with pytest.raises(ApiError, match="No tasks found"):
        dist_client.dist_task(0)


def test_non_object_response_raises(dist_client: DistClient) -> None:
    with pytest.raises(ApiError, match="Unexpected JSON response"):
        dist_client.node_view("aslist")


def test_missing_dist_url_raises() -> None:
    with pytest.raises(ConfigError, match="distributed URL not configured"):
        DistClient(Config(url="http://cape"))


def test_schemeless_dist_url_raises() -> None:
    with pytest.raises(ConfigError, match="needs an http"):
        DistClient(Config(url="http://cape", dist_url="cape-dist:9003"))


def test_request_failure_is_reported() -> None:
    config = Config(url="http://cape", dist_url=f"http://127.0.0.1:{_closed_port()}")
    with DistClient(config) as dist, pytest.raises(ApiError, match="Request failed"):
        dist.nodes_list()
