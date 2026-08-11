"""Tests for output rendering."""

import json
from pathlib import Path
from typing import Any

import pytest

from capecli.render import JSON, SARIF, TABLE, TOON, render

JsonDict = dict[str, Any]

COLLECTION: JsonDict = {
    "error": False,
    "data": [{"id": 1, "status": "reported"}, {"id": 2, "status": "pending"}],
}


@pytest.mark.parametrize("output_format", [TABLE, JSON, TOON])
def test_a_download_prints_its_path_in_every_format(output_format: str) -> None:
    """The path is the whole result; no format should dress it up."""
    assert render(Path("task_7.pcap"), output_format) == "task_7.pcap"


def test_a_download_is_no_exception_to_the_sarif_rule() -> None:
    """SARIF describes findings, and a download reports none. Letting the path
    through would answer a request for findings with something else."""
    with pytest.raises(ValueError, match="only available for commands"):
        render(Path("task_7.pcap"), SARIF)


def test_json_is_indented_and_key_sorted() -> None:
    assert render({"b": 1, "a": 2}, JSON) == '{\n  "a": 2,\n  "b": 1\n}'


def test_toon_delegates_to_the_encoder() -> None:
    assert render({"name": "Ada"}, TOON) == "name: Ada"


def test_sarif_uses_the_builder_the_command_supplied() -> None:
    rendered = render({"signatures": []}, SARIF, lambda payload: {"built": payload})
    assert json.loads(rendered) == {"built": {"signatures": []}}


def test_sarif_without_a_builder_explains_which_commands_support_it() -> None:
    with pytest.raises(ValueError, match="get report"):
        render({"any": "payload"}, SARIF)


def test_a_data_collection_becomes_a_column_table() -> None:
    rendered = render(COLLECTION, TABLE)
    header, *_ = [line for line in rendered.splitlines() if "id" in line]
    assert "id" in header and "status" in header
    assert "reported" in rendered and "pending" in rendered
    # The envelope key is dropped in favour of the collection itself.
    assert "error" not in rendered


def test_anything_else_becomes_a_key_value_table_with_dotted_paths() -> None:
    rendered = render({"data": {"info": {"score": 8.4}}}, TABLE)
    assert "Key" in rendered and "Value" in rendered
    assert "data.info.score" in rendered
    assert "8.4" in rendered


@pytest.mark.parametrize(
    ("payload", "expected"),
    [
        ({"a": {}}, "{}"),
        ({"a": []}, "[]"),
        ({"a": None}, "null"),
        ({"a": True}, "true"),
        ({"a": False}, "false"),
        ({"a": 3}, "3"),
        ({"a": 1.5}, "1.5"),
        ({"a": "text"}, "text"),
    ],
)
def test_leaf_values_render_readably(payload: JsonDict, expected: str) -> None:
    assert expected in render(payload, TABLE)


def test_list_leaves_are_indexed_in_the_path() -> None:
    rendered = render({"errors": ["first", "second"]}, TABLE)
    assert "errors[0]" in rendered and "errors[1]" in rendered


def test_long_values_are_truncated_in_the_table_only() -> None:
    payload = {"body": "x" * 500}
    table = render(payload, TABLE)
    assert "…" in table
    assert "x" * 500 not in table
    # The ellipsis replaces the last character kept rather than following the
    # last one allowed, so the cell is the width it promises and not one more.
    assert "x" * 99 + "…" in table
    assert "x" * 100 + "…" not in table
    # The lossless formats keep the whole value.
    assert "x" * 500 in render(payload, JSON)


def test_a_column_of_zeros_is_not_mistaken_for_an_empty_one() -> None:
    """Columns nothing fills are dropped to keep the table narrow. A count of
    zero is a measurement, not an absence, and dropping it hides the answer."""
    table = render({"data": [{"errors": 0, "id": 1}, {"errors": 0, "id": 2}]}, TABLE)
    assert "errors" in table


@pytest.mark.parametrize(
    "data",
    [
        "not-a-list",
        [],
        ["not-an-object"],
        [{}],
        [{"id": 1}, {"name": "other"}],
    ],
    ids=["scalar", "empty", "loose-item", "empty-object", "different-keys"],
)
def test_collections_that_are_not_uniform_fall_back_to_key_values(
    data: object,
) -> None:
    rendered = render({"data": data}, TABLE)
    assert "Key" in rendered and "Value" in rendered


def test_columns_empty_in_every_row_are_dropped() -> None:
    """CAPE returns a fixed record shape with most fields null; showing them
    all makes the table far wider than the data it carries."""
    payload = {
        "data": [
            {"id": 1, "status": "reported", "domains": None, "notes": "", "tags": []},
            {"id": 2, "status": "pending", "domains": None, "notes": "", "tags": []},
        ]
    }
    rendered = render(payload, TABLE)
    assert "id" in rendered and "status" in rendered
    for dropped in ("domains", "notes", "tags"):
        assert dropped not in rendered


def test_a_row_that_is_empty_throughout_still_shows_its_columns() -> None:
    rendered = render({"data": [{"a": None}, {"a": None}]}, TABLE)
    assert "a" in rendered


@pytest.mark.parametrize("output_format", [TABLE, TOON])
def test_a_payload_too_deep_to_walk_is_an_error_not_a_traceback(
    output_format: str,
) -> None:
    """The server chooses how deeply its response nests, and the walk over it
    is recursive, so the limit has to surface as a reportable error."""
    payload: JsonDict = {"leaf": 1}
    for _ in range(2000):
        payload = {"a": payload}
    with pytest.raises(ValueError, match="nests too deeply"):
        render(payload, output_format)


def test_a_structured_cell_renders_in_a_stable_order() -> None:
    """Two runs over the same task must produce the same table, or diffing one
    against another stops meaning anything."""
    payload = {"data": [{"id": 1, "guest": {"label": "win10", "arch": "x64"}}]}
    assert '{"arch": "x64", "label": "win10"}' in render(payload, TABLE)


def test_a_cell_holding_a_structure_is_shown_as_json() -> None:
    """Uniform rows can still carry a nested value in one column."""
    payload = {"data": [{"id": 1, "guest": {"label": "win10"}}]}
    assert '{"label": "win10"}' in render(payload, TABLE)
