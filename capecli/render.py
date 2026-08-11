"""Rendering of command results in the output format the user asked for."""

import json
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any

from prettytable import PrettyTable

from capecli import toon

JsonDict = dict[str, Any]
SarifBuilder = Callable[[JsonDict], JsonDict]

TABLE = "table"
JSON = "json"
TOON = "toon"
SARIF = "sarif"
FORMATS = (TABLE, JSON, TOON, SARIF)

# Long values are truncated in the table only; json and toon carry them whole.
# Columns are kept narrower than key/value rows, since a wide record already
# spends its width on the number of columns.
_MAX_CELL = 100
_MAX_COLUMN_CELL = 40
_ELLIPSIS = "…"


def _as_json(payload: object) -> str:
    return json.dumps(payload, indent=2, sort_keys=True)


def _cell(value: object, limit: int = _MAX_CELL) -> str:
    text = value if isinstance(value, str) else _scalar_text(value)
    if len(text) > limit:
        return text[: limit - 1] + _ELLIPSIS
    return text


def _is_empty(value: object) -> bool:
    return value is None or value in ("", [], {})


def _scalar_text(value: object) -> str:
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, str | int | float):
        return str(value)
    return json.dumps(value, sort_keys=True)


def _flatten(value: object, prefix: str = "") -> Iterator[tuple[str, object]]:
    """Walk a payload into (dotted path, value) pairs, one per leaf."""
    if isinstance(value, dict):
        if not value:
            yield prefix, "{}"
            return
        for name, child in value.items():
            path = f"{prefix}.{name}" if prefix else str(name)
            yield from _flatten(child, path)
    elif isinstance(value, list):
        if not value:
            yield prefix, "[]"
            return
        for index, child in enumerate(value):
            yield from _flatten(child, f"{prefix}[{index}]")
    else:
        yield prefix, value


def _uniform_rows(value: object) -> list[dict[str, Any]] | None:
    """Return the elements when a list holds objects that share their keys."""
    if not isinstance(value, list) or not value:
        return None
    rows: list[dict[str, Any]] = []
    for item in value:
        if not isinstance(item, dict) or not item:
            return None
        rows.append(item)
    columns = set(rows[0])
    if any(set(row) != columns for row in rows):
        return None
    return rows


def _populated_columns(rows: list[dict[str, Any]]) -> list[str]:
    """Keep only columns some row actually fills.

    CAPE returns a fixed record shape with many fields left null, so listing
    every column produces a table far wider than the data in it.
    """
    filled = [
        column for column in rows[0] if any(not _is_empty(row[column]) for row in rows)
    ]
    return filled or list(rows[0])


def _table(rows: list[dict[str, Any]]) -> str:
    table = PrettyTable()
    table.field_names = _populated_columns(rows)
    table.align = "l"
    for row in rows:
        table.add_row(
            [_cell(row[column], _MAX_COLUMN_CELL) for column in table.field_names]
        )
    return table.get_string()


def _key_value_table(payload: JsonDict) -> str:
    table = PrettyTable()
    table.field_names = ["Key", "Value"]
    table.align = "l"
    for path, value in _flatten(payload):
        table.add_row([path, _cell(value)])
    return table.get_string()


def _as_table(payload: JsonDict) -> str:
    """Tabulate the collection CAPE wraps in ``data``, else list every leaf.

    CAPE consistently returns collections under a ``data`` key, so this single
    rule is what makes "task list" and "machine list" read as real tables
    without teaching the renderer anything about individual endpoints.
    """
    rows = _uniform_rows(payload.get("data"))
    if rows is not None:
        return _table(rows)
    return _key_value_table(payload)


def check_format(output_format: str, sarif_builder: SarifBuilder | None) -> None:
    """Raise ValueError if the format cannot apply to what the command returns.

    Separate from render so a caller can find out before doing the work, rather
    than after it has already submitted or deleted something.
    """
    if output_format == SARIF and sarif_builder is None:
        raise ValueError(
            "sarif output is only available for commands that report "
            "findings: 'get report' and 'get iocs'"
        )


def render(
    result: JsonDict | Path,
    output_format: str,
    sarif_builder: SarifBuilder | None = None,
) -> str:
    """Render a command result, or raise ValueError if the format cannot apply."""
    check_format(output_format, sarif_builder)
    if isinstance(result, Path):
        # The path is the whole result; wrapping it in a table or an envelope
        # would only make it harder to pipe into the next command.
        return str(result)
    try:
        return _rendered(result, output_format, sarif_builder)
    except RecursionError:
        # The walk over a response is recursive, and the server chooses how
        # deeply its payload nests, so this has to fail as an error rather
        # than as a traceback.
        # Naming json as the deepest-walking format rather than as the thing to
        # try next keeps the advice true when json is what already failed: there
        # is nothing further to reach for, which is worth saying too.
        raise ValueError(
            f"The response nests too deeply to render as {output_format}; "
            "--output-format json walks the deepest nesting of any format"
        ) from None


def _rendered(
    result: JsonDict, output_format: str, sarif_builder: SarifBuilder | None
) -> str:
    if output_format == JSON:
        return _as_json(result)
    if output_format == TOON:
        return toon.encode(result)
    if sarif_builder is not None and output_format == SARIF:
        return _as_json(sarif_builder(result))
    return _as_table(result)
