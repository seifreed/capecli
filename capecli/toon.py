"""Encoder for TOON, Token-Oriented Object Notation.

TOON is a lossless, token-efficient rendering of JSON aimed at LLM prompts;
see https://github.com/toon-format/spec. Only encoding is implemented, since
CAPE responses travel one way: JSON in, TOON out.

The specification does not leave the choice of form to the encoder: it is read
off the shape and position of the value. An array of objects sharing a set of
keys becomes a table, with a column whose values are themselves uniform objects
written as a nested field group; an object whose values are uniform objects
becomes a table whose rows carry their own keys. Everything else nests.
"""

import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from decimal import Decimal
from typing import Any

DELIMITER = ","
NULL = "null"
EMPTY_ARRAY = "[]"

# Matched with fullmatch rather than anchors: "$" also matches just before a
# trailing newline, so "key\n" passed for a bare key and split its own line.
_BARE_KEY = re.compile(r"[A-Za-z_][A-Za-z0-9_.]*")
_NUMERIC_LIKE = re.compile(r"[+-]?[0-9]+(?:\.[0-9]+)?(?:e[+-]?[0-9]+)?", re.IGNORECASE)
_RESERVED = ("true", "false", NULL)
_FORBIDDEN_BARE = set(':"\\[]{}' + DELIMITER)
_ESCAPES = {"\\": "\\\\", '"': '\\"', "\n": "\\n", "\r": "\\r", "\t": "\\t"}


def _number(value: int | float) -> str:
    """Render a number canonically: no exponent in the common range, no trailing
    fractional zeros, and no decimal point when the value is integer-valued.

    TOON is a lossless encoding, so every branch here has to preserve the value
    exactly. Integers are rendered from the integer itself: they are arbitrary
    precision in Python and in JSON, and routing them through a float would
    round away digits beyond 2**53 and overflow entirely past 1e308.

    NaN and the infinities are the one exception, and not ours to make: TOON
    has no notation for them and the specification requires an encoder to write
    null. Python's JSON parser accepts all three, so a response can carry one.
    """
    if isinstance(value, int):
        return str(value)
    if value != value or value in (float("inf"), float("-inf")):
        return NULL
    if value == 0:
        return "0"
    if value.is_integer() and abs(value) < 1e21:
        return str(int(value))
    rendered = repr(value)
    if "e" in rendered and 1e-6 <= abs(value) < 1e21:
        # repr is the shortest form that round-trips; Decimal re-spells those
        # same digits positionally, where a fixed-precision format would cut
        # off the significant ones for small magnitudes.
        rendered = format(Decimal(rendered), "f")
    return rendered


def _is_surrogate(character: str) -> bool:
    return 0xD800 <= ord(character) <= 0xDFFF


def _must_escape(character: str) -> bool:
    """Characters that cannot appear literally in TOON.

    Control characters would break the line-oriented layout. Lone surrogates
    have no TOON representation at all: a decoder must reject the \\u escape
    for one, and substituting U+FFFD is forbidden too, so the only conforming
    answer is to refuse the value. Naming them here is what routes the string
    through _escape, which is where the refusal happens.
    """
    return ord(character) < 0x20 or _is_surrogate(character)


def _escape(text: str) -> str:
    parts = []
    for character in text:
        if _is_surrogate(character):
            raise ValueError(f"{text!r} has no TOON representation")
        escaped = _ESCAPES.get(character)
        if escaped is not None:
            parts.append(escaped)
        elif _must_escape(character):
            parts.append(f"\\u{ord(character):04x}")
        else:
            parts.append(character)
    return "".join(parts)


def _needs_quotes(text: str) -> bool:
    if not text or text != text.strip():
        return True
    if text in _RESERVED or _NUMERIC_LIKE.fullmatch(text):
        return True
    if text.startswith(("-", "#")):
        return True
    return any(
        character in _FORBIDDEN_BARE or _must_escape(character) for character in text
    )


def _scalar(value: object) -> str:
    """Render a JSON primitive, or raise for anything TOON cannot express."""
    if value is None:
        return NULL
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, int | float):
        return _number(value)
    if isinstance(value, str):
        return f'"{_escape(value)}"' if _needs_quotes(value) else value
    raise TypeError(f"{type(value).__name__} has no TOON representation")


def _is_scalar(value: object) -> bool:
    return value is None or isinstance(value, str | int | float | bool)


def _key(name: object) -> str:
    text = str(name)
    return text if _BARE_KEY.fullmatch(text) else f'"{_escape(text)}"'


@dataclass(frozen=True)
class _Column:
    """One column of a table: a key, and the columns below it when every value
    at that key is itself a uniform object. A column of primitives has none."""

    key: object
    children: tuple[_Column, ...] | None


def _columns(objects: Sequence[Mapping[Any, object]]) -> tuple[_Column, ...] | None:
    """Classify what a sequence of objects share, or None if it is not a table.

    A column holds primitives, or it holds non-empty objects that are uniform
    in the same sense all the way down. Anything else -- a column mixing null
    with objects, or holding an array or an empty object -- disqualifies the
    whole table, since there would be no single row shape to write.
    """
    first = objects[0]
    if not first:
        return None
    keys = set(first)
    if any(set(other) != keys for other in objects[1:]):
        return None
    columns = []
    for key in first:
        values = [obj[key] for obj in objects]
        if all(_is_scalar(value) for value in values):
            columns.append(_Column(key, None))
            continue
        nested: list[Mapping[Any, object]] = []
        for value in values:
            if not isinstance(value, dict) or not value:
                return None
            nested.append(value)
        children = _columns(nested)
        if children is None:
            return None
        columns.append(_Column(key, children))
    return tuple(columns)


def _table_columns(items: Sequence[object]) -> tuple[_Column, ...] | None:
    """The columns of an array of objects, or None if it is not one."""
    objects: list[Mapping[Any, object]] = []
    for item in items:
        if not isinstance(item, dict):
            return None
        objects.append(item)
    return _columns(objects)


def _keyed_columns(values: Mapping[Any, object]) -> tuple[_Column, ...] | None:
    """The columns of an object of uniform objects, or None if it is not one.

    One entry is left to nest: a header plus a single row spends more than the
    two lines it would replace.
    """
    if len(values) < 2:
        return None
    return _table_columns(list(values.values()))


def _header_fields(columns: tuple[_Column, ...]) -> str:
    """The field list of a table header, nested groups spelled out in place."""
    return DELIMITER.join(
        (
            _key(column.key)
            if column.children is None
            else f"{_key(column.key)}{{{_header_fields(column.children)}}}"
        )
        for column in columns
    )


def _leaf_values(columns: tuple[_Column, ...], obj: Any) -> list[object]:
    """One row's cells: the leaves of the field list, depth first and in order."""
    cells: list[object] = []
    for column in columns:
        value = obj[column.key]
        if column.children is None:
            cells.append(value)
        else:
            # Classifying the column is what established this value is an object.
            cells.extend(_leaf_values(column.children, value))
    return cells


class _Writer:
    """Accumulates TOON lines; every construct knows only its own depth."""

    def __init__(self, indent: int) -> None:
        self._indent = indent
        self.lines: list[str] = []

    def line(self, depth: int, text: str) -> None:
        self.lines.append(" " * (self._indent * depth) + text)

    def mapping(self, values: dict[str, object], depth: int) -> None:
        for name, value in values.items():
            self.field(_key(name), value, depth)

    def field(self, label: str, value: object, depth: int) -> None:
        if isinstance(value, dict):
            self.object_field(label, value, depth)
        elif isinstance(value, list):
            self.array(label, value, depth)
        else:
            self.line(depth, f"{label}: {_scalar(value)}")

    def object_field(self, label: str, values: dict[str, object], depth: int) -> None:
        """An object of uniform objects is a table whose rows carry their own
        keys; any other object nests."""
        columns = _keyed_columns(values)
        if columns is None:
            self.line(depth, f"{label}:")
            self.mapping(values, depth + 1)
            return
        self.keyed_table(label, values, columns, depth)

    def keyed_table(
        self,
        label: str,
        values: dict[str, object],
        columns: tuple[_Column, ...],
        depth: int,
    ) -> None:
        """Write the keyed tabular form: the shared shape once in the header,
        then one row per entry, labelled with the key it came from.

        The label is empty at the document root, which is how the form is
        spelled there: the header stands for the object itself.
        """
        fields = _header_fields(columns)
        self.line(depth, f"{label}[{len(values)}:]{{{fields}}}:")
        for name, entry in values.items():
            cells = self._row(_leaf_values(columns, entry))
            self.line(depth + 1, f"{_key(name)}: {cells}")

    def root_object(self, values: dict[str, object]) -> None:
        """The document root, where a keyed tabular header carries no key."""
        columns = _keyed_columns(values)
        if columns is None:
            self.mapping(values, 0)
            return
        self.keyed_table("", values, columns, 0)

    def array(self, label: str, items: list[object], depth: int) -> None:
        if not items:
            self.line(depth, f"{label}: {EMPTY_ARRAY}")
            return
        header = f"{label}[{len(items)}]"
        if all(_is_scalar(item) for item in items):
            self.line(depth, f"{header}: {self._row(items)}")
            return
        columns = _table_columns(items)
        if columns is not None:
            self.line(depth, f"{header}{{{_header_fields(columns)}}}:")
            for row in items:
                self.line(depth + 1, self._row(_leaf_values(columns, row)))
            return
        self.line(depth, f"{header}:")
        for item in items:
            self.item(item, depth + 1)

    def item(self, value: object, depth: int) -> None:
        """Write one element of a list-form array, prefixed with a hyphen.

        An object carries its first field on the hyphen line, so the rest of it
        is shifted one level to stand under that field. A nested array is not a
        field: its keyless header is the element itself, so its own items sit
        one level below the hyphen line with no shift on top.
        """
        if isinstance(value, list):
            self._nested_array(value, depth)
            return
        if not isinstance(value, dict):
            self.line(depth, f"- {_scalar(value)}")
            return
        inner = _Writer(self._indent)
        inner.mapping(value, 0)
        if not inner.lines:
            self.line(depth, "-")
            return
        self.line(depth, f"- {inner.lines[0]}")
        for continuation in inner.lines[1:]:
            self.line(depth, " " * self._indent + continuation)

    def _nested_array(self, items: list[object], depth: int) -> None:
        """Write an array that is itself an element of another array.

        The tabular form is unavailable in this position: a keyless header
        carrying field names is valid only at the document root, so a uniform
        array of objects is written as a list here. The field-level "[]" form
        does not apply either; an empty array is a zero-length header.
        """
        if not items:
            self.line(depth, "- [0]:")
            return
        header = f"- [{len(items)}]"
        if all(_is_scalar(element) for element in items):
            self.line(depth, f"{header}: {self._row(items)}")
            return
        self.line(depth, f"{header}:")
        for element in items:
            self.item(element, depth + 1)

    def _row(self, cells: list[object]) -> str:
        return DELIMITER.join(_scalar(cell) for cell in cells)


def encode(value: object, *, indent: int = 2) -> str:
    """Render a JSON-compatible value as TOON.

    Indentation is what carries the structure, so an indent of zero would flatten
    every nesting level into the one below it and change what the document means.
    """
    if indent < 1:
        raise ValueError(f"indent must be at least one space, got {indent}")
    writer = _Writer(indent)
    if isinstance(value, dict):
        writer.root_object(value)
    elif isinstance(value, list):
        if value:
            writer.array("", value, 0)
        else:
            writer.line(0, EMPTY_ARRAY)
    else:
        writer.line(0, _scalar(value))
    return "\n".join(writer.lines)
