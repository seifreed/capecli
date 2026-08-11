"""Tests for the TOON encoder, checked against the examples in the specification.

See https://github.com/toon-format/spec; section numbers below refer to it.
"""

import pytest

from capecli.toon import encode


def test_object_with_primitive_fields() -> None:
    assert encode({"name": "Ada"}) == "name: Ada"


def test_nested_object_indents_by_depth() -> None:
    assert encode({"user": {"id": 123, "name": "Ada"}}) == (
        "user:\n  id: 123\n  name: Ada"
    )


def test_indent_width_is_configurable() -> None:
    assert encode({"user": {"id": 1}}, indent=4) == "user:\n    id: 1"


def test_empty_object_field_has_nothing_after_the_colon() -> None:
    assert encode({"metadata": {}}) == "metadata:"


def test_primitive_array_uses_the_inline_form() -> None:
    assert encode({"tags": ["admin", "ops", "dev"]}) == "tags[3]: admin,ops,dev"


def test_empty_array_is_written_in_place() -> None:
    assert encode({"tags": []}) == "tags: []"


def test_uniform_objects_use_the_tabular_form() -> None:
    payload = {"items": [{"sku": "A1", "qty": 2}, {"sku": "B2", "qty": 1}]}
    assert encode(payload) == "items[2]{sku,qty}:\n  A1,2\n  B2,1"


def test_rows_follow_the_header_order_not_the_row_order() -> None:
    """Objects may list their keys in any order; the header fixes the columns."""
    payload = {"items": [{"sku": "A1", "qty": 2}, {"qty": 1, "sku": "B2"}]}
    assert encode(payload) == "items[2]{sku,qty}:\n  A1,2\n  B2,1"


@pytest.mark.parametrize(
    "items",
    [
        [{"sku": "A1"}, {"qty": 1}],
        [{"sku": "A1", "qty": 1}, {"sku": "B2"}],
        [{"sku": "A1"}, "loose"],
        [{}, {}],
        [{"a": {"x": 1}}, {"a": None}],
        [{"a": {"x": 1}}, {"a": {}}],
        [{"a": [1]}, {"a": [2]}],
        [{"a": {"b": {"c": 1}}}, {"a": {"b": None}}],
    ],
    ids=[
        "different-keys",
        "missing-key",
        "not-all-objects",
        "empty",
        "column-mixing-object-with-null",
        "column-holding-an-empty-object",
        "column-holding-an-array",
        "sub-column-that-disqualifies-its-group",
    ],
)
def test_arrays_that_do_not_qualify_fall_back_to_the_list_form(
    items: list[object],
) -> None:
    rendered = encode({"items": items})
    assert rendered.startswith(f"items[{len(items)}]:\n")
    assert "{" not in rendered.splitlines()[0]


def test_a_uniform_nested_column_becomes_a_nested_field_group() -> None:
    """The shared shape is declared once in the header and the rows stay flat,
    which is the whole saving the tabular form exists for."""
    payload = {
        "orders": [
            {"id": 1, "customer": {"name": "Ada", "country": "DK"}, "total": 99},
            {"id": 2, "customer": {"name": "Bo", "country": "SE"}, "total": 12},
        ]
    }
    assert encode(payload) == (
        "orders[2]{id,customer{name,country},total}:\n  1,Ada,DK,99\n  2,Bo,SE,12"
    )


def test_field_groups_nest_to_any_depth() -> None:
    rows = [{"a": {"b": {"c": 1, "d": 2}}}, {"a": {"b": {"c": 3, "d": 4}}}]
    assert encode({"r": rows}) == "r[2]{a{b{c,d}}}:\n  1,2\n  3,4"


def test_an_object_of_uniform_objects_becomes_a_keyed_table() -> None:
    """Each row carries the key it came from, so the shared field names are
    spent once rather than once per entry."""
    users = {"alice": {"age": 30, "city": "Berlin"}, "bob": {"age": 25, "city": "Oslo"}}
    assert encode({"users": users}) == (
        "users[2:]{age,city}:\n  alice: 30,Berlin\n  bob: 25,Oslo"
    )


def test_a_keyed_table_at_the_root_carries_no_key() -> None:
    payload = {"alice": {"age": 30}, "bob": {"age": 25}}
    assert encode(payload) == "[2:]{age}:\n  alice: 30\n  bob: 25"


def test_a_single_entry_object_still_nests() -> None:
    """A header plus one row spends more than the two lines it would replace."""
    assert encode({"only": {"age": 1, "city": "X"}}) == "only:\n  age: 1\n  city: X"


def test_an_array_element_never_takes_the_keyed_form() -> None:
    """A keyed header stands for a named object or for the root; an element of
    an array is neither, so it has no key to put in front of one and nests."""
    entries = {"alice": {"age": 30}, "bob": {"age": 25}}
    encoded = encode([entries, "x"])
    assert "[2:]" not in encoded
    assert encoded == "[2]:\n  - alice:\n      age: 30\n    bob:\n      age: 25\n  - x"


def test_list_form_of_scalars() -> None:
    assert encode({"items": [1, {"a": "hello"}]}) == "items[2]:\n  - 1\n  - a: hello"


def test_list_item_object_keeps_later_fields_under_the_hyphen() -> None:
    payload = {"items": [{"id": 1, "status": "active"}, {"id": 2, "status": "done"}]}
    # Two keys with primitive values qualify as tabular, so force a mismatch.
    payload["items"][1] = {"id": 2}
    assert encode(payload) == "items[2]:\n  - id: 1\n    status: active\n  - id: 2"


def test_empty_object_as_a_list_item_is_a_bare_hyphen() -> None:
    assert encode({"items": [{}, 1]}) == "items[2]:\n  -\n  - 1"


def test_nested_array_as_a_list_item() -> None:
    assert encode({"items": [[1, 2], 3]}) == "items[2]:\n  - [2]: 1,2\n  - 3"


def test_an_empty_array_as_a_list_item_is_a_zero_length_header() -> None:
    """The "[]" spelling is the field-level form and does not reach here; as a
    list item it would read as a field with an empty name."""
    assert encode({"items": [[1], []]}) == "items[2]:\n  - [1]: 1\n  - [0]:"


def test_uniform_objects_nested_in_a_list_item_take_the_list_form() -> None:
    """A keyless header carrying field names is valid only at the document
    root, so the tabular form is not available one level in."""
    assert encode([[{"a": 1}, {"a": 2}]]) == "[1]:\n  - [2]:\n    - a: 1\n    - a: 2"


def test_a_nested_array_puts_its_items_one_level_below_the_hyphen() -> None:
    """The keyless header is the list item itself rather than a field of one,
    so its items stand one level below it, not two."""
    assert encode([["q", [1, 2]]]) == "[1]:\n  - [2]:\n    - q\n    - [2]: 1,2"


def test_indentation_stays_a_multiple_of_the_indent_that_was_asked_for() -> None:
    """An object list item carries its first field on the hyphen line, and the
    rest of it is shifted one level; that level is the caller's, not two."""
    encoded = encode({"items": [{"a": 1, "b": {"c": 2}}, "x"]}, indent=4)
    assert encoded == "items[2]:\n    - a: 1\n        b:\n            c: 2\n    - x"
    for line in encoded.split("\n"):
        assert (len(line) - len(line.lstrip())) % 4 == 0


@pytest.mark.parametrize("name", ["note\n", "note\r", "note\n\n"])
def test_a_key_carrying_a_newline_is_quoted(name: str) -> None:
    """A regex "$" also matches just before a trailing newline, so such a key
    passed for a bare one and split the line it was written on, turning one
    field into a line of its own plus an orphaned value."""
    encoded = encode({name: "x"})
    assert len(encoded.split("\n")) == 1
    assert encoded.startswith('"note')


def test_an_indent_that_cannot_carry_structure_is_refused() -> None:
    with pytest.raises(ValueError, match="at least one space"):
        encode({"a": {"b": 1}}, indent=0)


def test_root_scalar_and_root_arrays() -> None:
    assert encode("bare") == "bare"
    assert encode([]) == "[]"
    assert encode([1, 2]) == "[2]: 1,2"


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        (None, "null"),
        (True, "true"),
        (False, "false"),
        (0, "0"),
        (-0.0, "0"),
        (1.5, "1.5"),
        (1.0, "1"),
        (1000000, "1000000"),
        (0.000001, "0.000001"),
        (1e-7, "1e-07"),
    ],
)
def test_primitive_rendering(value: object, expected: str) -> None:
    assert encode({"v": value}) == f"v: {expected}"


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("Ada", "Ada"),
        ("", '""'),
        (" pad ", '" pad "'),
        ("true", '"true"'),
        ("null", '"null"'),
        ("42", '"42"'),
        ("1.5e3", '"1.5e3"'),
        ("contains: colon", '"contains: colon"'),
        ("a,b", '"a,b"'),
        ("br[ack]et", '"br[ack]et"'),
        ("br{ac}e", '"br{ac}e"'),
        ("-dash", '"-dash"'),
        ("#hash", '"#hash"'),
        ('say "hi"', '"say \\"hi\\""'),
        ("back\\slash", '"back\\\\slash"'),
        ("line\nbreak", '"line\\nbreak"'),
        ("carriage\rreturn", '"carriage\\rreturn"'),
        ("tab\there", '"tab\\there"'),
        ("bell\x07", '"bell\\u0007"'),
    ],
)
def test_string_quoting_and_escaping(text: str, expected: str) -> None:
    assert encode({"v": text}) == f"v: {expected}"


@pytest.mark.parametrize(
    ("name", "expected"),
    [("user_id", "user_id"), ("x.y", "x.y"), ("my-key", '"my-key"'), ("", '""')],
)
def test_key_quoting(name: str, expected: str) -> None:
    assert encode({name: 1}) == f"{expected}: 1"


@pytest.mark.parametrize(
    "value",
    [
        10**25,
        10**400,
        12345678901234567890123456789,
        -(10**30),
        2**53 + 1,
    ],
    ids=["big", "beyond-float-range", "more-digits-than-float", "negative", "2**53+1"],
)
def test_large_integers_keep_every_digit(value: int) -> None:
    """Integers are arbitrary precision in Python and in JSON; rendering them
    through a float would round the low digits away and overflow past 1e308."""
    assert encode({"v": value}) == f"v: {value}"


@pytest.mark.parametrize(
    "value",
    [1.2345678901234567e-06, 1e-06, 1.5e20, 0.1, 1 / 3, 123456789.123456789, 5e-07],
)
def test_floats_survive_a_round_trip(value: float) -> None:
    """TOON is a lossless encoding, so the text must parse back to the value."""
    assert float(encode({"v": value}).removeprefix("v: ")) == value


def test_lone_surrogates_are_refused() -> None:
    """A lone surrogate has no TOON representation: literal, it is text no UTF-8
    stream can write, and escaped, it is an escape decoders must reject. The
    specification rules out substituting U+FFFD too, leaving only refusal."""
    with pytest.raises(ValueError, match="no TOON representation"):
        encode({"v": "\ud800"})
    with pytest.raises(ValueError, match="no TOON representation"):
        encode({"\ud800": "v"})


def test_an_interior_space_does_not_force_quoting() -> None:
    """Only a leading or trailing space is ambiguous. Quoting the rest would
    cost the compactness the format exists for."""
    assert encode({"v": "hello world"}) == "v: hello world"


def test_non_finite_numbers_become_null() -> None:
    """TOON has no notation for them, and the specification names null as the
    replacement. Python's JSON parser accepts all three, so they do arrive."""
    assert encode({"v": float("nan")}) == "v: null"
    assert encode({"v": float("inf")}) == "v: null"
    assert encode({"v": float("-inf")}) == "v: null"


def test_values_outside_json_are_rejected() -> None:
    with pytest.raises(TypeError, match="no TOON representation"):
        encode({"v": {1, 2}})


def test_toon_is_shorter_than_json_for_uniform_rows() -> None:
    """The whole point of the format: fewer characters for the same data."""
    import json

    payload = {"data": [{"id": n, "status": "reported"} for n in range(20)]}
    assert len(encode(payload)) < len(json.dumps(payload)) / 2
