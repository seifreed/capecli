"""Tests for the SARIF 2.1.0 rendering of CAPE findings."""

from typing import Any

import pytest

from capecli.sarif import SCHEMA, VERSION, iocs_to_sarif, report_to_sarif

JsonDict = dict[str, Any]

REPORT: JsonDict = {
    "info": {"version": "2.6"},
    "target": {"file": {"name": "sample.exe", "sha256": "ab" * 32}},
    "signatures": [
        {
            "name": "antivm_generic_disk",
            "description": "Checks for disk artifacts",
            "severity": 3,
        },
        {
            "name": "network_http",
            "description": "Performs HTTP requests",
            "severity": 1,
        },
    ],
}


def _run(document: JsonDict) -> JsonDict:
    runs = document["runs"]
    assert isinstance(runs, list) and len(runs) == 1
    first = runs[0]
    assert isinstance(first, dict)
    return first


def test_document_carries_the_required_envelope() -> None:
    document = report_to_sarif(REPORT)
    assert document["$schema"] == SCHEMA
    assert document["version"] == VERSION
    driver = _run(document)["tool"]["driver"]
    assert driver["name"] == "CAPE"
    assert driver["version"] == "2.6"


def test_each_signature_becomes_a_result() -> None:
    results = _run(report_to_sarif(REPORT))["results"]
    assert [result["ruleId"] for result in results] == [
        "antivm_generic_disk",
        "network_http",
    ]
    assert [result["message"]["text"] for result in results] == [
        "Checks for disk artifacts",
        "Performs HTTP requests",
    ]


def test_signatures_become_rules_once_each() -> None:
    payload = {**REPORT, "signatures": REPORT["signatures"] + REPORT["signatures"]}
    run = _run(report_to_sarif(payload))
    assert len(run["results"]) == 4
    assert [rule["id"] for rule in run["tool"]["driver"]["rules"]] == [
        "antivm_generic_disk",
        "network_http",
    ]


def test_results_point_at_the_analyzed_sample() -> None:
    result = _run(report_to_sarif(REPORT))["results"][0]
    uri = result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
    assert uri == "sample.exe"
    assert result["partialFingerprints"]["sha256"] == "ab" * 32


@pytest.mark.parametrize(
    ("severity", "level"),
    [(1, "note"), (2, "warning"), (3, "error"), (9, "error"), (None, "warning")],
)
def test_severity_maps_onto_sarif_levels(severity: object, level: str) -> None:
    payload = {"signatures": [{"name": "s", "severity": severity}]}
    assert _run(report_to_sarif(payload))["results"][0]["level"] == level


def test_signature_without_a_description_falls_back_to_its_name() -> None:
    payload = {"signatures": [{"name": "bare"}]}
    assert _run(report_to_sarif(payload))["results"][0]["message"]["text"] == "bare"


def test_report_wrapped_in_the_data_envelope_is_read() -> None:
    wrapped = {"error": False, "data": REPORT}
    assert len(_run(report_to_sarif(wrapped))["results"]) == 2


@pytest.mark.parametrize(
    "payload",
    [
        {},
        {"signatures": []},
        {"signatures": "not-a-list"},
        {"signatures": ["not-an-object"]},
        {"signatures": [{"description": "nameless"}]},
        {"data": "not-an-object"},
    ],
    ids=["empty", "none", "wrong-type", "loose-item", "no-name", "bad-envelope"],
)
def test_unrecognised_shapes_yield_an_empty_run_rather_than_an_error(
    payload: JsonDict,
) -> None:
    """A CAPE deployment may omit fields; that must not crash the renderer."""
    run = _run(report_to_sarif(payload))
    assert run["results"] == []
    assert run["tool"]["driver"]["rules"] == []
    assert "version" not in run["tool"]["driver"]


def test_wrongly_typed_fields_fall_back_instead_of_leaking_through() -> None:
    """A CAPE deployment may put a number where a string belongs; SARIF requires
    strings in these positions, so the fallback has to win."""
    payload = {
        "signatures": [{"name": "s", "description": 12345}],
        "target": {"file": {"name": 99, "sha256": 1234}},
    }
    result = _run(report_to_sarif(payload))["results"][0]
    assert result["message"]["text"] == "s"
    assert "locations" not in result
    assert "partialFingerprints" not in result


def test_report_without_a_sample_omits_locations() -> None:
    payload = {"signatures": [{"name": "s"}], "target": {"file": {}}}
    result = _run(report_to_sarif(payload))["results"][0]
    assert "locations" not in result
    assert "partialFingerprints" not in result


def test_target_that_is_not_an_object_is_ignored() -> None:
    payload = {"signatures": [{"name": "s"}], "target": "loose"}
    assert "locations" not in _run(report_to_sarif(payload))["results"][0]


def test_indicators_become_informational_results() -> None:
    run = _run(iocs_to_sarif({"data": {"domains": ["evil.tld", "bad.tld"]}}))
    assert [result["message"]["text"] for result in run["results"]] == [
        "evil.tld",
        "bad.tld",
    ]
    assert {result["level"] for result in run["results"]} == {"note"}
    assert run["tool"]["driver"]["rules"][0]["id"] == "ioc/domains"


def test_indicators_without_the_data_envelope() -> None:
    assert len(_run(iocs_to_sarif({"hosts": ["1.2.3.4"]}))["results"]) == 1


@pytest.mark.parametrize(
    "payload",
    [{}, {"domains": []}, {"domains": "not-a-list"}, {"domains": [1, 2]}],
    ids=["empty", "empty-list", "wrong-type", "non-string-items"],
)
def test_ioc_shapes_that_carry_nothing_yield_an_empty_run(payload: JsonDict) -> None:
    assert _run(iocs_to_sarif(payload))["results"] == []
