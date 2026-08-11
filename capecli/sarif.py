"""SARIF 2.1.0 rendering of CAPE findings.

See https://docs.oasis-open.org/sarif/sarif/v2.1.0/. SARIF describes findings —
a rule that fired, how severe it was, and what it fired on — so only the CAPE
responses that carry findings are rendered: the signatures in an analysis
report, and the indicators in an IOC response.

The builders are deliberately tolerant. A CAPE deployment may omit fields, and
a report whose shape is not recognised yields a valid run with no results
rather than an exception.
"""

from typing import Any

SCHEMA = (
    "https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/"
    "sarif-schema-2.1.0.json"
)
VERSION = "2.1.0"
TOOL_NAME = "CAPE"
TOOL_URI = "https://github.com/kevoreilly/CAPEv2"
DEFAULT_LEVEL = "warning"

JsonDict = dict[str, Any]

# CAPE scores signatures from 1 (informational) upwards.
_LEVELS = {1: "note", 2: "warning", 3: "error"}


def _section(payload: JsonDict, name: str) -> object:
    """Read a top-level key, tolerating the ``data`` envelope CAPE often adds."""
    if name in payload:
        return payload[name]
    envelope = payload.get("data")
    if isinstance(envelope, dict):
        return envelope.get(name)
    return None


def _level(severity: object) -> str:
    if isinstance(severity, bool) or not isinstance(severity, int):
        return DEFAULT_LEVEL
    return _LEVELS.get(severity, "error" if severity > 3 else DEFAULT_LEVEL)


def _text(value: object, fallback: str) -> str:
    return value if isinstance(value, str) and value else fallback


def _location(payload: JsonDict) -> tuple[list[JsonDict], dict[str, str]]:
    """Point findings at the analyzed sample when the report names one."""
    target = _section(payload, "target")
    sample = target.get("file") if isinstance(target, dict) else None
    if not isinstance(sample, dict):
        return [], {}
    name = sample.get("name")
    digest = sample.get("sha256")
    locations = (
        [{"physicalLocation": {"artifactLocation": {"uri": name}}}]
        if isinstance(name, str) and name
        else []
    )
    fingerprints = {"sha256": digest} if isinstance(digest, str) and digest else {}
    return locations, fingerprints


def _document(rules: list[JsonDict], results: list[JsonDict], version: str) -> JsonDict:
    driver: JsonDict = {
        "name": TOOL_NAME,
        "informationUri": TOOL_URI,
        "rules": rules,
    }
    if version:
        driver["version"] = version
    return {
        "$schema": SCHEMA,
        "version": VERSION,
        "runs": [{"tool": {"driver": driver}, "results": results}],
    }


def report_to_sarif(payload: JsonDict) -> JsonDict:
    """Render the signatures of an analysis report as SARIF results."""
    signatures = _section(payload, "signatures")
    info = _section(payload, "info")
    version = ""
    if isinstance(info, dict):
        version = _text(info.get("version"), "")
    locations, fingerprints = _location(payload)

    rules: list[JsonDict] = []
    seen: set[str] = set()
    results: list[JsonDict] = []
    for signature in signatures if isinstance(signatures, list) else []:
        if not isinstance(signature, dict):
            continue
        name = _text(signature.get("name"), "")
        if not name:
            continue
        description = _text(signature.get("description"), name)
        if name not in seen:
            seen.add(name)
            rules.append(
                {
                    "id": name,
                    "name": name,
                    "shortDescription": {"text": description},
                    "properties": {"severity": signature.get("severity")},
                }
            )
        result: JsonDict = {
            "ruleId": name,
            "level": _level(signature.get("severity")),
            "message": {"text": description},
        }
        if locations:
            result["locations"] = locations
        if fingerprints:
            result["partialFingerprints"] = fingerprints
        results.append(result)
    return _document(rules, results, version)


def iocs_to_sarif(payload: JsonDict) -> JsonDict:
    """Render indicators as informational results, one per indicator."""
    section = _section(payload, "data")
    indicators = section if isinstance(section, dict) else payload

    rules: list[JsonDict] = []
    results: list[JsonDict] = []
    for name, values in indicators.items():
        if not isinstance(values, list):
            continue
        scalars = [value for value in values if isinstance(value, str) and value]
        if not scalars:
            continue
        rule_id = f"ioc/{name}"
        rules.append(
            {
                "id": rule_id,
                "name": rule_id,
                "shortDescription": {"text": f"Indicator of type {name}"},
            }
        )
        results.extend(
            {
                "ruleId": rule_id,
                "level": "note",
                "message": {"text": value},
            }
            for value in scalars
        )
    return _document(rules, results, "")
