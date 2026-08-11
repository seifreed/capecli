"""The package surface is a contract, so it is exercised through the package.

Importing a submodule directly, as the other test modules do, proves nothing
about what ``import capecli`` actually offers: a name can sit in ``__all__``
long after the thing it points at has moved or gone.
"""

import capecli


def test_every_exported_name_resolves() -> None:
    missing = [name for name in capecli.__all__ if not hasattr(capecli, name)]
    assert missing == []


def test_exports_are_unique() -> None:
    assert sorted(set(capecli.__all__)) == sorted(capecli.__all__)


def test_toon_encoding_through_the_package() -> None:
    assert capecli.to_toon({"name": "Ada"}) == "name: Ada"


def test_sarif_building_through_the_package() -> None:
    document = capecli.report_to_sarif({"signatures": [{"name": "antivm"}]})
    assert document["version"] == "2.1.0"
    assert document["runs"][0]["results"][0]["ruleId"] == "antivm"
    assert capecli.iocs_to_sarif({"domains": ["evil.tld"]})["runs"][0]["results"]


def test_errors_share_one_base_through_the_package() -> None:
    assert issubclass(capecli.ApiError, capecli.CapeError)
    assert issubclass(capecli.ConfigError, capecli.CapeError)
