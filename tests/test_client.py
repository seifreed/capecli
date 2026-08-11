"""Tests for capecli.client against the in-process fake CAPE server."""

import os
import socket
import tempfile
import time
import tracemalloc
from collections.abc import Callable
from pathlib import Path

import pytest
from conftest import GZIP_BOMB_PLAIN_SIZE

from capecli.client import (
    TASK_RANGE_LIMIT,
    CapeClient,
    _file_payload,
    _temporary_prefix,
)
from capecli.config import Config
from capecli.errors import ApiError, ConfigError


def _closed_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.bind(("127.0.0.1", 0))
        return int(probe.getsockname()[1])


def test_obtain_token(cape_url: str) -> None:
    """The one call made without a token, since it is what fetches one."""
    with CapeClient(Config(url=cape_url)) as anonymous:
        assert anonymous.obtain_token("seifreed", "secret") == "t" * 40


@pytest.mark.parametrize("username", ["notoken", "emptytoken"])
def test_obtain_token_without_a_usable_token_in_the_response(
    cape_url: str, username: str
) -> None:
    """An absent token and an empty one are equally unusable for authenticating."""
    with (
        CapeClient(Config(url=cape_url)) as anonymous,
        pytest.raises(ApiError, match="carried no token"),
    ):
        anonymous.obtain_token(username, "secret")


def test_authorization_header_sent(client: CapeClient) -> None:
    assert client.cape_status()["authorization"] == "Token test-token"


def test_no_token_means_no_authorization_header(cape_url: str) -> None:
    with CapeClient(Config(url=cape_url)) as anonymous:
        assert anonymous.cape_status()["authorization"] == ""


def test_token_whitespace_is_trimmed(cape_url: str) -> None:
    """A token read from a file often carries a trailing newline."""
    with CapeClient(Config(url=cape_url, token="  test-token\n")) as cape:
        assert cape.cape_status()["authorization"] == "Token test-token"


@pytest.mark.parametrize(
    ("secret", "reason"),
    [
        ("tok\nX-Injected: 1", "control characters"),
        ("tokén", "non-ASCII"),
        ("tok\U0001f525", "non-ASCII"),
    ],
    ids=["header-injection", "accent", "emoji"],
)
def test_tokens_unusable_as_a_header_are_rejected_without_echoing_them(
    cape_url: str, secret: str, reason: str
) -> None:
    """Header values are ASCII, so anything else fails at request time as a
    codec complaint unless it is refused here as the configuration problem
    it is. The token itself never reaches the message."""
    with pytest.raises(ConfigError) as excinfo:
        CapeClient(Config(url=cape_url, token=secret))
    assert secret not in str(excinfo.value)
    assert reason in str(excinfo.value)


def test_trailing_slashes_in_url_do_not_double_up(cape_url: str) -> None:
    """A Config built directly (library use) must tolerate a trailing slash."""
    with CapeClient(Config(url=cape_url + "///")) as cape:
        assert cape.cape_status()["path"] == "/apiv2/cuckoo/status/"


def test_malformed_url_raises_config_error() -> None:
    with pytest.raises(ConfigError, match="Invalid CAPE URL"):
        CapeClient(Config(url="http://example.com:not-a-port"))


@pytest.mark.parametrize("url", ["cape.example.tld", "", "ftp://cape.example.tld"])
def test_a_url_without_a_usable_scheme_is_a_config_error(url: str) -> None:
    """httpx accepts a schemeless base URL and only objects once a request is
    made, where the failure reads as an unreachable server rather than as the
    setting it is."""
    with pytest.raises(ConfigError, match="needs an http:// or https:// scheme"):
        CapeClient(Config(url=url))


def test_an_apikey_given_twice_is_refused(client: CapeClient) -> None:
    """CAPE reads the key out of the analyzer options, so both spellings land
    in one field and honouring either would discard the other."""
    with pytest.raises(ValueError, match="'apikey' is already set"):
        client.submit_download_service(
            "deadbeef", apikey="explicit", options={"apikey": "in-options"}
        )


def test_file_option_is_reserved(client: CapeClient, tmp_path: Path) -> None:
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"content")
    with pytest.raises(ValueError, match="reserved for the uploaded sample"):
        client.submit_file(sample, arguments={"file": "injected"})


def test_argument_colliding_with_a_generated_field_is_refused(
    client: CapeClient,
) -> None:
    """Both sources name one CAPE field, so honouring either discards the other."""
    with pytest.raises(ValueError, match="'machine', 'options'"):
        client.submit_url(
            "http://example.tld",
            machine="vm1",
            options={"procdump": 1},
            arguments={"machine": "vm2", "options": "route=tor"},
        )


def test_argument_survives_when_its_dedicated_parameter_is_unused(
    client: CapeClient,
) -> None:
    """Nothing else fills the field, so the argument is the only way to reach it."""
    result = client.submit_url(
        "http://example.tld", arguments={"machine": "vm2", "options": "route=tor"}
    )
    assert "machine=vm2" in result["body"]
    assert "options=route%3Dtor" in result["body"]


@pytest.mark.parametrize("value", ["..", "."])
def test_relative_path_segments_stay_in_their_position(
    client: CapeClient, value: str
) -> None:
    """A value of ".." would otherwise be resolved away before the request left
    the client, silently querying a shorter path than the one asked for."""
    result = client.file_view("md5", value)
    encoded = value.replace(".", "%2E")
    assert result["path"] == f"/apiv2/files/view/md5/{encoded}/"


@pytest.mark.parametrize(
    "call",
    [
        pytest.param(lambda c: c.file_view("md5", ""), id="file_view"),
        pytest.param(lambda c: c.task_search("md5", ""), id="task_search"),
        pytest.param(lambda c: c.task_config(1, ""), id="task_config"),
        pytest.param(
            lambda c: c.file_download("md5", "", Path("x")), id="file_download"
        ),
    ],
)
def test_an_empty_path_segment_is_refused(
    client: CapeClient, call: Callable[[CapeClient], object]
) -> None:
    """An empty value collapses "files/view/md5//" into "files/view/md5/" on any
    server that folds repeated slashes, which queries the endpoint one level up
    instead of reporting the value as missing."""
    with pytest.raises(ValueError, match="path segment is empty"):
        call(client)


@pytest.mark.parametrize(
    "name",
    [
        # The surrogates are written out rather than obtained from
        # os.fsdecode(b"capture\xff\xfe.pcap"): that is what POSIX hands back
        # for those bytes, but Windows decodes filenames with surrogatepass
        # rather than surrogateescape, and raises on them instead -- at import,
        # taking the whole module's collection with it.
        pytest.param("capture\udcff\udcfe.pcap", id="no-codec-can-spell"),
        pytest.param("中" * 40, id="three-byte-characters"),
        pytest.param("\U0001f600" * 40, id="four-byte-characters"),
        pytest.param("é" * 80, id="two-byte-characters"),
        pytest.param("a" * 400, id="ascii"),
        pytest.param("\udcff" * 400, id="undecodable-bytes"),
        pytest.param("", id="empty"),
    ],
)
def test_a_temporary_can_be_named_after_any_destination_the_system_accepts(
    tmp_path: Path, name: str
) -> None:
    """A filename is bytes to the operating system, and the ones it accepts need
    not spell a valid string, nor survive a cut made partway through a character.
    Either one raised while naming the temporary, failing a download to a path
    the filesystem would have taken. Creating one is the whole contract.
    """
    handle, created = tempfile.mkstemp(dir=tmp_path, prefix=_temporary_prefix(name))
    os.close(handle)
    assert Path(created).is_file()


@pytest.mark.parametrize(
    "name",
    [
        pytest.param("中" * 40, id="three-byte-characters"),
        pytest.param("\U0001f600" * 40, id="four-byte-characters"),
        pytest.param("a" * 400, id="ascii"),
        pytest.param("\udcff" * 400, id="undecodable-bytes"),
    ],
)
def test_a_temporary_name_stays_within_the_byte_limit(name: str) -> None:
    """Filesystems bound a name in bytes, and one character can be four of them,
    so a cut made on characters would not bound anything."""
    assert len(os.fsencode(_temporary_prefix(name))) <= 102


def test_a_compressed_body_is_not_decoded_to_read_its_envelope(
    client: CapeClient, tmp_path: Path
) -> None:
    """Decoding is what has no bound: a body small on the wire is not small
    once decoded. The failure is still reported, without the envelope detail."""
    with pytest.raises(ApiError, match="Expected file content") as caught:
        client.task_pcap(207, tmp_path / "dump.pcap")
    assert "gzipped" not in str(caught.value)


def test_a_compressed_body_costs_no_more_than_it_weighs(
    client: CapeClient, tmp_path: Path
) -> None:
    """The reason an encoded body is left unread, stated as the cost itself.

    Refusing one used to decode it whole first, so a body that was nothing on
    the wire spent whatever it decoded to. Asserting the message alone cannot
    tell the two apart: undecoded gzip is not JSON either, so both spellings
    report the same failure and only the memory says which one ran.
    """
    tracemalloc.start()
    try:
        with pytest.raises(ApiError, match="Expected file content"):
            client.task_pcap(208, tmp_path / "dump.pcap")
        peak = tracemalloc.get_traced_memory()[1]
    finally:
        tracemalloc.stop()
    assert peak < GZIP_BOMB_PLAIN_SIZE // 4


@pytest.mark.parametrize(
    "download",
    [
        pytest.param(lambda c, d: c.task_keys(7, "tls", d), id="text-plain"),
        pytest.param(lambda c, d: c.task_etw(7, "all", d), id="application-x-ndjson"),
        pytest.param(lambda c, d: c.task_pcap(7, d), id="vnd-tcpdump-pcap"),
        pytest.param(lambda c, d: c.task_surifile(7, d), id="octet-stream-empty-param"),
        pytest.param(lambda c, d: c.task_dropped(7, d), id="application-zip"),
    ],
)
def test_an_artifact_is_saved_whatever_media_type_cape_serves_it_as(
    client: CapeClient,
    tmp_path: Path,
    download: Callable[[CapeClient, Path], Path],
) -> None:
    """CAPE serves artifacts as zip, as a capture, as plain text and as
    newline-delimited JSON, one of which is a text type and one of which spells
    its media type with an empty trailing parameter. Only JSON and HTML mean
    the body is not the artifact; everything else is the file that was asked
    for, and narrowing that to a list of known types would refuse real ones.
    """
    saved = download(client, tmp_path / "artifact")
    assert saved.read_bytes().startswith(b"/apiv2/tasks/get/")


def test_a_report_format_is_accepted_in_any_case(client: CapeClient) -> None:
    """The format is passed on as given and only our own expectation of the
    body is decided from it, so the case it was typed in must not decide
    whether the call is refused."""
    assert client.task_report(7, "JSON")["path"] == "/apiv2/tasks/get/report/7/JSON/"


def test_a_zero_valued_field_is_sent_rather_than_dropped(client: CapeClient) -> None:
    """Only an unset field is left out. A Unix timestamp of zero is a value the
    caller chose, and dropping it would widen the query it asked to narrow."""
    assert "completed_after=0" in client.tasks_list(10, 0, completed_after=0)["query"]


def test_a_json_body_past_the_envelope_ceiling_is_left_unread(
    client: CapeClient, tmp_path: Path
) -> None:
    """Reading stops at the ceiling, so a body too large to be an envelope is
    reported on without being buffered whole to find that out."""
    with pytest.raises(ApiError, match="Expected file content"):
        client.task_pcap(66, tmp_path / "dump.pcap")


@pytest.mark.parametrize("task_id", [100, 101], ids=["text/html", "TEXT/HTML"])
def test_html_on_a_json_endpoint_is_reported_as_a_restriction(
    client: CapeClient, task_id: int
) -> None:
    """A restricted endpoint answers with the web UI and a 200, which read as a
    parse failure until the content type was checked. Media types are
    case-insensitive, so the spelling must not decide whether it is noticed."""
    with pytest.raises(ApiError, match="endpoint restricted or unavailable"):
        client.task_view(task_id)


@pytest.mark.parametrize("task_id", [100, 101], ids=["text/html", "TEXT/HTML"])
def test_a_download_never_writes_the_web_ui_to_disk(
    client: CapeClient, tmp_path: Path, task_id: int
) -> None:
    """Saved under a .pcap name, the login page would look like a capture."""
    dest = tmp_path / "dump.pcap"
    with pytest.raises(ApiError, match="endpoint restricted or unavailable"):
        client.task_pcap(task_id, dest)
    assert not dest.exists()


def test_a_failing_status_carries_the_reason_the_server_gave(
    client: CapeClient,
) -> None:
    """CAPE answers many failures with a status code and an envelope naming the
    cause. Reporting the code alone leaves the caller guessing which it was."""
    with pytest.raises(ApiError, match=r"HTTP 503 .*: Task not found") as excinfo:
        client.task_view(503)
    assert excinfo.value.status_code == 503


def test_a_failing_download_reports_its_status_without_reading_the_body(
    client: CapeClient, tmp_path: Path, stalled_body_seconds: float
) -> None:
    """A download's body has not arrived when the status is checked, and the
    reason inside it is not worth what fetching it costs: this server never
    sends the body at all, so anything that waited on it would wait the whole
    read timeout for an error the status line already carried."""
    dest = tmp_path / "dump.pcap"
    started = time.monotonic()
    with pytest.raises(ApiError, match=r"HTTP 500 for tasks/get/pcap/205/$") as excinfo:
        client.task_pcap(205, dest)
    assert time.monotonic() - started < stalled_body_seconds
    assert excinfo.value.status_code == 500
    assert not dest.exists()


@pytest.mark.parametrize(
    "task_id",
    [500, 502, 504, 507],
    ids=[
        "not-json",
        "json-that-does-not-parse",
        "json-that-is-not-an-envelope",
        "a-stated-cause-larger-than-any-envelope",
    ],
)
def test_a_failing_status_with_no_reason_to_report_still_reports(
    client: CapeClient, task_id: int
) -> None:
    """A body that is not JSON, JSON that does not parse, and JSON that names
    no cause all leave the status code as the whole of what is known. Looking
    for a reason must not fail while a failure is already being reported."""
    with pytest.raises(ApiError, match=rf"HTTP {task_id} for tasks/view/{task_id}/$"):
        client.task_view(task_id)


def test_a_response_too_deep_to_parse_is_reported(client: CapeClient) -> None:
    """The parser recurses once per nesting level and the server picks how many
    there are, so a deep enough payload ends the process instead of the
    request unless it is caught where every other parse failure is."""
    with pytest.raises(ApiError, match="nests too deeply"):
        client.task_view(199)


def test_a_json_report_can_be_saved_to_a_file(
    client: CapeClient, tmp_path: Path
) -> None:
    """CAPE serves json, maec5 and litereport as JSON, so refusing a JSON body
    here refused the report itself rather than an endpoint serving the wrong
    thing. The error envelope is still JSON and still has to be ruled out."""
    dest = client.task_report_file(7, tmp_path / "report.json", "json")
    assert "/apiv2/tasks/get/report/7/json/" in dest.read_text(encoding="utf-8")


def test_a_json_report_too_large_to_be_an_envelope_is_kept(
    client: CapeClient, tmp_path: Path
) -> None:
    """The envelope check reads the saved file back, so it has a ceiling: past
    the size an envelope could be, the file is the report and stays put. A
    report can be hundreds of megabytes, and it was streamed to avoid holding
    one in memory."""
    dest = client.task_report_file(66, tmp_path / "report.json", "json")
    assert dest.stat().st_size > 64 * 1024


def test_a_json_report_that_does_not_parse_is_left_as_it_arrived(
    client: CapeClient, tmp_path: Path
) -> None:
    """Only an error envelope is worth rejecting. A body that does not parse is
    the server's business, and discarding what it sent would help no one."""
    dest = client.task_report_file(400, tmp_path / "report.json", "json")
    assert dest.read_bytes() == b"not-json"


def test_a_json_report_that_is_an_error_envelope_is_not_saved(
    client: CapeClient, tmp_path: Path
) -> None:
    dest = tmp_path / "report.json"
    with pytest.raises(ApiError, match="task not found"):
        client.task_report_file(404, dest, "json")
    assert not dest.exists()
    assert list(tmp_path.iterdir()) == []


def test_an_envelope_where_a_report_was_expected_spares_the_earlier_one(
    client: CapeClient, tmp_path: Path
) -> None:
    """The envelope cannot be told from the report until it is parsed, so it
    is parsed where it lands -- beside the destination. Recognising it after
    moving it into place would already have destroyed the earlier report."""
    dest = tmp_path / "report.json"
    dest.write_bytes(b"a good report from an earlier run")
    with pytest.raises(ApiError, match="task not found"):
        client.task_report_file(404, dest, "json")
    assert dest.read_bytes() == b"a good report from an earlier run"
    assert list(tmp_path.iterdir()) == [dest]


@pytest.mark.parametrize("fmt", ["maec", "metadata", "all", "pdf"])
def test_a_report_format_that_is_not_json_is_refused_by_the_json_call(
    client: CapeClient, fmt: str
) -> None:
    """CAPE serves these as XML, PDF or a zip bundle. None can come back as a
    dict, so the request cannot succeed however the server behaves."""
    with pytest.raises(ValueError, match="is not JSON"):
        client.task_report(7, fmt)


def test_a_download_answered_with_an_error_envelope_is_not_saved(
    client: CapeClient, tmp_path: Path
) -> None:
    """The envelope arrives as Application/JSON here, which is the same thing."""
    dest = tmp_path / "dump.pcap"
    with pytest.raises(ApiError, match="shouted"):
        client.task_pcap(102, dest)
    assert not dest.exists()


def test_a_download_that_dies_partway_leaves_the_earlier_file_alone(
    client: CapeClient, tmp_path: Path
) -> None:
    """The common failure: the connection drops with the body half sent.
    Writing to the destination would have emptied it before the first byte
    arrived, so the file an earlier download left there would be gone."""
    dest = tmp_path / "earlier.pcap"
    dest.write_bytes(b"an earlier download")
    with pytest.raises(ApiError, match="Request failed"):
        client.task_pcap(206, dest)
    assert dest.read_bytes() == b"an earlier download"
    assert list(tmp_path.iterdir()) == [dest]


def test_a_download_that_cannot_be_moved_into_place_reports_why(
    client: CapeClient, tmp_path: Path
) -> None:
    """A destination that is a directory cannot be replaced by a file, and the
    partial write beside it goes away rather than outliving the attempt."""
    dest = tmp_path / "a-directory.pcap"
    dest.mkdir()
    with pytest.raises(IsADirectoryError):
        client.task_pcap(7, dest)
    assert dest.is_dir()
    assert list(tmp_path.iterdir()) == [dest]


@pytest.mark.parametrize(
    "stem",
    ["a" * 250, "\N{EARTH GLOBE EUROPE-AFRICA}" * 60],
    ids=["ascii-at-the-limit", "characters-of-four-bytes-each"],
)
def test_a_download_to_a_name_near_the_length_limit_still_works(
    client: CapeClient, tmp_path: Path, stem: str
) -> None:
    """The file written beside the destination is named after it, and a name
    already close to what the filesystem allows leaves nothing to add to. The
    limit counts bytes, so cutting the name by characters would overrun it."""
    dest = tmp_path / f"{stem}.pcap"
    assert client.task_pcap(7, dest) == dest
    assert dest.read_bytes() == b"/apiv2/tasks/get/pcap/7/"


def test_a_download_keeps_the_mode_of_the_file_it_replaces(
    client: CapeClient, tmp_path: Path
) -> None:
    """A temporary is created private, which suits a new artifact; carrying
    that over to a file the caller already had changes something they did not
    ask to change."""
    dest = tmp_path / "earlier.pcap"
    dest.write_bytes(b"an earlier download")
    dest.chmod(0o644)
    client.task_pcap(7, dest)
    assert dest.stat().st_mode & 0o777 == 0o644


def test_a_download_replaces_what_was_there_and_leaves_nothing_beside_it(
    client: CapeClient, tmp_path: Path
) -> None:
    dest = tmp_path / "earlier.pcap"
    dest.write_bytes(b"an earlier download")
    assert client.task_pcap(7, dest) == dest
    assert dest.read_bytes() == b"/apiv2/tasks/get/pcap/7/"
    assert list(tmp_path.iterdir()) == [dest]


@pytest.mark.parametrize(
    ("options", "message"),
    [
        ({"custom": "a,b"}, "cannot contain ','"),
        ({"a,b": "1"}, "cannot contain ',' or '='"),
        ({"a=b": "1"}, "cannot contain ',' or '='"),
    ],
    ids=["comma-in-value", "comma-in-name", "equals-in-name"],
)
def test_options_that_cannot_survive_the_format_are_refused(
    client: CapeClient, options: dict[str, str], message: str
) -> None:
    """CAPE's options string has no escaping, so "custom=a,b" would arrive as
    an option "custom" of "a" plus a stray option "b"."""
    with pytest.raises(ValueError, match=message):
        client.submit_url("http://bad.tld", options=options)


def test_task_delete_rejects_empty_sequence(client: CapeClient) -> None:
    with pytest.raises(ValueError, match="no task IDs given"):
        client.task_delete([])


def test_task_delete_rejects_empty_selector(client: CapeClient) -> None:
    with pytest.raises(ValueError, match="no task selector given"):
        client.task_delete("")


@pytest.mark.parametrize(
    ("task_id", "message", "status_code"),
    [
        (500, "HTTP 500", 500),
        (400, "Invalid JSON", 200),
        (300, "Unexpected JSON", 200),
        (404, "task not found", 200),
        (401, "capitalised error flag", 200),
        (403, "duplicate file", 200),
        (409, "Task\\(s\\) ID\\(s\\) 9999 failed to remove", 200),
        (410, "Was impossible to retrieve url", 200),
        (411, "capitalised error string", 200),
        (412, "Unknown CAPE API error", 200),
        (413, "Invalid token.", 401),
        (414, "Unable to log in with provided credentials.", 400),
    ],
)
def test_failed_json_request_raises(
    client: CapeClient, task_id: int, message: str, status_code: int
) -> None:
    """Every failure shape reaches the caller as an ApiError with its HTTP status."""
    with pytest.raises(ApiError, match=message) as excinfo:
        client.task_view(task_id)
    assert excinfo.value.status_code == status_code


def test_submit_file(client: CapeClient, tmp_path: Path) -> None:
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"sample-content")
    result = client.submit_file(
        sample,
        machine="vm1",
        pcap=True,
        options={"procdump": 1},
        arguments={"timeout": 120},
    )
    assert result["path"] == "/apiv2/tasks/create/file/"
    assert 'filename="sample.bin"' in result["body"]
    assert "sample-content" in result["body"]
    assert 'name="machine"' in result["body"]
    assert 'name="pcap"' in result["body"]
    # timeout is a top-level CAPE argument; procdump belongs in the options string.
    assert 'name="timeout"' in result["body"]
    assert 'name="options"' in result["body"]
    assert "procdump=1" in result["body"]


def test_pcap_submission_sends_the_flag_cape_expects(
    client: CapeClient, tmp_path: Path
) -> None:
    """CAPE reads this field as a flag, so the value it carries is the point."""
    sample = tmp_path / "capture.pcap"
    sample.write_bytes(b"capture")
    body = client.submit_file(sample, pcap=True)["body"]
    field = body.split('name="pcap"')[1]
    assert field.split("\r\n\r\n")[1].startswith("1")


def test_submit_file_defaults(client: CapeClient, tmp_path: Path) -> None:
    sample = tmp_path / "plain.bin"
    sample.write_bytes(b"plain")
    result = client.submit_file(sample)
    assert 'name="machine"' not in result["body"]
    assert 'name="pcap"' not in result["body"]


def test_file_payload_streams_from_an_open_handle(tmp_path: Path) -> None:
    """Samples upload from an open handle so large files are never buffered whole."""
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"streamed-content")
    with _file_payload(sample) as files:
        name, handle = files["file"]
        assert name == "sample.bin"
        assert not isinstance(handle, bytes)
        assert handle.read() == b"streamed-content"
    assert handle.closed


def test_submit_large_file_transfers_intact(client: CapeClient, tmp_path: Path) -> None:
    sample = tmp_path / "large.bin"
    sample.write_bytes(b"A" * (4 * 1024 * 1024))
    result = client.submit_file(sample)
    assert result["path"] == "/apiv2/tasks/create/file/"
    assert result["body"].count("A") == 4 * 1024 * 1024


def test_submit_file_missing_path_raises_oserror(
    client: CapeClient, tmp_path: Path
) -> None:
    with pytest.raises(FileNotFoundError):
        client.submit_file(tmp_path / "absent.bin")


def test_submit_static(client: CapeClient, tmp_path: Path) -> None:
    sample = tmp_path / "static.bin"
    sample.write_bytes(b"static-content")
    result = client.submit_static(sample, priority=3, options={"procdump": 1})
    assert result["path"] == "/apiv2/tasks/create/static/"
    assert "static-content" in result["body"]
    assert 'name="priority"' in result["body"]
    assert "procdump=1" in result["body"]


def test_submit_static_defaults(client: CapeClient, tmp_path: Path) -> None:
    sample = tmp_path / "plain.bin"
    sample.write_bytes(b"plain")
    body = client.submit_static(sample)["body"]
    assert 'name="priority"' not in body
    assert 'name="options"' not in body


def test_submit_url(client: CapeClient) -> None:
    result = client.submit_url("http://bad.tld", machine="vm2")
    assert result["path"] == "/apiv2/tasks/create/url/"
    assert "url=http%3A%2F%2Fbad.tld" in result["body"]
    assert "machine=vm2" in result["body"]


def test_submit_url_without_machine(client: CapeClient) -> None:
    assert "machine" not in client.submit_url("http://bad.tld")["body"]


def test_submit_dlnexec(client: CapeClient) -> None:
    result = client.submit_dlnexec("http://bad.tld/x.exe", machine="vm3")
    assert result["path"] == "/apiv2/tasks/create/dlnexec/"
    assert "dlnexec=http%3A%2F%2Fbad.tld%2Fx.exe" in result["body"]
    assert "machine=vm3" in result["body"]


def test_submit_dlnexec_without_machine(client: CapeClient) -> None:
    assert "machine" not in client.submit_dlnexec("http://bad.tld/x.exe")["body"]


def test_file_view(client: CapeClient) -> None:
    result = client.file_view("sha256", "ab" * 32)
    assert result["path"] == f"/apiv2/files/view/sha256/{'ab' * 32}/"


def test_file_download(client: CapeClient, tmp_path: Path) -> None:
    dest = client.file_download("task", 7, tmp_path / "sample.bin")
    assert dest.read_bytes() == b"/apiv2/files/get/task/7/"


def test_file_download_encrypted(client: CapeClient, tmp_path: Path) -> None:
    dest = client.file_download("md5", "x" * 32, tmp_path / "s.bin", encrypted=True)
    assert dest.read_bytes() == f"/apiv2/files/get/md5/{'x' * 32}/?encrypted=1".encode()


def test_task_search(client: CapeClient) -> None:
    result = client.task_search("md5", "y" * 32)
    assert result["path"] == f"/apiv2/tasks/search/md5/{'y' * 32}/"


def test_task_extended_search(client: CapeClient) -> None:
    result = client.task_extended_search("domain", "evil.tld")
    assert result["path"] == "/apiv2/tasks/extendedsearch/"
    assert "option=domain" in result["body"]
    assert "argument=evil.tld" in result["body"]
    assert "search_limit" not in result["body"]


def test_task_extended_search_limit(client: CapeClient) -> None:
    result = client.task_extended_search("domain", "evil.tld", search_limit=500)
    assert "search_limit=500" in result["body"]


def test_tasks_list_plain(client: CapeClient) -> None:
    result = client.tasks_list()
    assert result["path"] == "/apiv2/tasks/list/"
    assert result["query"] == ""


def test_tasks_list_limit(client: CapeClient) -> None:
    assert client.tasks_list(10)["path"] == "/apiv2/tasks/list/10/"


def test_tasks_list_limit_offset_and_filters(client: CapeClient) -> None:
    result = client.tasks_list(10, 20, status="reported", option="procdump")
    assert result["path"] == "/apiv2/tasks/list/10/20/"
    assert "status=reported" in result["query"]
    assert "option=procdump" in result["query"]


@pytest.mark.parametrize(
    "method_name",
    ["task_view", "task_status", "task_reschedule", "task_reprocess", "task_machine"],
)
def test_task_id_only_endpoints(client: CapeClient, method_name: str) -> None:
    """Every task-id JSON endpoint must build its own path."""
    endpoint = method_name.removeprefix("task_")
    result = getattr(client, method_name)(7)
    assert result["path"] == f"/apiv2/tasks/{endpoint}/7/"


def test_tasks_latest(client: CapeClient) -> None:
    assert client.tasks_latest(3)["path"] == "/apiv2/tasks/get/latests/3/"


def test_task_delete_single(client: CapeClient) -> None:
    assert client.task_delete(7)["path"] == "/apiv2/tasks/delete/7/"


def test_task_delete_many_with_status(client: CapeClient) -> None:
    result = client.task_delete([7, 8, 9], status="failed_analysis")
    assert result["path"] == "/apiv2/tasks/delete/7,8,9/failed_analysis/"


def test_task_delete_range(client: CapeClient) -> None:
    assert client.task_delete("7-9")["path"] == "/apiv2/tasks/delete/7-9/"


def test_tasks_statistics(client: CapeClient) -> None:
    assert client.tasks_statistics(14)["path"] == "/apiv2/tasks/statistics/14/"


def test_tasks_list_offset_requires_limit(client: CapeClient) -> None:
    with pytest.raises(ValueError, match="offset requires limit"):
        client.tasks_list(offset=20)


def test_redirect_raises_and_reports_location(client: CapeClient) -> None:
    with pytest.raises(ApiError, match="HTTP 302") as excinfo:
        client.task_view(302)
    assert excinfo.value.status_code == 302
    assert "/accounts/login/" in str(excinfo.value)


def test_task_report_default(client: CapeClient) -> None:
    assert client.task_report(7)["path"] == "/apiv2/tasks/get/report/7/"


def test_task_report_format(client: CapeClient) -> None:
    path = client.task_report(7, "litereport")["path"]
    assert path == "/apiv2/tasks/get/report/7/litereport/"


def test_task_report_zip(client: CapeClient, tmp_path: Path) -> None:
    dest = client.task_report_zip(7, tmp_path / "report.zip")
    assert dest.read_bytes() == b"/apiv2/tasks/get/report/7/json/zip/"


def test_task_report_zip_with_format(client: CapeClient, tmp_path: Path) -> None:
    dest = client.task_report_zip(7, tmp_path / "report.zip", "all")
    assert dest.read_bytes() == b"/apiv2/tasks/get/report/7/all/zip/"


@pytest.mark.parametrize("fmt", ["html", "HTML", "liteHtml"])
def test_an_html_report_is_expected_however_the_format_was_typed(
    client: CapeClient, tmp_path: Path, fmt: str
) -> None:
    """The format reaches CAPE as given; the case it was typed in must not
    decide whether the HTML that comes back looks like a restriction."""
    dest = client.task_report_file(7, tmp_path / "report.html", fmt)
    assert dest.read_bytes() == b"<html>report</html>"


def test_task_report_file_accepts_html(client: CapeClient, tmp_path: Path) -> None:
    """An explicitly requested HTML report is content, not a blocked page."""
    dest = client.task_report_file(7, tmp_path / "report.html", "html")
    assert dest.read_bytes() == b"<html>report</html>"


@pytest.mark.parametrize("fmt", ["metadata", "pdf", "maec"])
def test_task_report_file_other_format(
    client: CapeClient, tmp_path: Path, fmt: str
) -> None:
    """Every non-HTML format the method documents is written to disk as served."""
    dest = client.task_report_file(7, tmp_path / f"report.{fmt}", fmt)
    assert dest.read_bytes() == f"/apiv2/tasks/get/report/7/{fmt}/".encode()


def test_task_iocs(client: CapeClient) -> None:
    assert client.task_iocs(7)["path"] == "/apiv2/tasks/get/iocs/7/"


def test_task_iocs_detailed(client: CapeClient) -> None:
    result = client.task_iocs(7, detailed=True)
    assert result["path"] == "/apiv2/tasks/get/iocs/7/detailed/"


def test_task_config(client: CapeClient) -> None:
    assert client.task_config(7)["path"] == "/apiv2/tasks/get/config/7/"


def test_task_screenshot_single(client: CapeClient, tmp_path: Path) -> None:
    dest = client.task_screenshots(7, tmp_path / "shot.jpg", number=2)
    assert dest.read_bytes() == b"/apiv2/tasks/get/screenshot/7/2/"


def test_task_dropped_max_size(client: CapeClient, tmp_path: Path) -> None:
    dest = client.task_dropped(7, tmp_path / "dropped.zip", max_size=50)
    assert dest.read_bytes() == b"/apiv2/tasks/get/dropped/7/?max_size=50"


def test_task_selfextracted_tool(client: CapeClient, tmp_path: Path) -> None:
    dest = client.task_selfextracted(7, tmp_path / "sx.zip", tool="unpacker")
    assert dest.read_bytes() == b"/apiv2/tasks/get/selfextracted/7/unpacker/"


def test_task_procmemory_pid(client: CapeClient, tmp_path: Path) -> None:
    dest = client.task_procmemory(7, tmp_path / "mem.zip", pid=1234)
    assert dest.read_bytes() == b"/apiv2/tasks/get/procmemory/7/1234/"


@pytest.mark.parametrize(
    ("method_name", "endpoint"),
    [
        ("task_pcap", "pcap"),
        ("task_tlspcap", "tlspcap"),
        ("task_evtx", "evtx"),
        ("task_surifile", "surifile"),
        ("task_fullmemory", "fullmemory"),
        ("task_payloadfiles", "payloadfiles"),
        ("task_procdumpfiles", "procdumpfiles"),
        ("task_mitmdump", "mitmdump"),
        ("task_screenshots", "screenshot"),
        ("task_dropped", "dropped"),
        ("task_selfextracted", "selfextracted"),
        ("task_procmemory", "procmemory"),
    ],
)
def test_task_id_only_downloads(
    client: CapeClient, tmp_path: Path, method_name: str, endpoint: str
) -> None:
    """Called with just a task id, every download must target its own endpoint."""
    download = getattr(client, method_name)
    dest = download(7, tmp_path / method_name)
    assert dest.read_bytes() == f"/apiv2/tasks/get/{endpoint}/7/".encode()


def test_download_creates_parent_dirs(client: CapeClient, tmp_path: Path) -> None:
    dest = client.task_pcap(7, tmp_path / "nested" / "dir" / "dump.pcap")
    assert dest.is_file()


@pytest.mark.parametrize(
    ("task_id", "message"),
    [
        (500, "HTTP 500"),
        (302, "HTTP 302"),
        (404, "task not found"),
        (200, "Expected file content"),
        (100, "got an HTML page"),
        (206, "Request failed"),
    ],
)
def test_failed_download_raises_and_leaves_no_file(
    client: CapeClient, tmp_path: Path, task_id: int, message: str
) -> None:
    """A failed download raises ApiError and never leaves a partial file behind."""
    dest = tmp_path / "dump.pcap"
    with pytest.raises(ApiError, match=message):
        client.task_pcap(task_id, dest)
    assert not dest.exists()


def test_unreachable_host_raises_api_error() -> None:
    with (
        CapeClient(Config(url=f"http://127.0.0.1:{_closed_port()}", timeout=2)) as cape,
        pytest.raises(ApiError, match="Request failed"),
    ):
        cape.task_view(1)


def test_unreachable_host_download_raises_api_error(tmp_path: Path) -> None:
    with (
        CapeClient(Config(url=f"http://127.0.0.1:{_closed_port()}", timeout=2)) as cape,
        pytest.raises(ApiError, match="Request failed"),
    ):
        cape.task_pcap(1, tmp_path / "dump.pcap")


def test_submit_download_service(client: CapeClient) -> None:
    """CAPE reads the hashes field and takes the API key from the options string."""
    result = client.submit_download_service("deadbeef", apikey="vt-key")
    assert result["path"] == "/apiv2/tasks/create/download_services/"
    assert "hashes=deadbeef" in result["body"]
    assert "options=apikey%3Dvt-key" in result["body"]


def test_submit_download_service_without_apikey(client: CapeClient) -> None:
    """Servers holding the key themselves get no options string at all."""
    body = client.submit_download_service("deadbeef")["body"]
    assert "hashes=deadbeef" in body
    assert "apikey" not in body
    assert "options" not in body


def test_options_are_folded_into_one_field(client: CapeClient) -> None:
    result = client.submit_url(
        "http://bad.tld", options={"procdump": 1, "route": "tor"}
    )
    body = result["body"]
    assert "options=procdump%3D1%2Croute%3Dtor" in body
    assert "procdump=1&" not in body


def test_tasks_list_extra_filters(client: CapeClient) -> None:
    result = client.tasks_list(
        5, category="file", completed_after=1700000000, ids_only=True
    )
    assert "category=file" in result["query"]
    assert "completed_after=1700000000" in result["query"]
    assert "ids=1" in result["query"]


def test_tasks_list_window(client: CapeClient) -> None:
    result = client.tasks_list(10, 20, window=24)
    assert result["path"] == "/apiv2/tasks/list/10/20/24/"


def test_tasks_list_window_requires_offset(client: CapeClient) -> None:
    with pytest.raises(ValueError, match="window requires limit and offset"):
        client.tasks_list(10, window=24)


def test_task_config_family(client: CapeClient) -> None:
    result = client.task_config(7, "Emotet")
    assert result["path"] == "/apiv2/tasks/get/config/7/Emotet/"


def test_exit_nodes(client: CapeClient) -> None:
    assert client.exit_nodes()["path"] == "/apiv2/exitnodes/"


def test_tasks_stats(client: CapeClient) -> None:
    assert client.tasks_stats()["path"] == "/apiv2/tasks/stats/"


def test_task_pcap_variant(client: CapeClient, tmp_path: Path) -> None:
    dest = client.task_pcap(7, tmp_path / "sorted.pcap", variant="sorted")
    assert dest.read_bytes() == b"/apiv2/tasks/get/pcap/7/sorted/"


@pytest.mark.parametrize(
    ("method_name", "endpoint", "argument"),
    [
        ("task_keys", "keys", "tls"),
        ("task_etw", "etw", "all"),
        ("task_bulkzip", "bulkzip", "CAPE"),
    ],
)
def test_task_downloads_with_a_kind(
    client: CapeClient, tmp_path: Path, method_name: str, endpoint: str, argument: str
) -> None:
    """The kind lands as a path segment between the task id and the trailing slash."""
    dest = getattr(client, method_name)(7, argument, tmp_path / method_name)
    assert dest.read_bytes() == f"/apiv2/tasks/get/{endpoint}/7/{argument}/".encode()


def test_machines_list(client: CapeClient) -> None:
    assert client.machines_list()["path"] == "/apiv2/machines/list/"


def test_machine_view(client: CapeClient) -> None:
    result = client.machine_view("win10-x64")
    assert result["path"] == "/apiv2/machines/view/win10-x64/"


def test_cape_status(client: CapeClient) -> None:
    assert client.cape_status()["path"] == "/apiv2/cuckoo/status/"


def test_tasks_delete_many_ok(client: CapeClient) -> None:
    result = client.tasks_delete_many([1, 2, 3])
    assert result["status"] == "OK"
    assert result["deleted"] == ["1", "2", "3"]
    assert result["delete_mongo"] == "1"


def test_tasks_delete_many_keeps_reports(client: CapeClient) -> None:
    assert client.tasks_delete_many("1-5", delete_mongo=False)["delete_mongo"] == "0"


def test_tasks_delete_many_spells_out_a_range(client: CapeClient) -> None:
    """CAPE takes only all-digit ids here, so the range cannot travel as one."""
    assert client.tasks_delete_many("1-5")["deleted"] == ["1", "2", "3", "4", "5"]


def test_tasks_delete_many_mixes_a_range_into_a_list(client: CapeClient) -> None:
    assert client.tasks_delete_many("7,1-3")["deleted"] == ["7", "1", "2", "3"]


@pytest.mark.parametrize("selector", ["5-1", "a-3", "3-b"])
def test_tasks_delete_many_rejects_an_unusable_range(
    client: CapeClient, selector: str
) -> None:
    with pytest.raises(ValueError, match="invalid task range"):
        client.tasks_delete_many(selector)


def test_tasks_delete_many_refuses_an_enormous_range(client: CapeClient) -> None:
    """A slip of the keyboard would otherwise build the whole string first."""
    with pytest.raises(ValueError, match="more than 10000 IDs"):
        client.tasks_delete_many(f"1-{TASK_RANGE_LIMIT + 2}")


def test_tasks_delete_many_partial_failure_raises(client: CapeClient) -> None:
    with pytest.raises(ApiError):
        client.tasks_delete_many([99])


def test_upload_yara_ok(client: CapeClient, tmp_path: Path) -> None:
    rule = tmp_path / "r.yar"
    rule.write_text("rule x { condition: true }")
    assert client.upload_yara(rule, "CAPE")["status"] == "success"


def test_upload_yara_rejects_unknown_category(
    client: CapeClient, tmp_path: Path
) -> None:
    rule = tmp_path / "r.yar"
    rule.write_text("rule x { condition: true }")
    with pytest.raises(ValueError, match="not one of"):
        client.upload_yara(rule, "nope")


def test_upload_yara_surfaces_message_detail(
    client: CapeClient, tmp_path: Path
) -> None:
    """The uploader states the reason under "message", which the client reads."""
    rule = tmp_path / "bad.yar"
    rule.write_text("syntaxerror")
    with pytest.raises(ApiError, match="YARA Syntax Error"):
        client.upload_yara(rule, "CAPE")


def test_upload_yara_disabled_envelope(client: CapeClient, tmp_path: Path) -> None:
    rule = tmp_path / "d.yar"
    rule.write_text("disabledtest")
    with pytest.raises(ApiError, match="Disabled"):
        client.upload_yara(rule, "CAPE")


def test_task_stream_writes_the_body(client: CapeClient, tmp_path: Path) -> None:
    dest = client.task_stream(7, "C:/malware.log", tmp_path / "s.bin")
    assert dest.read_bytes() == b"STREAM:C:/malware.log"


def test_task_stream_local(client: CapeClient, tmp_path: Path) -> None:
    dest = client.task_stream(7, "report.json", tmp_path / "s.bin", is_local=True)
    assert dest.read_bytes() == b"STREAM:report.json"


def test_task_stream_error_envelope_raises(client: CapeClient, tmp_path: Path) -> None:
    dest = tmp_path / "s.bin"
    with pytest.raises(ApiError, match="does not exist"):
        client.task_stream(7, "missing", dest)
    assert not dest.exists()


def test_set_task_visibility_ok(client: CapeClient) -> None:
    result = client.set_task_visibility(7, "public")
    assert result["data"] == {"task_id": 7, "visibility": "public"}


def test_set_task_visibility_invalid_raises(client: CapeClient) -> None:
    with pytest.raises(ApiError, match="invalid visibility"):
        client.set_task_visibility(7, "invalid")
