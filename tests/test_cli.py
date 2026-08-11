"""Tests for the capecli command-line interface."""

import contextlib
import json
import os
from pathlib import Path
from typing import Any

import pytest

from capecli import __version__
from capecli.cli import BROKEN_PIPE_EXIT, _write, main


class CliRunner:
    def __init__(self, cape_url: str, capsys: pytest.CaptureFixture[str]) -> None:
        self.cape_url = cape_url
        self.capsys = capsys

    def _invoke(self, argv: tuple[str, ...]) -> tuple[int, str, str]:
        code = main(["--url", self.cape_url, "--token", "cli-token", *argv])
        captured = self.capsys.readouterr()
        return code, captured.out, captured.err

    def json(self, *argv: str) -> dict[str, Any]:
        code, out, err = self._invoke(("--output-format", "json", *argv))
        assert code == 0, err
        payload = json.loads(out)
        assert isinstance(payload, dict)
        return payload

    def text(self, *argv: str) -> str:
        """Stdout as printed, so the default format can be asserted on."""
        code, out, err = self._invoke(argv)
        assert code == 0, err
        return out

    def download(self, *argv: str) -> Path:
        code, out, err = self._invoke(argv)
        assert code == 0, err
        dest = Path(out.strip())
        assert dest.is_file()
        return dest

    def failure(self, *argv: str) -> str:
        code, _, err = self._invoke(argv)
        assert code == 1
        return err


@pytest.fixture
def run(cape_url: str, capsys: pytest.CaptureFixture[str]) -> CliRunner:
    return CliRunner(cape_url, capsys)


def test_submit_file(run: CliRunner, tmp_path: Path) -> None:
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"cli-sample")
    result = run.json(
        "submit",
        "file",
        str(sample),
        "--machine",
        "vm1",
        "--pcap",
        "--argument",
        "timeout=120",
        "--option",
        "procdump=1",
    )
    assert result["path"] == "/apiv2/tasks/create/file/"
    assert "cli-sample" in result["body"]
    # --argument sets a top-level CAPE field, --option goes in the options string.
    assert 'name="timeout"' in result["body"]
    assert 'name="options"' in result["body"]
    assert "procdump=1" in result["body"]


def test_submit_file_rejects_bad_option(cape_url: str, tmp_path: Path) -> None:
    with pytest.raises(SystemExit) as excinfo:
        main(
            [
                "--url",
                cape_url,
                "submit",
                "file",
                str(tmp_path / "x.bin"),
                "--option",
                "not-a-pair",
            ]
        )
    assert excinfo.value.code == 2


def test_submit_missing_file_reported(run: CliRunner, tmp_path: Path) -> None:
    error = run.failure("submit", "file", str(tmp_path / "does-not-exist.bin"))
    assert error.startswith("error: ")


def test_submit_static(run: CliRunner, tmp_path: Path) -> None:
    sample = tmp_path / "static.bin"
    sample.write_bytes(b"static-cli")
    result = run.json(
        "submit", "static", str(sample), "--priority", "3", "--option", "procdump=1"
    )
    assert result["path"] == "/apiv2/tasks/create/static/"
    assert 'name="priority"' in result["body"]
    assert "procdump=1" in result["body"]


def test_submit_url(run: CliRunner) -> None:
    result = run.json("submit", "url", "http://bad.tld")
    assert result["path"] == "/apiv2/tasks/create/url/"


def test_submit_dlnexec(run: CliRunner) -> None:
    result = run.json("submit", "dlnexec", "http://bad.tld/x.exe", "--machine", "vm2")
    assert result["path"] == "/apiv2/tasks/create/dlnexec/"
    assert "machine=vm2" in result["body"]


def test_submit_download_services(run: CliRunner) -> None:
    """The key goes into the options string here, not its own field."""
    result = run.json(
        "submit",
        "download-services",
        "deadbeef",
        "--apikey",
        "mb-key",
        "--machine",
        "vm5",
    )
    assert result["path"] == "/apiv2/tasks/create/download_services/"
    assert "hashes=deadbeef" in result["body"]
    assert "options=apikey%3Dmb-key" in result["body"]
    assert "machine=vm5" in result["body"]


@pytest.mark.parametrize(
    "command", ["view", "status", "reschedule", "reprocess", "machine"]
)
def test_task_id_only_commands(run: CliRunner, command: str) -> None:
    """Each task-id command must reach its own CAPE endpoint."""
    assert run.json("task", command, "7")["path"] == f"/apiv2/tasks/{command}/7/"


def test_task_search(run: CliRunner) -> None:
    result = run.json("task", "search", "md5", "a" * 32)
    assert result["path"] == f"/apiv2/tasks/search/md5/{'a' * 32}/"


def test_task_extsearch(run: CliRunner) -> None:
    result = run.json("task", "extsearch", "domain", "evil.tld")
    assert result["path"] == "/apiv2/tasks/extendedsearch/"
    assert "option=domain" in result["body"]


def test_task_extsearch_limit(run: CliRunner) -> None:
    result = run.json("task", "extsearch", "domain", "evil.tld", "--limit", "500")
    assert "search_limit=500" in result["body"]


def test_task_list(run: CliRunner) -> None:
    assert run.json("task", "list")["path"] == "/apiv2/tasks/list/"


def test_task_list_with_filters(run: CliRunner) -> None:
    result = run.json(
        "task", "list", "10", "20", "--status", "reported", "--option", "procdump"
    )
    assert result["path"] == "/apiv2/tasks/list/10/20/"
    assert "status=reported" in result["query"]


def test_task_list_extra_filters(run: CliRunner) -> None:
    result = run.json(
        "task", "list", "5", "0", "--window", "60", "--category", "file", "--ids"
    )
    assert result["path"] == "/apiv2/tasks/list/5/0/60/"
    assert "category=file" in result["query"]
    assert "ids=1" in result["query"]


def test_task_latest(run: CliRunner) -> None:
    assert run.json("task", "latest", "3")["path"] == "/apiv2/tasks/get/latests/3/"


def test_task_delete(run: CliRunner) -> None:
    result = run.json("task", "delete", "7-9", "--status", "failed_analysis")
    assert result["path"] == "/apiv2/tasks/delete/7-9/failed_analysis/"


def test_get_report(run: CliRunner) -> None:
    assert run.json("get", "report", "7")["path"] == "/apiv2/tasks/get/report/7/"


def test_get_report_format(run: CliRunner) -> None:
    result = run.json("get", "report", "7", "--format", "litereport")
    assert result["path"] == "/apiv2/tasks/get/report/7/litereport/"


def test_get_report_zip(run: CliRunner, tmp_path: Path) -> None:
    dest = run.download(
        "get", "report", "7", "--zip", "-o", str(tmp_path / "report.zip")
    )
    assert dest.read_bytes() == b"/apiv2/tasks/get/report/7/json/zip/"


def test_get_report_zip_default_name(run: CliRunner, isolated_env: Path) -> None:
    """Without -o the zip lands in the working directory under a derived name."""
    assert run.download("get", "report", "7", "--zip").name == "task_7_report.zip"


def test_get_report_html_without_a_destination_says_where_it_should_go(
    run: CliRunner,
) -> None:
    """Fetched through the JSON path, an HTML body is indistinguishable from a
    restricted endpoint serving the web UI, so the request is refused first."""
    error = run.failure("get", "report", "7", "--format", "html")
    assert "-o" in error and "document, not JSON" in error


def test_get_report_html_to_file(run: CliRunner, tmp_path: Path) -> None:
    dest = run.download(
        "get", "report", "7", "--format", "html", "-o", str(tmp_path / "r.html")
    )
    assert dest.read_bytes() == b"<html>report</html>"


@pytest.mark.parametrize(
    ("command", "endpoint"),
    [
        ("pcap", "pcap"),
        ("tlspcap", "tlspcap"),
        ("evtx", "evtx"),
        ("surifile", "surifile"),
        ("fullmemory", "fullmemory"),
        ("payloads", "payloadfiles"),
        ("procdumps", "procdumpfiles"),
        ("mitmdump", "mitmdump"),
        ("dropped", "dropped"),
    ],
)
def test_task_id_only_downloads(
    run: CliRunner, tmp_path: Path, command: str, endpoint: str
) -> None:
    """Each command must map to its own CAPE endpoint and honour -o."""
    dest = run.download("get", command, "7", "-o", str(tmp_path / command))
    assert dest.read_bytes() == f"/apiv2/tasks/get/{endpoint}/7/".encode()


def test_get_iocs(run: CliRunner) -> None:
    assert run.json("get", "iocs", "7")["path"] == "/apiv2/tasks/get/iocs/7/"


def test_get_iocs_detailed(run: CliRunner) -> None:
    result = run.json("get", "iocs", "7", "--detailed")
    assert result["path"] == "/apiv2/tasks/get/iocs/7/detailed/"


def test_get_config(run: CliRunner) -> None:
    assert run.json("get", "config", "7")["path"] == "/apiv2/tasks/get/config/7/"


def test_get_config_family(run: CliRunner) -> None:
    result = run.json("get", "config", "7", "--family", "Emotet")
    assert result["path"] == "/apiv2/tasks/get/config/7/Emotet/"


def test_exitnodes(run: CliRunner) -> None:
    assert run.json("exitnodes")["path"] == "/apiv2/exitnodes/"


def test_taskstats(run: CliRunner) -> None:
    assert run.json("taskstats")["path"] == "/apiv2/tasks/stats/"


@pytest.mark.parametrize(
    ("command", "endpoint", "argument"),
    [("keys", "keys", "tls"), ("etw", "etw", "all"), ("bulkzip", "bulkzip", "CAPE")],
)
def test_get_downloads_with_a_kind(
    run: CliRunner, tmp_path: Path, command: str, endpoint: str, argument: str
) -> None:
    """Each command takes its kind as a second positional and honours -o."""
    dest = run.download("get", command, "7", argument, "-o", str(tmp_path / command))
    assert dest.read_bytes() == f"/apiv2/tasks/get/{endpoint}/7/{argument}/".encode()


def test_get_screenshots(run: CliRunner, tmp_path: Path) -> None:
    dest = run.download(
        "get", "screenshots", "7", "--number", "2", "-o", str(tmp_path / "shot.jpg")
    )
    assert dest.read_bytes() == b"/apiv2/tasks/get/screenshot/7/2/"


def test_get_dropped_max_size(run: CliRunner, tmp_path: Path) -> None:
    dest = run.download(
        "get", "dropped", "7", "--max-size", "50", "-o", str(tmp_path / "d.zip")
    )
    assert dest.read_bytes() == b"/apiv2/tasks/get/dropped/7/?max_size=50"


def test_get_selfextracted(run: CliRunner, tmp_path: Path) -> None:
    dest = run.download(
        "get",
        "selfextracted",
        "7",
        "--tool",
        "unpacker",
        "-o",
        str(tmp_path / "sx.zip"),
    )
    assert dest.read_bytes() == b"/apiv2/tasks/get/selfextracted/7/unpacker/"


def test_get_pcap_variant(run: CliRunner, tmp_path: Path) -> None:
    """--variant reaches CAPE's alternate capture, e.g. the sorted pcap."""
    dest = run.download(
        "get", "pcap", "7", "--variant", "sorted", "-o", str(tmp_path / "s.pcap")
    )
    assert dest.read_bytes() == b"/apiv2/tasks/get/pcap/7/sorted/"


def test_get_procmemory(run: CliRunner, tmp_path: Path) -> None:
    dest = run.download(
        "get", "procmemory", "7", "--pid", "1234", "-o", str(tmp_path / "mem.zip")
    )
    assert dest.read_bytes() == b"/apiv2/tasks/get/procmemory/7/1234/"


def test_sample_view(run: CliRunner) -> None:
    result = run.json("sample", "view", "sha256", "ab" * 32)
    assert result["path"] == f"/apiv2/files/view/sha256/{'ab' * 32}/"


def test_sample_download(run: CliRunner, tmp_path: Path) -> None:
    dest = run.download(
        "sample", "download", "task", "7", "--encrypted", "-o", str(tmp_path / "s.bin")
    )
    assert dest.read_bytes() == b"/apiv2/files/get/task/7/?encrypted=1"


def test_machine_list(run: CliRunner) -> None:
    assert run.json("machine", "list")["path"] == "/apiv2/machines/list/"


def test_machine_view(run: CliRunner) -> None:
    result = run.json("machine", "view", "win10-x64")
    assert result["path"] == "/apiv2/machines/view/win10-x64/"


def test_status(run: CliRunner) -> None:
    result = run.json("status")
    assert result["path"] == "/apiv2/cuckoo/status/"
    assert result["authorization"] == "Token cli-token"


def test_stats(run: CliRunner) -> None:
    assert run.json("stats", "14")["path"] == "/apiv2/tasks/statistics/14/"


def test_api_error_reported(run: CliRunner) -> None:
    assert "HTTP 500" in run.failure("task", "view", "500")


def test_empty_task_selector_reported(run: CliRunner) -> None:
    assert "no task selector given" in run.failure("task", "delete", "")


def test_negative_timeout_reported(run: CliRunner) -> None:
    error = run.failure("--timeout", "-5", "status")
    assert "Timeout must be a finite number greater than zero" in error


def test_missing_url_reported(
    isolated_env: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    code = main(["status"])
    assert code == 1
    assert "CAPE URL not configured" in capsys.readouterr().err


def test_token_command(run: CliRunner, isolated_env: Path) -> None:
    os.environ["CAPECLI_PASSWORD"] = "secret"
    assert run.json("token", "--username", "seifreed")["token"] == "t" * 40


def test_token_command_requires_the_password_in_the_environment(
    run: CliRunner, isolated_env: Path
) -> None:
    """The password is never accepted on the command line, so argv cannot leak it."""
    assert "CAPECLI_PASSWORD" in run.failure("token", "--username", "seifreed")


def test_default_output_is_a_table(run: CliRunner) -> None:
    """Task 77 is served as a collection under "data", so it tabulates."""
    rendered = run.text("task", "view", "77")
    assert "+----" in rendered
    assert "| id" in rendered and "status" in rendered
    assert "reported" in rendered


def test_nested_payloads_render_as_key_value_rows(run: CliRunner) -> None:
    rendered = run.text("task", "view", "7")
    assert "Key" in rendered and "Value" in rendered
    assert "/apiv2/tasks/view/7/" in rendered


def test_toon_output(run: CliRunner) -> None:
    rendered = run.text("--output-format", "toon", "task", "view", "77")
    assert "data[2]{id,status}:" in rendered
    assert "1,reported" in rendered


def test_sarif_output_for_a_report(run: CliRunner) -> None:
    rendered = run.text("--output-format", "sarif", "get", "report", "7")
    document = json.loads(rendered)
    assert document["version"] == "2.1.0"
    assert document["runs"][0]["tool"]["driver"]["name"] == "CAPE"


def test_sarif_output_for_iocs(run: CliRunner) -> None:
    document = json.loads(run.text("--output-format", "sarif", "get", "iocs", "7"))
    assert document["runs"][0]["results"] == []


def test_sarif_is_refused_before_the_command_runs(run: CliRunner) -> None:
    """Everything the check needs is on the command line, and a submission or a
    deletion must not happen only for its result to be refused afterwards. The
    missing sample is what says the handler never ran: it would have been the
    first thing to fail."""
    error = run.failure(
        "--output-format", "sarif", "submit", "file", "no-such-sample.bin"
    )
    assert "sarif output is only available" in error


@pytest.mark.parametrize("saving", [["-o", "r.json"], ["--zip"]])
def test_sarif_and_saving_the_report_cannot_both_apply(
    run: CliRunner, isolated_env: Path, saving: list[str]
) -> None:
    """One says render the findings, the other says save the report as a file.
    Every other command already refuses sarif before running; this one has to
    do it too, or the flag reads as ignored rather than as contradicted."""
    error = run.failure("--output-format", "sarif", "get", "report", "7", *saving)
    assert "only one of the two can apply" in error
    assert not list(isolated_env.iterdir())


def test_a_json_report_saved_to_a_file(run: CliRunner, tmp_path: Path) -> None:
    """-o names a destination for the report, and json is the default format;
    the most ordinary spelling of the flag has to work."""
    dest = run.download("get", "report", "7", "-o", str(tmp_path / "report.json"))
    assert "/apiv2/tasks/get/report/7/json/" in dest.read_text(encoding="utf-8")


def test_sarif_is_refused_for_commands_without_findings(run: CliRunner) -> None:
    error = run.failure("--output-format", "sarif", "machine", "list")
    assert "get report" in error and "get iocs" in error


def test_downloads_print_a_bare_path_whatever_the_format(
    run: CliRunner, tmp_path: Path
) -> None:
    dest = tmp_path / "d.pcap"
    for output_format in ("table", "json", "toon"):
        printed = run.text(
            "--output-format", output_format, "get", "pcap", "7", "-o", str(dest)
        )
        assert printed.strip() == str(dest)


@pytest.mark.parametrize(
    "argv",
    [[], ["submit"], ["task"], ["get"], ["sample"], ["machine"], ["token"]],
    ids=["bare", "submit", "task", "get", "sample", "machine", "token"],
)
def test_a_command_missing_its_subcommand_is_a_usage_error(argv: list[str]) -> None:
    """Without the required= markers argparse would accept these and main would
    reach for a handler that was never set."""
    with pytest.raises(SystemExit) as excinfo:
        main(["--url", "http://cape.invalid", *argv])
    assert excinfo.value.code == 2


def test_a_findings_command_still_renders_as_a_table(run: CliRunner) -> None:
    """get report carries a SARIF builder, which must not divert the other
    formats: the default output of the most common command is a table."""
    rendered = run.text("get", "report", "7")
    assert "Key" in rendered and "Value" in rendered
    assert "/apiv2/tasks/get/report/7/" in rendered


@pytest.mark.parametrize("output_format", ["table", "json"])
def test_text_no_stream_can_encode_is_shown_escaped(
    run: CliRunner, output_format: str
) -> None:
    """JSON admits lone surrogates, so a response can carry text that UTF-8
    cannot write. Rendering happens after the request succeeded; a character
    the stream rejects must not discard the result."""
    rendered = run.text("--output-format", output_format, "task", "view", "55")
    rendered.encode("utf-8")  # would raise if a surrogate survived
    assert "d800" in rendered.lower()


def test_toon_says_so_when_a_response_has_no_toon_form(run: CliRunner) -> None:
    """TOON cannot carry a lone surrogate, and an escape for one is an escape
    decoders must reject. Saying the format cannot hold the response points at
    the format that can, where emitting an undecodable document would not."""
    assert "no TOON representation" in run.failure(
        "--output-format", "toon", "task", "view", "55"
    )


def test_a_reader_that_stops_early_is_not_a_failure() -> None:
    """`capecli task list | head` closes the pipe once it has its lines. The
    write fails, and so does the flush the interpreter does on the way out;
    neither is a fault of ours to report."""
    read_end, write_end = os.pipe()
    os.close(read_end)
    with os.fdopen(write_end, "w", encoding="utf-8") as closed_pipe:
        assert _write("a line the reader will never take", closed_pipe) is False


def test_a_stopped_reader_is_reported_as_the_shell_would(cape_url: str) -> None:
    """`capecli task list | head` ends with the reader gone, which a shell
    reports as 141. The request succeeded, so it is not an error exit either."""
    read_end, write_end = os.pipe()
    os.close(read_end)
    with (
        os.fdopen(write_end, "w", encoding="utf-8") as closed_pipe,
        contextlib.redirect_stdout(closed_pipe),
    ):
        code = main(["--url", cape_url, "task", "view", "7"])
    assert code == BROKEN_PIPE_EXIT


def test_a_stopped_reader_costs_no_descriptor() -> None:
    """Retiring the stream opens the null device, and that handle is spare once
    it has been duplicated onto the stream. Holding it would spend a descriptor
    on every call, and main() is callable more than once per process.

    dup hands back the lowest free descriptor, so the same number coming back
    after the writes is what says none of them was retained.
    """

    def lowest_free() -> int:
        probe = os.dup(0)
        os.close(probe)
        return probe

    before = lowest_free()
    for _ in range(3):
        read_end, write_end = os.pipe()
        os.close(read_end)
        with os.fdopen(write_end, "w", encoding="utf-8") as closed_pipe:
            assert _write("unread", closed_pipe) is False
    assert lowest_free() == before


def test_a_result_that_cannot_be_written_is_reported(
    cape_url: str, capsys: pytest.CaptureFixture[str]
) -> None:
    """The request has already succeeded by then, so a stdout that refuses the
    write is still a failure to state rather than one to raise."""
    with (
        open(os.devnull, encoding="utf-8") as not_writable,
        contextlib.redirect_stdout(not_writable),
    ):
        code = main(["--url", cape_url, "task", "view", "7"])
    assert code == 1
    assert "cannot write the result" in capsys.readouterr().err


def test_writing_to_a_live_stream_reports_success(tmp_path: Path) -> None:
    destination = tmp_path / "out.txt"
    with destination.open("w", encoding="utf-8") as stream:
        assert _write("kept", stream) is True
    assert destination.read_text(encoding="utf-8") == "kept\n"


def test_version_flag(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as excinfo:
        main(["--version"])
    assert excinfo.value.code == 0
    assert f"capecli {__version__}" in capsys.readouterr().out


def test_cli_task_delete_many(run: CliRunner) -> None:
    result = run.json("task", "delete-many", "1,2")
    assert result["status"] == "OK"
    assert result["delete_mongo"] == "1"


def test_cli_task_delete_many_keep_reports(run: CliRunner) -> None:
    result = run.json("task", "delete-many", "1,2", "--keep-reports")
    assert result["delete_mongo"] == "0"


def test_cli_task_visibility(run: CliRunner) -> None:
    assert (
        run.json("task", "visibility", "7", "public")["data"]["visibility"] == "public"
    )


def test_cli_get_stream(run: CliRunner, tmp_path: Path) -> None:
    dest = run.download(
        "get", "stream", "7", "sample.log", "-o", str(tmp_path / "s.bin")
    )
    assert dest.read_bytes() == b"STREAM:sample.log"


def test_cli_get_stream_local(run: CliRunner, tmp_path: Path) -> None:
    dest = run.download(
        "get", "stream", "7", "report.json", "--local", "-o", str(tmp_path / "s2.bin")
    )
    assert dest.read_bytes() == b"STREAM:report.json"


def test_cli_yara_upload(run: CliRunner, tmp_path: Path) -> None:
    rule = tmp_path / "r.yar"
    rule.write_text("rule x { condition: true }")
    result = run.json("yara", "upload", str(rule), "--category", "CAPE")
    assert result["status"] == "success"


def _dist(
    dist_url: str, capsys: pytest.CaptureFixture[str], *argv: str
) -> tuple[int, str, str]:
    code = main(["--dist-url", dist_url, "--output-format", "json", "dist", *argv])
    captured = capsys.readouterr()
    return code, captured.out, captured.err


def test_cli_dist_nodes(dist_url: str, capsys: pytest.CaptureFixture[str]) -> None:
    code, out, err = _dist(dist_url, capsys, "nodes")
    assert code == 0, err
    assert "main" in json.loads(out)["nodes"]


def test_cli_dist_status(dist_url: str, capsys: pytest.CaptureFixture[str]) -> None:
    code, out, err = _dist(dist_url, capsys, "status")
    assert code == 0, err
    assert json.loads(out)["tasks"] == {"pending": 0}


def test_cli_dist_task(dist_url: str, capsys: pytest.CaptureFixture[str]) -> None:
    code, out, err = _dist(dist_url, capsys, "task", "5")
    assert code == 0, err
    assert json.loads(out)["Tasks"][0]["id"] == 5


def test_cli_dist_node_view(dist_url: str, capsys: pytest.CaptureFixture[str]) -> None:
    code, out, err = _dist(dist_url, capsys, "node", "view", "main")
    assert code == 0, err
    assert json.loads(out)["name"] == "main"


def test_cli_dist_node_add(dist_url: str, capsys: pytest.CaptureFixture[str]) -> None:
    code, out, err = _dist(
        dist_url, capsys, "node", "add", "w1", "--url", "http://w1", "--enabled"
    )
    assert code == 0, err
    assert json.loads(out)["name"] == "w1"


def test_cli_dist_node_update(
    dist_url: str, capsys: pytest.CaptureFixture[str]
) -> None:
    code, out, err = _dist(
        dist_url, capsys, "node", "update", "main", "--disable", "--no-exitnodes"
    )
    assert code == 0, err
    assert json.loads(out)["error"] is False


def test_cli_dist_node_delete(
    dist_url: str, capsys: pytest.CaptureFixture[str]
) -> None:
    code, out, err = _dist(dist_url, capsys, "node", "delete", "main")
    assert code == 0, err
    assert json.loads(out)["error"] is False


def test_cli_dist_without_url_errors(
    isolated_env: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert main(["dist", "nodes"]) == 1
    assert "distributed URL not configured" in capsys.readouterr().err
