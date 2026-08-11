"""Command-line interface for the CAPE v2 REST API."""

import argparse
import os
import sys
from collections.abc import Callable, Sequence
from pathlib import Path
from typing import TextIO

from capecli import __version__, render
from capecli.client import (
    JSON_REPORT_FORMATS,
    YARA_CATEGORIES,
    CapeClient,
    FormValue,
    JsonDict,
)
from capecli.config import load_config
from capecli.distributed import DistClient
from capecli.errors import CapeError, ConfigError
from capecli.sarif import iocs_to_sarif, report_to_sarif

CommandResult = JsonDict | Path
type SubParsers = argparse._SubParsersAction[argparse.ArgumentParser]

HASH_TYPES = ("md5", "sha1", "sha256")

# What a shell reports for a process ended by SIGPIPE. Python ignores that
# signal and raises BrokenPipeError instead, so the convention is reproduced
# here rather than inherited, and it holds on platforms without the signal.
BROKEN_PIPE_EXIT = 141


def _parse_option(value: str) -> tuple[str, str]:
    key, separator, option_value = value.partition("=")
    if not separator or not key:
        raise argparse.ArgumentTypeError(f"expected KEY=VALUE, got {value!r}")
    return key, option_value


def _options_dict(pairs: list[tuple[str, str]] | None) -> dict[str, FormValue]:
    return dict(pairs or [])


def _dest(output: str | None, default: str) -> Path:
    return Path(output) if output is not None else Path(default)


def _task_dest(args: argparse.Namespace, suffix: str) -> Path:
    """Where a task artifact lands: -o if given, else task_<id><suffix>."""
    return _dest(args.output, f"task_{args.task_id}{suffix}")


def _task_id_handler(
    method: Callable[[CapeClient, int], JsonDict],
) -> Callable[[CapeClient, argparse.Namespace], CommandResult]:
    """Build a handler for the JSON endpoints that take only a task id."""

    def handler(client: CapeClient, args: argparse.Namespace) -> CommandResult:
        return method(client, args.task_id)

    return handler


def _no_arg_handler(
    method: Callable[[CapeClient], JsonDict],
) -> Callable[[CapeClient, argparse.Namespace], CommandResult]:
    """Build a handler for the JSON endpoints that take no arguments."""

    def handler(client: CapeClient, args: argparse.Namespace) -> CommandResult:
        return method(client)

    return handler


def _download_handler(
    method: Callable[[CapeClient, int, Path], Path], suffix: str
) -> Callable[[CapeClient, argparse.Namespace], CommandResult]:
    """Build a handler for the artifact downloads that take only a task id."""

    def handler(client: CapeClient, args: argparse.Namespace) -> CommandResult:
        return method(client, args.task_id, _task_dest(args, suffix))

    return handler


def _add_option_flag(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--option",
        action="append",
        type=_parse_option,
        metavar="KEY=VALUE",
        help="Analyzer option folded into CAPE options string, repeatable",
    )


def _add_argument_flag(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--argument",
        action="append",
        type=_parse_option,
        metavar="KEY=VALUE",
        help="CAPE submission argument (package, timeout, priority, ...), repeatable",
    )


def _add_machine_flag(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--machine", help="Analysis VM name")


def _add_output_flag(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("-o", "--output", help="Output file path")


def _add_task_id_arg(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("task_id", type=int)


def _cmd_token(client: CapeClient, args: argparse.Namespace) -> CommandResult:
    """Read the password from the environment, never from the command line."""
    password = os.environ.get("CAPECLI_PASSWORD")
    if not password:
        raise ConfigError(
            "Set the CAPECLI_PASSWORD environment variable to the password for "
            f"{args.username!r}; it is not accepted as a command-line argument."
        )
    return {"token": client.obtain_token(args.username, password)}


# Submission commands


def _cmd_submit_file(client: CapeClient, args: argparse.Namespace) -> CommandResult:
    return client.submit_file(
        Path(args.path),
        machine=args.machine,
        pcap=args.pcap,
        options=_options_dict(args.option),
        arguments=_options_dict(args.argument),
    )


def _cmd_submit_static(client: CapeClient, args: argparse.Namespace) -> CommandResult:
    return client.submit_static(
        Path(args.path),
        priority=args.priority,
        options=_options_dict(args.option),
    )


def _cmd_submit_url(client: CapeClient, args: argparse.Namespace) -> CommandResult:
    return client.submit_url(
        args.target,
        machine=args.machine,
        options=_options_dict(args.option),
        arguments=_options_dict(args.argument),
    )


def _cmd_submit_dlnexec(client: CapeClient, args: argparse.Namespace) -> CommandResult:
    return client.submit_dlnexec(
        args.target,
        machine=args.machine,
        options=_options_dict(args.option),
        arguments=_options_dict(args.argument),
    )


def _cmd_submit_download_service(
    client: CapeClient, args: argparse.Namespace
) -> CommandResult:
    return client.submit_download_service(
        args.hash,
        apikey=args.apikey,
        machine=args.machine,
        options=_options_dict(args.option),
        arguments=_options_dict(args.argument),
    )


# Task commands


def _cmd_task_search(client: CapeClient, args: argparse.Namespace) -> CommandResult:
    return client.task_search(args.hash_type, args.value)


def _cmd_task_extsearch(client: CapeClient, args: argparse.Namespace) -> CommandResult:
    return client.task_extended_search(
        args.option, args.argument, search_limit=args.limit
    )


def _cmd_task_list(client: CapeClient, args: argparse.Namespace) -> CommandResult:
    return client.tasks_list(
        args.limit,
        args.offset,
        window=args.window,
        status=args.status,
        option=args.option,
        category=args.category,
        completed_after=args.completed_after,
        ids_only=args.ids,
    )


def _cmd_task_latest(client: CapeClient, args: argparse.Namespace) -> CommandResult:
    return client.tasks_latest(args.hours)


def _cmd_task_delete(client: CapeClient, args: argparse.Namespace) -> CommandResult:
    return client.task_delete(args.tasks, status=args.status)


def _cmd_task_delete_many(
    client: CapeClient, args: argparse.Namespace
) -> CommandResult:
    return client.tasks_delete_many(args.tasks, delete_mongo=not args.keep_reports)


def _cmd_task_visibility(client: CapeClient, args: argparse.Namespace) -> CommandResult:
    return client.set_task_visibility(args.task_id, args.visibility)


# Report and artifact commands


def _cmd_get_report(client: CapeClient, args: argparse.Namespace) -> CommandResult:
    if (args.zip or args.output is not None) and args.output_format == render.SARIF:
        # Both name what to do with the report, and they disagree. Saying so
        # before the request beats fetching it and then refusing to render it.
        raise ValueError(
            "sarif renders the report's findings, and -o and --zip save the "
            "report as a file instead; only one of the two can apply"
        )
    if args.zip:
        return client.task_report_zip(
            args.task_id, _task_dest(args, "_report.zip"), args.format
        )
    if args.output is not None:
        return client.task_report_file(
            args.task_id, Path(args.output), args.format or "json"
        )
    if args.format is not None and args.format.lower() not in JSON_REPORT_FORMATS:
        # Without a destination this would fetch the document through the JSON
        # path, where an XML or HTML body is indistinguishable from a restricted
        # endpoint serving the web UI.
        raise ValueError(
            f"the {args.format!r} report format is a document, not JSON; "
            "write it to a file with -o"
        )
    return client.task_report(args.task_id, args.format)


def _cmd_get_iocs(client: CapeClient, args: argparse.Namespace) -> CommandResult:
    return client.task_iocs(args.task_id, detailed=args.detailed)


def _cmd_get_config(client: CapeClient, args: argparse.Namespace) -> CommandResult:
    return client.task_config(args.task_id, args.family)


def _cmd_get_keys(client: CapeClient, args: argparse.Namespace) -> CommandResult:
    return client.task_keys(args.task_id, args.kind, _task_dest(args, "_keys.log"))


def _cmd_get_etw(client: CapeClient, args: argparse.Namespace) -> CommandResult:
    return client.task_etw(args.task_id, args.kind, _task_dest(args, "_etw.zip"))


def _cmd_get_bulkzip(client: CapeClient, args: argparse.Namespace) -> CommandResult:
    return client.task_bulkzip(args.task_id, args.folder, _task_dest(args, "_bulk.zip"))


def _cmd_get_screenshots(client: CapeClient, args: argparse.Namespace) -> CommandResult:
    return client.task_screenshots(
        args.task_id, _task_dest(args, "_screenshots.zip"), number=args.number
    )


def _cmd_get_dropped(client: CapeClient, args: argparse.Namespace) -> CommandResult:
    return client.task_dropped(
        args.task_id, _task_dest(args, "_dropped.zip"), max_size=args.max_size
    )


def _cmd_get_selfextracted(
    client: CapeClient, args: argparse.Namespace
) -> CommandResult:
    return client.task_selfextracted(
        args.task_id, _task_dest(args, "_selfextracted.zip"), tool=args.tool
    )


def _cmd_get_procmemory(client: CapeClient, args: argparse.Namespace) -> CommandResult:
    return client.task_procmemory(
        args.task_id, _task_dest(args, "_procmemory.zip"), pid=args.pid
    )


def _cmd_get_pcap(client: CapeClient, args: argparse.Namespace) -> CommandResult:
    return client.task_pcap(
        args.task_id, _task_dest(args, ".pcap"), variant=args.variant
    )


def _cmd_get_stream(client: CapeClient, args: argparse.Namespace) -> CommandResult:
    return client.task_stream(
        args.task_id,
        args.filepath,
        _task_dest(args, "_stream.bin"),
        is_local=args.local,
    )


def _cmd_yara_upload(client: CapeClient, args: argparse.Namespace) -> CommandResult:
    return client.upload_yara(Path(args.path), args.category)


# Sample commands


def _cmd_sample_view(client: CapeClient, args: argparse.Namespace) -> CommandResult:
    return client.file_view(args.criteria, args.value)


def _cmd_sample_download(client: CapeClient, args: argparse.Namespace) -> CommandResult:
    return client.file_download(
        args.criteria,
        args.value,
        _dest(args.output, f"sample_{Path(args.value).name}.bin"),
        encrypted=args.encrypted,
    )


# Infrastructure commands


def _cmd_machine_view(client: CapeClient, args: argparse.Namespace) -> CommandResult:
    return client.machine_view(args.name)


def _cmd_stats(client: CapeClient, args: argparse.Namespace) -> CommandResult:
    return client.tasks_statistics(args.days)


# Distributed commands (a separate service; these receive a DistClient)


def _cmd_dist_nodes(client: DistClient, args: argparse.Namespace) -> CommandResult:
    return client.nodes_list()


def _cmd_dist_status(client: DistClient, args: argparse.Namespace) -> CommandResult:
    return client.dist_status()


def _cmd_dist_task(client: DistClient, args: argparse.Namespace) -> CommandResult:
    return client.dist_task(args.main_task_id)


def _cmd_dist_node_view(client: DistClient, args: argparse.Namespace) -> CommandResult:
    return client.node_view(args.name)


def _cmd_dist_node_add(client: DistClient, args: argparse.Namespace) -> CommandResult:
    return client.node_add(
        args.name,
        args.url,
        apikey=args.apikey,
        exitnodes=args.exitnodes,
        enabled=args.enabled,
    )


def _cmd_dist_node_update(
    client: DistClient, args: argparse.Namespace
) -> CommandResult:
    return client.node_update(
        args.name,
        url=args.url,
        apikey=args.apikey,
        exitnodes=args.exitnodes,
        enabled=args.enabled,
    )


def _cmd_dist_node_delete(
    client: DistClient, args: argparse.Namespace
) -> CommandResult:
    return client.node_delete(args.name)


def _add_submit_parsers(subparsers: SubParsers) -> None:
    submit = subparsers.add_parser("submit", help="Submit samples or URLs for analysis")
    commands = submit.add_subparsers(dest="subcommand", required=True)

    file_parser = commands.add_parser("file", help="Submit a file for analysis")
    file_parser.add_argument("path")
    file_parser.add_argument(
        "--pcap", action="store_true", help="Treat the file as a PCAP"
    )
    _add_machine_flag(file_parser)
    _add_option_flag(file_parser)
    _add_argument_flag(file_parser)
    file_parser.set_defaults(handler=_cmd_submit_file)

    static_parser = commands.add_parser("static", help="Run static extraction only")
    static_parser.add_argument("path")
    static_parser.add_argument("--priority", type=int, help="Task priority")
    _add_option_flag(static_parser)
    static_parser.set_defaults(handler=_cmd_submit_static)

    for name, handler in (("url", _cmd_submit_url), ("dlnexec", _cmd_submit_dlnexec)):
        url_parser = commands.add_parser(name, help=f"Submit a {name} task")
        url_parser.add_argument("target")
        _add_machine_flag(url_parser)
        _add_option_flag(url_parser)
        _add_argument_flag(url_parser)
        url_parser.set_defaults(handler=handler)

    hash_parser = commands.add_parser(
        "download-services",
        help="Download a hash from VirusTotal or MalwareBazaar and analyze",
    )
    hash_parser.add_argument("hash")
    hash_parser.add_argument("--apikey", help="Download service API key")
    _add_machine_flag(hash_parser)
    _add_option_flag(hash_parser)
    _add_argument_flag(hash_parser)
    hash_parser.set_defaults(handler=_cmd_submit_download_service)


def _add_task_parsers(subparsers: SubParsers) -> None:
    task = subparsers.add_parser("task", help="Inspect and manage tasks")
    commands = task.add_subparsers(dest="subcommand", required=True)

    for name, method, description in (
        ("view", CapeClient.task_view, "View a task by ID"),
        ("status", CapeClient.task_status, "Show the status of a task by ID"),
        ("reschedule", CapeClient.task_reschedule, "Reschedule a task by ID"),
        ("reprocess", CapeClient.task_reprocess, "Reprocess a task by ID"),
        ("machine", CapeClient.task_machine, "Show the machine assigned to a task"),
    ):
        id_parser = commands.add_parser(name, help=description)
        _add_task_id_arg(id_parser)
        id_parser.set_defaults(handler=_task_id_handler(method))

    search = commands.add_parser("search", help="Search tasks by hash")
    search.add_argument("hash_type", choices=HASH_TYPES)
    search.add_argument("value")
    search.set_defaults(handler=_cmd_task_search)

    extsearch = commands.add_parser("extsearch", help="Extended search by option")
    extsearch.add_argument("option")
    extsearch.add_argument("argument")
    extsearch.add_argument(
        "--limit", type=int, help="Maximum results to return (CAPE defaults to 50)"
    )
    extsearch.set_defaults(handler=_cmd_task_extsearch)

    list_parser = commands.add_parser("list", help="List tasks")
    list_parser.add_argument("limit", nargs="?", type=int)
    list_parser.add_argument("offset", nargs="?", type=int)
    list_parser.add_argument("--status", help="Filter by task status")
    list_parser.add_argument("--option", help="Filter by option (LIKE match)")
    list_parser.add_argument("--category", help="Filter by task category")
    list_parser.add_argument(
        "--window",
        type=int,
        help=(
            "Only tasks completed in the last N minutes. CAPE carries this in "
            "the path after limit and offset, so both must be given too"
        ),
    )
    list_parser.add_argument(
        "--completed-after",
        type=int,
        metavar="TIMESTAMP",
        help="Only tasks completed after this Unix timestamp",
    )
    list_parser.add_argument("--ids", action="store_true", help="Return only task IDs")
    list_parser.set_defaults(handler=_cmd_task_list)

    latest = commands.add_parser("latest", help="Tasks finished in the latest N hours")
    latest.add_argument("hours", type=int)
    latest.set_defaults(handler=_cmd_task_latest)

    delete = commands.add_parser("delete", help="Delete tasks by ID, list, or range")
    delete.add_argument("tasks", help="Task ID, comma list (1,2) or range (1-5)")
    delete.add_argument("--status", help="Exact status when the job failed")
    delete.set_defaults(handler=_cmd_task_delete)

    delete_many = commands.add_parser(
        "delete-many", help="Bulk-delete tasks (CAPE's worker-cleanup path)"
    )
    delete_many.add_argument("tasks", help="Task IDs: comma list (1,2) or range (1-5)")
    delete_many.add_argument(
        "--keep-reports",
        action="store_true",
        help="Keep the stored reports (delete_mongo=false)",
    )
    delete_many.set_defaults(handler=_cmd_task_delete_many)

    visibility = commands.add_parser(
        "visibility", help="Set a task's multitenancy visibility (needs CAPE UI auth)"
    )
    _add_task_id_arg(visibility)
    visibility.add_argument(
        "visibility", help="Visibility value, e.g. public/tenant/private"
    )
    visibility.set_defaults(handler=_cmd_task_visibility)


def _add_get_parsers(subparsers: SubParsers) -> None:
    get = subparsers.add_parser("get", help="Fetch reports and analysis artifacts")
    commands = get.add_subparsers(dest="subcommand", required=True)

    report = commands.add_parser("report", help="Get the analysis report")
    _add_task_id_arg(report)
    report.add_argument(
        "--format",
        help=(
            "json, maec5 or litereport for JSON; html, pdf, maec or metadata "
            "for a document, which needs -o (see CAPE docs)"
        ),
    )
    report.add_argument("--zip", action="store_true", help="Download as a zip file")
    _add_output_flag(report)
    report.set_defaults(handler=_cmd_get_report, sarif_builder=report_to_sarif)

    iocs = commands.add_parser("iocs", help="Get potential IOCs")
    _add_task_id_arg(iocs)
    iocs.add_argument("--detailed", action="store_true")
    iocs.set_defaults(handler=_cmd_get_iocs, sarif_builder=iocs_to_sarif)

    config = commands.add_parser("config", help="Get the extracted malware config")
    _add_task_id_arg(config)
    config.add_argument("--family", help="Narrow the config to one CAPE family name")
    config.set_defaults(handler=_cmd_get_config)

    keys = commands.add_parser("keys", help="Download captured key material")
    _add_task_id_arg(keys)
    keys.add_argument("kind", help="Key material kind, e.g. tls")
    _add_output_flag(keys)
    keys.set_defaults(handler=_cmd_get_keys)

    etw = commands.add_parser("etw", help="Download Event Tracing for Windows data")
    _add_task_id_arg(etw)
    etw.add_argument("kind", help="ETW data kind")
    _add_output_flag(etw)
    etw.set_defaults(handler=_cmd_get_etw)

    dropped = commands.add_parser("dropped", help="Download dropped files")
    _add_task_id_arg(dropped)
    dropped.add_argument(
        "--max-size", type=int, metavar="MB", help="Refuse archives larger than N MB"
    )
    _add_output_flag(dropped)
    dropped.set_defaults(handler=_cmd_get_dropped)

    bulkzip = commands.add_parser("bulkzip", help="Download a whole analysis folder")
    _add_task_id_arg(bulkzip)
    bulkzip.add_argument(
        "folder",
        help=(
            "Analysis folder: logs, network or selfextracted. CAPE refuses the "
            "rest here; payloads (CAPE), procdumps and procmemory have routes "
            "of their own"
        ),
    )
    _add_output_flag(bulkzip)
    bulkzip.set_defaults(handler=_cmd_get_bulkzip)

    screenshots = commands.add_parser("screenshots", help="Download screenshots")
    _add_task_id_arg(screenshots)
    screenshots.add_argument("--number", type=int, help="Single screenshot number")
    _add_output_flag(screenshots)
    screenshots.set_defaults(handler=_cmd_get_screenshots)

    selfextracted = commands.add_parser(
        "selfextracted", help="Download self-extracted files"
    )
    _add_task_id_arg(selfextracted)
    selfextracted.add_argument("--tool", help="Extraction tool")
    _add_output_flag(selfextracted)
    selfextracted.set_defaults(handler=_cmd_get_selfextracted)

    procmemory = commands.add_parser("procmemory", help="Download process memory dumps")
    _add_task_id_arg(procmemory)
    procmemory.add_argument("--pid", type=int, help="Single process ID")
    _add_output_flag(procmemory)
    procmemory.set_defaults(handler=_cmd_get_procmemory)

    pcap = commands.add_parser("pcap", help="Download the network capture")
    _add_task_id_arg(pcap)
    pcap.add_argument("--variant", help="Capture variant served by CAPE, e.g. sorted")
    _add_output_flag(pcap)
    pcap.set_defaults(handler=_cmd_get_pcap)

    stream = commands.add_parser(
        "stream", help="Stream a file off the running analysis VM (open-ended)"
    )
    _add_task_id_arg(stream)
    stream.add_argument("filepath", help="File to stream from the guest")
    stream.add_argument(
        "--local",
        action="store_true",
        help="Resolve filepath under the task's analysis directory",
    )
    _add_output_flag(stream)
    stream.set_defaults(handler=_cmd_get_stream)

    for name, method, suffix, description in (
        (
            "tlspcap",
            CapeClient.task_tlspcap,
            "_tls.pcap",
            "Download the TLS-decrypted capture",
        ),
        ("evtx", CapeClient.task_evtx, ".evtx", "Download the Windows event log"),
        (
            "surifile",
            CapeClient.task_surifile,
            "_surifiles.zip",
            "Download Suricata captured files",
        ),
        (
            "fullmemory",
            CapeClient.task_fullmemory,
            ".dmp",
            "Download the full memory dump",
        ),
        (
            "payloads",
            CapeClient.task_payloadfiles,
            "_payloads.zip",
            "Download CAPE payload files",
        ),
        (
            "procdumps",
            CapeClient.task_procdumpfiles,
            "_procdumps.zip",
            "Download procdump files",
        ),
        (
            "mitmdump",
            CapeClient.task_mitmdump,
            ".har",
            "Download the mitmdump HAR file",
        ),
    ):
        download = commands.add_parser(name, help=description)
        _add_task_id_arg(download)
        _add_output_flag(download)
        download.set_defaults(handler=_download_handler(method, suffix))


def _add_sample_parsers(subparsers: SubParsers) -> None:
    sample = subparsers.add_parser("sample", help="Look up and download samples")
    commands = sample.add_subparsers(dest="subcommand", required=True)

    view = commands.add_parser("view", help="View sample information")
    view.add_argument("criteria", choices=(*HASH_TYPES, "id"))
    view.add_argument("value")
    view.set_defaults(handler=_cmd_sample_view)

    download = commands.add_parser("download", help="Download a sample")
    download.add_argument("criteria", choices=(*HASH_TYPES, "task"))
    download.add_argument("value")
    download.add_argument("--encrypted", action="store_true")
    _add_output_flag(download)
    download.set_defaults(handler=_cmd_sample_download)


def _add_machine_parsers(subparsers: SubParsers) -> None:
    machine = subparsers.add_parser("machine", help="Inspect analysis machines")
    commands = machine.add_subparsers(dest="subcommand", required=True)

    list_parser = commands.add_parser("list", help="List analysis machines")
    list_parser.set_defaults(handler=_no_arg_handler(CapeClient.machines_list))

    view = commands.add_parser("view", help="View one analysis machine")
    view.add_argument("name")
    view.set_defaults(handler=_cmd_machine_view)


def _add_yara_parsers(subparsers: SubParsers) -> None:
    yara = subparsers.add_parser("yara", help="Upload YARA rules")
    commands = yara.add_subparsers(dest="subcommand", required=True)

    upload = commands.add_parser("upload", help="Upload a YARA rule file")
    upload.add_argument("path")
    upload.add_argument(
        "--category",
        required=True,
        choices=sorted(YARA_CATEGORIES),
        help="YARA rule category",
    )
    upload.set_defaults(handler=_cmd_yara_upload)


def _add_dist_parsers(subparsers: SubParsers) -> None:
    dist = subparsers.add_parser(
        "dist", help="CAPE distributed nodes (separate service, needs --dist-url)"
    )
    # Every dist command talks to the distributed service, not the main API.
    dist.set_defaults(uses_dist=True)
    commands = dist.add_subparsers(dest="subcommand", required=True)

    commands.add_parser("nodes", help="List distributed nodes").set_defaults(
        handler=_cmd_dist_nodes
    )
    commands.add_parser("status", help="Distributed cluster status").set_defaults(
        handler=_cmd_dist_status
    )

    task = commands.add_parser("task", help="Distributed record for a main task id")
    task.add_argument("main_task_id", type=int)
    task.set_defaults(handler=_cmd_dist_task)

    node = commands.add_parser("node", help="Manage a distributed node")
    node_cmds = node.add_subparsers(dest="node_command", required=True)

    node_view = node_cmds.add_parser("view", help="View a node")
    node_view.add_argument("name")
    node_view.set_defaults(handler=_cmd_dist_node_view)

    node_add = node_cmds.add_parser("add", help="Register a node")
    node_add.add_argument("name")
    node_add.add_argument("--url", required=True, help="Node apiv2 base URL")
    node_add.add_argument("--apikey", help="Node API token")
    node_add.add_argument(
        "--enabled", action="store_true", default=None, help="Enable the node"
    )
    node_add.add_argument(
        "--exitnodes",
        action="store_true",
        default=None,
        help="Fetch exit nodes from this node",
    )
    node_add.set_defaults(handler=_cmd_dist_node_add)

    node_update = node_cmds.add_parser("update", help="Modify a node")
    node_update.add_argument("name")
    node_update.add_argument("--url", help="Node apiv2 base URL")
    node_update.add_argument("--apikey", help="Node API token")
    enabled = node_update.add_mutually_exclusive_group()
    enabled.add_argument("--enable", dest="enabled", action="store_true", default=None)
    enabled.add_argument("--disable", dest="enabled", action="store_false")
    exitnodes = node_update.add_mutually_exclusive_group()
    exitnodes.add_argument(
        "--exitnodes", dest="exitnodes", action="store_true", default=None
    )
    exitnodes.add_argument("--no-exitnodes", dest="exitnodes", action="store_false")
    node_update.set_defaults(handler=_cmd_dist_node_update)

    node_delete = node_cmds.add_parser("delete", help="Delete/disable a node")
    node_delete.add_argument("name")
    node_delete.set_defaults(handler=_cmd_dist_node_delete)


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="capecli", description="CLI for the CAPE v2 sandbox REST API"
    )
    parser.add_argument("--version", action="version", version=f"capecli {__version__}")
    parser.add_argument("--url", help="CAPE base URL (overrides env and config file)")
    parser.add_argument("--token", help="API token (overrides env and config file)")
    parser.add_argument("--timeout", type=float, help="HTTP timeout in seconds")
    parser.add_argument(
        "--dist-url",
        help="CAPE distributed service URL (for 'dist' commands; e.g. http://host:9003)",
    )
    parser.add_argument(
        "-F",
        "--output-format",
        choices=render.FORMATS,
        default=render.TABLE,
        help="How to print results (sarif suits only 'get report' and 'get iocs')",
    )
    # Commands that report findings attach their own builder; the absence of one
    # is what makes every other command reject --output-format sarif. Commands
    # that talk to the distributed service set uses_dist so main() builds the
    # right client.
    parser.set_defaults(sarif_builder=None, uses_dist=False)
    subparsers = parser.add_subparsers(dest="command", required=True)

    _add_submit_parsers(subparsers)
    _add_task_parsers(subparsers)
    _add_get_parsers(subparsers)
    _add_sample_parsers(subparsers)
    _add_machine_parsers(subparsers)
    _add_yara_parsers(subparsers)
    _add_dist_parsers(subparsers)

    status = subparsers.add_parser("status", help="View the CAPE host status")
    status.set_defaults(handler=_no_arg_handler(CapeClient.cape_status))

    stats = subparsers.add_parser("stats", help="Task statistics for the last N days")
    stats.add_argument("days", type=int)
    stats.set_defaults(handler=_cmd_stats)

    taskstats = subparsers.add_parser(
        "taskstats", help="Task statistics for the recent time window"
    )
    taskstats.set_defaults(handler=_no_arg_handler(CapeClient.tasks_stats))

    exitnodes = subparsers.add_parser("exitnodes", help="List configured exit nodes")
    exitnodes.set_defaults(handler=_no_arg_handler(CapeClient.exit_nodes))

    token = subparsers.add_parser(
        "token", help="Exchange a username and password for an API token"
    )
    token.add_argument("--username", required=True, help="CAPE account username")
    token.set_defaults(handler=_cmd_token)

    return parser


def _write(text: str, stream: TextIO) -> bool:
    """Print text the server chose, on a stream that may not take it.

    A response can carry characters the stream cannot represent -- JSON admits
    lone surrogates, and stdout is only UTF-8 by default on some platforms --
    and the write happens once the work is already done. Showing those
    characters escaped keeps a rendering detail from discarding the result.

    Returns False when the reader closed the stream first, as ``head`` does
    once it has the lines it wanted.
    """
    encoding = stream.encoding or "utf-8"
    try:
        print(text.encode(encoding, "backslashreplace").decode(encoding), file=stream)
        stream.flush()
    except BrokenPipeError:
        # The interpreter flushes this stream again while shutting down, and
        # would report that second failure on stderr as though it were ours.
        # Pointing the descriptor at the null device retires it quietly.
        devnull = os.open(os.devnull, os.O_WRONLY)
        try:
            os.dup2(devnull, stream.fileno())
        finally:
            # dup2 duplicates the description; this handle on it is spare, and
            # main() is callable more than once per process.
            os.close(devnull)
        return False
    return True


def main(argv: Sequence[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    try:
        # Before the handler runs: everything this needs is on the command line,
        # and a submission or a deletion should not happen only for its result
        # to be refused a rendering afterwards.
        render.check_format(args.output_format, args.sarif_builder)
        config = load_config(
            url=args.url,
            token=args.token,
            timeout=args.timeout,
            dist_url=args.dist_url,
            require_url=not args.uses_dist,
        )
        client_type: type[CapeClient] | type[DistClient] = (
            DistClient if args.uses_dist else CapeClient
        )
        with client_type(config) as client:
            result = args.handler(client, args)
        rendered = render.render(result, args.output_format, args.sarif_builder)
    except (CapeError, OSError, ValueError) as error:
        _write(f"error: {error}", sys.stderr)
        return 1
    try:
        delivered = _write(rendered, sys.stdout)
    except (OSError, ValueError) as error:
        # A full disk or a closed stdout arrives here, after the request has
        # already succeeded, and is still a failure the caller should be told
        # about rather than read out of a traceback.
        _write(f"error: cannot write the result: {error}", sys.stderr)
        return 1
    return 0 if delivered else BROKEN_PIPE_EXIT
