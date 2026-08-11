<p align="center">
  <img src="https://img.shields.io/badge/capecli-CAPE%20v2%20REST%20API-blue?style=for-the-badge" alt="capecli">
</p>

<h1 align="center">capecli</h1>

<p align="center">
  <strong>CLI and Python library for the CAPE v2 malware sandbox REST API</strong>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/python-3.14%2B-blue?style=flat-square&logo=python&logoColor=white" alt="Python Versions">
  <img src="https://img.shields.io/badge/platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey?style=flat-square" alt="Platforms">
  <img src="https://img.shields.io/badge/coverage-100%25%20line%20%26%20branch-brightgreen?style=flat-square" alt="Coverage">
  <img src="https://img.shields.io/badge/mypy-strict-blue?style=flat-square" alt="mypy strict">
</p>

<p align="center">
  <a href="https://github.com/seifreed/capecli/stargazers"><img src="https://img.shields.io/github/stars/seifreed/capecli?style=flat-square" alt="GitHub Stars"></a>
  <a href="https://github.com/seifreed/capecli/issues"><img src="https://img.shields.io/github/issues/seifreed/capecli?style=flat-square" alt="GitHub Issues"></a>
  <a href="https://buymeacoffee.com/seifreed"><img src="https://img.shields.io/badge/Buy%20Me%20a%20Coffee-support-yellow?style=flat-square&logo=buy-me-a-coffee&logoColor=white" alt="Buy Me a Coffee"></a>
</p>

---

## Overview

**capecli** is a Python toolkit for driving a [CAPE v2 sandbox](https://capev2.readthedocs.io/en/latest/usage/api.html) from the command line or from code. It covers the `/apiv2/` endpoints for token authentication, submission, task management, reports, IOCs, artifact downloads, sample downloads, machines, and host status.

### Key Features

| Feature | Description |
|---------|-------------|
| **Endpoint coverage** | Every `/apiv2/` endpoint plus CAPE's distributed node API: authentication, submission, tasks (including the worker-cleanup bulk delete and the multitenancy visibility toggle), reports, IOCs, artifacts, the live-VM file stream, YARA-rule upload, samples, machines, host status, and distributed node management |
| **CLI + Library** | Every endpoint reachable both as a subcommand and as a typed method |
| **Four output formats** | Readable tables by default, plus JSON, TOON for LLM prompts, and SARIF 2.1.0 for code scanning |
| **Typed** | Ships `py.typed`; the package is `mypy --strict` clean with no suppressions |
| **Streaming downloads** | Large artifacts stream to disk instead of being buffered whole |
| **Crash-safe writes** | A download is written beside its destination and moved onto it only once complete, so a dropped connection or a Ctrl-C leaves neither a partial file nor a damaged earlier one |
| **Credential hygiene** | Passwords are read from the environment, never from `argv` |
| **Two runtime dependencies** | `httpx` and `prettytable`, nothing else |
| **Cross-platform** | Windows, Linux, and macOS on x64 and ARM |
| **100% line and branch coverage** | Enforced by the suite, with no mocks anywhere |

### Behaviour

```text
Results         Rendered as a table by default; -F selects json, toon, or sarif
Downloads       Written to a path you choose; the path is printed on success
Errors          CAPE error envelopes and HTTP errors raise ApiError
Exit codes      0 on success, 1 on API or configuration errors, 2 on usage
                errors, 141 when the reader closed the pipe (as `| head` does)
```

---

## Installation

`capecli` is not published on PyPI; install it from source.

```bash
git clone https://github.com/seifreed/capecli.git
cd capecli
python3 -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate
pip install .
```

### For Development

All dependencies, runtime and development alike, live in `pyproject.toml`: the runtime dependency under `[project]` and the toolchain under `[dependency-groups]`.

```bash
pip install -e . --group dev
```

---

## Configuration

Settings resolve in this order, first match wins:

1. CLI flags: `--url`, `--token`, `--timeout`, `--dist-url`
2. Environment variables: `CAPECLI_URL`, `CAPECLI_TOKEN`, `CAPECLI_TIMEOUT`, `CAPECLI_DIST_URL`
3. Config file: `./capecli.toml`, then `~/.config/capecli/config.toml`

Example `capecli.toml`:

```toml
url = "https://cape.example.tld"
token = "YOUR_API_TOKEN"
timeout = 60
# Only needed for `dist` commands: CAPE's distributed service (default port 9003,
# a separate host and no token). Leave it out if you do not run distributed CAPE.
dist_url = "http://cape-dist.example.tld:9003"
```

`CAPECLI_PASSWORD` is read only by `capecli token`, and never from the command line.

Each setting resolves on its own, so a `capecli.toml` in the working directory can supply the
URL while the token still comes from the environment. That is worth knowing for this tool in
particular: analysis often means working inside a directory of files somebody else chose, and a
`capecli.toml` dropped there would point your token at the host it names. Run from a directory
you control, or pass `--url` explicitly, when the working directory holds untrusted files.

---

## Quick Start

```bash
# Obtain an API token (password comes from the environment, not argv)
read -rs CAPECLI_PASSWORD && export CAPECLI_PASSWORD
capecli token --username <user>

# Submit a sample and read the report
capecli submit file /path/to/sample --machine VM-Name
capecli get report 123

# Pull the network capture
capecli get pcap 123 -o task_123.pcap
```

---

## Usage

### Main Commands

| Command | Description |
|---------|-------------|
| `capecli token` | Exchange a username and password for an API token |
| `capecli submit` | Submit files, URLs, or hashes for analysis |
| `capecli task` | Inspect and manage tasks |
| `capecli get` | Fetch reports and analysis artifacts |
| `capecli sample` | Look up and download samples |
| `capecli machine` | Inspect analysis machines |
| `capecli status` / `stats` / `taskstats` / `exitnodes` | Host status and statistics |

### Global Options

| Option | Description |
|--------|-------------|
| `--url <url>` | CAPE base URL, overriding env and config file |
| `--token <token>` | API token, overriding env and config file |
| `--timeout <seconds>` | HTTP timeout |
| `--dist-url <url>` | CAPE distributed service URL, for `dist` commands (e.g. `http://host:9003`) |
| `-F, --output-format` | `table` (default), `json`, `toon`, or `sarif` |
| `--version` | Print the version and exit |

`-o, --output <file>` sets the destination for a command that downloads a file. It belongs to
those commands rather than to the program, so it follows the subcommand: `capecli get pcap 123
-o dump.pcap`.

### Output Formats

Global options come before the subcommand: `capecli -F toon task list 10 0`.

| Format | Use it for |
|--------|-----------|
| `table` | Reading at a terminal. Collections become columns; anything else becomes key/value rows with dotted paths. Columns that are empty in every row are dropped, and long values are truncated — use `json` when you need every byte. |
| `json` | Scripting and `jq`. Pretty-printed and key-sorted. |
| `toon` | Feeding results to an LLM. [TOON](https://github.com/toon-format/spec) is a lossless JSON encoding that spends far fewer tokens on syntax. |
| `sarif` | Pipelines and GitHub Code Scanning. SARIF 2.1.0 describes findings, so it applies only to `get report` (CAPE signatures) and `get iocs`; any other command rejects it rather than emit an empty run. |

```bash
capecli task list 10 0                          # table
capecli -F json task view 123 | jq .data.status
capecli -F toon get report 123                  # compact enough to paste into a prompt
capecli -F sarif get report 123 > results.sarif
```

Redirect to save SARIF: on `get report`, `-o` and `--zip` mean "save the report as a file",
which is the opposite of rendering its findings, so combining either with `-F sarif` is refused.
`--format` selects what CAPE serves: `json`, `maec5` and `litereport` come back as JSON, and
every other format is a document that needs `-o`.

Downloads print the destination path in `table`, `json` and `toon`, so `capecli get pcap 123`
stays pipeable.

### Submission

```bash
# --argument sets any top-level CAPE submission field: package, timeout, priority,
#   memory, enforce_timeout, unique, clock, tags, route, platform, tlp, custom, ...
# --option adds an analyzer option to CAPE's "key=value,key=value" options string
capecli submit file /path/to/sample --machine VM-Name --argument timeout=120
capecli submit file /path/to/sample --option procdump=1 --option route=tor
capecli submit file /path/to/capture.pcap --pcap
capecli submit static /path/to/sample
capecli submit url "http://somebadness.tld"
capecli submit dlnexec "https://somebadness.tld/malware.exe"
capecli submit download-services <hash> --apikey <API_KEY>   # VirusTotal or MalwareBazaar
```

### Tasks

```bash
capecli task view 123
capecli task status 123
capecli task machine 123
capecli task list 50 0 --status reported
capecli task list 50 0 --window 60 --category file --ids
capecli task search sha256 <hash>
capecli task extsearch domain evil.tld --limit 200
capecli task latest 24
capecli task reschedule 123
capecli task reprocess 123
capecli task delete 123
capecli task delete 100-110 --status failed_analysis
capecli task delete-many 100-110               # bulk delete (CAPE's worker-cleanup path)
capecli task delete-many 100-110 --keep-reports   # ... but keep the stored reports
capecli task visibility 123 public             # multitenancy; needs CAPE's UI auth
```

### Reports and Artifacts

```bash
capecli get report 123                              # table to stdout
capecli get report 123 -o report.json               # -o saves any format CAPE serves
capecli get report 123 --format html -o report.html # documents need -o
capecli get report 123 --zip -o report.zip
capecli get iocs 123 --detailed
capecli get config 123 --family Emotet
capecli get screenshots 123
capecli get dropped 123 --max-size 100
capecli get pcap 123
capecli get pcap 123 --variant sorted
capecli get tlspcap 123
capecli get evtx 123
capecli get keys 123 tls
capecli get etw 123 all
capecli get bulkzip 123 CAPE
capecli get selfextracted 123 --tool unpacker
capecli get surifile 123
capecli get procmemory 123 --pid 1234
capecli get fullmemory 123
capecli get payloads 123
capecli get procdumps 123
capecli get mitmdump 123
capecli get stream 123 C:/analysis/output.log   # a file off the running VM (open-ended)
```

### Samples and Infrastructure

```bash
capecli sample view sha256 <hash>
capecli sample download task 123 -o sample.bin
capecli sample download sha256 <hash> --encrypted

capecli machine list
capecli machine view VM-Name
capecli status
capecli stats 7
capecli taskstats
capecli exitnodes
```

### YARA Rules

```bash
# Categories: binaries, urls, memory, CAPE, macro, monitor
capecli yara upload rule.yar --category CAPE
```

### Distributed

CAPE's distributed layer is a **separate service** (default port 9003, no token), so
these commands use `--dist-url` (or `CAPECLI_DIST_URL`, or `dist_url` in the config file)
instead of the main `--url`.

```bash
capecli --dist-url http://cape-dist:9003 dist nodes
capecli --dist-url http://cape-dist:9003 dist status
capecli --dist-url http://cape-dist:9003 dist task 123
capecli --dist-url http://cape-dist:9003 dist node view worker1
capecli --dist-url http://cape-dist:9003 dist node add worker1 --url http://worker1:8090 --apikey <token> --enabled
capecli --dist-url http://cape-dist:9003 dist node update worker1 --disable
capecli --dist-url http://cape-dist:9003 dist node delete worker1
```

> **Caveats.** `get stream` is open-ended — CAPE keeps streaming the file while the guest
> runs, so the command returns when the guest stops or the server closes the stream.
> `task visibility` is gated behind CAPE's web-UI session auth and needs multitenancy
> enabled, so a token-authenticated client usually gets 401/403 there.

---

## Python Library

### Basic Usage

```python
from pathlib import Path

from capecli import CapeClient, load_config

config = load_config()  # or Config(url="https://cape.example.tld", token="...")
with CapeClient(config) as cape:
    task = cape.submit_file(Path("sample.exe"), machine="VM-Name")
    report = cape.task_report(task["data"]["task_ids"][0])
    cape.task_pcap(123, Path("task_123.pcap"))
```

All JSON endpoints return `dict`; download endpoints write to a `Path` you provide and return it.
`to_toon`, `report_to_sarif`, and `iocs_to_sarif` are exported for rendering results yourself.
`DistClient` (constructed the same way, from a `Config` carrying `dist_url`) drives CAPE's
distributed node API.

### Obtaining a Token

`obtain_token` is the one call made through a client built without a token, since it is what produces one.

```python
from capecli import CapeClient, Config

with CapeClient(Config(url="https://cape.example.tld")) as cape:
    token = cape.obtain_token("username", "password")
```

### Error Handling

```python
from capecli import ApiError, CapeError, ConfigError

try:
    ...
except ApiError as error:      # CAPE error envelope or HTTP failure
    print(error, error.status_code)
except ConfigError as error:   # missing or invalid configuration
    print(error)
# both derive from CapeError
```

---

## Development

Quality and security gates, all of which must pass with no errors, warnings, or suppressions:

```bash
black --check .
ruff check .
mypy .
bandit -c pyproject.toml -r .
pip-audit
pytest  # 100% line and branch coverage; warnings fail the run
```

Tests run against a real in-process HTTP server that emulates the CAPE API. There are no mocks, stubs, or patched objects anywhere in the suite.

---

## Requirements

- Python 3.14+
- `httpx` and `prettytable` (the only runtime dependencies)
- See [pyproject.toml](pyproject.toml) for the development toolchain

---

## Contributing

Contributions are welcome.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

Every gate listed under [Development](#development) must pass before a pull request is merged.

---

## Support the Project

If this project is useful in your workflows, you can support development:

<a href="https://buymeacoffee.com/seifreed" target="_blank">
  <img src="https://cdn.buymeacoffee.com/buttons/v2/default-yellow.png" alt="Buy Me A Coffee" height="50">
</a>

---

## Attribution

- Author: **Marc Rivero López** | [@seifreed](https://github.com/seifreed)
- Repository: [github.com/seifreed/capecli](https://github.com/seifreed/capecli)

---

<p align="center">
  <sub>Built for practical malware analysis workflows and sandbox automation</sub>
</p>
