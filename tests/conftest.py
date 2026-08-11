"""Shared fixtures: a real in-process HTTP server emulating the CAPE API.

The server echoes request details as JSON for regular endpoints so tests can
assert exact URL construction, and returns the request path as bytes for
binary (download) endpoints. Special whole path segments trigger error
behaviours: 500 -> HTTP error, 404 -> CAPE error envelope, 400 -> invalid
JSON, 300 -> non-object JSON, 200 -> JSON body on a download endpoint,
100 -> HTML page (as served by restricted web endpoints), 302 -> redirect
to a login page (as served by disabled API endpoints), 206 -> truncated
body (connection closed before the declared length is sent), 401 -> error
envelope using CAPE's capitalised "Error" key, 403 -> error envelope whose
detail lives in an "errors" list instead of "error_value", 207 -> a gzipped
error envelope (one that cannot be read within a bound), 208 -> a gzipped body
that is tiny on the wire and enormous once decoded.
"""

import gzip
import json
import os
import threading
import time
from collections.abc import Iterator
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

import pytest

from capecli.client import CapeClient
from capecli.config import Config
from capecli.distributed import DistClient

# The media type CAPE itself serves for each artifact route, read off its own
# views. Answering every one of them as application/octet-stream would have the
# double agreeing with the client about a type the real server never sends: an
# artifact arrives as a zip, a capture, plain text or newline-delimited JSON,
# and only the last two are anywhere near the types the client rejects.
#
# "application/octet-stream;" is CAPE's own spelling for surifile, trailing
# semicolon and all, and is left exactly as it is: a media type with an empty
# parameter is what the client has to read the type out of.
BINARY_ROUTES: tuple[tuple[str, str], ...] = (
    ("/get/screenshot/", "application/zip"),
    ("/get/tlspcap/", "application/vnd.tcpdump.pcap"),
    ("/get/pcap/", "application/vnd.tcpdump.pcap"),
    ("/get/dropped/", "application/zip"),
    ("/get/selfextracted/", "application/zip"),
    ("/get/surifile/", "application/octet-stream;"),
    ("/get/procmemory/", "application/zip"),
    ("/get/fullmemory/", "application/octet-stream"),
    ("/get/payloadfiles/", "application/zip"),
    ("/get/procdumpfiles/", "application/zip"),
    ("/get/mitmdump/", "text/plain"),
    ("/get/evtx/", "application/zip"),
    ("/get/keys/", "text/plain"),
    ("/get/etw/", "application/x-ndjson"),
    ("/get/bulkzip/", "application/octet-stream"),
    ("/files/get/", "application/octet-stream"),
)

CANNED_RESPONSES: tuple[tuple[str, int, str, bytes], ...] = (
    ("500", 500, "text/plain", b"server error"),
    (
        # CAPE states many failures as a status code plus an envelope naming
        # the cause, which the code on its own does not convey.
        "503",
        503,
        "application/json",
        json.dumps({"error": True, "error_value": "Task not found"}).encode(),
    ),
    # A failure whose body claims to be JSON but states no cause: unparsable,
    # and parsed but not an envelope. The status code is then all there is.
    ("502", 502, "application/json", b"not-json"),
    ("504", 504, "application/json", b"[1, 2, 3]"),
    (
        # A failure whose stated cause is larger than any envelope. The size is
        # the server's choice and the message is going to a terminal.
        "507",
        507,
        "application/json",
        json.dumps({"error": True, "error_value": "E" * 70_000}).encode(),
    ),
    ("400", 200, "application/json", b"not-json"),
    (
        "404",
        200,
        "application/json",
        json.dumps({"error": True, "error_value": "task not found"}).encode(),
    ),
    (
        "401",
        200,
        "application/json",
        json.dumps({"Error": True, "error_value": "capitalised error flag"}).encode(),
    ),
    (
        "403",
        200,
        "application/json",
        json.dumps(
            {"error": True, "errors": [{"sample.bin": "duplicate file"}]}
        ).encode(),
    ),
    (
        # The delete route's spelling: the flag says there was a failure and
        # "failed" says which it was.
        "409",
        200,
        "application/json",
        json.dumps(
            {"error": True, "failed": "Task(s) ID(s) 9999 failed to remove"}
        ).encode(),
    ),
    (
        # Several routes put the whole reason in the field that elsewhere only
        # says whether there was one.
        "410",
        200,
        "application/json",
        json.dumps({"error": "Was impossible to retrieve url"}).encode(),
    ),
    (
        # The same, capitalised, as CAPE spells the flag in places.
        "411",
        200,
        "application/json",
        json.dumps({"Error": "capitalised error string"}).encode(),
    ),
    (
        # A failure that names no cause at all: the flag is the whole message.
        "412",
        200,
        "application/json",
        json.dumps({"error": True, "status": "partial_error"}).encode(),
    ),
    (
        # Not CAPE's envelope but the REST framework's underneath it, as served
        # for a token CAPE does not know.
        "413",
        401,
        "application/json",
        json.dumps({"detail": "Invalid token."}).encode(),
    ),
    (
        # The same layer's spelling for a rejected username and password.
        "414",
        400,
        "application/json",
        json.dumps(
            {"non_field_errors": ["Unable to log in with provided credentials."]}
        ).encode(),
    ),
    (
        # A collection under "data", the shape CAPE returns for list endpoints
        # and the one the table renderer turns into real columns.
        "77",
        200,
        "application/json",
        json.dumps(
            {
                "error": False,
                "data": [
                    {"id": 1, "status": "reported"},
                    {"id": 2, "status": "pending"},
                ],
            }
        ).encode(),
    ),
    (
        # A lone surrogate, which JSON admits and no UTF-8 stream can write.
        "55",
        200,
        "application/json",
        rb'{"error": false, "note": "\ud800"}',
    ),
    (
        # Nested past what the JSON parser can recurse through. The server
        # chooses how deeply its payload nests, so this is a response the
        # client has to report on rather than die of.
        "199",
        200,
        "application/json",
        b'{"a":' * 200_000 + b"1" + b"}" * 200_000,
    ),
    (
        # A JSON report past the size an error envelope could ever be.
        "66",
        200,
        "application/json",
        json.dumps({"error": False, "data": {"pad": "x" * 70_000}}).encode(),
    ),
    ("300", 200, "application/json", b"[1, 2, 3]"),
    ("200", 200, "application/json", b'{"error": false}'),
    ("100", 200, "text/html", b"<!DOCTYPE html><html></html>"),
    # Media types are case-insensitive and carry parameters; a server or proxy
    # spelling them differently describes exactly the same content.
    ("101", 200, "TEXT/HTML; charset=utf-8", b"<!DOCTYPE html><html></html>"),
    ("102", 200, "Application/JSON", b'{"error": true, "error_value": "shouted"}'),
)

# A body that is nothing on the wire and enormous once decoded, which is what
# makes decoding a streamed body to look inside it unaffordable. Kept far above
# any ceiling a reader could apply and far below anything that would trouble a
# machine running the suite.
GZIP_BOMB_PLAIN_SIZE = 32 * 1024 * 1024
GZIP_BOMB = gzip.compress(
    b'{"error": true, "error_value": "' + b"A" * GZIP_BOMB_PLAIN_SIZE + b'"}'
)

# Long enough that a client which waits on the body is unmistakably waiting,
# short enough not to hold the suite up. Handler threads are daemons, so a
# sleeping one never delays shutdown.
STALLED_BODY_SECONDS = 3.0

ISOLATED_ENV_KEYS = (
    "CAPECLI_URL",
    "CAPECLI_TOKEN",
    "CAPECLI_TIMEOUT",
    "CAPECLI_DIST_URL",
    "CAPECLI_PASSWORD",
    "HOME",
    "USERPROFILE",
    "HOMEDRIVE",
    "HOMEPATH",
)


def _binary_content_type(path: str) -> str | None:
    """The media type CAPE serves for this artifact route, or None if it is not one."""
    for marker, content_type in BINARY_ROUTES:
        if marker in path:
            return content_type
    return "application/zip" if path.endswith("/zip/") else None


class FakeCapeHandler(BaseHTTPRequestHandler):
    """Emulates CAPE API responses for the test suite."""

    def log_message(self, format: str, *args: object) -> None:
        """Keep test output quiet."""

    def do_GET(self) -> None:
        self._respond("GET", b"")

    def do_POST(self) -> None:
        length = int(self.headers.get("Content-Length", "0"))
        self._respond("POST", self.rfile.read(length))

    def do_PATCH(self) -> None:
        length = int(self.headers.get("Content-Length", "0"))
        self._respond("PATCH", self.rfile.read(length))

    def _respond(self, method: str, body: bytes) -> None:
        split = urlsplit(self.path)
        path = split.path
        segments = set(path.strip("/").split("/"))
        for marker, status, content_type, canned in CANNED_RESPONSES:
            if marker in segments:
                self._send(status, content_type, canned)
                return
        if "302" in segments:
            self.send_response(302)
            self.send_header("Location", "/accounts/login/")
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        if "208" in segments:
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Encoding", "gzip")
            self.send_header("Content-Length", str(len(GZIP_BOMB)))
            self.end_headers()
            self.wfile.write(GZIP_BOMB)
            return
        if "207" in segments:
            # An error envelope that arrives compressed. Decoding one to read
            # it is what has no bound, so its detail is not surfaced.
            body = gzip.compress(
                json.dumps({"error": True, "error_value": "gzipped"}).encode()
            )
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Encoding", "gzip")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        if "206" in segments:
            self.send_response(200)
            self.send_header("Content-Type", "application/octet-stream")
            self.send_header("Content-Length", "1000")
            self.end_headers()
            self.wfile.write(b"truncated")
            return
        if "205" in segments:
            # A failing status whose JSON body never arrives. Reading it would
            # cost a full read timeout for an error the status line already
            # carried, so nothing may wait on it.
            self.send_response(500)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", "1000")
            self.end_headers()
            time.sleep(STALLED_BODY_SECONDS)
            return
        if path == "/apiv2/api-token-auth/":
            # The real service answers {"token": "<40 chars>"}; a username of
            # "notoken" stands in for a response that omits it.
            if b"username=notoken" in body:
                token: dict[str, str] = {}
            elif b"username=emptytoken" in body:
                token = {"token": ""}
            else:
                token = {"token": "t" * 40}
            self._send(200, "application/json", json.dumps(token).encode())
            return
        if path == "/apiv2/tasks/delete_many/":
            fields = parse_qs(body.decode())
            ids = [i for i in fields.get("ids", [""])[0].split(",") if i]
            invalid = [i for i in ids if not i.isdigit()]
            if invalid:
                # CAPE splits this field on commas and keeps only all-digit
                # tokens, so a range reaches it as one invalid id and nothing
                # is deleted. It names them in a list, not under error_value.
                self._send_json(
                    {
                        "error": True,
                        "status": "partial_error",
                        "invalid_ids": invalid,
                    }
                )
            elif "99" in ids:
                # A partial failure comes back as an error envelope.
                self._send_json(
                    {"error": True, "status": "partial_error", "99": "error"}
                )
            else:
                self._send_json(
                    {
                        "error": False,
                        "status": "OK",
                        "deleted": ids,
                        "delete_mongo": fields.get("delete_mongo", [""])[0],
                    }
                )
            return
        if path == "/apiv2/yara_uploader/":
            if b"syntaxerror" in body:
                # The uploader reports the reason under "message", not error_value.
                self._send_json(
                    {"status": "error", "message": "YARA Syntax Error: bad rule"}, 400
                )
            elif b"disabledtest" in body:
                self._send_json(
                    {"error": True, "error_value": "Yara Uploader API is Disabled"}
                )
            else:
                self._send_json({"status": "success", "message": "uploaded"})
            return
        if "/tasks/get/stream/" in path:
            filepath = parse_qs(body.decode()).get("filepath", [""])[0]
            if filepath == "missing":
                self._send_json(
                    {"error": True, "error_value": f"{filepath} does not exist"}
                )
            else:
                self._send(
                    200, "application/octet-stream", f"STREAM:{filepath}".encode()
                )
            return
        if "/tasks/visibility/" in path:
            vis = parse_qs(body.decode()).get("visibility", [""])[0]
            if vis == "invalid":
                self._send_json(
                    {"error": True, "error_value": "invalid visibility"}, 400
                )
            else:
                task_id = int(path.rstrip("/").rsplit("/", 1)[-1])
                self._send_json(
                    {"error": False, "data": {"task_id": task_id, "visibility": vis}}
                )
            return
        if "/get/report/" in path:
            # Matched case-insensitively, as a server accepting the format name
            # in any case would.
            report_format = path.rstrip("/").rsplit("/", 1)[-1].lower()
            if report_format.endswith("html"):
                self._send(200, "text/html", b"<html>report</html>")
                return
            if report_format in ("metadata", "pdf", "maec"):
                self._send(200, "application/octet-stream", path.encode())
                return
        artifact_type = _binary_content_type(path)
        if artifact_type is not None:
            marker = path + (f"?{split.query}" if split.query else "")
            self._send(200, artifact_type, marker.encode())
            return
        payload = {
            "error": False,
            "method": method,
            "path": path,
            "query": split.query,
            "content_type": self.headers.get("Content-Type", ""),
            "body": body.decode("utf-8", errors="replace"),
            "authorization": self.headers.get("Authorization", ""),
        }
        self._send(200, "application/json", json.dumps(payload).encode())

    def _send(self, status: int, content_type: str, body: bytes) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _send_json(self, obj: object, status: int = 200) -> None:
        self._send(status, "application/json", json.dumps(obj).encode())


@pytest.fixture(scope="session")
def cape_url() -> Iterator[str]:
    server = ThreadingHTTPServer(("127.0.0.1", 0), FakeCapeHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}"
    finally:
        server.shutdown()
        thread.join()
        # shutdown() only stops the accept loop; without this the listening
        # socket survives until the garbage collector finalizes it.
        server.server_close()


@pytest.fixture
def client(cape_url: str) -> Iterator[CapeClient]:
    with CapeClient(Config(url=cape_url, token="test-token")) as cape:
        yield cape


class FakeDistHandler(BaseHTTPRequestHandler):
    """Emulates CAPE's distributed Flask API (/node, /status, /task)."""

    def log_message(self, format: str, *args: object) -> None:
        """Keep test output quiet."""

    def _body(self) -> bytes:
        length = int(self.headers.get("Content-Length", "0"))
        return self.rfile.read(length)

    def do_GET(self) -> None:
        self._respond("GET", b"")

    def do_POST(self) -> None:
        self._respond("POST", self._body())

    def do_PUT(self) -> None:
        self._respond("PUT", self._body())

    def do_DELETE(self) -> None:
        self._respond("DELETE", b"")

    def _respond(self, method: str, body: bytes) -> None:
        parts = urlsplit(self.path).path.strip("/").split("/")
        fields = parse_qs(body.decode()) if body else {}
        if parts == ["node"] and method == "GET":
            self._send({"nodes": {"main": {"url": "http://n1", "enabled": True}}})
        elif parts == ["node"] and method == "POST":
            name = fields.get("name", [""])[0]
            if name == "existing":
                self._send({"success": False, "message": f"Node {name} already exists"})
            else:
                self._send({"name": name, "machines": ["win10"], "exitnodes": []})
        elif len(parts) == 2 and parts[0] == "node":
            self._node(method, parts[1])
        elif parts == ["status"] and method == "GET":
            self._send({"nodes": {}, "tasks": {"pending": 0}})
        elif len(parts) == 2 and parts[0] == "task" and method == "GET":
            if parts[1] == "0":
                self._send({"error": True, "error_value": "No tasks found"})
            else:
                self._send({"Tasks": [{"id": int(parts[1])}]})
        else:
            self._send({"error": True, "error_value": "not found"}, 404)

    def _node(self, method: str, name: str) -> None:
        if name == "aslist":
            # A non-object body, to exercise the client's shape check.
            self._send([1, 2, 3])
        elif name == "ghost":
            self._send({"error": True, "error_value": "Node doesn't exist"})
        elif method == "GET":
            self._send({"name": name, "url": "http://n1"})
        elif method == "PUT":
            self._send({"error": False, "error_value": f"Modified node: {name}"})
        else:  # DELETE
            self._send({"error": False, "error_value": f"Deleted node: {name}"})

    def _send(self, obj: object, status: int = 200) -> None:
        body = json.dumps(obj).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


@pytest.fixture(scope="session")
def dist_url() -> Iterator[str]:
    server = ThreadingHTTPServer(("127.0.0.1", 0), FakeDistHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}"
    finally:
        server.shutdown()
        thread.join()
        server.server_close()


@pytest.fixture
def dist_client(dist_url: str) -> Iterator[DistClient]:
    with DistClient(Config(url="http://unused", dist_url=dist_url)) as dist:
        yield dist


@pytest.fixture
def stalled_body_seconds() -> float:
    """How long the stalling route withholds its body."""
    return STALLED_BODY_SECONDS


@pytest.fixture
def isolated_env(tmp_path: Path) -> Iterator[Path]:
    """Run in tmp_path with capecli env vars cleared and home dirs redirected."""
    saved = {key: os.environ.get(key) for key in ISOLATED_ENV_KEYS}
    for key in ISOLATED_ENV_KEYS:
        os.environ.pop(key, None)
    os.environ["HOME"] = str(tmp_path)
    os.environ["USERPROFILE"] = str(tmp_path)
    previous_cwd = Path.cwd()
    os.chdir(tmp_path)
    try:
        yield tmp_path
    finally:
        os.chdir(previous_cwd)
        for key, value in saved.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value
