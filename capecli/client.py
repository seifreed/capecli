"""HTTP client covering every endpoint of the CAPE v2 REST API."""

import json
import os
import sys
import tempfile
from collections.abc import Iterator, Mapping, Sequence
from contextlib import contextmanager, suppress
from pathlib import Path
from types import TracebackType
from typing import IO, Any, Self
from urllib.parse import quote

import httpx

from capecli.config import Config
from capecli.errors import ApiError, ConfigError

JsonDict = dict[str, Any]
FormValue = str | int
FilePayload = Mapping[str, tuple[str, IO[bytes]]]

# CAPE joins analyzer options into one field with this separator.
OPTIONS_SEPARATOR = ","

# The report formats CAPE serves as JSON. It serves every other one as XML,
# HTML, PDF or a zip bundle, none of which a JSON endpoint could return.
JSON_REPORT_FORMATS = frozenset({"json", "maec5", "litereport"})

# The rule categories CAPE's YARA uploader accepts.
YARA_CATEGORIES = frozenset({"binaries", "urls", "memory", "CAPE", "macro", "monitor"})

# An error envelope is a short object and a report is orders of magnitude
# larger, so a saved file above this size is the report and needs no reading
# back. Without a ceiling the check would buffer whole what it just streamed.
ENVELOPE_SIZE_LIMIT = 64 * 1024

# How many IDs a range may expand to. A typed "1-99999999" is a slip, not a
# request, and expanding it would build the string before anything could refuse
# it.
TASK_RANGE_LIMIT = 10_000

# How much of a destination's name a temporary beside it may carry. Filesystems
# bound a name in bytes, which one character can be four of, and mkstemp adds
# its own; a download to a legal path may not fail over the name we chose.
TEMPORARY_NAME_BYTES = 100


def _segment(value: object) -> str:
    """Percent-encode one path segment.

    A segment of "." or ".." is a relative path step, and would be resolved
    away before the request left the client: a hash of ".." turned
    "files/view/md5/../" into "files/view/", quietly querying a different
    endpoint. Encoding the dots keeps such a value a literal segment, which
    the server can then reject.

    An empty value collapses the same way and cannot be encoded out of it:
    "files/view/md5//" is "files/view/md5/" to a server that folds repeated
    slashes, so an empty hash would query the endpoint one level up instead of
    being rejected as the missing value it is. Refusing it here is what keeps
    the request the caller asked for the one that gets made.
    """
    text = str(value)
    if not text:
        raise ValueError("path segment is empty; this value is required")
    encoded = quote(text, safe=",")
    if encoded in (".", ".."):
        return encoded.replace(".", "%2E")
    return encoded


def _path(*parts: object) -> str:
    """Join path segments, skipping unset ones.

    CAPE encodes optional arguments as trailing path segments, so a ``None``
    part means "the caller did not ask for this segment".
    """
    return "/".join(_segment(part) for part in parts if part is not None) + "/"


def _fields(**fields: FormValue | None) -> dict[str, FormValue]:
    """Drop unset values so CAPE only receives the fields actually requested."""
    return {key: value for key, value in fields.items() if value is not None}


def _task_selector(tasks: int | str | Sequence[int]) -> str:
    if isinstance(tasks, int | str):
        if not str(tasks):
            raise ValueError("no task selector given")
        return str(tasks)
    if not tasks:
        raise ValueError("no task IDs given")
    return ",".join(str(task_id) for task_id in tasks)


def _expanded_selector(tasks: int | str | Sequence[int]) -> str:
    """A task selector with its ranges spelled out.

    The single-task delete route carries the selector in the URL, where CAPE's
    own pattern accepts ``1-5``. The bulk delete carries it in the body, and
    there CAPE splits on commas and keeps only all-digit tokens, so it answers
    a range with ``{"invalid_ids": ["1-5"], "status": "partial_error"}`` and
    deletes nothing. Expanding here is what makes one spelling work on both.
    """
    parts: list[str] = []
    for token in _task_selector(tasks).split(","):
        first, dash, last = token.strip().partition("-")
        if not dash:
            parts.append(first)
            continue
        if not (first.isdigit() and last.isdigit()) or int(last) < int(first):
            raise ValueError(f"invalid task range: {token.strip()!r}")
        parts.extend(str(task_id) for task_id in range(int(first), int(last) + 1))
        if len(parts) > TASK_RANGE_LIMIT:
            raise ValueError(
                f"task range covers more than {TASK_RANGE_LIMIT} IDs: {token.strip()!r}"
            )
    return ",".join(parts)


@contextmanager
def _file_payload(path: Path) -> Iterator[FilePayload]:
    """Open a sample for streamed multipart upload, so large files are not buffered."""
    with path.open("rb") as handle:
        yield {"file": (path.name, handle)}


def _options_string(options: Mapping[str, FormValue] | None) -> str | None:
    """Render analyzer options the way CAPE expects them: "key=value,key=value".

    The format has no escape syntax, so a name or value carrying a separator
    cannot be expressed: "custom=a,b" would reach the analyzer as an option
    "custom" of "a" plus a second option "b". Such input is refused rather than
    silently turned into a different analyzer configuration.
    """
    if not options:
        return None
    pairs = []
    for key, value in options.items():
        if OPTIONS_SEPARATOR in key or "=" in key:
            raise ValueError(
                f"analyzer option name {key!r} cannot contain "
                f"{OPTIONS_SEPARATOR!r} or '='"
            )
        if OPTIONS_SEPARATOR in str(value):
            raise ValueError(
                f"analyzer option {key!r} cannot contain {OPTIONS_SEPARATOR!r}"
            )
        pairs.append(f"{key}={value}")
    return OPTIONS_SEPARATOR.join(pairs)


def _form_data(
    arguments: Mapping[str, FormValue] | None,
    options: Mapping[str, FormValue] | None = None,
    **fields: FormValue | None,
) -> dict[str, FormValue]:
    """Build the POST body from CAPE submission arguments plus analyzer options.

    ``arguments`` are top-level fields CAPE parses individually (package, timeout,
    priority, memory, ...); ``options`` is collapsed into the single options field.

    A submission argument naming a field this call fills itself is refused: two
    sources for one CAPE field mean one of them is discarded, and the caller
    asked for both. An argument whose dedicated parameter went unused is left
    alone, so it stays the way to reach a field with no parameter of its own.
    """
    generated = _fields(**fields)
    rendered = _options_string(options)
    if rendered is not None:
        generated["options"] = rendered
    data: dict[str, FormValue] = dict(arguments or {})
    reserved = sorted(data.keys() & generated.keys())
    if reserved:
        names = ", ".join(repr(name) for name in reserved)
        raise ValueError(f"submission argument {names} is already set by this call")
    data.update(generated)
    return data


def _validated_token(token: str | None) -> str:
    """Trim surrounding whitespace and reject tokens unusable as a header value.

    The token is never echoed back, so a malformed one cannot leak into logs.
    """
    if token is None:
        return ""
    trimmed = token.strip()
    if any(character in trimmed for character in "\r\n\x00"):
        raise ConfigError("API token contains control characters")
    if not trimmed.isascii():
        # Header values are ASCII; without this the token fails at request
        # time as a codec complaint rather than as a configuration problem.
        raise ConfigError("API token contains non-ASCII characters")
    return trimmed


def _media_type(response: httpx.Response) -> str:
    """The response's media type alone, lowercased.

    Media types are case-insensitive and may carry parameters, so "TEXT/HTML"
    and "text/html; charset=utf-8" both describe an HTML page.
    """
    header: str = response.headers.get("content-type", "")
    return header.split(";")[0].strip().lower()


def _error_body(response: httpx.Response) -> bytes:
    """The failing response's body, when it is already in hand.

    A streamed body is left where it is. Fetching one means a live read taken
    while a failure is already being reported, and it cannot be made cheap
    enough to be worth it. Nothing is yielded until a chunk fills or the
    timeout expires, so a server that stalls costs a full read timeout and one
    that trickles costs a great many; and a compressed body is decoded whole
    before any of it can be looked at, so a few hundred bytes on the wire can
    cost hundreds of megabytes, chained encodings multiplying that again.

    The status is what the server has already managed to say. A download
    reports that on its own rather than pay either price for the reason.
    """
    try:
        return response.content
    except httpx.ResponseNotRead:
        return b""


def _envelope_body(response: httpx.Response) -> bytes | None:
    """A streamed body while it could still be an error envelope, else None.

    Only as many bytes as an envelope could be are taken, and only while they
    arrive unencoded. Decoding is what has no bound: a content encoding
    expands what travelled on the wire, so a body that arrives small is not
    small once decoded -- a few hundred bytes can cost hundreds of megabytes,
    and chained encodings multiply that again -- and the expansion happens a
    whole chunk at a time, before any ceiling could measure it. So an encoded
    body is left unread rather than decoded to find out how big it was.

    What that costs is the detail in the message, not the report of the
    failure, which the status and the media type already carry.
    """
    if response.headers.get("content-encoding"):
        return None
    chunks: list[bytes] = []
    size = 0
    for chunk in response.iter_raw():
        size += len(chunk)
        if size > ENVELOPE_SIZE_LIMIT:
            return None
        chunks.append(chunk)
    return b"".join(chunks)


def _raise_for_envelope_in(body: bytes, status_code: int) -> None:
    """Report the error envelope a body carries, where it carries one."""
    try:
        payload = json.loads(body)
    except ValueError:
        return
    _raise_for_error_envelope(payload, status_code)


def _envelope_detail(payload: dict[str, Any]) -> str:
    """The reason an error envelope names, in the order CAPE fills the fields.

    Both the failing-status message and the error-on-success check read the
    cause from the same keys; sharing this keeps them from ever disagreeing on
    which one wins. ``message`` is the YARA uploader's spelling of the same
    thing, ``failed`` the delete route's, and ``invalid_ids`` the bulk delete's.

    ``detail`` and ``non_field_errors`` are not CAPE's own but the REST
    framework's underneath it, and they carry the two failures a caller is
    likeliest to meet: "Invalid token." for a wrong token and "Unable to log in
    with provided credentials." for a wrong password. Without them each arrives
    as a bare status code, which reads no differently from a server that is
    misbehaving.

    The flag itself is read last, and only when it is a string: several routes
    spell the whole envelope as ``{"error": "Was impossible to retrieve url"}``,
    putting the reason in the field that elsewhere only says whether there was
    one. Reading it first would let a bare ``true`` outrank a real message.
    """
    detail = (
        payload.get("error_value")
        or payload.get("errors")
        or payload.get("message")
        or payload.get("failed")
        or payload.get("invalid_ids")
        or payload.get("detail")
        or payload.get("non_field_errors")
    )
    if not detail:
        for flag in (payload.get("error"), payload.get("Error")):
            if isinstance(flag, str):
                detail = flag
                break
    if not detail:
        return ""
    # Several of these fields hold a list of sentences. Printing the list itself
    # would show the reader a Python repr of the message rather than the message.
    if isinstance(detail, list) and all(isinstance(item, str) for item in detail):
        return "; ".join(detail)
    return str(detail)


def _error_detail(response: httpx.Response) -> str:
    """The reason a failing response states, where it states one in JSON.

    CAPE answers many failures with a status code and an envelope naming the
    cause -- "Task not found", "Report format not found: xml" -- and the code
    on its own leaves the caller to guess which of them it was. Which failures
    can be explained this way is decided by _error_body.
    """
    if _media_type(response) != "application/json":
        return ""
    body = _error_body(response)
    if len(body) > ENVELOPE_SIZE_LIMIT:
        return ""
    try:
        payload = json.loads(body)
    except ValueError:
        return ""
    if not isinstance(payload, dict):
        return ""
    return _envelope_detail(payload)


def _raise_for_status(response: httpx.Response, path: str) -> None:
    if response.is_success:
        return
    message = f"HTTP {response.status_code} for {path}"
    detail = _error_detail(response)
    if detail:
        message += f": {detail}"
    location = response.headers.get("location")
    if location:
        message += (
            f" (server redirected to {location}; "
            "check the configured URL scheme and host)"
        )
    raise ApiError(message, status_code=response.status_code)


def _temporary_prefix(name: str) -> str:
    """Name a temporary after its destination, within the limit on names.

    Names are bounded in bytes and one character can be four of them, so the
    cut is made on the encoded form. Recognising a leftover is all the name is
    for, so a cut landing inside a character costs nothing.

    The filesystem codec is what encodes here, not UTF-8: a name is bytes to
    the operating system, and the ones it accepts need not spell a valid
    string. Encoding through UTF-8 raised on such a name instead, failing a
    download to a path the filesystem would have taken.

    Decoding back drops what it cannot read, which is both the bytes no codec
    claims and whatever part of a character the cut left. Neither can be
    reported through a name, and refusing to name a temporary over either
    would fail the same download from the other side: os.fsdecode carries the
    first back out but raises on the second wherever the platform's error
    handler is surrogatepass rather than surrogateescape.
    """
    encoded = os.fsencode(name)[:TEMPORARY_NAME_BYTES]
    return f".{encoded.decode(sys.getfilesystemencoding(), 'ignore')}."


def _keep_the_mode_of(dest: Path, partial: Path) -> None:
    """Give a replacement the mode the file it replaces already had.

    A temporary is created private, which suits an artifact pulled from a
    sandbox. It does not suit carrying that mode over to a file the caller
    already had and did not ask to have changed.
    """
    with suppress(OSError):
        partial.chmod(dest.stat().st_mode & 0o777)


def _save_beside_then_move(
    response: httpx.Response, dest: Path, *, check_envelope: bool
) -> None:
    """Save the response body at dest, or leave dest exactly as it was.

    The bytes land beside the destination and are moved onto it only once they
    have all arrived and been accepted, so a download that fails partway -- a
    dropped connection, a full disk, Ctrl-C, or an error envelope where a
    report was expected -- costs neither a half-written file nor the one that
    was already there. Writing to the destination directly would have emptied
    it before the first byte was read.

    Two things follow from moving a file into place rather than writing
    through the destination. The parent directory has to be writable, where
    overwriting a file needed only the file to be; and whatever occupies the
    destination is replaced rather than written through, whether it is a
    symlink, one of several hard links, or not a regular file at all -- a
    device node or a FIFO named as the destination is replaced by the download,
    so "-o /dev/null" leaves a regular file where the device was rather than
    discarding the bytes. Both are the safer reading of "put the download
    here", and neither is reachable without permission on the directory anyway.

    A process killed outright still leaves the temporary behind: SIGKILL
    cannot be caught, and SIGTERM unwinds nothing unless asked to.
    """
    handle, name = tempfile.mkstemp(
        dir=dest.parent, prefix=_temporary_prefix(dest.name)
    )
    partial = Path(name)
    try:
        with open(handle, "wb") as output:
            for chunk in response.iter_bytes():
                output.write(chunk)
            output.flush()
            # On the disk before the move, so a machine that dies during it
            # cannot leave the destination renamed onto bytes that never landed.
            os.fsync(output.fileno())
        if check_envelope:
            _raise_for_saved_envelope(partial, response.status_code)
        _keep_the_mode_of(dest, partial)
        partial.replace(dest)
    except BaseException:
        # A cleanup that fails must not replace the failure that called for it,
        # which is the one worth reporting.
        with suppress(OSError):
            partial.unlink(missing_ok=True)
        raise


def _raise_for_saved_envelope(saved: Path, status_code: int) -> None:
    """Report the error envelope CAPE answers with in place of a JSON report.

    It arrives as JSON on a successful status, so it cannot be told apart from
    the report itself until it has been parsed, by which point it has been
    written. Reading back only a file small enough to be an envelope is what
    keeps this from holding whole a report that was streamed to disk precisely
    to avoid that; a report that size parses to an object with no error in it.

    The file read here is the temporary, so raising costs the caller nothing
    that was already at the destination.
    """
    if saved.stat().st_size > ENVELOPE_SIZE_LIMIT:
        return
    _raise_for_envelope_in(saved.read_bytes(), status_code)


def _raise_for_html(response: httpx.Response, path: str, expected: str) -> None:
    """Reject the web UI served in place of an API response.

    A CAPE instance that restricts an endpoint answers it with the HTML login
    or detail page and a 200, so the status code alone reveals nothing.
    """
    if _media_type(response) == "text/html":
        raise ApiError(
            f"Expected {expected} for {path}, got an HTML page "
            "(endpoint restricted or unavailable on this server)",
            status_code=response.status_code,
        )


def _json_payload(response: httpx.Response, path: str) -> object:
    try:
        return response.json()
    except ValueError as exc:
        raise ApiError(
            f"Invalid JSON response for {path}", status_code=response.status_code
        ) from exc
    except RecursionError as exc:
        # The parser recurses per nesting level and the server chooses how many
        # there are, so a deep enough payload ends the process rather than the
        # request. That is a response to report on, not a defect to crash on.
        raise ApiError(
            f"The response to {path} nests too deeply to parse",
            status_code=response.status_code,
        ) from exc


def _raise_for_error_envelope(payload: object, status_code: int) -> None:
    if not isinstance(payload, dict):
        return
    if payload.get("error") or payload.get("Error"):
        detail = _envelope_detail(payload) or "Unknown CAPE API error"
        raise ApiError(detail, status_code=status_code)


def _parse_json_body(response: httpx.Response, path: str) -> JsonDict:
    _raise_for_status(response, path)
    _raise_for_html(response, path, "JSON")
    payload = _json_payload(response, path)
    _raise_for_error_envelope(payload, response.status_code)
    if not isinstance(payload, dict):
        raise ApiError(
            f"Unexpected JSON response for {path}", status_code=response.status_code
        )
    return payload


def _build_http(
    base_url: str,
    headers: dict[str, str],
    timeout: float,
    *,
    url_label: str,
    url_value: str,
) -> httpx.Client:
    """Open an httpx client at ``base_url``, failing as a configuration problem.

    httpx takes a schemeless base URL and only objects once a request is made,
    where it reads as the server being unreachable rather than as the setting it
    actually is; the scheme is checked here so it surfaces as what it is.
    """
    try:
        client = httpx.Client(base_url=base_url, headers=headers, timeout=timeout)
    except httpx.InvalidURL as exc:
        raise ConfigError(f"Invalid {url_label} {url_value!r}: {exc}") from exc
    if client.base_url.scheme not in ("http", "https"):
        client.close()
        raise ConfigError(
            f"{url_label} {url_value!r} needs an http:// or https:// scheme"
        )
    return client


class CapeClient:
    """Client for a CAPE v2 instance, one method per REST endpoint."""

    def __init__(self, config: Config) -> None:
        headers: dict[str, str] = {}
        token = _validated_token(config.token)
        if token:
            headers["Authorization"] = f"Token {token}"
        self._http = _build_http(
            f"{config.url.rstrip('/')}/apiv2/",
            headers,
            config.timeout,
            url_label="CAPE URL",
            url_value=config.url,
        )

    def close(self) -> None:
        self._http.close()

    def __enter__(self) -> Self:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        self.close()

    def _json(
        self,
        method: str,
        path: str,
        *,
        data: Mapping[str, FormValue] | None = None,
        files: FilePayload | None = None,
        params: Mapping[str, FormValue] | None = None,
    ) -> JsonDict:
        try:
            response = self._http.request(
                method, path, data=data, files=files, params=params
            )
        except httpx.HTTPError as exc:
            raise ApiError(f"Request failed for {path}: {exc}") from exc
        return _parse_json_body(response, path)

    def _download(
        self,
        path: str,
        dest: Path,
        *,
        params: Mapping[str, FormValue] | None = None,
        allow_html: bool = False,
        allow_json: bool = False,
        method: str = "GET",
        data: Mapping[str, FormValue] | None = None,
    ) -> Path:
        try:
            return self._stream_to_file(
                path, dest, params, allow_html, allow_json, method, data
            )
        except httpx.HTTPError as exc:
            raise ApiError(f"Request failed for {path}: {exc}") from exc

    def _stream_to_file(
        self,
        path: str,
        dest: Path,
        params: Mapping[str, FormValue] | None,
        allow_html: bool,
        allow_json: bool,
        method: str = "GET",
        data: Mapping[str, FormValue] | None = None,
    ) -> Path:
        with self._http.stream(method, path, params=params, data=data) as response:
            _raise_for_status(response, path)
            serves_json = _media_type(response) == "application/json"
            if serves_json and not allow_json:
                body = _envelope_body(response)
                if body is not None:
                    _raise_for_envelope_in(body, response.status_code)
                raise ApiError(
                    f"Expected file content for {path}, got JSON",
                    status_code=response.status_code,
                )
            if not allow_html:
                _raise_for_html(response, path, "file content")
            dest.parent.mkdir(parents=True, exist_ok=True)
            _save_beside_then_move(response, dest, check_envelope=serves_json)
        return dest

    # Authentication

    def obtain_token(self, username: str, password: str) -> str:
        """Exchange credentials for an API token.

        The token is what every other method authenticates with, so this is the
        one call made against a client built without one.
        """
        payload = self._json(
            "POST",
            "api-token-auth/",
            data={"username": username, "password": password},
        )
        token = payload.get("token")
        if not isinstance(token, str) or not token:
            raise ApiError("Authentication response carried no token")
        return token

    # Task submission

    def submit_file(
        self,
        path: Path,
        *,
        machine: str | None = None,
        pcap: bool = False,
        options: Mapping[str, FormValue] | None = None,
        arguments: Mapping[str, FormValue] | None = None,
    ) -> JsonDict:
        if arguments and "file" in arguments:
            raise ValueError("argument 'file' is reserved for the uploaded sample")
        data = _form_data(arguments, options, machine=machine, pcap=1 if pcap else None)
        with _file_payload(path) as files:
            return self._json("POST", "tasks/create/file/", data=data, files=files)

    def submit_static(
        self,
        path: Path,
        *,
        priority: int | None = None,
        options: Mapping[str, FormValue] | None = None,
    ) -> JsonDict:
        """Run static extractors only; CAPE also accepts priority and options here."""
        data = _form_data(None, options, priority=priority)
        with _file_payload(path) as files:
            return self._json("POST", "tasks/create/static/", data=data, files=files)

    def submit_url(
        self,
        url: str,
        *,
        machine: str | None = None,
        options: Mapping[str, FormValue] | None = None,
        arguments: Mapping[str, FormValue] | None = None,
    ) -> JsonDict:
        data = _form_data(arguments, options, url=url, machine=machine)
        return self._json("POST", "tasks/create/url/", data=data)

    def submit_dlnexec(
        self,
        url: str,
        *,
        machine: str | None = None,
        options: Mapping[str, FormValue] | None = None,
        arguments: Mapping[str, FormValue] | None = None,
    ) -> JsonDict:
        data = _form_data(arguments, options, dlnexec=url, machine=machine)
        return self._json("POST", "tasks/create/dlnexec/", data=data)

    def submit_download_service(
        self,
        file_hash: str,
        *,
        apikey: str | None = None,
        machine: str | None = None,
        options: Mapping[str, FormValue] | None = None,
        arguments: Mapping[str, FormValue] | None = None,
    ) -> JsonDict:
        """Fetch a sample from VirusTotal or MalwareBazaar and analyze it.

        CAPE reads the API key from the analyzer options, so an explicit apikey
        is merged into them rather than sent as a field of its own.
        """
        merged = dict(options or {})
        if apikey is not None:
            if "apikey" in merged:
                raise ValueError("analyzer option 'apikey' is already set by this call")
            merged["apikey"] = apikey
        data = _form_data(arguments, merged, hashes=file_hash, machine=machine)
        return self._json("POST", "tasks/create/download_services/", data=data)

    # Samples

    def file_view(self, criteria: str, value: str | int) -> JsonDict:
        """Look up a sample by criteria: md5, sha1, sha256, or id."""
        return self._json("GET", _path("files", "view", criteria, value))

    def file_download(
        self,
        criteria: str,
        value: str | int,
        dest: Path,
        *,
        encrypted: bool = False,
    ) -> Path:
        """Download a sample by criteria: task, md5, sha1, or sha256."""
        return self._download(
            _path("files", "get", criteria, value),
            dest,
            params=_fields(encrypted=1 if encrypted else None),
        )

    # Task information

    def task_search(self, hash_type: str, value: str) -> JsonDict:
        """Search tasks by hash_type: md5, sha1, or sha256."""
        return self._json("GET", _path("tasks", "search", hash_type, value))

    def task_extended_search(
        self, option: str, argument: str, *, search_limit: int | None = None
    ) -> JsonDict:
        """Search tasks by one indexed option; CAPE returns 50 results unless raised."""
        data = _fields(option=option, argument=argument, search_limit=search_limit)
        return self._json("POST", "tasks/extendedsearch/", data=data)

    def tasks_list(
        self,
        limit: int | None = None,
        offset: int | None = None,
        *,
        window: int | None = None,
        status: str | None = None,
        option: str | None = None,
        category: str | None = None,
        completed_after: int | None = None,
        ids_only: bool = False,
    ) -> JsonDict:
        """List tasks; ``window`` is a look-back in minutes, ``completed_after`` a
        Unix timestamp, and ``option`` matches the options string with a LIKE search.
        """
        if limit is None and offset is not None:
            raise ValueError("offset requires limit")
        if offset is None and window is not None:
            raise ValueError("window requires limit and offset")
        return self._json(
            "GET",
            _path("tasks", "list", limit, offset, window),
            params=_fields(
                status=status,
                option=option,
                category=category,
                completed_after=completed_after,
                ids=1 if ids_only else None,
            ),
        )

    def task_view(self, task_id: int) -> JsonDict:
        return self._json("GET", _path("tasks", "view", task_id))

    def task_status(self, task_id: int) -> JsonDict:
        return self._json("GET", _path("tasks", "status", task_id))

    def tasks_latest(self, hours: int) -> JsonDict:
        return self._json("GET", _path("tasks", "get", "latests", hours))

    def task_reschedule(self, task_id: int) -> JsonDict:
        return self._json("GET", _path("tasks", "reschedule", task_id))

    def task_reprocess(self, task_id: int) -> JsonDict:
        return self._json("GET", _path("tasks", "reprocess", task_id))

    def task_delete(
        self, tasks: int | str | Sequence[int], *, status: str | None = None
    ) -> JsonDict:
        """Delete tasks by ID, sequence of IDs, comma list ("1,2"), or range ("1-5")."""
        return self._json(
            "GET", _path("tasks", "delete", _task_selector(tasks), status)
        )

    def tasks_delete_many(
        self, tasks: int | str | Sequence[int], *, delete_mongo: bool = True
    ) -> JsonDict:
        """Bulk-delete tasks; this is CAPE's worker-cleanup path, a POST that
        takes the IDs in the body rather than the URL.

        ``delete_mongo`` False keeps the stored reports. A partial failure comes
        back as an error envelope, so it raises like any other API error.
        """
        return self._json(
            "POST",
            "tasks/delete_many/",
            data={
                "ids": _expanded_selector(tasks),
                "delete_mongo": 1 if delete_mongo else 0,
            },
        )

    def set_task_visibility(self, task_id: int, visibility: str) -> JsonDict:
        """Set a task's multitenancy visibility (PATCH).

        CAPE gates this behind the web UI's own session auth and only accepts it
        with multitenancy enabled, so a token-authenticated client will usually
        get 401/403 or a "multitenancy is not enabled" error here.
        """
        return self._json(
            "PATCH",
            _path("tasks", "visibility", task_id),
            data={"visibility": visibility},
        )

    def tasks_statistics(self, days: int) -> JsonDict:
        return self._json("GET", _path("tasks", "statistics", days))

    # Reports and analysis results

    def task_report(self, task_id: int, fmt: str | None = None) -> JsonDict:
        """Fetch the report as JSON; fmt: json, maec5, or litereport.

        CAPE serves maec and metadata as XML, pdf and html as documents, and
        the bundles as zip archives. None of those can come back as a dict, so
        asking for one here is refused rather than reported as a server that
        answered with something unparsable; task_report_file saves them.
        """
        if fmt is not None and fmt.lower() not in JSON_REPORT_FORMATS:
            raise ValueError(
                f"report format {fmt!r} is not JSON; save it to a file instead"
            )
        return self._json("GET", _path("tasks", "get", "report", task_id, fmt))

    def task_report_zip(self, task_id: int, dest: Path, fmt: str | None = None) -> Path:
        return self._download(
            _path("tasks", "get", "report", task_id, fmt or "json", "zip"), dest
        )

    def task_report_file(self, task_id: int, dest: Path, fmt: str) -> Path:
        """Save any report format to disk: json, html, pdf, maec, metadata, ...

        Only the media type the format is served as counts as the document
        asked for, so an error page served in place of a PDF is still reported
        instead of being written to disk.
        """
        # The format is passed on as given; only our own expectation of the body
        # is decided here, and the case it was typed in does not change what the
        # caller asked for.
        name = fmt.lower()
        return self._download(
            _path("tasks", "get", "report", task_id, fmt),
            dest,
            allow_html=name.endswith("html"),
            allow_json=name in JSON_REPORT_FORMATS,
        )

    def task_iocs(self, task_id: int, *, detailed: bool = False) -> JsonDict:
        return self._json(
            "GET",
            _path("tasks", "get", "iocs", task_id, "detailed" if detailed else None),
        )

    def task_config(self, task_id: int, cape_name: str | None = None) -> JsonDict:
        """Fetch the extracted config, optionally narrowed to one CAPE family name."""
        return self._json("GET", _path("tasks", "get", "config", task_id, cape_name))

    def task_machine(self, task_id: int) -> JsonDict:
        """Return the analysis machine assigned to a task."""
        return self._json("GET", _path("tasks", "machine", task_id))

    def exit_nodes(self) -> JsonDict:
        return self._json("GET", "exitnodes/")

    def tasks_stats(self) -> JsonDict:
        """Return task statistics for the recent time window."""
        return self._json("GET", "tasks/stats/")

    # Artifact downloads

    def task_screenshots(
        self, task_id: int, dest: Path, number: int | None = None
    ) -> Path:
        return self._download(
            _path("tasks", "get", "screenshot", task_id, number), dest
        )

    def task_pcap(self, task_id: int, dest: Path, variant: str | None = None) -> Path:
        return self._download(_path("tasks", "get", "pcap", task_id, variant), dest)

    def task_tlspcap(self, task_id: int, dest: Path) -> Path:
        """Download the TLS-decrypted network capture."""
        return self._download(_path("tasks", "get", "tlspcap", task_id), dest)

    def task_evtx(self, task_id: int, dest: Path) -> Path:
        """Download the Windows event log collected during analysis."""
        return self._download(_path("tasks", "get", "evtx", task_id), dest)

    def task_keys(self, task_id: int, kind: str, dest: Path) -> Path:
        """Download captured key material, e.g. kind "tls" for the TLS key log."""
        return self._download(_path("tasks", "get", "keys", task_id, kind), dest)

    def task_etw(self, task_id: int, kind: str, dest: Path) -> Path:
        """Download Event Tracing for Windows data of the given kind."""
        return self._download(_path("tasks", "get", "etw", task_id, kind), dest)

    def task_bulkzip(self, task_id: int, folder: str, dest: Path) -> Path:
        """Download a whole analysis folder, e.g. "CAPE" or "procdump", as a zip."""
        return self._download(_path("tasks", "get", "bulkzip", task_id, folder), dest)

    def task_dropped(
        self, task_id: int, dest: Path, max_size: int | None = None
    ) -> Path:
        """Download dropped files; max_size refuses archives larger than N megabytes."""
        return self._download(
            _path("tasks", "get", "dropped", task_id),
            dest,
            params=_fields(max_size=max_size),
        )

    def task_selfextracted(
        self, task_id: int, dest: Path, tool: str | None = None
    ) -> Path:
        return self._download(
            _path("tasks", "get", "selfextracted", task_id, tool), dest
        )

    def task_surifile(self, task_id: int, dest: Path) -> Path:
        return self._download(_path("tasks", "get", "surifile", task_id), dest)

    def task_procmemory(self, task_id: int, dest: Path, pid: int | None = None) -> Path:
        return self._download(_path("tasks", "get", "procmemory", task_id, pid), dest)

    def task_fullmemory(self, task_id: int, dest: Path) -> Path:
        return self._download(_path("tasks", "get", "fullmemory", task_id), dest)

    def task_payloadfiles(self, task_id: int, dest: Path) -> Path:
        return self._download(_path("tasks", "get", "payloadfiles", task_id), dest)

    def task_procdumpfiles(self, task_id: int, dest: Path) -> Path:
        return self._download(_path("tasks", "get", "procdumpfiles", task_id), dest)

    def task_mitmdump(self, task_id: int, dest: Path) -> Path:
        return self._download(_path("tasks", "get", "mitmdump", task_id), dest)

    def task_stream(
        self, task_id: int, filepath: str, dest: Path, *, is_local: bool = False
    ) -> Path:
        """Stream a file off the running analysis VM to disk.

        CAPE holds the stream open while the guest runs, so this returns once the
        server closes it -- the guest stopped, or the file was read to its end.
        ``is_local`` resolves ``filepath`` under the task's own analysis
        directory instead of reading it from the live guest.
        """
        return self._download(
            _path("tasks", "get", "stream", task_id),
            dest,
            method="POST",
            data=_fields(filepath=filepath, is_local=1 if is_local else None),
        )

    # YARA rules

    def upload_yara(self, path: Path, category: str) -> JsonDict:
        """Upload a YARA rule file under one of CAPE's rule categories."""
        if category not in YARA_CATEGORIES:
            raise ValueError(
                f"category {category!r} is not one of {sorted(YARA_CATEGORIES)}"
            )
        with _file_payload(path) as files:
            return self._json(
                "POST", "yara_uploader/", data={"category": category}, files=files
            )

    # Infrastructure

    def machines_list(self) -> JsonDict:
        return self._json("GET", "machines/list/")

    def machine_view(self, name: str) -> JsonDict:
        return self._json("GET", _path("machines", "view", name))

    def cape_status(self) -> JsonDict:
        return self._json("GET", "cuckoo/status/")
