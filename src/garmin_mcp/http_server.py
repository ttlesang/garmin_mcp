"""
HTTP/SSE wrapper for the existing Garmin MCP stdio server.
"""

from __future__ import annotations

import asyncio
import base64
import contextlib
import hashlib
import hmac
import html
import json
import os
import secrets
import sys
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, AsyncIterator, Awaitable, Callable, Mapping
from urllib.parse import parse_qs, parse_qsl, urlencode, urlsplit, urlunsplit

import uvicorn
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import (
    HTMLResponse,
    JSONResponse,
    RedirectResponse,
    Response,
    StreamingResponse,
)


AUTH_CODE_TTL_SECONDS = 300
ACCESS_TOKEN_TTL_SECONDS = int(os.getenv("GARMIN_MCP_ACCESS_TOKEN_TTL", "3600"))
REFRESH_TOKEN_TTL_SECONDS = int(os.getenv("GARMIN_MCP_REFRESH_TOKEN_TTL", str(30 * 24 * 3600)))
# Each MCP session runs its own stdio subprocess (~50-100 MB); without a cap and
# an idle reaper, abandoned sessions accumulate until the host runs out of memory.
SESSION_IDLE_TTL_SECONDS = int(os.getenv("GARMIN_MCP_SESSION_IDLE_TTL", "900"))
SESSION_REAP_INTERVAL_SECONDS = int(os.getenv("GARMIN_MCP_SESSION_REAP_INTERVAL", "60"))
MAX_SESSIONS = int(os.getenv("GARMIN_MCP_MAX_SESSIONS", "8"))
# Upper bound on a single tool call; a hung Garmin request must not pin an HTTP
# worker (and the client) forever.
REQUEST_TIMEOUT_SECONDS = float(os.getenv("GARMIN_MCP_REQUEST_TIMEOUT", "300"))
MAX_BODY_BYTES = int(os.getenv("GARMIN_MCP_MAX_BODY_BYTES", str(2 * 1024 * 1024)))
# Dynamic client registration is unauthenticated by design (MCP clients need
# it), so cap how much state an anonymous caller can make us persist.
MAX_REGISTERED_CLIENTS = int(os.getenv("GARMIN_MCP_MAX_CLIENTS", "50"))
MAX_REDIRECT_URIS = 10
MAX_URI_LENGTH = 2048
# Brute-force protection for the authorization page. The counter is global
# (not per IP) because behind a reverse proxy every request shares one IP.
LOGIN_MAX_FAILURES = 5
LOGIN_LOCKOUT_SECONDS = 900
LOGIN_FAILURE_DELAY_SECONDS = 1.0  # slows down online guessing
MIN_ADMIN_PASSWORD_LENGTH = 12
SUPPORTED_TOKEN_AUTH_METHODS = {"none", "client_secret_post", "client_secret_basic"}
SUPPORTED_CODE_CHALLENGE_METHODS = {"S256"}
FORBIDDEN_REDIRECT_SCHEMES = {"javascript", "data", "file", "vbscript", "blob"}
LOOPBACK_HOSTS = {"localhost", "127.0.0.1", "::1"}
SESSION_HEADER = "MCP-Session-Id"
ADMIN_PASSWORD_ENV = "GARMIN_MCP_ADMIN_PASSWORD"
TOKEN_JSON_SECRET_ENV = "GARMIN_TOKENS_JSON_BASE64"
TOKEN_JSON_RAW_ENV = "GARMIN_TOKENS_JSON"
LEGACY_TOKENSTORE_BASE64_ENV = "GARMINTOKENS_BASE64"
# Secrets only the bridge needs; the per-session subprocess must not inherit them.
BRIDGE_ONLY_ENV_VARS = (
    ADMIN_PASSWORD_ENV,
    TOKEN_JSON_SECRET_ENV,
    TOKEN_JSON_RAW_ENV,
    LEGACY_TOKENSTORE_BASE64_ENV,
)
# On-disk format of the OAuth stores. Version 2 stores SHA-256 hashes of
# tokens and client secrets instead of the secrets themselves.
STORE_VERSION = 2
TOKEN_SEED_MARKER = ".garmin_tokens.seed"


class SessionClosedError(RuntimeError):
    """The stdio subprocess behind an MCP session is gone."""


@dataclass
class ClientRegistration:
    client_id: str
    redirect_uris: list[str]
    client_name: str | None
    token_endpoint_auth_method: str
    grant_types: list[str]
    response_types: list[str]
    client_id_issued_at: int
    client_secret_hash: str | None = None
    client_secret_expires_at: int = 0


@dataclass
class AuthorizationCodeRecord:
    code: str
    client_id: str
    redirect_uri: str
    code_challenge: str
    code_challenge_method: str
    resource: str
    scope: str
    expires_at: int


@dataclass
class AccessTokenRecord:
    client_id: str
    resource: str
    scope: str
    expires_at: int


@dataclass
class RefreshTokenRecord:
    client_id: str
    resource: str
    scope: str
    expires_at: int


@dataclass
class AuthorizeRequest:
    client: ClientRegistration
    redirect_uri: str
    state: str | None
    code_challenge: str
    code_challenge_method: str
    resource: str
    scope: str


def _now() -> int:
    return int(time.time())


def _hash_secret(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _secret_matches(candidate: str | None, expected_hash: str | None) -> bool:
    if not candidate or not expected_hash:
        return False
    return hmac.compare_digest(_hash_secret(candidate), expected_hash)


def _write_private_file(path: Path, content: str) -> None:
    """Atomically write a file readable only by its owner.

    The temp file is created with 0600 from the start (no window where the
    secret is world-readable) and swapped in with os.replace, so a crash
    mid-write can never leave a truncated store behind.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = path.with_name(f"{path.name}.tmp")
    fd = os.open(tmp_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        handle.write(content)
    os.replace(tmp_path, path)


def _normalize_base_url(base_url: str) -> str:
    cleaned = base_url.strip().rstrip("/")
    if not cleaned:
        raise ValueError("BASE_URL must not be empty")
    return cleaned


def _make_url(base_url: str, path: str) -> str:
    return f"{base_url}{path}"


def _json_rpc_id_key(message_id: Any) -> str:
    return json.dumps(message_id, separators=(",", ":"), sort_keys=True)


def _pkce_challenge(verifier: str) -> str:
    digest = hashlib.sha256(verifier.encode("utf-8")).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


def _append_query_params(url: str, params: dict[str, str]) -> str:
    parts = urlsplit(url)
    query = dict(parse_qsl(parts.query, keep_blank_values=True))
    query.update(params)
    return urlunsplit(
        (
            parts.scheme,
            parts.netloc,
            parts.path,
            urlencode(query),
            parts.fragment,
        )
    )


def _is_existing_file(value: str) -> bool:
    # A long base64 blob used as a path raises ENAMETOOLONG instead of
    # returning False on Linux.
    try:
        return Path(os.path.expanduser(value)).is_file()
    except (OSError, ValueError):
        return False


def _extract_token_json_from_env(resolved_env: Mapping[str, str]) -> tuple[str | None, str | None]:
    raw_json = resolved_env.get(TOKEN_JSON_RAW_ENV)
    if raw_json:
        return raw_json, TOKEN_JSON_RAW_ENV

    encoded = resolved_env.get(TOKEN_JSON_SECRET_ENV)
    if encoded:
        try:
            return base64.b64decode(encoded).decode("utf-8"), TOKEN_JSON_SECRET_ENV
        except (ValueError, UnicodeDecodeError) as exc:
            raise RuntimeError(
                f"{TOKEN_JSON_SECRET_ENV} must contain base64-encoded garmin_tokens.json content"
            ) from exc

    legacy_value = resolved_env.get(LEGACY_TOKENSTORE_BASE64_ENV)
    if not legacy_value:
        return None, None

    if _is_existing_file(legacy_value):
        legacy_path = Path(os.path.expanduser(legacy_value))
        try:
            return (
                base64.b64decode(legacy_path.read_text(encoding="utf-8")).decode("utf-8"),
                f"{LEGACY_TOKENSTORE_BASE64_ENV} file",
            )
        except (ValueError, UnicodeDecodeError) as exc:
            raise RuntimeError(
                f"{LEGACY_TOKENSTORE_BASE64_ENV} file must contain base64-encoded garmin_tokens.json content"
            ) from exc

    try:
        return base64.b64decode(legacy_value).decode("utf-8"), LEGACY_TOKENSTORE_BASE64_ENV
    except (ValueError, UnicodeDecodeError) as exc:
        raise RuntimeError(
            f"{LEGACY_TOKENSTORE_BASE64_ENV} must be either an existing file path or base64-encoded garmin_tokens.json content"
        ) from exc


def _ensure_bootstrap_tokens(env: Mapping[str, str] | None = None) -> tuple[Path | None, str | None]:
    """Seed the Garmin token store from the environment secret.

    garminconnect refreshes its tokens in place (and may rotate the refresh
    token), so the store on disk is newer than the env secret after the first
    refresh. The seed is therefore written only when the store is missing or
    when the env secret itself changed (tracked by a fingerprint file) —
    never on every start, which would roll back refreshed tokens to stale ones.
    """
    resolved_env = os.environ if env is None else env
    token_json, source = _extract_token_json_from_env(resolved_env)
    if not token_json:
        return None, None

    try:
        json.loads(token_json)
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"{source} does not decode to valid JSON") from exc

    token_dir = Path(os.path.expanduser(resolved_env.get("GARMINTOKENS") or "~/.garminconnect"))
    token_dir.mkdir(parents=True, exist_ok=True)
    with contextlib.suppress(PermissionError, OSError):
        os.chmod(token_dir, 0o700)

    token_json_path = token_dir / "garmin_tokens.json"
    seed_marker = token_dir / TOKEN_SEED_MARKER
    fingerprint = _hash_secret(token_json)
    previous = seed_marker.read_text(encoding="utf-8").strip() if seed_marker.exists() else None

    if previous != fingerprint or not token_json_path.exists():
        _write_private_file(token_json_path, token_json)
        _write_private_file(seed_marker, fingerprint)

    return token_json_path, source


def _default_oauth_clients_store_path() -> Path:
    """Default location for the persisted OAuth client registry.

    Reuses the same directory as the Garmin token store (already a mounted
    volume in typical deployments) so registered MCP clients survive
    container restarts/redeploys instead of forcing every connected client
    to redo the OAuth dance.
    """
    token_dir = Path(os.path.expanduser(os.getenv("GARMINTOKENS") or "~/.garminconnect"))
    return Path(os.getenv("OAUTH_CLIENTS_STORE") or (token_dir / "oauth_clients.json"))


def _default_oauth_tokens_store_path() -> Path:
    """Default location for persisted OAuth access/refresh tokens.

    Lives next to the client registry on the mounted token volume so issued
    tokens survive container restarts/redeploys; otherwise every restart
    invalidates all bearer tokens and connected clients are forced through
    an interactive re-authorization.
    """
    token_dir = Path(os.path.expanduser(os.getenv("GARMINTOKENS") or "~/.garminconnect"))
    return Path(os.getenv("OAUTH_TOKENS_STORE") or (token_dir / "oauth_tokens.json"))


def _oauth_error_response(
    error: str,
    *,
    description: str,
    status_code: int,
    headers: dict[str, str] | None = None,
) -> JSONResponse:
    return JSONResponse(
        {"error": error, "error_description": description},
        status_code=status_code,
        headers=headers,
    )


def _redirect_oauth_error(redirect_uri: str, error: str, state: str | None, description: str) -> RedirectResponse:
    params = {"error": error, "error_description": description}
    if state:
        params["state"] = state
    return RedirectResponse(_append_query_params(redirect_uri, params), status_code=302)


def _format_sse(data: dict[str, Any] | str | None, *, event_id: int | None = None) -> str:
    lines: list[str] = []
    if event_id is not None:
        lines.append(f"id: {event_id}")

    if data is None:
        payload = ""
    elif isinstance(data, str):
        payload = data
    else:
        payload = json.dumps(data, separators=(",", ":"), ensure_ascii=False)

    for line in payload.splitlines() or [""]:
        lines.append(f"data: {line}")

    return "\n".join(lines) + "\n\n"


def _pop_newline_delimited_messages(buffer: bytearray) -> list[dict[str, Any]]:
    messages: list[dict[str, Any]] = []

    while True:
        newline_index = buffer.find(b"\n")
        if newline_index < 0:
            break

        raw_line = bytes(buffer[:newline_index]).rstrip(b"\r")
        del buffer[: newline_index + 1]

        if not raw_line:
            continue

        # A stray print() in a dependency must not tear down the whole session.
        try:
            message = json.loads(raw_line.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            print(
                f"Ignoring non JSON-RPC stdout line from MCP subprocess: {raw_line[:200]!r}",
                file=sys.stderr,
            )
            continue
        if isinstance(message, dict):
            messages.append(message)

    return messages


def _parse_basic_auth(header_value: str | None) -> tuple[str, str] | None:
    if not header_value:
        return None

    scheme, _, encoded = header_value.partition(" ")
    if scheme.lower() != "basic" or not encoded:
        return None

    try:
        decoded = base64.b64decode(encoded).decode("utf-8")
    except (ValueError, UnicodeDecodeError):
        return None

    username, sep, password = decoded.partition(":")
    if not sep:
        return None
    return username, password


def _require_string_list(value: Any, field_name: str) -> list[str]:
    if not isinstance(value, list) or not value or not all(
        isinstance(item, str) and item for item in value
    ):
        raise HTTPException(
            status_code=400,
            detail=f"{field_name} must be a non-empty list of strings",
        )
    return list(value)


def _is_allowed_redirect_uri(uri: str) -> bool:
    """https anywhere, http only on loopback, custom app schemes allowed.

    Plain http to a remote host would leak the authorization code in clear
    text; script-capable schemes could turn the redirect into XSS.
    """
    if len(uri) > MAX_URI_LENGTH:
        return False
    parts = urlsplit(uri)
    scheme = parts.scheme.lower()
    if not scheme or parts.fragment or scheme in FORBIDDEN_REDIRECT_SCHEMES:
        return False
    if scheme == "https":
        return bool(parts.netloc)
    if scheme == "http":
        return parts.hostname in LOOPBACK_HOSTS
    return bool(parts.netloc or parts.path)


async def _read_form_body(request: Request) -> dict[str, str]:
    body = await request.body()
    parsed = parse_qs(body.decode("utf-8", errors="replace"), keep_blank_values=True)
    return {key: values[-1] if values else "" for key, values in parsed.items()}


class BodySizeLimitMiddleware:
    """Reject request bodies above ``max_bytes`` (declared or streamed)."""

    def __init__(self, app: Any, max_bytes: int) -> None:
        self.app = app
        self.max_bytes = max_bytes

    async def __call__(self, scope: dict, receive: Callable, send: Callable) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        for name, value in scope.get("headers", []):
            if name == b"content-length":
                try:
                    too_large = int(value) > self.max_bytes
                except ValueError:
                    too_large = True
                if too_large:
                    response = JSONResponse({"detail": "Request body too large"}, status_code=413)
                    await response(scope, receive, send)
                    return

        received = 0

        async def limited_receive() -> dict:
            nonlocal received
            message = await receive()
            if message["type"] == "http.request":
                received += len(message.get("body", b""))
                if received > self.max_bytes:
                    raise HTTPException(status_code=413, detail="Request body too large")
            return message

        await self.app(scope, limited_receive, send)


class StdioMcpSession:
    """One stdio MCP subprocess bound to a single MCP session id."""

    def __init__(
        self,
        session_id: str,
        process: asyncio.subprocess.Process,
    ) -> None:
        self.session_id = session_id
        self.process = process
        self._pending: dict[str, asyncio.Future[dict[str, Any]]] = {}
        self._listeners: set[asyncio.Queue[tuple[int, dict[str, Any]] | None]] = set()
        self._write_lock = asyncio.Lock()
        self._event_counter = 0
        self._closed = False
        self._reader_task = asyncio.create_task(self._stdout_reader())
        self._stderr_task = asyncio.create_task(self._stderr_reader())

    @classmethod
    async def create(cls, session_id: str) -> "StdioMcpSession":
        env = os.environ.copy()
        env["GARMIN_MCP_TRANSPORT"] = "stdio"
        env.pop("GARMIN_MCP_HOST", None)
        env.pop("GARMIN_MCP_PORT", None)
        for name in BRIDGE_ONLY_ENV_VARS:
            env.pop(name, None)
        # Tools that read/write the host filesystem make no sense for a remote
        # client and would let it touch arbitrary paths on the server.
        env.setdefault("GARMIN_MCP_DISABLE_LOCAL_FILE_TOOLS", "true")

        repo_root = Path(__file__).resolve().parents[2]
        src_root = repo_root / "src"
        python_path = env.get("PYTHONPATH")
        env["PYTHONPATH"] = (
            f"{src_root}{os.pathsep}{python_path}" if python_path else str(src_root)
        )

        process = await asyncio.create_subprocess_exec(
            sys.executable,
            "-u",
            "-m",
            "garmin_mcp",
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            cwd=str(repo_root),
            env=env,
        )
        return cls(session_id, process)

    @property
    def is_dead(self) -> bool:
        return self._closed or self.process.returncode is not None

    def subscribe(self) -> asyncio.Queue[tuple[int, dict[str, Any]] | None]:
        queue: asyncio.Queue[tuple[int, dict[str, Any]] | None] = asyncio.Queue()
        self._listeners.add(queue)
        return queue

    def unsubscribe(self, queue: asyncio.Queue[tuple[int, dict[str, Any]] | None]) -> None:
        self._listeners.discard(queue)

    async def send_message(self, message: dict[str, Any]) -> None:
        if self._closed or self.process.stdin is None:
            raise SessionClosedError("MCP session is closed")

        payload = json.dumps(message, separators=(",", ":"), ensure_ascii=False)
        try:
            async with self._write_lock:
                self.process.stdin.write(payload.encode("utf-8") + b"\n")
                await self.process.stdin.drain()
        except (BrokenPipeError, ConnectionResetError) as exc:
            raise SessionClosedError("MCP subprocess is no longer reading") from exc

    async def send_request(
        self, message: dict[str, Any], timeout: float | None = None
    ) -> dict[str, Any]:
        if "id" not in message:
            raise ValueError("JSON-RPC request must include an id")

        request_id = _json_rpc_id_key(message["id"])
        if request_id in self._pending:
            raise ValueError(f"Duplicate in-flight JSON-RPC id: {message['id']!r}")

        loop = asyncio.get_running_loop()
        future: asyncio.Future[dict[str, Any]] = loop.create_future()
        self._pending[request_id] = future
        try:
            await self.send_message(message)
            try:
                return await asyncio.wait_for(future, timeout=timeout or REQUEST_TIMEOUT_SECONDS)
            except asyncio.TimeoutError:
                # Tell the server to stop working on it; the late answer, if
                # any, is then just an unmatched message.
                with contextlib.suppress(SessionClosedError):
                    await self.send_message(
                        {
                            "jsonrpc": "2.0",
                            "method": "notifications/cancelled",
                            "params": {"requestId": message["id"], "reason": "timeout"},
                        }
                    )
                raise
        finally:
            self._pending.pop(request_id, None)

    async def close(self) -> None:
        if self._closed:
            return

        self._closed = True

        if self.process.stdin is not None:
            with contextlib.suppress(Exception):
                self.process.stdin.close()

        if self.process.returncode is None:
            self.process.terminate()
            with contextlib.suppress(asyncio.TimeoutError):
                await asyncio.wait_for(self.process.wait(), timeout=5)
            if self.process.returncode is None:
                self.process.kill()
                with contextlib.suppress(Exception):
                    await self.process.wait()

        for task in (self._reader_task, self._stderr_task):
            if not task.done():
                task.cancel()
                with contextlib.suppress(asyncio.CancelledError):
                    await task

    async def _stdout_reader(self) -> None:
        assert self.process.stdout is not None

        error: Exception | None = None
        buffer = bytearray()
        try:
            while True:
                chunk = await self.process.stdout.read(65536)
                if not chunk:
                    break

                buffer.extend(chunk)
                for message in _pop_newline_delimited_messages(buffer):
                    delivered = False
                    if "id" in message:
                        request_id = _json_rpc_id_key(message["id"])
                        future = self._pending.get(request_id)
                        if future and not future.done():
                            future.set_result(message)
                            delivered = True

                    if not delivered:
                        await self._broadcast(message)

            if buffer.strip():
                raise RuntimeError("MCP subprocess emitted an unterminated stdout frame")
        except Exception as exc:  # pragma: no cover - defensive path
            error = exc
        finally:
            self._closed = True
            process_error = SessionClosedError(
                f"MCP subprocess exited for session {self.session_id}"
                + (f": {error}" if error else "")
            )
            for future in list(self._pending.values()):
                if not future.done():
                    future.set_exception(process_error)

            for queue in list(self._listeners):
                await queue.put(None)

    async def _stderr_reader(self) -> None:
        assert self.process.stderr is not None

        try:
            while True:
                line = await self.process.stderr.readline()
                if not line:
                    break
                sys.stderr.write(
                    f"[garmin-mcp:{self.session_id}] {line.decode('utf-8', errors='replace')}"
                )
                sys.stderr.flush()
        except asyncio.CancelledError:
            raise
        except Exception:  # pragma: no cover - defensive logging path
            return

    async def _broadcast(self, message: dict[str, Any]) -> None:
        self._event_counter += 1
        item = (self._event_counter, message)
        for queue in list(self._listeners):
            await queue.put(item)


SessionFactory = Callable[[str], Awaitable[StdioMcpSession]]


class OAuthMcpBridge:
    def __init__(
        self,
        base_url: str,
        session_factory: SessionFactory | None = None,
        clients_store_path: Path | None = None,
        tokens_store_path: Path | None = None,
    ) -> None:
        self.base_url = _normalize_base_url(base_url)
        self.session_factory = session_factory or StdioMcpSession.create
        self.clients_store_path = clients_store_path or _default_oauth_clients_store_path()
        self.tokens_store_path = tokens_store_path or _default_oauth_tokens_store_path()
        self.clients: dict[str, ClientRegistration] = self._load_clients()
        self.authorization_codes: dict[str, AuthorizationCodeRecord] = {}
        # Both token maps are keyed by the SHA-256 of the token, never the token.
        self.access_tokens: dict[str, AccessTokenRecord] = {}
        self.refresh_tokens: dict[str, RefreshTokenRecord] = {}
        self._load_tokens()
        self.sessions: dict[str, StdioMcpSession] = {}
        self.session_last_used: dict[str, float] = {}
        self.session_owners: dict[str, str] = {}
        self._login_failures: list[float] = []

    @staticmethod
    def _read_store(path: Path) -> dict[str, Any] | None:
        if not path.exists():
            return None
        raw = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(raw, dict):
            raise ValueError("store root must be a JSON object")
        return raw

    def _load_clients(self) -> dict[str, ClientRegistration]:
        try:
            raw = self._read_store(self.clients_store_path)
            if raw is None:
                return {}
            entries = raw.get("clients", {}) if raw.get("version") == STORE_VERSION else raw
            clients: dict[str, ClientRegistration] = {}
            for client_id, fields in entries.items():
                fields = dict(fields)
                # v1 stored the client secret in clear text.
                if "client_secret" in fields:
                    secret = fields.pop("client_secret")
                    fields["client_secret_hash"] = _hash_secret(secret) if secret else None
                clients[client_id] = ClientRegistration(**fields)
            return clients
        except (OSError, ValueError, TypeError, AttributeError) as exc:
            print(
                f"Warning: could not load persisted OAuth clients from "
                f"{self.clients_store_path}: {exc}",
                file=sys.stderr,
            )
            return {}

    def persist_clients(self) -> None:
        payload = {
            "version": STORE_VERSION,
            "clients": {client_id: asdict(client) for client_id, client in self.clients.items()},
        }
        try:
            _write_private_file(self.clients_store_path, json.dumps(payload))
        except OSError as exc:
            print(
                f"Warning: could not persist OAuth clients to "
                f"{self.clients_store_path}: {exc}",
                file=sys.stderr,
            )

    def _load_tokens(self) -> None:
        try:
            raw = self._read_store(self.tokens_store_path)
            if raw is None:
                return
            # v1 keyed the maps by the raw token; hash them on the way in so
            # existing client connections survive the upgrade.
            already_hashed = raw.get("version") == STORE_VERSION

            def _load(section: str, record_cls: type) -> dict[str, Any]:
                loaded = {}
                for key, fields in raw.get(section, {}).items():
                    fields = dict(fields)
                    fields.pop("token", None)
                    loaded[key if already_hashed else _hash_secret(key)] = record_cls(**fields)
                return loaded

            self.access_tokens = _load("access_tokens", AccessTokenRecord)
            self.refresh_tokens = _load("refresh_tokens", RefreshTokenRecord)
            if not already_hashed:
                self.persist_tokens()
        except (OSError, ValueError, TypeError, AttributeError) as exc:
            print(
                f"Warning: could not load persisted OAuth tokens from "
                f"{self.tokens_store_path}: {exc}",
                file=sys.stderr,
            )
            self.access_tokens = {}
            self.refresh_tokens = {}

    def persist_tokens(self) -> None:
        payload = {
            "version": STORE_VERSION,
            "access_tokens": {key: asdict(record) for key, record in self.access_tokens.items()},
            "refresh_tokens": {key: asdict(record) for key, record in self.refresh_tokens.items()},
        }
        try:
            _write_private_file(self.tokens_store_path, json.dumps(payload))
        except OSError as exc:
            print(
                f"Warning: could not persist OAuth tokens to "
                f"{self.tokens_store_path}: {exc}",
                file=sys.stderr,
            )

    def register_client(self, client: ClientRegistration) -> None:
        # Evict the oldest registrations first: a long-connected client keeps
        # working through refresh tokens only if it is still registered, and
        # the most recent registrations are the ones in active use.
        while len(self.clients) >= MAX_REGISTERED_CLIENTS:
            oldest = min(self.clients.values(), key=lambda c: c.client_id_issued_at)
            del self.clients[oldest.client_id]
        self.clients[client.client_id] = client
        self.persist_clients()

    def find_access_token(self, token: str) -> AccessTokenRecord | None:
        return self.access_tokens.get(_hash_secret(token))

    def pop_refresh_token(self, token: str) -> RefreshTokenRecord | None:
        return self.refresh_tokens.pop(_hash_secret(token), None)

    def login_locked(self) -> bool:
        cutoff = time.monotonic() - LOGIN_LOCKOUT_SECONDS
        self._login_failures = [t for t in self._login_failures if t > cutoff]
        return len(self._login_failures) >= LOGIN_MAX_FAILURES

    def record_login_failure(self) -> None:
        self._login_failures.append(time.monotonic())

    def reset_login_failures(self) -> None:
        self._login_failures.clear()

    def prune_expired(self) -> None:
        now = _now()
        self.authorization_codes = {
            code: record
            for code, record in self.authorization_codes.items()
            if record.expires_at > now
        }
        live_access = {
            token: record
            for token, record in self.access_tokens.items()
            if record.expires_at > now
        }
        live_refresh = {
            token: record
            for token, record in self.refresh_tokens.items()
            if record.expires_at > now
        }
        tokens_changed = len(live_access) != len(self.access_tokens) or len(
            live_refresh
        ) != len(self.refresh_tokens)
        self.access_tokens = live_access
        self.refresh_tokens = live_refresh
        if tokens_changed:
            self.persist_tokens()

    def validate_resource(self, resource: str | None) -> str:
        if not resource:
            return self.base_url

        if resource.strip().rstrip("/") != self.base_url:
            raise HTTPException(status_code=400, detail="Unsupported resource")
        return self.base_url

    async def create_session(self, owner: str | None = None) -> StdioMcpSession:
        await self.reap_sessions()

        # Hard cap: evict the least-recently-used sessions rather than letting
        # subprocesses accumulate without bound.
        while len(self.sessions) >= MAX_SESSIONS:
            oldest_id = min(
                self.sessions,
                key=lambda sid: self.session_last_used.get(sid, 0.0),
            )
            await self.drop_session(oldest_id)

        session_id = secrets.token_urlsafe(24)
        session = await self.session_factory(session_id)
        self.sessions[session_id] = session
        self.session_last_used[session_id] = time.monotonic()
        if owner is not None:
            self.session_owners[session_id] = owner
        return session

    async def get_session(self, session_id: str | None, owner: str | None = None) -> StdioMcpSession:
        if not session_id:
            raise HTTPException(status_code=400, detail=f"{SESSION_HEADER} header is required")

        session = self.sessions.get(session_id)
        # A session is only usable by the OAuth client that created it; answer
        # exactly like an unknown id so ids cannot be probed.
        expected_owner = self.session_owners.get(session_id)
        if session is None or (
            owner is not None and expected_owner is not None and owner != expected_owner
        ):
            raise HTTPException(status_code=404, detail="Unknown MCP session")

        if getattr(session, "is_dead", False):
            await self.drop_session(session_id)
            raise HTTPException(status_code=404, detail="MCP session has terminated")

        self.session_last_used[session_id] = time.monotonic()
        return session

    async def drop_session(self, session_id: str) -> None:
        session = self.sessions.pop(session_id, None)
        self.session_last_used.pop(session_id, None)
        self.session_owners.pop(session_id, None)
        if session is not None:
            await session.close()

    async def reap_sessions(self, idle_ttl: float = SESSION_IDLE_TTL_SECONDS) -> None:
        """Drop dead subprocesses and sessions with no recent traffic."""
        now = time.monotonic()
        for session_id, session in list(self.sessions.items()):
            last_used = self.session_last_used.get(session_id, now)
            if getattr(session, "is_dead", False) or now - last_used > idle_ttl:
                await self.drop_session(session_id)

    async def shutdown(self) -> None:
        for session_id in list(self.sessions):
            await self.drop_session(session_id)


def _validate_client_auth(
    client: ClientRegistration,
    form: dict[str, str],
    authorization_header: str | None,
) -> bool:
    method = client.token_endpoint_auth_method
    if method == "none":
        return form.get("client_id") == client.client_id

    if method == "client_secret_post":
        return form.get("client_id") == client.client_id and _secret_matches(
            form.get("client_secret"), client.client_secret_hash
        )

    if method == "client_secret_basic":
        creds = _parse_basic_auth(authorization_header)
        return (
            creds is not None
            and creds[0] == client.client_id
            and _secret_matches(creds[1], client.client_secret_hash)
        )

    return False


def _extract_bearer_token(request: Request) -> str:
    header = request.headers.get("Authorization")
    if not header:
        raise HTTPException(
            status_code=401,
            detail="Bearer token required",
            headers={"WWW-Authenticate": 'Bearer realm="garmin-mcp"'},
        )

    scheme, _, token = header.partition(" ")
    if scheme.lower() != "bearer" or not token:
        raise HTTPException(
            status_code=401,
            detail="Invalid bearer token",
            headers={"WWW-Authenticate": 'Bearer error="invalid_token"'},
        )
    return token


def _require_access_token(request: Request) -> AccessTokenRecord:
    bridge: OAuthMcpBridge = request.app.state.bridge
    bridge.prune_expired()
    token = _extract_bearer_token(request)
    record = bridge.find_access_token(token)
    if record is None or record.resource != bridge.base_url:
        raise HTTPException(
            status_code=401,
            detail="Invalid or expired bearer token",
            headers={"WWW-Authenticate": 'Bearer error="invalid_token"'},
        )
    return record


async def _read_json_object(request: Request, what: str) -> dict[str, Any]:
    try:
        body = await request.json()
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise HTTPException(status_code=400, detail=f"{what} must be valid JSON") from exc

    if not isinstance(body, dict):
        raise HTTPException(status_code=400, detail=f"{what} must be a JSON object")
    return body


AUTHORIZE_FIELDS = (
    "response_type",
    "client_id",
    "redirect_uri",
    "state",
    "code_challenge",
    "code_challenge_method",
    "resource",
    "scope",
)

# The consent page must never be framed (clickjacking) or cached. form-action is
# deliberately absent: browsers apply it to the post-submit redirect as well,
# which would block the hop back to the MCP client.
AUTHORIZE_PAGE_HEADERS = {
    "Cache-Control": "no-store",
    "Pragma": "no-cache",
    "X-Frame-Options": "DENY",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
    "Content-Security-Policy": (
        "default-src 'none'; style-src 'unsafe-inline'; "
        "frame-ancestors 'none'; base-uri 'none'"
    ),
}


def _parse_authorize_request(
    bridge: OAuthMcpBridge, params: Mapping[str, str]
) -> AuthorizeRequest | Response:
    """Validate an authorization request (GET query or POSTed form).

    Errors that happen before the redirect URI is trusted are returned as a
    plain 400; later errors are sent back to the client via the redirect URI,
    as RFC 6749 section 4.1.2.1 requires.
    """
    client_id = params.get("client_id")
    redirect_uri = params.get("redirect_uri")
    state = params.get("state") or None

    if not client_id:
        raise HTTPException(status_code=400, detail="client_id is required")
    client = bridge.clients.get(client_id)
    if client is None:
        raise HTTPException(status_code=400, detail="Unknown client_id")

    if not redirect_uri or redirect_uri not in client.redirect_uris:
        raise HTTPException(status_code=400, detail="redirect_uri is not registered")

    if params.get("response_type") != "code":
        return _redirect_oauth_error(
            redirect_uri, "unsupported_response_type", state, "Only response_type=code is supported"
        )

    code_challenge = params.get("code_challenge")
    code_challenge_method = params.get("code_challenge_method")
    if not code_challenge or code_challenge_method not in SUPPORTED_CODE_CHALLENGE_METHODS:
        return _redirect_oauth_error(
            redirect_uri, "invalid_request", state, "PKCE with code_challenge_method=S256 is required"
        )

    try:
        resource = bridge.validate_resource(params.get("resource"))
    except HTTPException as exc:
        return _redirect_oauth_error(redirect_uri, "invalid_target", state, str(exc.detail))

    return AuthorizeRequest(
        client=client,
        redirect_uri=redirect_uri,
        state=state,
        code_challenge=code_challenge,
        code_challenge_method=code_challenge_method,
        resource=resource,
        scope=params.get("scope") or "mcp",
    )


def _render_authorize_page(
    auth: AuthorizeRequest,
    params: Mapping[str, str],
    *,
    error: str | None = None,
    status_code: int = 200,
) -> HTMLResponse:
    esc = html.escape
    hidden_fields = "\n".join(
        f'<input type="hidden" name="{name}" value="{esc(params[name])}">'
        for name in AUTHORIZE_FIELDS
        if params.get(name)
    )
    client_label = esc(auth.client.client_name or "Client MCP inconnu")
    redirect_host = esc(urlsplit(auth.redirect_uri).netloc or auth.redirect_uri)
    error_html = f'<p class="error">{esc(error)}</p>' if error else ""

    page = f"""<!doctype html>
<html lang="fr">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Garmin MCP — Autorisation</title>
<style>
  body {{ font-family: system-ui, sans-serif; background: #f4f5f7; color: #1d1d1f;
         display: flex; justify-content: center; padding: 48px 16px; margin: 0; }}
  main {{ background: #fff; border-radius: 12px; padding: 32px; max-width: 420px; width: 100%;
          box-shadow: 0 2px 12px rgba(0,0,0,.08); }}
  h1 {{ font-size: 1.3rem; margin-top: 0; }}
  .muted {{ color: #555; font-size: .92rem; }}
  label {{ display: block; margin: 20px 0 6px; font-weight: 600; }}
  input[type=password] {{ width: 100%; box-sizing: border-box; padding: 10px; font-size: 1rem;
                          border: 1px solid #c7c7cc; border-radius: 8px; }}
  .actions {{ display: flex; gap: 12px; margin-top: 20px; }}
  button {{ flex: 1; padding: 10px; font-size: 1rem; border-radius: 8px; border: 0; cursor: pointer; }}
  .approve {{ background: #0a66c2; color: #fff; }}
  .deny {{ background: #e5e5ea; color: #1d1d1f; }}
  .error {{ color: #b00020; font-weight: 600; }}
</style>
</head>
<body>
<main>
  <h1>Autoriser l'accès à vos données Garmin</h1>
  <p class="muted"><strong>{client_label}</strong> demande l'accès à ce serveur MCP Garmin.
  Après validation, vous serez redirigé vers <strong>{redirect_host}</strong>.</p>
  {error_html}
  <form method="post" action="/oauth/authorize">
    {hidden_fields}
    <label for="password">Mot de passe du serveur</label>
    <input id="password" name="password" type="password" autocomplete="current-password" autofocus>
    <div class="actions">
      <button class="deny" type="submit" name="decision" value="deny">Refuser</button>
      <button class="approve" type="submit" name="decision" value="approve">Autoriser</button>
    </div>
  </form>
</main>
</body>
</html>"""
    return HTMLResponse(page, status_code=status_code, headers=AUTHORIZE_PAGE_HEADERS)


def _json_rpc_error(message_id: Any, code: int, text: str) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": message_id, "error": {"code": code, "message": text}}


def create_app(
    *,
    base_url: str,
    admin_password: str,
    session_factory: SessionFactory | None = None,
    clients_store_path: Path | None = None,
    tokens_store_path: Path | None = None,
) -> FastAPI:
    if not admin_password or len(admin_password) < MIN_ADMIN_PASSWORD_LENGTH:
        raise ValueError(
            f"{ADMIN_PASSWORD_ENV} must be set to at least {MIN_ADMIN_PASSWORD_LENGTH} characters"
        )
    admin_password_hash = _hash_secret(admin_password)

    bridge = OAuthMcpBridge(
        base_url,
        session_factory=session_factory,
        clients_store_path=clients_store_path,
        tokens_store_path=tokens_store_path,
    )

    @contextlib.asynccontextmanager
    async def lifespan(_app: FastAPI) -> AsyncIterator[None]:
        async def _reap_loop() -> None:
            while True:
                await asyncio.sleep(SESSION_REAP_INTERVAL_SECONDS)
                try:
                    await bridge.reap_sessions()
                except Exception as exc:  # keep reaping even if one pass fails
                    print(f"Warning: session reaper failed: {exc}", file=sys.stderr)

        reaper = asyncio.create_task(_reap_loop())
        try:
            yield
        finally:
            reaper.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await reaper
            await bridge.shutdown()

    app = FastAPI(
        title="Garmin MCP HTTP Bridge",
        lifespan=lifespan,
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
    )
    app.state.bridge = bridge
    app.add_middleware(BodySizeLimitMiddleware, max_bytes=MAX_BODY_BYTES)

    @app.get("/health")
    async def health() -> dict[str, str]:
        return {"status": "ok"}

    def _protected_resource_metadata() -> dict[str, Any]:
        return {
            "resource": bridge.base_url,
            "authorization_servers": [bridge.base_url],
        }

    app.add_api_route("/.well-known/oauth-protected-resource", _protected_resource_metadata)
    app.add_api_route("/.well-known/oauth-protected-resource/sse", _protected_resource_metadata)

    @app.get("/.well-known/oauth-authorization-server")
    async def oauth_authorization_server() -> dict[str, Any]:
        return {
            "issuer": bridge.base_url,
            "authorization_endpoint": _make_url(bridge.base_url, "/oauth/authorize"),
            "token_endpoint": _make_url(bridge.base_url, "/oauth/token"),
            "registration_endpoint": _make_url(bridge.base_url, "/oauth/register"),
            "response_types_supported": ["code"],
            "grant_types_supported": ["authorization_code", "refresh_token"],
            "token_endpoint_auth_methods_supported": sorted(SUPPORTED_TOKEN_AUTH_METHODS),
            "code_challenge_methods_supported": sorted(SUPPORTED_CODE_CHALLENGE_METHODS),
            "scopes_supported": ["mcp"],
            "bearer_methods_supported": ["header"],
            "resource_parameter_supported": True,
        }

    @app.post("/oauth/register")
    async def oauth_register(request: Request) -> JSONResponse:
        payload = await _read_json_object(request, "Registration payload")

        redirect_uris = _require_string_list(payload.get("redirect_uris"), "redirect_uris")
        if len(redirect_uris) > MAX_REDIRECT_URIS:
            raise HTTPException(status_code=400, detail="Too many redirect_uris")
        for uri in redirect_uris:
            if not _is_allowed_redirect_uri(uri):
                raise HTTPException(status_code=400, detail=f"redirect_uri not allowed: {uri[:200]}")

        token_auth_method = payload.get("token_endpoint_auth_method", "none")
        if token_auth_method not in SUPPORTED_TOKEN_AUTH_METHODS:
            raise HTTPException(status_code=400, detail="Unsupported token_endpoint_auth_method")

        grant_types = _require_string_list(
            payload.get("grant_types", ["authorization_code"]),
            "grant_types",
        )
        response_types = _require_string_list(
            payload.get("response_types", ["code"]),
            "response_types",
        )
        if "authorization_code" not in grant_types or "code" not in response_types:
            raise HTTPException(status_code=400, detail="Only authorization_code / code clients are supported")

        client_name = payload.get("client_name")
        if client_name is not None and not isinstance(client_name, str):
            raise HTTPException(status_code=400, detail="client_name must be a string")

        client_secret = secrets.token_urlsafe(32) if token_auth_method != "none" else None
        client = ClientRegistration(
            client_id=secrets.token_urlsafe(24),
            redirect_uris=redirect_uris,
            client_name=client_name[:200] if client_name else None,
            token_endpoint_auth_method=token_auth_method,
            grant_types=grant_types,
            response_types=response_types,
            client_id_issued_at=_now(),
            client_secret_hash=_hash_secret(client_secret) if client_secret else None,
        )
        bridge.register_client(client)

        response: dict[str, Any] = {
            "client_id": client.client_id,
            "client_id_issued_at": client.client_id_issued_at,
            "redirect_uris": client.redirect_uris,
            "grant_types": client.grant_types,
            "response_types": client.response_types,
            "token_endpoint_auth_method": client.token_endpoint_auth_method,
        }
        if client.client_name:
            response["client_name"] = client.client_name
        if client_secret:
            # Returned exactly once; only its hash is kept.
            response["client_secret"] = client_secret
            response["client_secret_expires_at"] = client.client_secret_expires_at

        return JSONResponse(response, status_code=201)

    @app.get("/oauth/authorize")
    async def oauth_authorize(request: Request) -> Response:
        bridge.prune_expired()
        params = dict(request.query_params)
        auth = _parse_authorize_request(bridge, params)
        if isinstance(auth, Response):
            return auth
        return _render_authorize_page(auth, params)

    @app.post("/oauth/authorize")
    async def oauth_authorize_submit(request: Request) -> Response:
        bridge.prune_expired()
        form = await _read_form_body(request)
        auth = _parse_authorize_request(bridge, form)
        if isinstance(auth, Response):
            return auth

        if form.get("decision") == "deny":
            return _redirect_oauth_error(
                auth.redirect_uri, "access_denied", auth.state, "The user denied the request"
            )

        if bridge.login_locked():
            return _render_authorize_page(
                auth,
                form,
                error="Trop de tentatives échouées. Réessayez dans quelques minutes.",
                status_code=429,
            )

        if not _secret_matches(form.get("password"), admin_password_hash):
            bridge.record_login_failure()
            await asyncio.sleep(LOGIN_FAILURE_DELAY_SECONDS)
            return _render_authorize_page(
                auth, form, error="Mot de passe incorrect.", status_code=401
            )

        bridge.reset_login_failures()
        code = secrets.token_urlsafe(32)
        bridge.authorization_codes[code] = AuthorizationCodeRecord(
            code=code,
            client_id=auth.client.client_id,
            redirect_uri=auth.redirect_uri,
            code_challenge=auth.code_challenge,
            code_challenge_method=auth.code_challenge_method,
            resource=auth.resource,
            scope=auth.scope,
            expires_at=_now() + AUTH_CODE_TTL_SECONDS,
        )
        # 303 so the browser follows the redirect with a GET.
        return RedirectResponse(
            _append_query_params(
                auth.redirect_uri,
                {"code": code, **({"state": auth.state} if auth.state else {})},
            ),
            status_code=303,
        )

    def _issue_tokens(client_id: str, resource: str, scope: str) -> JSONResponse:
        access_token = secrets.token_urlsafe(32)
        refresh_token = secrets.token_urlsafe(32)
        bridge.access_tokens[_hash_secret(access_token)] = AccessTokenRecord(
            client_id=client_id,
            resource=resource,
            scope=scope,
            expires_at=_now() + ACCESS_TOKEN_TTL_SECONDS,
        )
        bridge.refresh_tokens[_hash_secret(refresh_token)] = RefreshTokenRecord(
            client_id=client_id,
            resource=resource,
            scope=scope,
            expires_at=_now() + REFRESH_TOKEN_TTL_SECONDS,
        )
        bridge.persist_tokens()

        return JSONResponse(
            {
                "access_token": access_token,
                "token_type": "Bearer",
                "expires_in": ACCESS_TOKEN_TTL_SECONDS,
                "refresh_token": refresh_token,
                "scope": scope,
                "resource": resource,
            },
            headers={"Cache-Control": "no-store", "Pragma": "no-cache"},
        )

    def _authenticate_client(
        request: Request, form: dict[str, str]
    ) -> ClientRegistration | JSONResponse:
        client_id = form.get("client_id")
        if not client_id:
            # client_secret_basic carries the id in the Authorization header.
            creds = _parse_basic_auth(request.headers.get("Authorization"))
            client_id = creds[0] if creds else None
            if client_id:
                form = {**form, "client_id": client_id}

        client = bridge.clients.get(client_id) if client_id else None
        if client is None or not _validate_client_auth(
            client, form, request.headers.get("Authorization")
        ):
            return _oauth_error_response(
                "invalid_client",
                description="Client authentication failed",
                status_code=401,
                headers={"WWW-Authenticate": 'Basic realm="garmin-mcp"'},
            )
        return client

    def _check_token_resource(form: dict[str, str], expected: str) -> JSONResponse | None:
        try:
            requested_resource = bridge.validate_resource(form.get("resource"))
        except HTTPException as exc:
            return _oauth_error_response(
                "invalid_target", description=str(exc.detail), status_code=400
            )
        if requested_resource != expected:
            return _oauth_error_response(
                "invalid_target",
                description="Token resource does not match the original grant",
                status_code=400,
            )
        return None

    @app.post("/oauth/token")
    async def oauth_token(request: Request) -> JSONResponse:
        bridge.prune_expired()
        form = await _read_form_body(request)

        grant_type = form.get("grant_type")
        if grant_type not in ("authorization_code", "refresh_token"):
            return _oauth_error_response(
                "unsupported_grant_type",
                description="Only the authorization_code and refresh_token grants are supported",
                status_code=400,
            )

        client = _authenticate_client(request, form)
        if isinstance(client, JSONResponse):
            return client

        if grant_type == "refresh_token":
            refresh_token = form.get("refresh_token")
            if not refresh_token:
                return _oauth_error_response(
                    "invalid_request", description="refresh_token is required", status_code=400
                )
            # Rotate: a refresh token is single-use, whatever the outcome.
            record = bridge.pop_refresh_token(refresh_token)
            if record is None or record.client_id != client.client_id:
                bridge.persist_tokens()
                return _oauth_error_response(
                    "invalid_grant",
                    description="Refresh token is invalid or expired",
                    status_code=400,
                )
            error = _check_token_resource(form, record.resource)
            if error is not None:
                bridge.persist_tokens()
                return error
            return _issue_tokens(client.client_id, record.resource, record.scope)

        code = form.get("code")
        redirect_uri = form.get("redirect_uri")
        code_verifier = form.get("code_verifier")
        if not code or not redirect_uri or not code_verifier:
            return _oauth_error_response(
                "invalid_request",
                description="code, redirect_uri and code_verifier are required",
                status_code=400,
            )

        # Authorization codes are single-use: consume it before any check so a
        # failed attempt cannot be retried with another verifier.
        record = bridge.authorization_codes.pop(code, None)
        if record is None:
            return _oauth_error_response(
                "invalid_grant",
                description="Authorization code is invalid or expired",
                status_code=400,
            )

        if (
            record.client_id != client.client_id
            or record.redirect_uri != redirect_uri
            or record.code_challenge_method != "S256"
            or not hmac.compare_digest(_pkce_challenge(code_verifier), record.code_challenge)
        ):
            return _oauth_error_response(
                "invalid_grant",
                description="Authorization code validation failed",
                status_code=400,
            )

        error = _check_token_resource(form, record.resource)
        if error is not None:
            return error

        return _issue_tokens(client.client_id, record.resource, record.scope)

    @app.post("/sse")
    async def sse_post(request: Request) -> Response:
        token = _require_access_token(request)
        message = await _read_json_object(request, "JSON-RPC message")
        session_id = request.headers.get(SESSION_HEADER)

        is_request = "method" in message and "id" in message
        is_initialize = (
            is_request
            and message.get("method") == "initialize"
            and not session_id
        )

        if is_initialize:
            session = await bridge.create_session(owner=token.client_id)
        else:
            session = await bridge.get_session(session_id, owner=token.client_id)

        headers = {SESSION_HEADER: session.session_id}
        try:
            if is_request:
                try:
                    response = await session.send_request(message)
                except asyncio.TimeoutError:
                    response = _json_rpc_error(
                        message["id"], -32001, f"Request timed out after {REQUEST_TIMEOUT_SECONDS:g}s"
                    )
                except ValueError as exc:
                    response = _json_rpc_error(message["id"], -32600, str(exc))
                return JSONResponse(response, headers=headers)

            await session.send_message(message)
            return Response(status_code=202, headers=headers)
        except SessionClosedError as exc:
            # 404 tells MCP clients to start a fresh session (spec behaviour).
            await bridge.drop_session(session.session_id)
            raise HTTPException(status_code=404, detail="MCP session has terminated") from exc
        except Exception:
            if is_initialize:
                await bridge.drop_session(session.session_id)
            raise

    @app.delete("/sse")
    async def sse_delete(request: Request) -> Response:
        token = _require_access_token(request)
        session = await bridge.get_session(request.headers.get(SESSION_HEADER), owner=token.client_id)
        await bridge.drop_session(session.session_id)
        return Response(status_code=204)

    @app.get("/sse")
    async def sse_get(request: Request) -> StreamingResponse:
        token = _require_access_token(request)
        session = await bridge.get_session(request.headers.get(SESSION_HEADER), owner=token.client_id)
        queue = session.subscribe()

        async def event_stream() -> AsyncIterator[str]:
            try:
                # Prime the client for reconnects with an initial event id.
                yield _format_sse("", event_id=0)
                while True:
                    if await request.is_disconnected():
                        break

                    try:
                        item = await asyncio.wait_for(queue.get(), timeout=15)
                    except asyncio.TimeoutError:
                        yield ": keepalive\n\n"
                        continue

                    if item is None:
                        break

                    event_id, message = item
                    yield _format_sse(message, event_id=event_id)
            finally:
                session.unsubscribe(queue)

        return StreamingResponse(
            event_stream(),
            media_type="text/event-stream",
            headers={
                "Cache-Control": "no-cache",
                "Connection": "keep-alive",
                "X-Accel-Buffering": "no",  # stop nginx from buffering the stream
                SESSION_HEADER: session.session_id,
            },
        )

    return app


def main() -> None:
    port = int(os.getenv("PORT", "3000"))
    host = os.getenv("GARMIN_MCP_HOST", "0.0.0.0")
    base_url = os.getenv("BASE_URL", f"http://127.0.0.1:{port}")
    admin_password = os.getenv(ADMIN_PASSWORD_ENV, "")
    if len(admin_password) < MIN_ADMIN_PASSWORD_LENGTH:
        print(
            f"ERROR: {ADMIN_PASSWORD_ENV} must be set (min {MIN_ADMIN_PASSWORD_LENGTH} characters). "
            "It protects the OAuth authorization page; without it anyone who knows "
            "the server URL could read your Garmin data.",
            file=sys.stderr,
        )
        sys.exit(1)

    bootstrapped_token_path, token_source = _ensure_bootstrap_tokens()
    if bootstrapped_token_path is not None:
        print(
            f"Garmin token store ready at {bootstrapped_token_path} (seed: {token_source})",
            file=sys.stderr,
        )
    elif os.getenv("GARMIN_EMAIL") or os.getenv("GARMIN_PASSWORD"):
        print(
            "No pre-generated Garmin token secret detected; runtime credential login remains enabled and may hit Garmin 429 limits.",
            file=sys.stderr,
        )
    app = create_app(base_url=base_url, admin_password=admin_password)
    # proxy_headers lets uvicorn trust X-Forwarded-* from the local reverse proxy.
    uvicorn.run(app, host=host, port=port, proxy_headers=True)


if __name__ == "__main__":
    main()
