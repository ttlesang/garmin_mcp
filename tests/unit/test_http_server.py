import base64
import json
import tempfile
import time
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

from fastapi.testclient import TestClient

from garmin_mcp.http_server import (
    AccessTokenRecord,
    OAuthMcpBridge,
    _hash_secret,
    _pkce_challenge,
    _extract_token_json_from_env,
    _ensure_bootstrap_tokens,
    _pop_newline_delimited_messages,
    create_app,
)


class FakeSession:
    def __init__(self, session_id: str) -> None:
        self.session_id = session_id
        self.request_messages: list[dict] = []
        self.sent_messages: list[dict] = []
        self.closed = False
        self.is_dead = False

    def subscribe(self):
        raise NotImplementedError

    def unsubscribe(self, _queue):
        return None

    async def send_request(self, message: dict) -> dict:
        self.request_messages.append(message)
        return {
            "jsonrpc": "2.0",
            "id": message["id"],
            "result": {
                "protocolVersion": "2025-06-18",
                "capabilities": {},
                "serverInfo": {"name": "fake-garmin", "version": "1.0.0"},
            },
        }

    async def send_message(self, message: dict) -> None:
        self.sent_messages.append(message)

    async def close(self) -> None:
        self.closed = True


ADMIN_PASSWORD = "correct-horse-battery"
BASE_URL = "https://garmin-mcp.example.com"


def _make_client(store_dir: Path | None = None, session_cls=None):
    created_sessions: dict[str, FakeSession] = {}

    async def factory(session_id: str) -> FakeSession:
        session = (session_cls or FakeSession)(session_id)
        created_sessions[session_id] = session
        return session

    if store_dir is None:
        store_dir = Path(tempfile.mkdtemp(prefix="garmin-mcp-test-"))

    app = create_app(
        base_url=BASE_URL,
        admin_password=ADMIN_PASSWORD,
        session_factory=factory,
        clients_store_path=store_dir / "oauth_clients.json",
        tokens_store_path=store_dir / "oauth_tokens.json",
    )
    app.state.bridge.access_tokens[_hash_secret("valid-token")] = AccessTokenRecord(
        client_id="test-client",
        resource="https://garmin-mcp.example.com",
        scope="mcp",
        expires_at=int(time.time()) + 3600,
    )
    return TestClient(app), created_sessions


def test_oauth_metadata_endpoints():
    client, _ = _make_client()
    with client:
        protected = client.get("/.well-known/oauth-protected-resource")
        assert protected.status_code == 200
        assert protected.json() == {
            "resource": "https://garmin-mcp.example.com",
            "authorization_servers": ["https://garmin-mcp.example.com"],
        }

        protected_sse = client.get("/.well-known/oauth-protected-resource/sse")
        assert protected_sse.status_code == 200
        assert protected_sse.json() == protected.json()

        metadata = client.get("/.well-known/oauth-authorization-server")
        assert metadata.status_code == 200
        body = metadata.json()
        assert body["issuer"] == "https://garmin-mcp.example.com"
        assert body["authorization_endpoint"].endswith("/oauth/authorize")
        assert body["token_endpoint"].endswith("/oauth/token")
        assert body["registration_endpoint"].endswith("/oauth/register")
        assert "S256" in body["code_challenge_methods_supported"]


def test_register_authorize_and_exchange_token():
    client, _ = _make_client()
    redirect_uri = "https://claude.ai/api/mcp/auth_callback"
    verifier = "pkce-verifier-123456789"
    challenge = _pkce_challenge(verifier)

    with client:
        registration = client.post(
            "/oauth/register",
            json={
                "client_name": "Claude",
                "redirect_uris": [redirect_uri],
            },
        )
        assert registration.status_code == 201
        client_id = registration.json()["client_id"]

        params = {
            "response_type": "code",
            "client_id": client_id,
            "redirect_uri": redirect_uri,
            "state": "state-123",
            "code_challenge": challenge,
            "code_challenge_method": "S256",
            "resource": "https://garmin-mcp.example.com",
        }
        page = client.get("/oauth/authorize", params=params, follow_redirects=False)
        assert page.status_code == 200
        assert "code=" not in page.headers.get("location", "")
        assert page.headers["X-Frame-Options"] == "DENY"

        authorize = client.post(
            "/oauth/authorize",
            data={**params, "password": ADMIN_PASSWORD, "decision": "approve"},
            follow_redirects=False,
        )
        assert authorize.status_code == 303

        location = authorize.headers["location"]
        query = parse_qs(urlsplit(location).query)
        assert query["state"] == ["state-123"]
        code = query["code"][0]

        token = client.post(
            "/oauth/token",
            data={
                "grant_type": "authorization_code",
                "client_id": client_id,
                "code": code,
                "redirect_uri": redirect_uri,
                "code_verifier": verifier,
                "resource": "https://garmin-mcp.example.com",
            },
        )
        assert token.status_code == 200
        body = token.json()
        assert body["token_type"] == "Bearer"
        assert body["resource"] == "https://garmin-mcp.example.com"
        assert body["access_token"]
        assert body["refresh_token"]


def _register_and_get_tokens(client) -> tuple[str, dict]:
    redirect_uri = "https://claude.ai/api/mcp/auth_callback"
    verifier = "pkce-verifier-123456789"
    challenge = _pkce_challenge(verifier)

    registration = client.post(
        "/oauth/register",
        json={"client_name": "Claude", "redirect_uris": [redirect_uri]},
    )
    client_id = registration.json()["client_id"]

    authorize = client.post(
        "/oauth/authorize",
        data={
            "response_type": "code",
            "client_id": client_id,
            "redirect_uri": redirect_uri,
            "code_challenge": challenge,
            "code_challenge_method": "S256",
            "password": ADMIN_PASSWORD,
            "decision": "approve",
        },
        follow_redirects=False,
    )
    code = parse_qs(urlsplit(authorize.headers["location"]).query)["code"][0]

    token = client.post(
        "/oauth/token",
        data={
            "grant_type": "authorization_code",
            "client_id": client_id,
            "code": code,
            "redirect_uri": redirect_uri,
            "code_verifier": verifier,
        },
    )
    return client_id, token.json()


def test_refresh_token_grant_rotates_tokens():
    client, _ = _make_client()
    with client:
        client_id, body = _register_and_get_tokens(client)

        refreshed = client.post(
            "/oauth/token",
            data={
                "grant_type": "refresh_token",
                "client_id": client_id,
                "refresh_token": body["refresh_token"],
            },
        )
        assert refreshed.status_code == 200
        new_body = refreshed.json()
        assert new_body["access_token"] != body["access_token"]
        assert new_body["refresh_token"] != body["refresh_token"]

        # The used refresh token is single-use: replaying it must fail.
        replay = client.post(
            "/oauth/token",
            data={
                "grant_type": "refresh_token",
                "client_id": client_id,
                "refresh_token": body["refresh_token"],
            },
        )
        assert replay.status_code == 400
        assert replay.json()["error"] == "invalid_grant"


def test_tokens_survive_bridge_restart(tmp_path):
    client, _ = _make_client(tmp_path)
    with client:
        _, body = _register_and_get_tokens(client)

    restarted_client, _ = _make_client(tmp_path)
    with restarted_client:
        response = restarted_client.post(
            "/sse",
            json={"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}},
            headers={"Authorization": f"Bearer {body['access_token']}"},
        )
        assert response.status_code == 200


def test_sse_requires_bearer_token():
    client, _ = _make_client()
    with client:
        response = client.post(
            "/sse",
            json={"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}},
        )
        assert response.status_code == 401


def test_initialize_creates_stdio_session():
    client, created_sessions = _make_client()
    headers = {"Authorization": "Bearer valid-token"}
    initialize = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": "2025-06-18",
            "capabilities": {},
            "clientInfo": {"name": "test-client", "version": "1.0.0"},
        },
    }

    with client:
        response = client.post("/sse", json=initialize, headers=headers)
        assert response.status_code == 200
        session_id = response.headers["MCP-Session-Id"]
        assert session_id in created_sessions
        assert created_sessions[session_id].request_messages == [initialize]

        follow_up = client.post(
            "/sse",
            json={"jsonrpc": "2.0", "method": "notifications/initialized"},
            headers={**headers, "MCP-Session-Id": session_id},
        )
        assert follow_up.status_code == 202
        assert created_sessions[session_id].sent_messages == [
            {"jsonrpc": "2.0", "method": "notifications/initialized"}
        ]


def test_dead_session_returns_404_and_is_dropped():
    client, created_sessions = _make_client()
    headers = {"Authorization": "Bearer valid-token"}
    initialize = {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}}

    with client:
        response = client.post("/sse", json=initialize, headers=headers)
        session_id = response.headers["MCP-Session-Id"]
        session = created_sessions[session_id]
        session.is_dead = True

        follow_up = client.post(
            "/sse",
            json={"jsonrpc": "2.0", "id": 2, "method": "tools/list"},
            headers={**headers, "MCP-Session-Id": session_id},
        )
        assert follow_up.status_code == 404
        assert session_id not in client.app.state.bridge.sessions


def test_session_cap_evicts_least_recently_used(monkeypatch):
    import garmin_mcp.http_server as http_server

    monkeypatch.setattr(http_server, "MAX_SESSIONS", 2)
    client, created_sessions = _make_client()
    headers = {"Authorization": "Bearer valid-token"}
    initialize = {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}}

    with client:
        first = client.post("/sse", json=initialize, headers=headers).headers["MCP-Session-Id"]
        second = client.post("/sse", json=initialize, headers=headers).headers["MCP-Session-Id"]
        third = client.post("/sse", json=initialize, headers=headers).headers["MCP-Session-Id"]

        bridge = client.app.state.bridge
        assert len(bridge.sessions) == 2
        assert first not in bridge.sessions
        assert created_sessions[first].closed
        assert second in bridge.sessions
        assert third in bridge.sessions


async def test_reap_sessions_drops_idle_and_dead(tmp_path):
    async def factory(session_id: str) -> FakeSession:
        return FakeSession(session_id)

    bridge = OAuthMcpBridge(
        "https://garmin-mcp.example.com",
        session_factory=factory,
        clients_store_path=tmp_path / "oauth_clients.json",
        tokens_store_path=tmp_path / "oauth_tokens.json",
    )

    idle = await bridge.create_session()
    dead = await bridge.create_session()
    active = await bridge.create_session()

    bridge.session_last_used[idle.session_id] -= 10_000
    dead.is_dead = True

    await bridge.reap_sessions(idle_ttl=900)

    assert set(bridge.sessions) == {active.session_id}
    assert idle.closed
    assert dead.closed


def test_sse_delete_terminates_session():
    client, created_sessions = _make_client()
    headers = {"Authorization": "Bearer valid-token"}
    initialize = {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}}

    with client:
        response = client.post("/sse", json=initialize, headers=headers)
        session_id = response.headers["MCP-Session-Id"]

        delete = client.delete(
            "/sse", headers={**headers, "MCP-Session-Id": session_id}
        )
        assert delete.status_code == 204
        assert session_id not in client.app.state.bridge.sessions
        assert created_sessions[session_id].closed


def test_pop_newline_delimited_messages_handles_large_frames():
    payload = {"jsonrpc": "2.0", "id": 1, "result": {"tools": ["x" * 70000]}}
    encoded = (
        b'{"jsonrpc":"2.0","method":"ping"}\n'
        + json.dumps(payload, separators=(",", ":")).encode("utf-8")
        + b"\n"
    )
    buffer = bytearray(encoded)

    messages = _pop_newline_delimited_messages(buffer)

    assert buffer == bytearray()
    assert messages == [{"jsonrpc": "2.0", "method": "ping"}, payload]


def test_ensure_bootstrap_tokens_writes_token_store(tmp_path):
    token_json = json.dumps({"oauth1": {"token": "a"}, "oauth2": {"access_token": "b"}})
    env = {
        "GARMINTOKENS": str(tmp_path / "tokens"),
        "GARMIN_TOKENS_JSON_BASE64": base64.b64encode(
            token_json.encode("utf-8")
        ).decode("ascii"),
    }

    written, source = _ensure_bootstrap_tokens(env)

    assert written == Path(env["GARMINTOKENS"]) / "garmin_tokens.json"
    assert written.read_text(encoding="utf-8") == token_json
    assert source == "GARMIN_TOKENS_JSON_BASE64"


def test_extract_token_json_from_legacy_env_value():
    token_json = json.dumps({"oauth1": {"token": "a"}, "oauth2": {"access_token": "b"}})
    env = {
        "GARMINTOKENS_BASE64": base64.b64encode(token_json.encode("utf-8")).decode("ascii")
    }

    decoded, source = _extract_token_json_from_env(env)

    assert decoded == token_json
    assert source == "GARMINTOKENS_BASE64"


# --- Security hardening -----------------------------------------------------

import asyncio

import pytest

import garmin_mcp.http_server as http_server
from garmin_mcp.http_server import (
    STORE_VERSION,
    SessionClosedError,
    _is_allowed_redirect_uri,
)

REDIRECT_URI = "https://claude.ai/api/mcp/auth_callback"
VERIFIER = "pkce-verifier-123456789"


def _register(client, redirect_uri: str = REDIRECT_URI, **extra) -> str:
    response = client.post(
        "/oauth/register",
        json={"client_name": "Claude", "redirect_uris": [redirect_uri], **extra},
    )
    assert response.status_code == 201, response.text
    return response.json()["client_id"]


def _authorize_params(client_id: str) -> dict:
    return {
        "response_type": "code",
        "client_id": client_id,
        "redirect_uri": REDIRECT_URI,
        "state": "s1",
        "code_challenge": _pkce_challenge(VERIFIER),
        "code_challenge_method": "S256",
    }


def _approve(client, client_id: str) -> str:
    response = client.post(
        "/oauth/authorize",
        data={**_authorize_params(client_id), "password": ADMIN_PASSWORD, "decision": "approve"},
        follow_redirects=False,
    )
    assert response.status_code == 303, response.text
    return parse_qs(urlsplit(response.headers["location"]).query)["code"][0]


def test_create_app_requires_strong_admin_password():
    with pytest.raises(ValueError):
        create_app(base_url=BASE_URL, admin_password="")
    with pytest.raises(ValueError):
        create_app(base_url=BASE_URL, admin_password="short")


def test_authorize_get_never_issues_a_code():
    client, _ = _make_client()
    with client:
        client_id = _register(client)
        page = client.get(
            "/oauth/authorize", params=_authorize_params(client_id), follow_redirects=False
        )
        assert page.status_code == 200
        assert "location" not in page.headers
        assert client.app.state.bridge.authorization_codes == {}


def test_authorize_page_escapes_client_name():
    client, _ = _make_client()
    with client:
        response = client.post(
            "/oauth/register",
            json={"client_name": "<script>alert(1)</script>", "redirect_uris": [REDIRECT_URI]},
        )
        client_id = response.json()["client_id"]
        page = client.get("/oauth/authorize", params=_authorize_params(client_id))
        assert "<script>alert(1)</script>" not in page.text
        assert "&lt;script&gt;" in page.text


def test_wrong_password_is_rejected(monkeypatch):
    monkeypatch.setattr(http_server, "LOGIN_FAILURE_DELAY_SECONDS", 0)
    client, _ = _make_client()
    with client:
        client_id = _register(client)
        response = client.post(
            "/oauth/authorize",
            data={**_authorize_params(client_id), "password": "nope", "decision": "approve"},
            follow_redirects=False,
        )
        assert response.status_code == 401
        assert client.app.state.bridge.authorization_codes == {}


def test_login_locks_after_repeated_failures(monkeypatch):
    monkeypatch.setattr(http_server, "LOGIN_FAILURE_DELAY_SECONDS", 0)
    client, _ = _make_client()
    with client:
        client_id = _register(client)
        data = {**_authorize_params(client_id), "decision": "approve"}
        for _ in range(http_server.LOGIN_MAX_FAILURES):
            client.post("/oauth/authorize", data={**data, "password": "bad"})

        # Even the right password is refused while locked.
        locked = client.post(
            "/oauth/authorize",
            data={**data, "password": ADMIN_PASSWORD},
            follow_redirects=False,
        )
        assert locked.status_code == 429
        assert client.app.state.bridge.authorization_codes == {}


def test_deny_redirects_with_access_denied():
    client, _ = _make_client()
    with client:
        client_id = _register(client)
        response = client.post(
            "/oauth/authorize",
            data={**_authorize_params(client_id), "decision": "deny"},
            follow_redirects=False,
        )
        assert response.status_code == 302
        query = parse_qs(urlsplit(response.headers["location"]).query)
        assert query["error"] == ["access_denied"]
        assert query["state"] == ["s1"]


def test_authorization_code_is_single_use_even_on_failure():
    client, _ = _make_client()
    with client:
        client_id = _register(client)
        code = _approve(client, client_id)
        base = {
            "grant_type": "authorization_code",
            "client_id": client_id,
            "code": code,
            "redirect_uri": REDIRECT_URI,
        }
        bad = client.post("/oauth/token", data={**base, "code_verifier": "wrong-verifier"})
        assert bad.status_code == 400
        retry = client.post("/oauth/token", data={**base, "code_verifier": VERIFIER})
        assert retry.status_code == 400
        assert retry.json()["error"] == "invalid_grant"


@pytest.mark.parametrize(
    "uri,allowed",
    [
        ("https://claude.ai/api/mcp/auth_callback", True),
        ("http://localhost:33418/callback", True),
        ("http://127.0.0.1:8080/cb", True),
        ("cursor://anysphere.cursor-mcp/oauth/callback", True),
        ("http://evil.example.com/cb", False),
        ("javascript:alert(1)", False),
        ("data:text/html,hi", False),
        ("https://claude.ai/cb#frag", False),
        ("not a uri", False),
    ],
)
def test_redirect_uri_policy(uri, allowed):
    assert _is_allowed_redirect_uri(uri) is allowed


def test_register_rejects_disallowed_redirect_uri():
    client, _ = _make_client()
    with client:
        response = client.post(
            "/oauth/register",
            json={"redirect_uris": ["http://evil.example.com/cb"]},
        )
        assert response.status_code == 400


def test_register_rejects_invalid_json():
    client, _ = _make_client()
    with client:
        response = client.post(
            "/oauth/register",
            content=b"{not json",
            headers={"Content-Type": "application/json"},
        )
        assert response.status_code == 400


def test_registered_clients_are_capped(monkeypatch):
    monkeypatch.setattr(http_server, "MAX_REGISTERED_CLIENTS", 3)
    client, _ = _make_client()
    with client:
        for _ in range(5):
            _register(client)
        assert len(client.app.state.bridge.clients) == 3


def test_oversized_body_is_rejected():
    client, _ = _make_client()
    with client:
        response = client.post(
            "/oauth/register",
            content=b"x" * (http_server.MAX_BODY_BYTES + 1),
            headers={"Content-Type": "application/json"},
        )
        assert response.status_code == 413


def test_secrets_are_hashed_at_rest(tmp_path):
    client, _ = _make_client(tmp_path)
    with client:
        registration = client.post(
            "/oauth/register",
            json={
                "redirect_uris": [REDIRECT_URI],
                "token_endpoint_auth_method": "client_secret_post",
            },
        ).json()
        client_id, secret = registration["client_id"], registration["client_secret"]
        code = _approve(client, client_id)
        response = client.post(
            "/oauth/token",
            data={
                "grant_type": "authorization_code",
                "client_id": client_id,
                "client_secret": secret,
                "code": code,
                "redirect_uri": REDIRECT_URI,
                "code_verifier": VERIFIER,
            },
        )
        assert response.status_code == 200, response.text
        tokens = response.json()

    tokens_file = (tmp_path / "oauth_tokens.json").read_text(encoding="utf-8")
    clients_file = (tmp_path / "oauth_clients.json").read_text(encoding="utf-8")
    assert tokens["access_token"] not in tokens_file
    assert tokens["refresh_token"] not in tokens_file
    assert secret not in clients_file
    assert json.loads(tokens_file)["version"] == STORE_VERSION


def test_client_secret_basic_auth():
    client, _ = _make_client()
    with client:
        registration = client.post(
            "/oauth/register",
            json={
                "redirect_uris": [REDIRECT_URI],
                "token_endpoint_auth_method": "client_secret_basic",
            },
        ).json()
        client_id, secret = registration["client_id"], registration["client_secret"]
        code = _approve(client, client_id)
        data = {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": REDIRECT_URI,
            "code_verifier": VERIFIER,
        }
        wrong = client.post("/oauth/token", data=data, auth=(client_id, "wrong"))
        assert wrong.status_code == 401
        # The failed attempt did not consume the code: client auth runs first.
        ok = client.post("/oauth/token", data=data, auth=(client_id, secret))
        assert ok.status_code == 200, ok.text


def test_v1_stores_are_migrated(tmp_path):
    expires = int(time.time()) + 3600
    (tmp_path / "oauth_tokens.json").write_text(
        json.dumps(
            {
                "access_tokens": {
                    "legacy-access": {
                        "token": "legacy-access",
                        "client_id": "legacy-client",
                        "resource": BASE_URL,
                        "scope": "mcp",
                        "expires_at": expires,
                    }
                },
                "refresh_tokens": {},
            }
        ),
        encoding="utf-8",
    )
    (tmp_path / "oauth_clients.json").write_text(
        json.dumps(
            {
                "legacy-client": {
                    "client_id": "legacy-client",
                    "redirect_uris": [REDIRECT_URI],
                    "client_name": "Claude",
                    "token_endpoint_auth_method": "client_secret_post",
                    "grant_types": ["authorization_code"],
                    "response_types": ["code"],
                    "client_id_issued_at": 1,
                    "client_secret": "legacy-secret",
                    "client_secret_expires_at": 0,
                }
            }
        ),
        encoding="utf-8",
    )

    bridge = OAuthMcpBridge(
        BASE_URL,
        clients_store_path=tmp_path / "oauth_clients.json",
        tokens_store_path=tmp_path / "oauth_tokens.json",
    )

    assert bridge.find_access_token("legacy-access").client_id == "legacy-client"
    assert bridge.clients["legacy-client"].client_secret_hash == _hash_secret("legacy-secret")
    assert "legacy-access" not in (tmp_path / "oauth_tokens.json").read_text(encoding="utf-8")


def test_session_is_bound_to_its_client():
    client, _ = _make_client()
    bridge = client.app.state.bridge
    bridge.access_tokens[_hash_secret("other-token")] = AccessTokenRecord(
        client_id="other-client",
        resource=BASE_URL,
        scope="mcp",
        expires_at=int(time.time()) + 3600,
    )
    initialize = {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}}

    with client:
        session_id = client.post(
            "/sse", json=initialize, headers={"Authorization": "Bearer valid-token"}
        ).headers["MCP-Session-Id"]

        hijack = client.post(
            "/sse",
            json={"jsonrpc": "2.0", "id": 2, "method": "tools/list"},
            headers={"Authorization": "Bearer other-token", "MCP-Session-Id": session_id},
        )
        assert hijack.status_code == 404
        assert session_id in bridge.sessions


class TimeoutSession(FakeSession):
    async def send_request(self, message: dict, timeout=None) -> dict:
        if message.get("method") == "initialize":
            return await super().send_request(message)
        raise asyncio.TimeoutError


class ClosedSession(FakeSession):
    async def send_request(self, message: dict, timeout=None) -> dict:
        if message.get("method") == "initialize":
            return await super().send_request(message)
        raise SessionClosedError("gone")


def _open_session(client, headers) -> str:
    return client.post(
        "/sse", json={"jsonrpc": "2.0", "id": 1, "method": "initialize"}, headers=headers
    ).headers["MCP-Session-Id"]


def test_tool_call_timeout_returns_json_rpc_error():
    client, _ = _make_client(session_cls=TimeoutSession)
    headers = {"Authorization": "Bearer valid-token"}
    with client:
        session_id = _open_session(client, headers)
        response = client.post(
            "/sse",
            json={"jsonrpc": "2.0", "id": 7, "method": "tools/call"},
            headers={**headers, "MCP-Session-Id": session_id},
        )
        assert response.status_code == 200
        assert response.json()["id"] == 7
        assert response.json()["error"]["code"] == -32001


def test_closed_session_returns_404_and_is_dropped():
    client, _ = _make_client(session_cls=ClosedSession)
    headers = {"Authorization": "Bearer valid-token"}
    with client:
        session_id = _open_session(client, headers)
        response = client.post(
            "/sse",
            json={"jsonrpc": "2.0", "id": 2, "method": "tools/list"},
            headers={**headers, "MCP-Session-Id": session_id},
        )
        assert response.status_code == 404
        assert session_id not in client.app.state.bridge.sessions


def test_non_json_stdout_lines_are_skipped():
    buffer = bytearray(b'garbage from a print()\n{"jsonrpc":"2.0","method":"ping"}\n')
    assert _pop_newline_delimited_messages(buffer) == [{"jsonrpc": "2.0", "method": "ping"}]


def test_bootstrap_does_not_overwrite_refreshed_tokens(tmp_path):
    seed = json.dumps({"di_token": "seed"})
    env = {
        "GARMINTOKENS": str(tmp_path / "tokens"),
        "GARMIN_TOKENS_JSON": seed,
    }
    path, _ = _ensure_bootstrap_tokens(env)

    # garminconnect refreshes the store in place...
    refreshed = json.dumps({"di_token": "refreshed"})
    path.write_text(refreshed, encoding="utf-8")

    # ...and a restart with the same env secret must keep the refreshed tokens.
    _ensure_bootstrap_tokens(env)
    assert path.read_text(encoding="utf-8") == refreshed

    # A new secret in the env is an explicit re-seed.
    new_seed = json.dumps({"di_token": "new-seed"})
    _ensure_bootstrap_tokens({**env, "GARMIN_TOKENS_JSON": new_seed})
    assert path.read_text(encoding="utf-8") == new_seed


def test_legacy_env_value_longer_than_a_path_is_decoded():
    token_json = json.dumps({"blob": "x" * 5000})
    env = {"GARMINTOKENS_BASE64": base64.b64encode(token_json.encode()).decode()}
    decoded, _ = _extract_token_json_from_env(env)
    assert decoded == token_json


# --- Hosting platform defaults ----------------------------------------------

from garmin_mcp.http_server import _apply_platform_defaults


def test_railway_defaults_fill_base_url_and_token_dir():
    env = {"RAILWAY_PUBLIC_DOMAIN": "garmin-abc.up.railway.app", "RAILWAY_VOLUME_MOUNT_PATH": "/data"}
    assert _apply_platform_defaults(env, 3000) == "https://garmin-abc.up.railway.app"
    assert env["GARMINTOKENS"] == "/data"


def test_explicit_settings_win_over_platform_defaults():
    env = {
        "BASE_URL": "https://mcp.example.com",
        "GARMINTOKENS": "/custom",
        "RAILWAY_PUBLIC_DOMAIN": "garmin-abc.up.railway.app",
        "RAILWAY_VOLUME_MOUNT_PATH": "/data",
    }
    assert _apply_platform_defaults(env, 3000) == "https://mcp.example.com"
    assert env["GARMINTOKENS"] == "/custom"


def test_local_default_base_url():
    env = {}
    assert _apply_platform_defaults(env, 4000) == "http://127.0.0.1:4000"
    assert "GARMINTOKENS" not in env
