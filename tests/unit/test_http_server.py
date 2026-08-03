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


def _make_client(store_dir: Path | None = None):
    created_sessions: dict[str, FakeSession] = {}

    async def factory(session_id: str) -> FakeSession:
        session = FakeSession(session_id)
        created_sessions[session_id] = session
        return session

    if store_dir is None:
        store_dir = Path(tempfile.mkdtemp(prefix="garmin-mcp-test-"))

    app = create_app(
        base_url="https://garmin-mcp.example.com",
        session_factory=factory,
        clients_store_path=store_dir / "oauth_clients.json",
        tokens_store_path=store_dir / "oauth_tokens.json",
    )
    app.state.bridge.access_tokens["valid-token"] = AccessTokenRecord(
        token="valid-token",
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

        authorize = client.get(
            "/oauth/authorize",
            params={
                "response_type": "code",
                "client_id": client_id,
                "redirect_uri": redirect_uri,
                "state": "state-123",
                "code_challenge": challenge,
                "code_challenge_method": "S256",
                "resource": "https://garmin-mcp.example.com",
            },
            follow_redirects=False,
        )
        assert authorize.status_code == 302

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

    authorize = client.get(
        "/oauth/authorize",
        params={
            "response_type": "code",
            "client_id": client_id,
            "redirect_uri": redirect_uri,
            "code_challenge": challenge,
            "code_challenge_method": "S256",
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
