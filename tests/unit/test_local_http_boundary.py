"""Security boundary tests for the unauthenticated local HTTP API."""

import importlib.machinery
import importlib.util
import re
from pathlib import Path

import httpx
import pytest
from infra.local_http import (
    LocalHTTPBoundaryMiddleware,
    extension_origin_regex,
    is_allowed_local_origin,
)
from starlette.applications import Starlette
from starlette.responses import JSONResponse
from starlette.routing import Route


async def _endpoint(request):
    return JSONResponse({"ok": True})


TRUSTED_EXTENSIONS = (
    "chrome-extension://dibilaenlekndomfbampadehjeahemha",
    "moz-extension://d28b2a6e-2456-4f45-9f65-e11c8ea1e65d",
)


def _app() -> Starlette:
    app = Starlette(
        routes=[Route("/", _endpoint, methods=["GET", "POST", "PUT", "PATCH", "DELETE"])]
    )
    app.add_middleware(
        LocalHTTPBoundaryMiddleware,
        app_origin="http://localhost:3000",
        extension_origins=TRUSTED_EXTENSIONS,
    )
    return app


async def _request(
    method: str = "GET",
    *,
    host: str = "localhost:8000",
    origin: str | None = None,
    extra_headers: dict[str, str] | None = None,
) -> httpx.Response:
    headers = {"host": host, **(extra_headers or {})}
    if origin is not None:
        headers["origin"] = origin
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=_app()),
        base_url="http://localhost:8000",
    ) as client:
        return await client.request(method, "/", headers=headers)


@pytest.mark.parametrize("host", ["localhost", "localhost:8000", "127.0.0.1:8000", "[::1]:8000"])
async def test_accepts_only_explicit_loopback_hosts(host):
    assert (await _request(host=host)).status_code == 200


@pytest.mark.parametrize(
    "host",
    [
        "attacker.example:8000",
        "workspace.localhost:8000",
        "127.0.0.2:8000",
        "",
        "[::1]:bad",
        f"localhost:{'9' * 5000}",
    ],
)
async def test_rejects_dns_rebinding_and_malformed_hosts(host):
    response = await _request(host=host)
    assert response.status_code == 400
    assert response.text == "Invalid Host header"


@pytest.mark.parametrize("method", ["POST", "PUT", "PATCH", "DELETE"])
async def test_allows_local_web_ui_mutations(method):
    response = await _request(method, origin="http://localhost:3000")
    assert response.status_code == 200


@pytest.mark.parametrize(
    "origin",
    [
        "chrome-extension://dibilaenlekndomfbampadehjeahemha",
        "moz-extension://d28b2a6e-2456-4f45-9f65-e11c8ea1e65d",
    ],
)
async def test_allows_browser_extension_mutations(origin):
    assert is_allowed_local_origin(origin, "http://localhost:3000", TRUSTED_EXTENSIONS)
    assert (await _request("POST", origin=origin)).status_code == 200


async def test_rejects_untrusted_browser_extension():
    origin = "chrome-extension://abcdefghijklmnopqrstuvwxyzabcdef"
    assert not is_allowed_local_origin(origin, "http://localhost:3000", TRUSTED_EXTENSIONS)
    assert (await _request("POST", origin=origin)).status_code == 403


def test_extension_cors_regex_matches_only_configured_ids():
    pattern = extension_origin_regex(TRUSTED_EXTENSIONS)
    assert re.fullmatch(pattern, TRUSTED_EXTENSIONS[0])
    assert not re.fullmatch(
        pattern,
        "chrome-extension://abcdefghijklmnopqrstuvwxyzabcdef",
    )


@pytest.mark.parametrize("origin", ["https://attacker.example", "null", "http://localhost:3001"])
async def test_rejects_foreign_browser_mutations(origin):
    response = await _request("POST", origin=origin)
    assert response.status_code == 403
    assert response.text == "Origin not allowed"


def test_configured_app_origin_must_itself_be_loopback():
    assert not is_allowed_local_origin(
        "https://attacker.example",
        "https://attacker.example",
    )


async def test_non_browser_mutation_without_origin_still_works():
    assert (await _request("POST")).status_code == 200


async def test_cross_site_browser_mutation_cannot_hide_missing_origin():
    response = await _request("POST", extra_headers={"sec-fetch-site": "cross-site"})
    assert response.status_code == 403


async def test_foreign_origin_is_harmless_on_safe_get():
    assert (await _request("GET", origin="https://attacker.example")).status_code == 200


@pytest.mark.parametrize("ports", [{}, {"api_port": 18473, "web_port": 18474}])
def test_cli_launches_api_on_ipv4_loopback(tmp_path, monkeypatch, ports):
    loader = importlib.machinery.SourceFileLoader(
        "llmwiki_cli_for_test",
        str(Path(__file__).resolve().parents[2] / "llmwiki"),
    )
    spec = importlib.util.spec_from_loader(loader.name, loader)
    assert spec is not None
    cli = importlib.util.module_from_spec(spec)
    loader.exec_module(cli)

    workspace = tmp_path / "workspace"
    (workspace / ".llmwiki").mkdir(parents=True)
    (workspace / ".llmwiki" / "index.db").touch()

    launches: list[list[str]] = []
    environments = []
    supervised = []

    class _Process:
        def terminate(self):
            pass

    def fake_popen(args, **kwargs):
        launches.append(args)
        environments.append(kwargs["env"])
        return _Process()

    web_dir = tmp_path / "web"
    (web_dir / "node_modules" / ".bin").mkdir(parents=True)
    (web_dir / "node_modules" / ".bin" / "next").touch()

    monkeypatch.setattr(cli.subprocess, "Popen", fake_popen)
    monkeypatch.setattr(cli, "WEB_DIR", web_dir)
    monkeypatch.setattr(cli, "_supervise", lambda *args: supervised.append(args))

    cli.cmd_serve(str(workspace), open_browser=False, **ports)

    api_command, web_command = launches
    assert api_command[api_command.index("--host") + 1] == "127.0.0.1"
    assert web_command[web_command.index("--hostname") + 1] == "127.0.0.1"
    api_port = ports.get("api_port", 8000)
    web_port = ports.get("web_port", 3000)
    assert api_command[api_command.index("--port") + 1] == str(api_port)
    assert web_command[web_command.index("--port") + 1] == str(web_port)
    assert environments[0]["APP_URL"] == f"http://localhost:{web_port}"
    assert environments[0]["API_URL"] == f"http://localhost:{api_port}"
    assert environments[1]["NEXT_PUBLIC_API_URL"] == f"http://localhost:{api_port}"
    assert environments[1]["LOCAL_API_PROXY_URL"] == f"http://127.0.0.1:{api_port}"
    assert supervised[0][2:] == (False, f"http://localhost:{web_port}")
