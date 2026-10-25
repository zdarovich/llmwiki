"""The local MCP proxy accepts the opt-in origin without trusting remote Hosts."""

import importlib.util
from pathlib import Path

import pytest
from mcp.server.fastmcp import FastMCP
from mcp.server.transport_security import (
    TransportSecurityMiddleware,
    TransportSecuritySettings,
)


@pytest.fixture
def trust_proxy_origin(monkeypatch):
    monkeypatch.setenv("SUPAVAULT_USER_ID", "test-local-mcp")
    path = Path(__file__).resolve().parents[2] / "mcp" / "local_server.py"
    spec = importlib.util.spec_from_file_location("local_server_for_test", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module._trust_proxy_origin


def test_mcp_remote_origin_is_explicit_and_host_checks_remain_enabled(trust_proxy_origin):
    server = FastMCP()
    security = TransportSecurityMiddleware(server.settings.transport_security)
    origin = "https://llmwiki.example.ts.net"
    assert not security._validate_origin(origin)

    trust_proxy_origin(server, origin)

    assert security.settings.enable_dns_rebinding_protection
    assert security._validate_origin(origin)
    assert security._validate_origin("http://localhost:3000")
    assert security._validate_origin(None)
    assert not security._validate_origin("https://attacker.ts.net")
    assert not security._validate_origin(origin + ".attacker.test")
    assert security._validate_host("127.0.0.1:8100")
    assert not security._validate_host("attacker.ts.net")
    assert not security._validate_host("llmwiki.example.ts.net")


def test_mcp_without_remote_opt_in_preserves_defaults(trust_proxy_origin):
    server = FastMCP()
    security = server.settings.transport_security
    assert security is not None
    before = security.model_copy(deep=True)
    trust_proxy_origin(server, "")
    assert security == before


@pytest.mark.parametrize(
    "security",
    [None, TransportSecuritySettings(enable_dns_rebinding_protection=False)],
)
def test_mcp_remote_access_requires_host_protection(trust_proxy_origin, security):
    server = FastMCP()
    server.settings.transport_security = security
    with pytest.raises(RuntimeError, match="DNS rebinding protection"):
        trust_proxy_origin(server, "https://llmwiki.example.ts.net")
