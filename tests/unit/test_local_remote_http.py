"""Explicit remote opt-in must preserve local-mode Host and origin protections."""

import httpx
import pytest
from infra.local_http import LocalHTTPBoundaryMiddleware
from starlette.applications import Starlette
from starlette.responses import JSONResponse
from starlette.routing import Route

REMOTE_ORIGIN = "https://llmwiki.example.ts.net"


async def _endpoint(request):
    return JSONResponse({"ok": True})


def _app(trusted_origin: str = REMOTE_ORIGIN) -> Starlette:
    app = Starlette(routes=[Route("/", _endpoint, methods=["GET", "POST"])])
    app.add_middleware(
        LocalHTTPBoundaryMiddleware,
        app_origin=REMOTE_ORIGIN,
        trusted_origin=trusted_origin,
    )
    return app


@pytest.mark.parametrize(
    ("host", "origin", "status"),
    [
        ("llmwiki.example.ts.net", REMOTE_ORIGIN, 200),
        ("llmwiki.example.ts.net:443", REMOTE_ORIGIN, 200),
        ("LLMWIKI.EXAMPLE.TS.NET", REMOTE_ORIGIN, 200),
        ("127.0.0.1:8000", REMOTE_ORIGIN, 200),
        ("localhost:8000", REMOTE_ORIGIN, 200),
        ("llmwiki.example.ts.net", REMOTE_ORIGIN + ":443", 200),
        ("llmwiki.example.ts.net", None, 200),
        ("attacker.ts.net", REMOTE_ORIGIN, 400),
        ("llmwiki.example.ts.net.attacker.test", REMOTE_ORIGIN, 400),
        ("llmwiki.example.ts.net:444", REMOTE_ORIGIN, 400),
        ("llmwiki.example.ts.net", "https://attacker.ts.net", 403),
        ("llmwiki.example.ts.net", "http://llmwiki.example.ts.net", 403),
        ("llmwiki.example.ts.net", REMOTE_ORIGIN + ":444", 403),
        ("llmwiki.example.ts.net", "null", 403),
    ],
)
async def test_remote_access_is_scoped_to_exact_host_and_origin(host, origin, status):
    headers = {"host": host}
    if origin is not None:
        headers["origin"] = origin
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=_app()), base_url=REMOTE_ORIGIN
    ) as client:
        response = await client.post("/", headers=headers)
    assert response.status_code == status


async def test_app_url_alone_does_not_enable_remote_access():
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=_app(trusted_origin="")),
        base_url=REMOTE_ORIGIN,
    ) as client:
        assert (await client.get("/")).status_code == 400
        assert (
            await client.post(
                "/", headers={"host": "localhost:8000", "origin": REMOTE_ORIGIN}
            )
        ).status_code == 403


@pytest.mark.parametrize(
    "origin",
    [
        "http://llmwiki.example.ts.net",
        "https://*.ts.net",
        "https://llmwiki.example.ts.net/",
        "https://llmwiki.example.ts.net/path",
        "https://llmwiki.example.ts.net?query=1",
        "https://llmwiki.example.ts.net#fragment",
        "https://user:password@llmwiki.example.ts.net",
        "https://llmwiki.example.ts.net:invalid",
        "https://llmwiki.example.ts.net:0",
        "https://llmwiki.example.ts.net:99999",
        "https://bad host.ts.net",
    ],
)
def test_invalid_remote_configuration_fails_explicitly(origin):
    with pytest.raises(ValueError, match="LOCAL_TRUSTED_ORIGIN"):
        LocalHTTPBoundaryMiddleware(Starlette(), REMOTE_ORIGIN, trusted_origin=origin)


async def test_remote_access_rejects_duplicate_origin_headers():
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=_app()), base_url=REMOTE_ORIGIN
    ) as client:
        response = await client.post(
            "/", headers=[("origin", REMOTE_ORIGIN), ("origin", "https://attacker.test")]
        )
    assert response.status_code == 403


async def test_remote_access_preserves_cross_site_fetch_guard():
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=_app()), base_url=REMOTE_ORIGIN
    ) as client:
        response = await client.post("/", headers={"sec-fetch-site": "cross-site"})
    assert response.status_code == 403
