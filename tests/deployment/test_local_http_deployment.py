"""Opt-in live tests; creates and removes one uniquely named temporary note."""

import json
import os
import re
import uuid
from urllib.parse import urlsplit

import httpx
import pytest


@pytest.fixture(scope="module")
def client():
    url = os.environ.get("LLMWIKI_DEPLOYMENT_URL")
    if not url:
        pytest.skip("Set LLMWIKI_DEPLOYMENT_URL to run live deployment tests")
    origin = os.environ.get("LLMWIKI_DEPLOYMENT_ORIGIN", url).rstrip("/")
    with httpx.Client(
        base_url=url,
        headers={"host": urlsplit(origin).netloc, "origin": origin},
        timeout=30,
        follow_redirects=True,
        trust_env=False,
    ) as connection:
        yield connection


def test_ui_and_javascript_assets(client):
    response = client.get("/wikis")
    assert response.status_code == 200
    assert "text/html" in response.headers["content-type"]
    scripts = re.findall(r'src="(/_next/[^"]+\.js[^"]*)"', response.text)
    assert scripts
    asset = client.get(scripts[0])
    assert asset.status_code == 200
    assert "javascript" in asset.headers["content-type"]


def test_health(client):
    response = client.get("/api/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_workspace_and_documents_are_readable(client):
    response = client.get("/api/v1/knowledge-bases")
    assert response.status_code == 200
    workspaces = response.json()
    assert workspaces
    documents = client.get(f"/api/v1/knowledge-bases/{workspaces[0]['id']}/documents")
    assert documents.status_code == 200
    assert isinstance(documents.json(), list)


def test_existing_document_and_original_file_are_readable(client):
    workspace = client.get("/api/v1/knowledge-bases").json()[0]
    documents = client.get(
        f"/api/v1/knowledge-bases/{workspace['id']}/documents"
    ).json()
    if not documents:
        pytest.skip("No existing documents to validate")
    document_id = documents[0]["id"]
    metadata = client.get(f"/api/v1/documents/{document_id}")
    assert metadata.status_code == 200
    assert metadata.json()["id"] == document_id
    content = client.get(f"/api/v1/documents/{document_id}/content")
    assert content.status_code == 200
    location = client.get(f"/api/v1/documents/{document_id}/url")
    assert location.status_code == 200
    url = location.json()["url"]
    assert url.startswith(client.headers["origin"] + "/api/")
    original = client.get(urlsplit(url).path)
    assert original.status_code == 200
    assert original.content


def test_note_create_read_update_and_cleanup(client):
    workspace = client.get("/api/v1/knowledge-bases").json()[0]
    filename = f"deployment-smoke-{uuid.uuid4().hex}.md"
    content = "# Deployment smoke test\n\nTemporary validation note.\n"
    response = client.post(
        f"/api/v1/knowledge-bases/{workspace['id']}/documents/note",
        json={"filename": filename, "path": "/", "content": content},
    )
    assert response.status_code == 201
    document_id = response.json()["id"]
    try:
        endpoint = f"/api/v1/documents/{document_id}/content"
        read = client.get(endpoint)
        assert read.status_code == 200
        assert read.json()["content"] == content
        updated_content = content + "\nUpdate verified.\n"
        update = client.put(endpoint, json={"content": updated_content})
        assert update.status_code == 200
        assert client.get(endpoint).json()["content"] == updated_content
    finally:
        cleanup = client.delete(f"/api/v1/documents/{document_id}")
        assert cleanup.status_code == 204, "Temporary deployment note cleanup failed"
    documents = client.get(f"/api/v1/knowledge-bases/{workspace['id']}/documents")
    assert all(document["id"] != document_id for document in documents.json())


@pytest.mark.parametrize("origin", ["https://untrusted.invalid", "null"])
def test_api_rejects_foreign_browser_mutations(client, origin):
    response = client.post(
        "/api/v1/knowledge-bases",
        headers={"origin": origin},
        json={},
    )
    assert response.status_code == 403


def _rpc_response(response):
    assert response.status_code == 200
    if "text/event-stream" in response.headers["content-type"]:
        messages = [
            json.loads(line[5:].strip())
            for line in response.text.splitlines()
            if line.startswith("data:")
        ]
        assert len(messages) == 1
        return messages[0]
    return response.json()


def test_mcp_initialize_discover_and_ping(client):
    headers = {"accept": "application/json, text/event-stream"}
    response = client.post(
        "/mcp",
        headers=headers,
        json={
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-03-26",
                "capabilities": {},
                "clientInfo": {"name": "deployment-smoke", "version": "1.0"},
            },
        },
    )
    assert "protocolVersion" in _rpc_response(response)["result"]
    headers["mcp-session-id"] = response.headers["mcp-session-id"]
    try:
        initialized = client.post(
            "/mcp",
            headers=headers,
            json={"jsonrpc": "2.0", "method": "notifications/initialized"},
        )
        assert initialized.status_code == 202
        tools = _rpc_response(
            client.post(
                "/mcp",
                headers=headers,
                json={"jsonrpc": "2.0", "id": 2, "method": "tools/list"},
            )
        )["result"]["tools"]
        assert any(tool["name"] == "ping" for tool in tools)
        result = _rpc_response(
            client.post(
                "/mcp",
                headers=headers,
                json={
                    "jsonrpc": "2.0",
                    "id": 3,
                    "method": "tools/call",
                    "params": {"name": "ping", "arguments": {}},
                },
            )
        )["result"]
        assert any(part.get("text") == "pong" for part in result["content"])
    finally:
        assert client.delete("/mcp", headers=headers).status_code == 200


def test_mcp_rejects_foreign_browser_origin(client):
    response = client.post(
        "/mcp",
        headers={
            "origin": "https://untrusted.invalid",
            "accept": "application/json, text/event-stream",
        },
        json={"jsonrpc": "2.0", "id": 1, "method": "initialize"},
    )
    assert response.status_code == 403
