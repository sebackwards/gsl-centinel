"""Tests for Knowledge Base (Phase 2) endpoints."""
import pytest
from httpx import AsyncClient


ENTRY_PAYLOAD = {
    "title": "SQL Injection in Login Form",
    "summary": "Authentication bypass via SQL injection in the login endpoint",
    "content": "## Description\nThe login form is vulnerable to SQL injection...",
    "category": "sql-injection",
    "severity": "critical",
    "cwe": "CWE-89",
    "source_ticket_id": "SEC-1234",
}


@pytest.fixture
async def created_entry(client: AsyncClient, editor_token: str) -> dict:
    """Helper fixture: create a KB entry and return its response data."""
    resp = await client.post(
        "/api/v1/kb/entries",
        json=ENTRY_PAYLOAD,
        headers={"Authorization": f"Bearer {editor_token}"},
    )
    assert resp.status_code == 201
    return resp.json()


async def test_editor_can_create_kb_entry(client: AsyncClient, editor_token: str):
    resp = await client.post(
        "/api/v1/kb/entries",
        json=ENTRY_PAYLOAD,
        headers={"Authorization": f"Bearer {editor_token}"},
    )
    assert resp.status_code == 201
    data = resp.json()
    assert data["title"] == ENTRY_PAYLOAD["title"]
    assert data["category"] == "sql-injection"
    assert data["severity"] == "critical"
    assert data["cwe"] == "CWE-89"
    assert data["id"]


async def test_consumer_cannot_create_kb_entry(
    client: AsyncClient, consumer_token: str
):
    resp = await client.post(
        "/api/v1/kb/entries",
        json=ENTRY_PAYLOAD,
        headers={"Authorization": f"Bearer {consumer_token}"},
    )
    assert resp.status_code == 403


async def test_anyone_can_list_entries(
    client: AsyncClient, consumer_token: str, created_entry: dict
):
    resp = await client.get(
        "/api/v1/kb/entries",
        headers={"Authorization": f"Bearer {consumer_token}"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["total"] >= 1
    assert len(data["entries"]) >= 1


async def test_anyone_can_get_entry(
    client: AsyncClient, consumer_token: str, created_entry: dict
):
    entry_id = created_entry["id"]
    resp = await client.get(
        f"/api/v1/kb/entries/{entry_id}",
        headers={"Authorization": f"Bearer {consumer_token}"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["id"] == entry_id
    assert data["title"] == ENTRY_PAYLOAD["title"]


async def test_editor_can_update_entry(
    client: AsyncClient, editor_token: str, created_entry: dict
):
    entry_id = created_entry["id"]
    resp = await client.put(
        f"/api/v1/kb/entries/{entry_id}",
        json={"title": "Updated Title", "severity": "high"},
        headers={"Authorization": f"Bearer {editor_token}"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["title"] == "Updated Title"
    assert data["severity"] == "high"
    # Unchanged fields remain
    assert data["category"] == "sql-injection"


async def test_consumer_cannot_update_entry(
    client: AsyncClient, consumer_token: str, created_entry: dict
):
    entry_id = created_entry["id"]
    resp = await client.put(
        f"/api/v1/kb/entries/{entry_id}",
        json={"title": "Hacked Title"},
        headers={"Authorization": f"Bearer {consumer_token}"},
    )
    assert resp.status_code == 403


async def test_editor_can_delete_entry(
    client: AsyncClient, editor_token: str, created_entry: dict
):
    entry_id = created_entry["id"]
    resp = await client.delete(
        f"/api/v1/kb/entries/{entry_id}",
        headers={"Authorization": f"Bearer {editor_token}"},
    )
    assert resp.status_code == 204

    # Verify it's no longer accessible
    resp = await client.get(
        f"/api/v1/kb/entries/{entry_id}",
        headers={"Authorization": f"Bearer {editor_token}"},
    )
    assert resp.status_code == 404


async def test_consumer_cannot_delete_entry(
    client: AsyncClient, consumer_token: str, created_entry: dict
):
    entry_id = created_entry["id"]
    resp = await client.delete(
        f"/api/v1/kb/entries/{entry_id}",
        headers={"Authorization": f"Bearer {consumer_token}"},
    )
    assert resp.status_code == 403


async def test_search_returns_matching_entries(
    client: AsyncClient, editor_token: str, created_entry: dict
):
    resp = await client.post(
        "/api/v1/kb/search",
        json={"query": "SQL Injection", "limit": 5},
        headers={"Authorization": f"Bearer {editor_token}"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["query"] == "SQL Injection"
    assert len(data["results"]) >= 1
    assert data["results"][0]["entry_id"] == created_entry["id"]


async def test_search_filters_by_category(
    client: AsyncClient, editor_token: str, created_entry: dict
):
    # Search with matching category
    resp = await client.post(
        "/api/v1/kb/search",
        json={"query": "SQL", "category": "sql-injection"},
        headers={"Authorization": f"Bearer {editor_token}"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert len(data["results"]) >= 1

    # Search with non-matching category
    resp = await client.post(
        "/api/v1/kb/search",
        json={"query": "SQL", "category": "xss"},
        headers={"Authorization": f"Bearer {editor_token}"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert len(data["results"]) == 0


async def test_get_nonexistent_entry_returns_404(
    client: AsyncClient, editor_token: str
):
    resp = await client.get(
        "/api/v1/kb/entries/nonexistent-id-12345",
        headers={"Authorization": f"Bearer {editor_token}"},
    )
    assert resp.status_code == 404
