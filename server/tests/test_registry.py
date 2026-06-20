"""Tests for /api/registry — public MCP-OAuth registry.

Hermetic: monkey-patches ``_scan_one`` so the registry logic (caching,
grade counts, slugs, error paths) is exercised without network I/O.
"""

from __future__ import annotations

import time

import pytest

from authgent_server.endpoints import registry as registry_module


@pytest.fixture(autouse=True)
def _clear_cache():
    registry_module._cache.clear()
    yield
    registry_module._cache.clear()


def _fake_entry(grade: str = "A", score: int = 100) -> registry_module._CacheEntry:
    return registry_module._CacheEntry(
        grade=grade,
        score=score,
        blocking=score < 70,
        finding_count=0 if grade == "A" else 1,
        headline_finding=None
        if grade == "A"
        else {
            "check_id": "MCP-PRM-001",
            "severity": "critical",
            "title": "Missing PRM",
        },
        last_scanned=time.time(),
        findings=[],
    )


def _async_returning(value):
    async def _f(*_args, **_kwargs):
        return value

    return _f


# --- /api/registry ---------------------------------------------------------


def test_registry_returns_all_targets(test_client, monkeypatch):
    monkeypatch.setattr(registry_module, "_scan_one", _async_returning(_fake_entry("A", 100)))
    resp = test_client.get("/api/registry")
    assert resp.status_code == 200
    body = resp.json()
    assert body["total"] == len(registry_module._REGISTRY_TARGETS)
    assert len(body["rows"]) == len(registry_module._REGISTRY_TARGETS)
    for row in body["rows"]:
        assert row["url"]
        assert row["vendor"]
        assert row["name"]


def test_registry_includes_grade_counts(test_client, monkeypatch):
    monkeypatch.setattr(registry_module, "_scan_one", _async_returning(_fake_entry("B", 85)))
    resp = test_client.get("/api/registry")
    body = resp.json()
    assert body["grade_counts"].get("B") == len(registry_module._REGISTRY_TARGETS)


def test_registry_skips_re_scan_when_cached(test_client, monkeypatch):
    counter = {"calls": 0}

    async def counting(*_args, **_kwargs):
        counter["calls"] += 1
        return _fake_entry("A", 100)

    monkeypatch.setattr(registry_module, "_scan_one", counting)

    test_client.get("/api/registry")
    first_calls = counter["calls"]
    test_client.get("/api/registry")
    assert counter["calls"] == first_calls


def test_registry_failed_scan_returns_pending_status(test_client, monkeypatch):
    async def always_none(*_args, **_kwargs):
        return None

    monkeypatch.setattr(registry_module, "_scan_one", always_none)
    resp = test_client.get("/api/registry")
    body = resp.json()
    assert body["scanned"] == 0
    for row in body["rows"]:
        assert row["status"] == "pending"
        assert row["grade"] is None


def test_registry_detail_unknown_vendor_returns_404(test_client, monkeypatch):
    monkeypatch.setattr(registry_module, "_scan_one", _async_returning(_fake_entry("A", 100)))
    resp = test_client.get("/api/registry/who-is-this")
    assert resp.status_code == 404


def test_registry_detail_known_vendor_returns_findings(test_client, monkeypatch):
    """Detail endpoint resolves a vendor slug from the registry. We use
    Notion here because it's curated to be live; the actual list rotates
    as vendors come online and this test should follow."""
    monkeypatch.setattr(registry_module, "_scan_one", _async_returning(_fake_entry("D", 50)))
    resp = test_client.get("/api/registry/Notion")
    assert resp.status_code == 200
    body = resp.json()
    assert body["vendor"] == "Notion"
    assert body["grade"] == "D"
    assert "findings" in body


# --- /api/scan/cached ------------------------------------------------------


def test_scan_cached_unsafe_url_rejected(test_client):
    resp = test_client.get("/api/scan/cached", params={"url": "http://localhost"})
    assert resp.status_code == 400


def test_scan_cached_returns_iso_timestamp(test_client, monkeypatch):
    monkeypatch.setattr(registry_module, "_scan_one", _async_returning(_fake_entry("A", 100)))
    resp = test_client.get(
        "/api/scan/cached",
        params={"url": "https://example.com"},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["last_scanned_iso"]
    assert body["grade"] == "A"


# --- embargo + opt-out -----------------------------------------------------


def test_embargoed_target_renders_pending_with_no_grade(test_client, monkeypatch):
    """A future ``embargo_until`` MUST show the entry as embargoed and
    suppress the grade entirely."""
    fake_target = {
        "name": "Embargoed Co",
        "url": "https://embargoed.example",
        "vendor": "EmbargoedCo",
        "embargo_until": "2099-01-01T00:00:00Z",
    }
    monkeypatch.setattr(registry_module, "_REGISTRY_TARGETS", [fake_target])
    monkeypatch.setattr(registry_module, "_scan_one", _async_returning(_fake_entry("F", 0)))

    resp = test_client.get("/api/registry")
    assert resp.status_code == 200
    body = resp.json()
    assert body["total"] == 1
    assert body["embargoed"] == 1
    assert body["scanned"] == 0
    row = body["rows"][0]
    assert row["status"] == "embargoed"
    assert row["grade"] is None
    assert row["embargo_until"].startswith("2099-")


def test_opted_out_target_is_hidden(test_client, monkeypatch):
    """A target with ``opted_out: true`` MUST NOT appear in the response."""
    targets = [
        {"name": "Listed", "url": "https://listed.example", "vendor": "Listed"},
        {
            "name": "OptedOut",
            "url": "https://opted.example",
            "vendor": "OptedOutCo",
            "opted_out": True,
        },
    ]
    monkeypatch.setattr(registry_module, "_REGISTRY_TARGETS", targets)
    monkeypatch.setattr(registry_module, "_scan_one", _async_returning(_fake_entry("A", 100)))

    resp = test_client.get("/api/registry")
    body = resp.json()
    assert body["total"] == 1
    vendors = [r["vendor"] for r in body["rows"]]
    assert "OptedOutCo" not in vendors
    assert "Listed" in vendors


def test_disclosure_policy_url_in_response(test_client, monkeypatch):
    monkeypatch.setattr(registry_module, "_scan_one", _async_returning(_fake_entry("A", 100)))
    resp = test_client.get("/api/registry")
    body = resp.json()
    assert body["disclosure_policy_url"].endswith("docs/disclosure-policy.md")
