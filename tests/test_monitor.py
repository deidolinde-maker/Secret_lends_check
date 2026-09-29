import json
from pathlib import Path

import requests

from monitor import UrlTarget, load_targets, proxy_preflight, probe_url
from alerts import format_success_mini_report
from alert_state import notification_due


def test_load_targets_rejects_duplicate_urls(tmp_path: Path):
    path = tmp_path / "urls.json"
    path.write_text(json.dumps({"sites": [{"site": "example.com", "urls": ["https://example.com", "https://example.com"]}]}), encoding="utf-8")
    try:
        load_targets(path)
    except ValueError as exc:
        assert "Duplicate URL" in str(exc)
    else:
        raise AssertionError("duplicate URL was accepted")


def test_proxy_preflight_retries_three_times(monkeypatch):
    calls = {"count": 0}

    class FakeResponse:
        def raise_for_status(self):
            return None

        def json(self):
            return {"ip": "203.0.113.10"}

    class FakeSession:
        def get(self, *args, **kwargs):
            calls["count"] += 1
            raise requests.ConnectionError("proxy down")

    result = proxy_preflight("http://proxy:8080", "203.0.113.10", attempts=3, session=FakeSession())
    assert result.ok is False
    assert result.attempts == 3
    assert calls["count"] == 3


def test_probe_classifies_403_as_ok(monkeypatch):
    class FakeResponse:
        url = "https://example.com/final"
        status_code = 403

    class FakeSession:
        max_redirects = 0

        def get(self, *args, **kwargs):
            return FakeResponse()

    result = probe_url(UrlTarget("example.com", "https://example.com"), {"https": "http://proxy:8080"}, session=FakeSession())
    assert result.classification == "OK"
    assert result.status_code == 403


def test_direct_connection_is_forbidden():
    try:
        from monitor import proxy_mapping

        proxy_mapping("")
    except ValueError as exc:
        assert "direct connections are forbidden" in str(exc)
    else:
        raise AssertionError("empty proxy URL was accepted")


def test_success_mini_report_contains_duration_and_counts():
    report = format_success_mini_report(
        {"total": 689, "failed": 0, "ssl_errors": 0, "started_at": "2026-09-29T10:00:00+00:00", "duration_ms": 1234}
    )
    assert "Проверено страниц: 689" in report
    assert "Длительность прогона: 1234 мс" in report


def test_notification_schedule_is_one_four_twelve_then_24_hours():
    assert notification_due(1, None, "2026-09-29T10:00:00+00:00")
    assert notification_due(4, "2026-09-29T10:00:00+00:00", "2026-09-29T10:20:00+00:00")
    assert notification_due(12, "2026-09-29T10:00:00+00:00", "2026-09-29T10:20:00+00:00")
    assert not notification_due(13, "2026-09-29T10:00:00+00:00", "2026-09-30T09:59:00+00:00")
    assert notification_due(13, "2026-09-29T10:00:00+00:00", "2026-09-30T10:00:00+00:00")
