import json
from pathlib import Path

import requests

from monitor import HttpResult, UrlTarget, load_targets, proxy_preflight, probe_url, result_record
from alerts import MAX_TELEGRAM_TEXT_LENGTH, format_group_alert, format_success_mini_report
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

    result = probe_url(
        UrlTarget("example.com", "https://example.com"),
        {"http": "http://proxy:8080", "https": "http://proxy:8080"},
        session=FakeSession(),
    )
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


def test_ssl_failure_is_not_reported_as_available_when_http_is_200():
    record = result_record(
        "example.com",
        HttpResult(
            url="https://example.com",
            final_url="https://example.com/",
            status_code=200,
            response_ms=100,
            classification="OK",
            ssl_error="certificate expired",
        ),
        "2026-09-29T10:00:00+00:00",
    )
    assert record["error_type"] == "SSL"
    assert record["availability"] == "FAILED"
    assert record["http_status_role"] == "DIAGNOSTIC_ONLY"


def test_group_alert_contains_all_pages_for_one_site_and_error_type():
    results = [
        {"url": "https://example.com/one"},
        {"url": "https://example.com/two"},
    ]
    messages = format_group_alert(
        "example.com",
        "HTTP_5XX",
        results,
        {"first_seen_at": "2026-09-29T10:00:00+00:00", "consecutive_runs": 1},
        "2026-09-29T10:01:00+00:00",
    )
    assert len(messages) == 1
    assert "Страницы с ошибкой (2):" in messages[0]
    assert "https://example.com/one" in messages[0]
    assert "https://example.com/two" in messages[0]


def test_large_group_alert_uses_one_compact_domain_message():
    results = [{"url": f"https://example.com/page-{index}"} for index in range(500)]
    messages = format_group_alert(
        "example.com",
        "HTTP_5XX",
        results,
        {"first_seen_at": "2026-09-29T10:00:00+00:00", "consecutive_runs": 1},
        "2026-09-29T10:01:00+00:00",
    )
    assert len(messages) == 1
    assert len(messages[0]) < MAX_TELEGRAM_TEXT_LENGTH
    assert "Все страницы домена вернули ошибку HTTP_5XX (500 страниц)" in messages[0]
    assert "page-499" not in messages[0]
