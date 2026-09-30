from __future__ import annotations

import json
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any
from zoneinfo import ZoneInfo


SUMMARY_STATE_KEY = "__summary__"
MOSCOW_ZONE = ZoneInfo("Europe/Moscow")


def load_state(path: str | Path) -> dict[str, dict[str, Any]]:
    state_path = Path(path)
    if not state_path.exists():
        return {}
    data = json.loads(state_path.read_text(encoding="utf-8"))
    return data if isinstance(data, dict) else {}


def save_state(path: str | Path, state: dict[str, dict[str, Any]]) -> None:
    state_path = Path(path)
    state_path.parent.mkdir(parents=True, exist_ok=True)
    temporary = state_path.with_suffix(state_path.suffix + ".tmp")
    temporary.write_text(json.dumps(state, ensure_ascii=False, indent=2), encoding="utf-8")
    temporary.replace(state_path)


def state_key(site: str, url: str, error_type: str) -> str:
    return f"{site}||{url}||{error_type}"


def notification_due(consecutive_runs: int, last_notified_at: str | None, started_at: str) -> bool:
    if consecutive_runs in {1, 4, 12}:
        return True
    if consecutive_runs < 12 or not last_notified_at:
        return False
    try:
        previous = datetime.fromisoformat(last_notified_at)
        current = datetime.fromisoformat(started_at)
        return current >= previous + timedelta(hours=24)
    except ValueError:
        return False


def observe_error(
    state: dict[str, dict[str, Any]],
    *,
    site: str,
    url: str,
    error_type: str,
    started_at: str,
) -> tuple[dict[str, Any], bool]:
    key = state_key(site, url, error_type)
    previous = state.get(key, {})
    consecutive = int(previous.get("consecutive_runs", 0)) + 1
    first_seen = previous.get("first_seen_at", started_at)
    # Legacy state files did not record delivery confirmation. Retry once for
    # those entries so an earlier failed/disabled sender cannot suppress alerts.
    due = notification_due(consecutive, previous.get("last_notified_at"), started_at) or previous.get("notification_delivered") is not True
    current = {
        "active": True,
        "site": site,
        "error_type": error_type,
        "first_seen_at": first_seen,
        "last_seen_at": started_at,
        "consecutive_runs": consecutive,
        # Notification time is updated only after Telegram confirms delivery.
        "last_notified_at": previous.get("last_notified_at"),
        "notification_delivered": previous.get("notification_delivered", False),
        "url": url,
    }
    state[key] = current
    return current, due


def mark_notification_sent(
    state: dict[str, dict[str, Any]],
    *,
    site: str,
    url: str,
    error_type: str,
    notified_at: str,
) -> None:
    entry = state.get(state_key(site, url, error_type))
    if entry is not None:
        entry["last_notified_at"] = notified_at
        entry["notification_delivered"] = True


def close_error(state: dict[str, dict[str, Any]], *, site: str, url: str, error_type: str) -> dict[str, Any] | None:
    key = state_key(site, url, error_type)
    previous = state.pop(key, None)
    return previous if previous and previous.get("active") else None


def summary_slot(started_at: str) -> str | None:
    """Return the Moscow summary slot for a run starting at 09:00 or 17:00."""
    try:
        current = datetime.fromisoformat(started_at).astimezone(MOSCOW_ZONE)
    except ValueError:
        return None
    if current.hour not in {9, 17}:
        return None
    return current.strftime("%Y-%m-%d-%H")


def summary_due(state: dict[str, dict[str, Any]], slot: str | None) -> bool:
    if not slot:
        return False
    return state.get(SUMMARY_STATE_KEY, {}).get("last_slot") != slot


def mark_summary_sent(state: dict[str, dict[str, Any]], *, slot: str, sent_at: str) -> None:
    state[SUMMARY_STATE_KEY] = {"last_slot": slot, "last_sent_at": sent_at}


def summary_period(started_at: str) -> str:
    """Return the Moscow aggregation period containing a run."""
    current = datetime.fromisoformat(started_at).astimezone(MOSCOW_ZONE)
    if 9 <= current.hour < 17:
        return current.strftime("%Y-%m-%d-09")
    if current.hour >= 17:
        return current.strftime("%Y-%m-%d-17")
    previous_day = current.date() - timedelta(days=1)
    return f"{previous_day:%Y-%m-%d}-17"


def add_summary_run(state: dict[str, dict[str, Any]], *, period: str, summary: dict[str, Any]) -> None:
    summary_state = state.setdefault(SUMMARY_STATE_KEY, {})
    periods = summary_state.setdefault("periods", {})
    aggregate = periods.setdefault(
        period,
        {
            "runs": 0,
            "total": 0,
            "passed": 0,
            "failed": 0,
            "broken": 0,
            "skipped": 0,
            "ssl_errors": 0,
            "policy_warnings": 0,
            "duration_ms": 0,
            "problem_urls": [],
            "ssl_urls": [],
            "started_at": summary["started_at"],
            "last_started_at": summary["started_at"],
        },
    )
    aggregate.setdefault("problem_urls", [])
    aggregate.setdefault("ssl_urls", [])
    for key in ("runs", "total", "passed", "failed", "broken", "skipped", "ssl_errors", "policy_warnings", "duration_ms"):
        aggregate[key] += 1 if key == "runs" else int(summary.get(key, 0))
    for result in summary.get("results", []):
        url = result.get("url")
        if result.get("classification") in {"HTTP_404", "HTTP_5XX", "TIMEOUT", "NO_CONNECTION"} and url not in aggregate["problem_urls"]:
            aggregate["problem_urls"].append(url)
        if result.get("ssl_error") and url not in aggregate["ssl_urls"]:
            aggregate["ssl_urls"].append(url)
    aggregate["last_started_at"] = summary["started_at"]


def pending_summary_periods(state: dict[str, dict[str, Any]], current_period: str) -> list[str]:
    periods = state.get(SUMMARY_STATE_KEY, {}).get("periods", {})
    return sorted(period for period in periods if period != current_period)


def get_summary_period(state: dict[str, dict[str, Any]], period: str) -> dict[str, Any] | None:
    periods = state.get(SUMMARY_STATE_KEY, {}).get("periods", {})
    value = periods.get(period)
    return value if isinstance(value, dict) else None


def mark_summary_period_sent(state: dict[str, dict[str, Any]], *, period: str, sent_at: str) -> None:
    summary_state = state.setdefault(SUMMARY_STATE_KEY, {})
    periods = summary_state.setdefault("periods", {})
    periods.pop(period, None)
    summary_state["last_sent_period"] = period
    summary_state["last_sent_at"] = sent_at
