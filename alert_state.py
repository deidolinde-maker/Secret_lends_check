from __future__ import annotations

import json
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any


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


def state_key(site: str, error_type: str) -> str:
    return f"{site}||{error_type}"


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
    error_type: str,
    urls: list[str],
    started_at: str,
) -> tuple[dict[str, Any], bool]:
    key = state_key(site, error_type)
    previous = state.get(key, {})
    consecutive = int(previous.get("consecutive_runs", 0)) + 1
    first_seen = previous.get("first_seen_at", started_at)
    due = notification_due(consecutive, previous.get("last_notified_at"), started_at)
    current = {
        "active": True,
        "site": site,
        "error_type": error_type,
        "first_seen_at": first_seen,
        "last_seen_at": started_at,
        "consecutive_runs": consecutive,
        "last_notified_at": started_at if due else previous.get("last_notified_at"),
        "last_urls": sorted(urls),
    }
    state[key] = current
    return current, due


def close_error(state: dict[str, dict[str, Any]], *, site: str, error_type: str) -> dict[str, Any] | None:
    key = state_key(site, error_type)
    previous = state.pop(key, None)
    return previous if previous and previous.get("active") else None
