from __future__ import annotations

import logging
import os
from dataclasses import dataclass
from datetime import datetime
from typing import Any
from zoneinfo import ZoneInfo

import requests


LOGGER = logging.getLogger("secret_landings.sheets")
ERROR_TYPES = {"HTTP_404", "HTTP_5XX", "TIMEOUT", "NO_CONNECTION"}
MOSCOW_ZONE = ZoneInfo("Europe/Moscow")


def _moscow_time(value: str) -> str:
    try:
        return datetime.fromisoformat(value).astimezone(MOSCOW_ZONE).isoformat(timespec="seconds")
    except ValueError:
        return value


def error_rows(summary: dict[str, Any], *, run_id: str, state: dict[str, dict[str, Any]] | None = None) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for result in summary.get("results", []):
        common = {
            "run_id": run_id,
            "checked_at_msk": _moscow_time(result.get("checked_at", "")),
            "site": result.get("site", ""),
            "url": result.get("url", ""),
            "response_ms": result.get("response_ms", ""),
            "first_seen_at": "",
            "consecutive_runs": "",
        }
        if result.get("ssl_error"):
            series = (state or {}).get(f"{result.get('site', '')}||{result.get('url', '')}||SSL", {})
            rows.append(
                {
                    **common,
                    "error_type": "SSL",
                    "http_status": "SSL",
                    "ssl_error": result.get("ssl_error", ""),
                    "first_seen_at": series.get("first_seen_at", ""),
                    "consecutive_runs": series.get("consecutive_runs", ""),
                }
            )
        classification = result.get("classification")
        if classification in ERROR_TYPES:
            series = (state or {}).get(
                f"{result.get('site', '')}||{result.get('url', '')}||{classification}",
                {},
            )
            rows.append(
                {
                    **common,
                    "error_type": classification,
                    "http_status": result.get("status_code") or classification,
                    "ssl_error": "",
                    "first_seen_at": series.get("first_seen_at", ""),
                    "consecutive_runs": series.get("consecutive_runs", ""),
                }
            )
    return rows


@dataclass
class GoogleSheetsWebhook:
    url: str
    token: str
    proxy_url: str
    timeout: float = 20.0

    def append_rows(self, rows: list[dict[str, Any]]) -> bool:
        if not rows:
            return True
        proxies = {"http": self.proxy_url, "https": self.proxy_url} if self.proxy_url else None
        try:
            with requests.Session() as client:
                client.trust_env = False
                response = client.post(
                    self.url,
                    json={"token": self.token, "rows": rows},
                    proxies=proxies,
                    timeout=self.timeout,
                )
            response.raise_for_status()
            payload = response.json()
            if payload.get("ok") is not True:
                LOGGER.error("Google Sheets webhook rejected rows: %s", payload.get("error", "unknown error"))
                return False
            LOGGER.info("Google Sheets rows appended: %s", payload.get("appended", len(rows)))
            return True
        except (requests.RequestException, ValueError) as exc:
            LOGGER.error("Google Sheets webhook delivery failed: %s", exc)
            return False


def webhook_from_env(proxy_url: str) -> GoogleSheetsWebhook | None:
    url = os.getenv("SHEETS_WEBHOOK_URL", "").strip()
    token = os.getenv("SHEETS_WEBHOOK_TOKEN", "").strip()
    if not url and not token:
        return None
    if not url or not token:
        LOGGER.error("Google Sheets webhook credentials are incomplete")
        return None
    return GoogleSheetsWebhook(url=url, token=token, proxy_url=proxy_url)
