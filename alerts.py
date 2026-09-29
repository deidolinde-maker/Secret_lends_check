from __future__ import annotations

import html
import logging
import os
from dataclasses import dataclass

import requests


LOGGER = logging.getLogger("secret_landings.alerts")


@dataclass
class TelegramProxySender:
    proxy_url: str
    auth_secret: str
    creds: str
    timeout: float = 15.0

    def send(self, text: str) -> bool:
        if not self.proxy_url or not self.auth_secret or not self.creds:
            LOGGER.error("Telegram proxy credentials are incomplete")
            return False
        try:
            response = requests.post(
                self.proxy_url,
                headers={
                    "Content-Type": "application/json",
                    "X-Authentication": self.auth_secret,
                },
                json={
                    "title": html.escape("Secret landings monitor"),
                    "text": html.escape(text),
                    "creds": self.creds,
                    "parse_mode": "HTML",
                    "disable_notification": False,
                },
                timeout=self.timeout,
            )
            if not response.ok:
                LOGGER.error("Telegram proxy returned %s", response.status_code)
                return False
            return True
        except requests.RequestException as exc:
            LOGGER.error("Telegram proxy delivery failed: %s", exc)
            return False


def sender_from_env() -> TelegramProxySender | None:
    if os.getenv("ALERTS_ENABLED", "false").lower() not in {"1", "true", "yes", "on"}:
        return None
    return TelegramProxySender(
        proxy_url=os.getenv("TELEGRAM_PROXY_URL", "").strip(),
        auth_secret=os.getenv("TELEGRAM_PROXY_AUTH_SECRET", "").strip(),
        creds=os.getenv("TELEGRAM_PROXY_CREDS", "").strip(),
        timeout=float(os.getenv("TELEGRAM_PROXY_TIMEOUT_SEC", "15")),
    )


def format_error_alert(result: dict) -> str:
    lines = [
        "❌ [ALERT] Ошибка проверки лендинга",
        f"Сайт: {result['site']}",
        f"Страница: {result['url']}",
        f"Тип ошибки: {result['classification']}",
    ]
    if result.get("status_code") is not None:
        lines.append(f"HTTP-код: {result['status_code']}")
    if result.get("ssl_error"):
        lines.append("SSL: проблема с сертификатом")
    if result.get("response_ms") is not None:
        lines.append(f"Время ответа: {result['response_ms']} мс")
    lines.append(f"Время проверки: {result['checked_at']}")
    return "\n".join(lines)


def format_policy_warning(site: str, results: list[dict], checked_at: str) -> str:
    urls = "\n".join(f"- {result['url']}" for result in results)
    return "\n".join(
        [
            "⚠️ [WARNING] Возможная политика доступа сайта",
            f"Сайт: {site}",
            f"Страницы получили HTTP 401 ({len(results)}):",
            urls,
            f"Время проверки: {checked_at}",
        ]
    )


def format_group_alert(site: str, error_type: str, results: list[dict], state: dict, checked_at: str) -> list[str]:
    urls = [result["url"] for result in results]
    if error_type == "SSL":
        return [
            "\n".join(
                [
                    "❌ [ALERT] Проблема с SSL сертификатом🔒",
                    f"Сайт: {site}",
                    f"Страница: {result['url']}",
                    f"Время проверки: {checked_at}",
                ]
            )
            for result in results
        ]
    if len(urls) >= 6:
        return [
            "\n".join(
                [
                    "❌ [ALERT] Ошибка доступа к страницам",
                    f"Сайт: {site}",
                    f"{len(urls)} страниц сайта вернули ошибку {error_type}",
                    f"Время проверки: {checked_at}",
                    f"Время первой фиксации ошибки: {state['first_seen_at']}",
                    f"Сколько прогонов подряд падает: {state['consecutive_runs']}",
                ]
            )
        ]
    return [format_error_alert({**result, "site": site, "classification": error_type, "checked_at": checked_at}) for result in results]


def format_recovery(site: str, error_type: str, state: dict, checked_at: str) -> str:
    urls = state.get("last_urls", [])
    return "\n".join(
        [
            "✅ [ALERT] Ошибка восстановлена",
            f"Сайт: {site}",
            f"Тип ошибки: {error_type}",
            f"Восстановлено страниц: {len(urls)}",
            f"Время проверки: {checked_at}",
        ]
    )


def format_success_mini_report(summary: dict) -> str:
    return "\n".join(
        [
            "✅ Мини-отчёт проверки лендингов (Секретные)",
            f"Проверено страниц: {summary['total']}",
            f"Ошибок: {summary['failed']}",
            f"SSL-проблем: {summary['ssl_errors']}",
            f"Предупреждений policy: {summary.get('policy_warnings', 0)}",
            f"Время проверки: {summary['started_at']}",
            f"Длительность прогона: {summary['duration_ms']} мс",
        ]
    )
