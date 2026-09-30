from __future__ import annotations

import html
import logging
import os
from dataclasses import dataclass
from datetime import datetime, timedelta

import requests


LOGGER = logging.getLogger("secret_landings.alerts")
MAX_TELEGRAM_TEXT_LENGTH = 3500


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
                if response.status_code == 429:
                    LOGGER.error("Telegram proxy returned 429: rate limit while delivering alert")
                else:
                    LOGGER.error("Telegram proxy returned %s", response.status_code)
                return False
            LOGGER.info("Telegram alert delivery confirmed")
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
    error_type = "SSL" if result.get("ssl_error") else result["classification"]
    lines = [
        "❌ [ALERT] Ошибка проверки лендинга",
        f"Сайт: {result['site']}",
        f"Страница: {result['url']}",
        f"Тип ошибки: {error_type}",
    ]
    if result.get("status_code") is not None:
        lines.append(f"HTTP-код: {result['status_code']}")
    if result.get("ssl_error"):
        lines.append("SSL: проблема с сертификатом")
        if result.get("status_code") is not None:
            lines.append(f"HTTP-код (диагностический): {result['status_code']}")
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
    title = "❌ [ALERT] Проблема с SSL сертификатом🔒" if error_type == "SSL" else "❌ [ALERT] Ошибка проверки страниц"
    details = [
        title,
        f"Сайт: {site}",
        f"Тип ошибки: {error_type}",
        f"Страницы с ошибкой ({len(urls)}):",
        *(f"- {url}" for url in urls),
        f"Время проверки: {checked_at}",
        f"Время первой фиксации ошибки: {state['first_seen_at']}",
        f"Сколько прогонов подряд падает: {state['consecutive_runs']}",
    ]

    # Keep one logical alert per site/error type. If the URL list is too large,
    # send one compact domain-level alert instead of several Telegram messages.
    message = "\n".join(details)
    if len(message) <= MAX_TELEGRAM_TEXT_LENGTH:
        return [message]
    return [
        "\n".join(
            [
                title,
                f"Сайт: {site}",
                f"Все страницы домена вернули ошибку {error_type} ({len(urls)} страниц)",
                "Список URL сокращён: сообщение превысило лимит Telegram.",
                f"Время проверки: {checked_at}",
                f"Время первой фиксации ошибки: {state['first_seen_at']}",
                f"Сколько прогонов подряд падает: {state['consecutive_runs']}",
            ]
        )
    ]


def format_recovery(site: str, error_type: str, states: list[dict], checked_at: str) -> str:
    urls = [state.get("url", "") for state in states if state.get("url")]
    lines = [
        "✅ [ALERT] Ошибка восстановлена",
        f"Сайт: {site}",
        f"Тип ошибки: {error_type}",
        f"Восстановлено страниц: {len(urls)}",
    ]
    lines.extend(f"- {url}" for url in urls[:20])
    if len(urls) > 20:
        lines.append("Список URL сокращён.")
    lines.append(f"Время проверки: {checked_at}")
    return "\n".join(lines)


def format_critical_alert(site: str, error_type: str, results: list[dict], state: dict, checked_at: str) -> str:
    return "\n".join(
        [
            "🚨 [CRITICAL] Ошибка доступа ко всем страницам на лендинге",
            f"Сайт: {site}",
            f"Тип ошибки: {error_type}",
            f"Все страницы вернули ошибку: {len(results)}",
            f"Время проверки: {checked_at}",
            f"Время первой фиксации ошибки: {state['first_seen_at']}",
            f"Сколько прогонов подряд падает: {state['consecutive_runs']}",
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


def format_scheduled_summary(summary: dict, slot: str, report_url: str = "") -> str:
    date = datetime.fromisoformat(slot[:10]).date()
    if slot.endswith("-09"):
        period = f"{date - timedelta(days=1)} 17:00 — {date} 09:00"
    else:
        period = f"{date} 09:00 — {date} 17:00"
    problem_count = len(summary.get("problem_urls", []))
    ssl_count = len(summary.get("ssl_urls", []))
    return "\n".join(
        [
            f"📊 Отчет за период — лендинги (Секретные)",
            f"Период: {period} МСК",
            f"Завершено прогонов: {summary.get('runs', 1)}",
            f"Проверено страниц: {summary['total']}",
            f"Успешно: {summary.get('passed', 0)}",
            f"Проблемных страниц: {problem_count}",
            f"Предупреждений policy (HTTP 401): {summary.get('policy_warnings', 0)}",
            f"SSL-проблем на сайтах: {ssl_count}",
            *([f"Ссылка на отчет: {report_url}"] if report_url else []),
        ]
    )
