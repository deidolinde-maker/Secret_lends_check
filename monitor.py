from __future__ import annotations

import argparse
import json
import logging
import os
import socket
import ssl
import time
import uuid
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning

from alert_state import (
    close_error,
    add_summary_run,
    get_summary_period,
    load_state,
    mark_notification_sent,
    mark_summary_period_sent,
    observe_error,
    save_state,
    pending_summary_periods,
    summary_period,
)
from alerts import (
    format_group_alert,
    format_critical_alert,
    format_policy_warning,
    format_recovery,
    format_scheduled_summary,
    sender_from_env,
)
from sheets_webhook import error_rows, webhook_from_env


LOGGER = logging.getLogger("secret_landings")
ERROR_TYPES = {"HTTP_404", "HTTP_5XX", "TIMEOUT", "NO_CONNECTION"}
requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)


@dataclass(frozen=True)
class UrlTarget:
    site: str
    url: str


@dataclass
class ProxyPreflightResult:
    ok: bool
    attempts: int
    external_ip: str | None = None
    error: str | None = None


@dataclass
class HttpResult:
    url: str
    final_url: str | None
    status_code: int | None
    response_ms: int | None
    classification: str
    ssl_error: str | None = None
    error_detail: str | None = None


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def load_targets(path: str | Path) -> list[UrlTarget]:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(data, dict) or not isinstance(data.get("sites"), list):
        raise ValueError("URL config must contain a 'sites' array")

    targets: list[UrlTarget] = []
    seen: set[str] = set()
    for site_entry in data["sites"]:
        if not isinstance(site_entry, dict):
            raise ValueError("Each site entry must be an object")
        site = str(site_entry.get("site", "")).strip()
        urls = site_entry.get("urls")
        if not site or not isinstance(urls, list):
            raise ValueError("Each site must contain non-empty 'site' and list 'urls'")
        for raw_url in urls:
            url = str(raw_url).strip()
            parsed = urlparse(url)
            if parsed.scheme != "https" or not parsed.netloc:
                raise ValueError(f"Invalid HTTPS URL: {url}")
            if url in seen:
                raise ValueError(f"Duplicate URL: {url}")
            seen.add(url)
            targets.append(UrlTarget(site=site, url=url))
    if not targets:
        raise ValueError("URL config contains no targets")
    return targets


def select_targets(targets: list[UrlTarget], target_site: str = "") -> list[UrlTarget]:
    """Return all configured targets unless an exact site filter was supplied."""
    normalized_site = target_site.strip()
    if not normalized_site:
        return targets
    selected = [target for target in targets if target.site == normalized_site]
    if not selected:
        raise ValueError(f"Target site was not found in URL config: {normalized_site}")
    return selected


def proxy_mapping(proxy_url: str) -> dict[str, str]:
    parsed = urlparse(proxy_url.strip())
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise ValueError("A valid HTTP(S) proxy URL is required; direct connections are forbidden")
    return {"http": proxy_url, "https": proxy_url}


def _session_without_environment_proxy(session: requests.Session | None) -> requests.Session:
    client = session or requests.Session()
    # Do not silently inherit HTTP(S)_PROXY/NO_PROXY from the local machine.
    # The only allowed route is the explicit dedicated proxy passed by the job.
    client.trust_env = False
    return client


def proxy_preflight(
    proxy_url: str,
    expected_ip: str,
    *,
    attempts: int = 3,
    timeout: float = 15,
    ip_check_url: str = "https://api.ipify.org?format=json",
    session: requests.Session | None = None,
) -> ProxyPreflightResult:
    if attempts < 1:
        raise ValueError("attempts must be greater than zero")
    client = _session_without_environment_proxy(session)
    proxies = proxy_mapping(proxy_url)
    last_error = "unknown proxy error"
    for attempt in range(1, attempts + 1):
        try:
            response = client.get(ip_check_url, proxies=proxies, timeout=timeout)
            response.raise_for_status()
            payload = response.json()
            external_ip = str(payload.get("ip", "")).strip()
            if not external_ip:
                raise RuntimeError("proxy response did not contain external IP")
            if expected_ip and external_ip != expected_ip:
                last_error = f"external IP mismatch: expected {expected_ip}, got {external_ip}"
                LOGGER.warning("Proxy preflight attempt %s/%s failed: %s", attempt, attempts, last_error)
                continue
            return ProxyPreflightResult(ok=True, attempts=attempt, external_ip=external_ip)
        except Exception as exc:  # noqa: BLE001 - preflight must convert all transport failures
            last_error = str(exc)
            LOGGER.warning("Proxy preflight attempt %s/%s failed: %s", attempt, attempts, last_error)
    return ProxyPreflightResult(ok=False, attempts=attempts, error=last_error)


def _classification(status_code: int | None, error: Exception | None) -> str:
    if isinstance(error, requests.Timeout):
        return "TIMEOUT"
    if error is not None:
        return "NO_CONNECTION"
    if status_code == 404:
        return "HTTP_404"
    if status_code is not None and 500 <= status_code <= 599:
        return "HTTP_5XX"
    return "OK"


def result_record(site: str, result: HttpResult, checked_at: str) -> dict[str, Any]:
    record = {"site": site, **asdict(result), "checked_at": checked_at}
    if result.ssl_error:
        record.update(
            {
                "error_type": "SSL",
                "availability": "FAILED",
                "http_status_role": "DIAGNOSTIC_ONLY",
            }
        )
    else:
        record.update(
            {
                "error_type": result.classification,
                "availability": "OK" if result.classification == "OK" else "FAILED",
                "http_status_role": "PRIMARY",
            }
        )
    return record


def _state_urls(state: dict[str, dict[str, Any]], site: str, error_type: str) -> list[str]:
    urls: list[str] = []
    prefix = f"{site}||"
    for key in state:
        parts = key.split("||")
        if key.startswith(prefix) and len(parts) == 3 and parts[2] == error_type:
            urls.append(parts[1])
    return urls


def probe_url(
    target: UrlTarget,
    proxies: dict[str, str],
    *,
    timeout: float = 10,
    max_redirects: int = 10,
    session: requests.Session | None = None,
) -> HttpResult:
    if not proxies or not proxies.get("http") or not proxies.get("https"):
        raise ValueError("Explicit proxy mapping is required; direct connections are forbidden")
    client = _session_without_environment_proxy(session)
    client.max_redirects = max_redirects
    started = time.perf_counter()
    ssl_error: str | None = None
    try:
        response = client.get(
            target.url,
            proxies=proxies,
            timeout=timeout,
            allow_redirects=True,
            verify=True,
        )
        elapsed = int(round((time.perf_counter() - started) * 1000))
        return HttpResult(
            url=target.url,
            final_url=response.url,
            status_code=response.status_code,
            response_ms=elapsed,
            classification=_classification(response.status_code, None),
        )
    except requests.exceptions.SSLError as exc:
        ssl_error = str(exc)
        # SSL and HTTP are independent: retry without certificate verification
        # strictly to obtain the final HTTP status, still through the proxy.
        try:
            response = client.get(
                target.url,
                proxies=proxies,
                timeout=timeout,
                allow_redirects=True,
                verify=False,
            )
            elapsed = int(round((time.perf_counter() - started) * 1000))
            return HttpResult(
                url=target.url,
                final_url=response.url,
                status_code=response.status_code,
                response_ms=elapsed,
                classification=_classification(response.status_code, None),
                ssl_error=ssl_error,
            )
        except Exception as retry_error:  # noqa: BLE001
            elapsed = int(round((time.perf_counter() - started) * 1000))
            return HttpResult(
                url=target.url,
                final_url=None,
                status_code=None,
                response_ms=elapsed,
                classification=_classification(None, retry_error),
                ssl_error=ssl_error,
                error_detail=str(retry_error),
            )
    except requests.TooManyRedirects as exc:
        elapsed = int(round((time.perf_counter() - started) * 1000))
        return HttpResult(target.url, None, None, elapsed, "TIMEOUT", error_detail=str(exc))
    except Exception as exc:  # noqa: BLE001 - result must classify every URL
        elapsed = int(round((time.perf_counter() - started) * 1000))
        return HttpResult(
            url=target.url,
            final_url=None,
            status_code=None,
            response_ms=elapsed,
            classification=_classification(None, exc),
            ssl_error=ssl_error,
            error_detail=str(exc),
        )


def _write_attachment(results_dir: Path, name: str, content: str) -> str:
    attachment_id = str(uuid.uuid4())
    (results_dir / f"{attachment_id}-attachment.txt").write_text(content, encoding="utf-8")
    return f"{attachment_id}-attachment.txt"


def write_allure_result(
    results_dir: Path,
    *,
    name: str,
    status: str,
    full_name: str,
    labels: dict[str, str],
    steps: list[dict[str, Any]],
    attachment_text: str,
) -> None:
    results_dir.mkdir(parents=True, exist_ok=True)
    result_id = str(uuid.uuid4())
    result = {
        "uuid": result_id,
        "historyId": full_name,
        "name": name,
        "fullName": full_name,
        "status": status,
        "stage": "finished",
        "start": int(time.time() * 1000),
        "stop": int(time.time() * 1000),
        "steps": steps,
        "attachments": [{"name": "result.json", "source": _write_attachment(results_dir, result_id, attachment_text), "type": "text/plain"}],
        "labels": [{"name": key, "value": value} for key, value in labels.items()],
    }
    (results_dir / f"{result_id}-result.json").write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")


def run_once(
    urls_file: str | Path,
    proxy_url: str,
    expected_ip: str,
    allure_dir: str | Path,
    *,
    timeout: float = 10,
    max_redirects: int = 10,
    preflight_attempts: int = 3,
    alert_state_file: str | Path = "alert_state.json",
    target_site: str = "",
) -> dict[str, Any]:
    run_started = time.perf_counter()
    started_at = utc_now()
    results_dir = Path(allure_dir)
    if not proxy_url.strip():
        raise ValueError("Proxy URL is required; monitor refuses to run without proxy")
    preflight = proxy_preflight(proxy_url, expected_ip, attempts=preflight_attempts)
    summary: dict[str, Any] = {
        "started_at": started_at,
        "proxy_preflight": asdict(preflight),
        "total": 0,
        "passed": 0,
        "failed": 0,
        "broken": 0,
        "skipped": 0,
        "ssl_errors": 0,
        "policy_warnings": 0,
        "results": [],
    }
    if not preflight.ok:
        write_allure_result(
            results_dir,
            name="Proxy preflight",
            status="failed",
            full_name="AUTOMATIZATION-35 / secret_landings / proxy_preflight",
            labels={"profile": "secret_landings", "error_type": "PROXY_PREFLIGHT"},
            steps=[],
            attachment_text=json.dumps({"message": "Ошибка подключения прокси, прогон остановлен", **asdict(preflight)}, ensure_ascii=False),
        )
        summary["message"] = "Ошибка подключения прокси, прогон остановлен"
        summary["duration_ms"] = int(round((time.perf_counter() - run_started) * 1000))
        return summary

    targets = select_targets(load_targets(urls_file), target_site)
    proxies = proxy_mapping(proxy_url)
    sender = sender_from_env()
    sheets_webhook = webhook_from_env(proxy_url)
    state = load_state(alert_state_file)
    if sender is None:
        LOGGER.warning("Telegram alerts are disabled or unavailable; no alert messages will be sent")
    current_period = summary_period(started_at)
    if sender:
        for pending_period in pending_summary_periods(state, current_period):
            aggregate = get_summary_period(state, pending_period)
            if aggregate and sender.send(
                format_scheduled_summary(aggregate, pending_period, os.getenv("SHEETS_REPORT_URL", ""))
            ):
                mark_summary_period_sent(state, period=pending_period, sent_at=started_at)
                save_state(alert_state_file, state)
                LOGGER.info("Aggregated Telegram summary delivered: period=%s", pending_period)
            else:
                LOGGER.warning("Aggregated Telegram summary was not delivered; period remains due: %s", pending_period)
    grouped: dict[str, list[UrlTarget]] = {}
    for target in targets:
        grouped.setdefault(target.site, []).append(target)

    # Process and alert per site. We do not wait for the whole 689-page run.
    for site, site_targets in grouped.items():
        site_results: list[dict[str, Any]] = []
        for target in site_targets:
            result = probe_url(target, proxies, timeout=timeout, max_redirects=max_redirects)
            is_policy_warning = result.status_code == 401 and result.classification == "OK"
            status = "broken" if is_policy_warning else ("failed" if result.classification != "OK" or result.ssl_error else "passed")
            summary["total"] += 1
            summary[status] += 1
            if result.ssl_error:
                summary["ssl_errors"] += 1
            result_dict = result_record(target.site, result, started_at)
            site_results.append(result_dict)
            summary["results"].append(result_dict)
            write_allure_result(
                results_dir,
                name=target.url,
                status=status,
                full_name=f"AUTOMATIZATION-35 / secret_landings / {target.site} / {target.url}",
                labels={
                    "profile": "secret_landings",
                    "site": target.site,
                    "error_type": "HTTP_401_POLICY" if is_policy_warning else ("SSL" if result.ssl_error else result.classification),
                },
                steps=[{"name": "HTTP probe", "status": status}],
                attachment_text=json.dumps(result_dict, ensure_ascii=False),
            )

        current_by_type: dict[str, list[dict[str, Any]]] = {}
        for result in site_results:
            if result.get("ssl_error"):
                current_by_type.setdefault("SSL", []).append(result)
            elif result["classification"] != "OK":
                current_by_type.setdefault(result["classification"], []).append(result)
            if not result.get("ssl_error") and result.get("status_code") == 401:
                current_by_type.setdefault("HTTP_401_POLICY", []).append(result)

        summary["policy_warnings"] += len(current_by_type.get("HTTP_401_POLICY", []))
        known_types = {
            key.rsplit("||", 1)[1]
            for key in state
            if key.startswith(f"{site}||") and len(key.split("||")) == 3
        }
        for error_type in sorted(known_types | set(current_by_type)):
            current_results = current_by_type.get(error_type, [])
            current_urls = {item["url"] for item in current_results}
            recovered: list[dict[str, Any]] = []
            for old_url in _state_urls(state, site, error_type):
                if old_url not in current_urls:
                    closed = close_error(state, site=site, url=old_url, error_type=error_type)
                    if closed:
                        recovered.append(closed)

            if recovered and sender and error_type != "HTTP_401_POLICY":
                sender.send(format_recovery(site, error_type, recovered, started_at))

            if current_results:
                due_series: list[dict[str, Any]] = []
                for result in current_results:
                    series, due = observe_error(
                        state,
                        site=site,
                        url=result["url"],
                        error_type=error_type,
                        started_at=started_at,
                    )
                    if due:
                        due_series.append(series)
                if sender and due_series:
                    aggregate_state = {
                        "first_seen_at": min(item["first_seen_at"] for item in due_series),
                        "consecutive_runs": max(item["consecutive_runs"] for item in due_series),
                    }
                    all_pages_same_error = (
                        error_type in {"HTTP_404", "HTTP_5XX", "NO_CONNECTION"}
                        and len(current_results) == len(site_targets)
                    )
                    if error_type == "HTTP_401_POLICY":
                        delivered = sender.send(format_policy_warning(site, current_results, started_at))
                    elif all_pages_same_error:
                        delivered = sender.send(format_critical_alert(site, error_type, current_results, aggregate_state, started_at))
                    else:
                        delivered = True
                        for message in format_group_alert(site, error_type, current_results, aggregate_state, started_at):
                            delivered = sender.send(message) and delivered
                    if delivered:
                        for series in due_series:
                            mark_notification_sent(
                                state,
                                site=site,
                                url=series["url"],
                                error_type=error_type,
                                notified_at=started_at,
                            )
                        LOGGER.info("Telegram alert delivered: site=%s error_type=%s", site, error_type)
                    else:
                        LOGGER.warning(
                            "Telegram alert was not delivered; it will remain due for retry: site=%s error_type=%s",
                            site,
                            error_type,
                        )
                elif due_series:
                    LOGGER.warning("Telegram alert is due but sender is unavailable: site=%s error_type=%s", site, error_type)
        save_state(alert_state_file, state)
    summary["duration_ms"] = int(round((time.perf_counter() - run_started) * 1000))
    run_id = uuid.uuid4().hex
    table_rows = error_rows(summary, run_id=run_id, state=state)
    summary["run_id"] = run_id
    summary["table_rows"] = len(table_rows)
    if sheets_webhook and not sheets_webhook.append_rows(table_rows):
        LOGGER.error("Google Sheets write failed; monitor result remains available in Allure and logs")
    add_summary_run(state, period=current_period, summary=summary)
    save_state(alert_state_file, state)
    return summary


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Secret landings availability monitor")
    parser.add_argument("--urls-file", required=True)
    parser.add_argument("--proxy-url", required=True)
    parser.add_argument("--expected-ip", default="")
    parser.add_argument("--allure-dir", default="allure-results")
    parser.add_argument("--timeout", type=float, default=10)
    parser.add_argument("--max-redirects", type=int, default=10)
    parser.add_argument("--preflight-attempts", type=int, default=3)
    parser.add_argument("--alert-state-file", default="alert_state.json")
    parser.add_argument("--site", default="", help="Check only one configured site")
    return parser


def main() -> int:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    args = build_parser().parse_args()
    summary = run_once(
        args.urls_file,
        args.proxy_url,
        args.expected_ip,
        args.allure_dir,
        timeout=args.timeout,
        max_redirects=args.max_redirects,
        preflight_attempts=args.preflight_attempts,
        alert_state_file=args.alert_state_file,
        target_site=args.site,
    )
    print(json.dumps(summary, ensure_ascii=False, indent=2))
    return 0 if summary["proxy_preflight"]["ok"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
