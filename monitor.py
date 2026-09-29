from __future__ import annotations

import argparse
import json
import logging
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

from alerts import format_error_alert, format_success_mini_report, sender_from_env


LOGGER = logging.getLogger("secret_landings")
ERROR_TYPES = {"HTTP_404", "HTTP_5XX", "TIMEOUT", "NO_CONNECTION"}


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
        "skipped": 0,
        "ssl_errors": 0,
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

    targets = load_targets(urls_file)
    proxies = proxy_mapping(proxy_url)
    for target in targets:
        result = probe_url(target, proxies, timeout=timeout, max_redirects=max_redirects)
        status = "failed" if result.classification != "OK" or result.ssl_error else "passed"
        summary["total"] += 1
        summary[status] += 1
        if result.ssl_error:
            summary["ssl_errors"] += 1
        summary["results"].append({"site": target.site, **asdict(result)})
        write_allure_result(
            results_dir,
            name=target.url,
            status=status,
            full_name=f"AUTOMATIZATION-35 / secret_landings / {target.site} / {target.url}",
            labels={
                "profile": "secret_landings",
                "site": target.site,
                "error_type": result.classification if result.classification != "OK" else "NONE",
            },
            steps=[{"name": "HTTP probe", "status": status}],
            attachment_text=json.dumps(asdict(result), ensure_ascii=False),
        )
    summary["duration_ms"] = int(round((time.perf_counter() - run_started) * 1000))
    sender = sender_from_env()
    if sender:
        for result in summary["results"]:
            if result["classification"] != "OK" or result.get("ssl_error"):
                result["checked_at"] = started_at
                sender.send(format_error_alert(result))
        if summary["failed"] == 0 and summary["ssl_errors"] == 0:
            sender.send(format_success_mini_report(summary))
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
    )
    print(json.dumps(summary, ensure_ascii=False, indent=2))
    return 0 if summary["proxy_preflight"]["ok"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
