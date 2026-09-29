from __future__ import annotations

import base64
import os
import socket
import ssl
import tempfile
from pathlib import Path
from urllib.parse import unquote, urlsplit


HOST = "t2-internet.online"
PORT = 443


def open_proxy_tunnel(proxy_url: str) -> socket.socket:
    parsed = urlsplit(proxy_url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname or not parsed.port:
        raise ValueError("A valid authenticated HTTP(S) proxy is required")
    if parsed.username is None or parsed.password is None:
        raise ValueError("Proxy credentials are required")

    auth = base64.b64encode(
        f"{unquote(parsed.username)}:{unquote(parsed.password)}".encode("utf-8")
    ).decode("ascii")
    connection = socket.create_connection((parsed.hostname, parsed.port), timeout=20)
    request = (
        f"CONNECT {HOST}:{PORT} HTTP/1.1\r\n"
        f"Host: {HOST}:{PORT}\r\n"
        "Proxy-Connection: Keep-Alive\r\n"
        f"Proxy-Authorization: Basic {auth}\r\n\r\n"
    )
    connection.sendall(request.encode("ascii"))
    response = b""
    while b"\r\n\r\n" not in response:
        chunk = connection.recv(4096)
        if not chunk:
            break
        response += chunk
    status_line = response.split(b"\r\n", 1)[0].decode("latin1", errors="replace")
    if " 200 " not in status_line:
        connection.close()
        raise RuntimeError(f"Proxy CONNECT failed: {status_line}")
    return connection


def certificate_summary(certificate: dict) -> dict[str, object]:
    return {
        "subject": certificate.get("subject"),
        "issuer": certificate.get("issuer"),
        "subjectAltName": certificate.get("subjectAltName"),
        "notBefore": certificate.get("notBefore"),
        "notAfter": certificate.get("notAfter"),
    }


def inspect_peer_certificate(proxy_url: str) -> None:
    verified_connection = open_proxy_tunnel(proxy_url)
    try:
        context = ssl.create_default_context()
        with context.wrap_socket(verified_connection, server_hostname=HOST):
            print("TLS verified: PASS")
    except ssl.SSLCertVerificationError as exc:
        print(f"TLS verified: FAIL {exc.verify_message}")
    finally:
        verified_connection.close()

    raw_connection = open_proxy_tunnel(proxy_url)
    try:
        context = ssl._create_unverified_context()
        with context.wrap_socket(raw_connection, server_hostname=HOST) as connection:
            pem = ssl.DER_cert_to_PEM_cert(connection.getpeercert(binary_form=True))
        with tempfile.NamedTemporaryFile("w", suffix=".pem", delete=False) as certificate_file:
            certificate_file.write(pem)
            certificate_path = Path(certificate_file.name)
        try:
            decoded = ssl._ssl._test_decode_cert(str(certificate_path))
            print("TLS peer certificate:", certificate_summary(decoded))
        finally:
            certificate_path.unlink(missing_ok=True)
    finally:
        raw_connection.close()


def main() -> None:
    try:
        inspect_peer_certificate(os.environ["PROXY_URL"])
    except Exception as exc:  # noqa: BLE001 - diagnostic must not hide the main monitor result
        print(f"TLS peer certificate diagnostics unavailable: {type(exc).__name__}: {exc}")


if __name__ == "__main__":
    main()
