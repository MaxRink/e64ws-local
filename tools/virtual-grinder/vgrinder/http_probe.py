"""HTTP/HTTPS probes and REST helpers for the virtual grinder."""

from __future__ import annotations

import http.client
import json
import ssl
import time
from typing import Any


def request(host: str, port: int, method: str, path: str, body: bytes | None = None,
            headers: dict[str, str] | None = None, https: bool = False,
            timeout: float = 6.0) -> dict:
    if https:
        ctx = ssl._create_unverified_context()
        conn = http.client.HTTPSConnection(host, port, timeout=timeout, context=ctx)
    else:
        conn = http.client.HTTPConnection(host, port, timeout=timeout)
    try:
        conn.request(method, path, body=body, headers=headers or {})
        response = conn.getresponse()
        data = response.read(65536)
        return {
            "ok": True,
            "status": response.status,
            "reason": response.reason,
            "headers": {k.lower(): v for k, v in response.getheaders()},
            "body": data.decode(errors="replace"),
            "bytes": len(data),
        }
    except Exception as exc:  # noqa: BLE001 - probe reports failures as data
        return {"ok": False, "error": str(exc)}
    finally:
        conn.close()


def probe_http(port: int, path: str = "/login.php", https: bool = False,
               host: str = "127.0.0.1") -> dict:
    started = time.time()
    result = request(host, port, "GET", path, https=https)
    result["latency_ms"] = round((time.time() - started) * 1000, 1)
    result["url"] = f"{'https' if https else 'http'}://{host}:{port}{path}"
    if result.get("ok"):
        result["title"] = _title(result.get("body", ""))
    return result


def _title(html: str) -> str | None:
    lower = html.lower()
    start = lower.find("<title>")
    end = lower.find("</title>", start + 7)
    if start >= 0 and end > start:
        return html[start + 7:end].strip()
    return None


def rest_login(port: int, role: str = "Owner", password: str = "",
               https: bool = True, host: str = "127.0.0.1") -> dict:
    """POST /login.php and return any Authorization header + cookies."""
    payload = (
        f"login=1&requestDeveloper=1&password={password}&userRole={role}"
    ).encode()
    return request(
        host, port, "POST", "/login.php", body=payload,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        https=https,
    )


def rest_json(port: int, route: str, method: str = "GET", data: Any = None,
              token: str | None = None, https: bool = True,
              host: str = "127.0.0.1") -> dict:
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    body = json.dumps(data).encode() if data is not None else None
    return request(host, port, method, f"/rest_api.php/{route}", body=body,
                   headers=headers, https=https)
