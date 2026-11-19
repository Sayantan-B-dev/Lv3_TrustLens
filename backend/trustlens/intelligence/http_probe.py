"""SSRF-safe HTTP fetching and redirect-chain capture.

The request is sent over a socket pinned to the DNS address that was validated
immediately before connecting. TLS SNI and certificate verification still use
the original hostname. Redirect targets are re-normalised and re-resolved.
"""

from __future__ import annotations

import http.client
import socket
import ssl
import time
from dataclasses import dataclass, field
from urllib.parse import urljoin

from ..config import Settings
from ..security.netguard import (
    UnsafeTargetError,
    assert_connected_peer_is_public,
    resolve_public,
)
from ..security.tlsctx import build_ssl_context
from .normalize import InvalidInput, URLInfo, normalize_url, safe_fetch_ready


@dataclass
class FetchResult:
    url: str
    final_url: str
    status: int | None = None
    headers: dict[str, str] = field(default_factory=dict)
    body: str = ""
    body_truncated: bool = False
    redirect_chain: list[dict] = field(default_factory=list)
    elapsed_ms: int = 0
    resolved_ip: str | None = None
    error: str | None = None
    tls_verified: bool | None = None

    @property
    def ok(self) -> bool:
        return self.status is not None and self.error is None


def _decode_body(raw: bytes, content_type: str) -> str:
    charset = "utf-8"
    if "charset=" in content_type:
        charset = content_type.split("charset=", 1)[1].split(";")[0].strip().strip('"') or "utf-8"
    try:
        return raw.decode(charset, errors="replace")
    except LookupError:
        return raw.decode("utf-8", errors="replace")


def _request_once(info: URLInfo, settings: Settings, deadline: float) -> tuple[int, dict[str, str], bytes, bool, str | None, str, str | None]:
    if info.had_credentials:
        raise UnsafeTargetError("embedded credentials are not fetched")
    if not info.port_allowed:
        raise UnsafeTargetError(f"port {info.port} is not fetched")
    if deadline <= 0:
        raise TimeoutError("total fetch deadline exceeded")

    target = resolve_public(info.host, info.port)
    remaining = max(1.0, min(settings.fetch_connect_timeout_seconds, deadline))
    sock = socket.create_connection(target.sockaddr, timeout=remaining)
    peer_ip = sock.getpeername()[0]
    tls_verified: bool | None = None
    try:
        assert_connected_peer_is_public(sock)
        if info.scheme == "https":
            context = build_ssl_context(verify=True)
            sock.settimeout(max(1.0, min(settings.fetch_timeout_seconds, deadline)))
            sock = context.wrap_socket(sock, server_hostname=info.host)
            tls_verified = True

        sock.settimeout(max(1.0, min(settings.fetch_timeout_seconds, deadline)))
        path = info.path or "/"
        if info.query:
            path = f"{path}?{info.query}"
        request = (
            f"GET {path} HTTP/1.1\r\n"
            f"Host: {info.host}\r\n"
            f"User-Agent: {settings.fetch_user_agent}\r\n"
            "Accept: text/html,application/xhtml+xml,application/json;q=0.8,*/*;q=0.5\r\n"
            "Accept-Encoding: identity\r\n"
            "Connection: close\r\n"
            "\r\n"
        ).encode("ascii", errors="replace")
        sock.sendall(request)

        response = http.client.HTTPResponse(sock, method="GET")
        response.begin()
        headers: dict[str, str] = {}
        for key, value in response.getheaders():
            lowered = key.lower()
            headers[lowered] = f"{headers[lowered]}, {value}" if lowered in headers else value
        raw = response.read(settings.fetch_max_bytes + 1)
        truncated = len(raw) > settings.fetch_max_bytes
        if truncated:
            raw = raw[: settings.fetch_max_bytes]
        response.close()
        body = _decode_body(raw, headers.get("content-type", ""))
        return response.status, headers, raw, truncated, body, peer_ip, tls_verified
    finally:
        try:
            sock.close()
        except OSError:
            pass


def follow(url: str, settings: Settings) -> FetchResult:
    """Fetch a URL, following a bounded number of revalidated redirects."""
    started = time.monotonic()
    result = FetchResult(url=url, final_url=url)
    deadline_total = started + settings.fetch_timeout_seconds * (settings.fetch_max_redirects + 1)
    current = url
    seen: set[str] = set()

    try:
        first = normalize_url(url)
    except InvalidInput as exc:
        result.error = str(exc)
        return result

    for _hop in range(settings.fetch_max_redirects + 1):
        if current in seen:
            result.error = "Redirect loop detected."
            break
        seen.add(current)
        result.final_url = current
        try:
            info = first if current == url else normalize_url(current)
        except InvalidInput as exc:
            result.error = str(exc)
            break

        ready, reason = safe_fetch_ready(info)
        if not ready:
            result.error = reason
            break

        remaining = deadline_total - time.monotonic()
        if remaining <= 1:
            result.error = "Total fetch timeout exceeded."
            break
        try:
            status, headers, _raw, truncated, body, peer_ip, tls_verified = _request_once(
                info, settings, remaining
            )
        except (UnsafeTargetError, TimeoutError, socket.timeout, ssl.SSLError, OSError, http.client.HTTPException) as exc:
            result.error = f"Request failed: {exc.__class__.__name__}: {str(exc)[:180]}"
            break

        result.status = status
        result.headers = headers
        result.body = body
        result.body_truncated = truncated
        result.resolved_ip = peer_ip
        result.tls_verified = tls_verified

        location = headers.get("location")
        if status in {301, 302, 303, 307, 308} and location:
            next_url = urljoin(current, location)
            result.redirect_chain.append(
                {"from": current, "status": status, "to": next_url, "ip": peer_ip}
            )
            try:
                normalize_url(next_url)
            except InvalidInput:
                result.error = "Redirect destination is not an inspectable public http(s) URL."
                break
            current = next_url
            continue
        break

    if len(result.redirect_chain) >= settings.fetch_max_redirects and result.headers.get("location"):
        result.error = result.error or "Maximum redirect depth reached."

    result.elapsed_ms = int((time.monotonic() - started) * 1000)
    return result


def analyse_redirects(result: FetchResult) -> dict:
    chain = result.redirect_chain
    findings: list[dict] = []
    if result.error and "Redirect" in (result.error or ""):
        findings.append(
            {
                "rule_id": "redirect.invalid_destination",
                "severity": "medium",
                "title": "Redirect could not be safely followed",
                "summary": result.error,
                "evidence": {"chain": chain},
                "impact": "The final destination cannot be assessed, and the redirect may target a non-public address or unsupported scheme.",
                "remediation": "Do not follow the link in a browser until its destination is understood.",
                "limitations": ["TrustLens intentionally refuses redirects it cannot validate."],
                "authoritative": False,
            }
        )
    if len(chain) >= 3:
        findings.append(
            {
                "rule_id": "redirect.long_chain",
                "severity": "low",
                "title": "Long redirect chain",
                "summary": f"The link passed through {len(chain)} redirects before reaching the final page.",
                "evidence": {"chain": chain},
                "impact": "Long chains are used to obscure the true destination and evade link scanners.",
                "remediation": "Inspect the final domain before entering any information.",
                "limitations": ["Marketing and login flows can legitimately use several redirects."],
                "authoritative": False,
            }
        )
    if chain:
        first_host = (urlsplit_safe(chain[0]["from"]) or "").lower()
        final_host = (urlsplit_safe(result.final_url) or "").lower()
        if first_host and final_host and first_host != final_host:
            findings.append(
                {
                    "rule_id": "redirect.cross_domain",
                    "severity": "medium",
                    "title": "Redirect leaves the original domain",
                    "summary": "The link redirects to a different host than the one submitted.",
                    "evidence": {"from": chain[0]["from"], "to": result.final_url, "chain": chain},
                    "impact": "Users may believe they are staying on the submitted site while landing on unrelated infrastructure.",
                    "remediation": "Confirm that the destination domain is expected and trustworthy.",
                    "limitations": ["Legitimate URL shorteners and authentication flows also cross domains."],
                    "authoritative": False,
                }
            )
    return {"status": "completed", "chain": chain, "final_url": result.final_url, "findings": findings}


def urlsplit_safe(url: str) -> str:
    from urllib.parse import urlsplit

    try:
        return urlsplit(url).hostname or ""
    except ValueError:
        return ""
