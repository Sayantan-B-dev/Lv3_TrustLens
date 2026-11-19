"""URL normalisation, validation and input classification."""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from urllib.parse import quote, urlsplit, urlunsplit

from ..config import get_settings
from ..security.netguard import UnsafeTargetError, parse_possibly_obfuscated_ip

DOMAIN_RE = re.compile(
    r"(?i)^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:[a-z]{2,63}|xn--[a-z0-9-]{2,59})$"
)
URL_IN_TEXT_RE = re.compile(r"(?i)\b(?:https?://|www\.)[^\s<>\"'()\[\]{}]+")
_SCHEME_RE = re.compile(r"^([a-z][a-z0-9+.-]*):", re.IGNORECASE)
_SENSITIVE_PARAMS = {
    "token",
    "access_token",
    "session",
    "sessionid",
    "password",
    "passwd",
    "otp",
    "key",
    "apikey",
    "api_key",
    "email",
    "auth",
    "signature",
}


class InvalidInput(ValueError):
    """Raised for malformed or unsupported user input."""


@dataclass(frozen=True)
class URLInfo:
    original: str
    url: str
    scheme: str
    host: str  # ASCII/IDNA form
    unicode_host: str
    port: int
    path: str
    query: str
    is_ip_literal: bool
    had_credentials: bool
    port_allowed: bool

    @property
    def base_url(self) -> str:
        return urlunsplit((self.scheme, self.netloc, self.path, self.query, ""))

    @property
    def netloc(self) -> str:
        host = f"[{self.host}]" if ":" in self.host else self.host
        default = 443 if self.scheme == "https" else 80
        return host if self.port == default else f"{host}:{self.port}"

    @property
    def display(self) -> str:
        return redact_url_for_display(self.base_url)


def detect_input_type(raw: str) -> str:
    text = raw.strip()
    if not text:
        raise InvalidInput("Input is empty.")
    lowered = text.lower()
    if lowered.startswith(("http://", "https://")):
        return "url"
    if re.fullmatch(r"[^\s/]+\.[a-z]{2,}(?:/\S*)?", lowered) and " " not in text:
        return "url"
    if "\n" in text or len(text) > 280:
        return "message"
    if text.count(" ") >= 4:
        return "message"
    return "url"


def _idna_encode(host: str) -> str:
    try:
        return host.encode("idna").decode("ascii").lower().rstrip(".")
    except UnicodeError as exc:
        raise InvalidInput("Hostname cannot be encoded as IDN.") from exc


def _decode_unicode_host(host: str) -> str:
    if not host.startswith("xn--") and "xn--" not in host:
        return host
    try:
        return host.encode("ascii").decode("idna")
    except UnicodeError:
        return host


def redact_url_for_display(url: str, limit: int = 300) -> str:
    """Mask sensitive-looking query values in anything shown or logged."""
    try:
        parts = urlsplit(url)
    except ValueError:
        return url[:limit]
    if parts.query:
        pairs = []
        for pair in parts.query.split("&"):
            key, sep, _value = pair.partition("=")
            if sep and key.lower() in _SENSITIVE_PARAMS:
                pairs.append(f"{key}=[redacted]")
            elif not sep:
                pairs.append(key)
            else:
                pairs.append(pair)
        query = "&".join(pairs)
    else:
        query = ""
    clean = urlunsplit((parts.scheme, parts.netloc, parts.path, query, ""))
    return clean[:limit]


def normalize_url(raw: str) -> URLInfo:
    text = "".join(ch for ch in raw.strip() if ch >= " " and ch != "\x7f")
    if not text:
        raise InvalidInput("URL is empty.")
    if len(text) > 4096:
        raise InvalidInput("URL is too long (maximum 4096 characters).")

    scheme_match = _SCHEME_RE.match(text)
    if scheme_match and scheme_match.group(1).lower() not in {"http", "https"}:
        raise InvalidInput("Only http:// and https:// URLs can be investigated.")
    if scheme_match and text.lower().startswith(("http:/", "https:/")) and not text.lower().startswith(
        ("http://", "https://")
    ):
        text = text.split(":", 1)[1].lstrip("/")
        scheme_match = None
    if not scheme_match:
        text = "https://" + text

    try:
        parts = urlsplit(text)
    except ValueError as exc:
        raise InvalidInput("The URL could not be parsed.") from exc

    scheme = parts.scheme.lower()
    if scheme not in {"http", "https"}:
        raise InvalidInput("Only http:// and https:// URLs can be investigated.")
    if not parts.hostname:
        raise InvalidInput("The URL does not include a valid hostname.")

    had_credentials = bool(parts.username or parts.password)
    host_raw = parts.hostname.rstrip(".")
    if any(ch.isspace() for ch in host_raw):
        raise InvalidInput("The hostname contains whitespace.")

    try:
        host = _idna_encode(host_raw)
    except UnicodeError as exc:
        raise InvalidInput("The hostname is not valid IDN.") from exc

    if host.startswith("[") and host.endswith("]"):
        host = host[1:-1]
    literal = parse_possibly_obfuscated_ip(host)
    is_ip_literal = literal is not None
    if not is_ip_literal and not DOMAIN_RE.match(host) and host != "localhost":
        raise InvalidInput("The hostname is not a valid public domain name.")
    if host == "localhost":
        raise InvalidInput("Localhost cannot be investigated.")

    try:
        port = parts.port or (443 if scheme == "https" else 80)
    except ValueError as exc:
        raise InvalidInput("The URL contains an invalid port.") from exc
    if not 1 <= port <= 65535:
        raise InvalidInput("The URL contains an invalid port.")
    port_allowed = port in get_settings().allowed_port_set

    path = quote(parts.path or "/", safe="/%:@!$&'()*+,;=-._~")
    query = quote(parts.query, safe="=&%:@!$'()*+,;/?-._~")
    netloc_host = host
    default_port = 443 if scheme == "https" else 80
    netloc = netloc_host if port == default_port else f"{netloc_host}:{port}"
    if ":" in netloc_host:
        netloc = f"[{netloc_host}]" if port == default_port else f"[{netloc_host}]:{port}"

    return URLInfo(
        original=raw.strip(),
        url=urlunsplit((scheme, netloc, path, query, "")),
        scheme=scheme,
        host=host,
        unicode_host=_decode_unicode_host(host_raw) if is_ip_literal is False else host,
        port=port,
        path=path,
        query=query,
        is_ip_literal=is_ip_literal,
        had_credentials=had_credentials,
        port_allowed=port_allowed,
    )


def extract_urls(text: str, limit: int = 10) -> list[str]:
    found: list[str] = []
    for match in URL_IN_TEXT_RE.finditer(text):
        candidate = match.group(0).rstrip(".,;:!?)]}\"'")
        if candidate.lower().startswith("www."):
            candidate = "https://" + candidate
        if candidate not in found:
            found.append(candidate)
        if len(found) >= limit:
            break
    return found


def host_is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host.strip("[]"))
        return True
    except ValueError:
        return parse_possibly_obfuscated_ip(host) is not None


def safe_fetch_ready(info: URLInfo) -> tuple[bool, str]:
    if info.had_credentials:
        return False, "URLs containing embedded credentials are not fetched."
    if not info.port_allowed:
        return False, "Only ports 80 and 443 are fetched."
    try:
        parse_possibly_obfuscated_ip(info.host)
    except UnsafeTargetError:  # pragma: no cover - defensive
        return False, "The hostname could not be validated."
    return True, ""
