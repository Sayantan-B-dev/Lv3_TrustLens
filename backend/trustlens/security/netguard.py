"""SSRF defence primitives.

TrustLens is a URL inspector, which makes it a potential proxy into private
networks. Every outbound connection goes through these checks *at connection
time* — not just when the URL is first parsed.
"""

from __future__ import annotations

import ipaddress
import re
import socket
from dataclasses import dataclass

from ..config import get_settings

IPAddress = ipaddress.IPv4Address | ipaddress.IPv6Address
IPNetwork = ipaddress.IPv4Network | ipaddress.IPv6Network

# Explicitly special-use / non-public ranges. ``is_global`` already excludes
# most of these; the list is defence in depth and documents intent.
_BLOCKED_NETWORKS: tuple[IPNetwork, ...] = tuple(
    ipaddress.ip_network(cidr)
    for cidr in (
        "0.0.0.0/8",
        "10.0.0.0/8",
        "100.64.0.0/10",
        "127.0.0.0/8",
        "169.254.0.0/16",
        "172.16.0.0/12",
        "192.0.0.0/24",
        "192.0.2.0/24",
        "192.88.99.0/24",
        "192.168.0.0/16",
        "198.18.0.0/15",
        "198.51.100.0/24",
        "203.0.113.0/24",
        "224.0.0.0/4",
        "240.0.0.0/4",
        "255.255.255.255/32",
        "::/128",
        "::1/128",
        "::ffff:0:0/96",
        "64:ff9b::/96",
        "100::/64",
        "2001:db8::/32",
        "fc00::/7",
        "fe80::/10",
        "ff00::/8",
    )
)

# Cloud metadata services (all are already non-public, listed for clarity).
METADATA_ADDRESSES = frozenset(
    {
        ipaddress.ip_address("169.254.169.254"),
        ipaddress.ip_address("169.254.170.2"),
        ipaddress.ip_address("100.100.100.200"),
        ipaddress.ip_address("192.0.0.192"),
        ipaddress.ip_address("fd00:ec2::254"),
    }
)


class UnsafeTargetError(ValueError):
    """Raised when a target is malformed or resolves to a non-public address."""


@dataclass(frozen=True)
class ResolvedTarget:
    host: str
    family: int
    ip: str
    sockaddr: tuple
    all_ips: tuple[str, ...]


def _settings_allow_private() -> bool:
    return get_settings().allow_private_targets_for_tests


def classify_ip(raw: str | IPAddress) -> IPAddress:
    if isinstance(raw, (ipaddress.IPv4Address, ipaddress.IPv6Address)):
        return raw
    value = str(raw).strip().strip("[]")
    try:
        return ipaddress.ip_address(value)
    except ValueError as exc:
        raise UnsafeTargetError("not an IP address") from exc


def is_public_ip(value: str | IPAddress) -> bool:
    try:
        address = classify_ip(value)
    except UnsafeTargetError:
        return False
    if address in METADATA_ADDRESSES:
        return False
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped:
        return is_public_ip(address.ipv4_mapped)
    if getattr(address, "is_global", False) is False:
        return False
    return not any(address in network for network in _BLOCKED_NETWORKS)


def parse_possibly_obfuscated_ip(host: str) -> IPAddress | None:
    """Catch decimal/octal/hex IPv4 encodings some resolvers accept.

    ``http://2130706433/``, ``http://0177.0.0.1/`` and ``http://0x7f000001/``
    must never be treated as harmless hostnames.
    """
    candidate = host.strip().strip("[]").lower()
    if not candidate:
        return None
    try:
        return ipaddress.ip_address(candidate)
    except ValueError:
        pass

    labels = candidate.split(".")
    if all(re.fullmatch(r"0x[0-9a-f]+|0[0-7]+|[0-9]+", label) for label in labels):

        def to_int(label: str) -> int:
            if label.startswith("0x"):
                return int(label, 16)
            if len(label) > 1 and label.startswith("0"):
                return int(label, 8)
            return int(label, 10)

        try:
            numbers = [to_int(label) for label in labels]
        except ValueError:
            return None
        if len(numbers) == 1 and numbers[0] < 2**32:
            return ipaddress.ip_address(numbers[0])
        if len(numbers) == 4 and all(0 <= n <= 255 for n in numbers):
            return ipaddress.ip_address(".".join(str(n) for n in numbers))
        return None

    # A single long numeric label that is not a valid integer IP is still a
    # numeric host, which no legitimate public site uses in practice.
    if re.fullmatch(r"[0-9]+", candidate) and len(candidate) >= 8:
        return ipaddress.ip_address(0)
    return None


def resolve_public(host: str, port: int) -> ResolvedTarget:
    """Resolve *host* and require every returned address to be public."""
    host = host.strip().rstrip(".")
    if not host:
        raise UnsafeTargetError("empty host")

    literal = parse_possibly_obfuscated_ip(host)
    if literal is not None:
        if not is_public_ip(literal) and not _settings_allow_private():
            raise UnsafeTargetError("target resolves to a non-public address")
        family = socket.AF_INET6 if literal.version == 6 else socket.AF_INET
        sockaddr = (str(literal), port, 0, 0) if family == socket.AF_INET6 else (str(literal), port)
        return ResolvedTarget(host, family, str(literal), sockaddr, (str(literal),))

    try:
        infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise UnsafeTargetError(f"DNS resolution failed for {host}") from exc

    if not infos:
        raise UnsafeTargetError(f"no DNS records for {host}")

    addresses: list[ipaddress.IPv4Address | ipaddress.IPv6Address] = []
    chosen: tuple[int, tuple] | None = None
    for family, _type, _proto, _canon, sockaddr in infos:
        ip_text = sockaddr[0]
        try:
            address = ipaddress.ip_address(ip_text)
        except ValueError as exc:  # pragma: no cover - OS should always be valid
            raise UnsafeTargetError("resolver returned an invalid address") from exc
        addresses.append(address)
        if chosen is None:
            chosen = (family, sockaddr)

    # DNS rebinding protection: if ANY answer is private, refuse the host.
    if not _settings_allow_private():
        for address in addresses:
            if not is_public_ip(address):
                raise UnsafeTargetError(
                    f"DNS for {host} includes a non-public address ({address}); refusing"
                )
    if chosen is None:  # pragma: no cover
        raise UnsafeTargetError("no usable address")

    unique = tuple(dict.fromkeys(str(a) for a in addresses))
    return ResolvedTarget(host, chosen[0], str(addresses[0]), chosen[1], unique)


def assert_connected_peer_is_public(sock: socket.socket) -> None:
    """Verify the *actual* peer after connect (defeats rebinding races)."""
    if _settings_allow_private():
        return
    peer = sock.getpeername()[0]
    if not is_public_ip(peer):
        raise UnsafeTargetError("connected peer is a non-public address")
