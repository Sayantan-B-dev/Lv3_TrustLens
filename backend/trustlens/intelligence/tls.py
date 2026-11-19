"""TLS handshake, certificate-chain and trust analysis.

A valid certificate proves only that the connection is encrypted to a party
the trust store accepts. It does not prove the site is honest. TrustLens says
so explicitly in every TLS result.

Limitations are real: revocation checking is not performed (Python's default
verification does not consult OCSP/CRL), and a CA's internal key-generation
weakness cannot be inferred from one public certificate.
"""

from __future__ import annotations

import socket
import ssl
import time
from datetime import datetime, timezone

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, ed448, rsa
from cryptography.x509.oid import NameOID

from ..security.netguard import resolve_public
from ..security.tlsctx import build_ssl_context

DISTRUSTED_ISSUERS: tuple[tuple[str, str], ...] = (
    ("symantec", "Symantec roots were distrusted by major browsers after repeated misissuance."),
    ("verisign", "Legacy VeriSign roots are distrusted by modern trust stores."),
    ("wosign", "WoSign roots were distrusted after certificate misissuance."),
    ("startcom", "StartCom roots were distrusted after certificate misissuance."),
    ("cnnic", "CNNIC intermediate certificates were distrusted by browsers."),
    ("trustcor", "TrustCor roots were removed from major trust stores."),
    ("e-tugra", "E-Tugra roots were distrusted by major browser programmes in 2024."),
)


def _name_to_text(name: x509.Name) -> str:
    parts = []
    for attribute in name:
        if attribute.oid in (NameOID.COMMON_NAME, NameOID.ORGANIZATION_NAME, NameOID.COUNTRY_NAME):
            parts.append(str(attribute.value))
    return ", ".join(parts)


def _public_key_details(cert: x509.Certificate) -> tuple[str, int | None]:
    key = cert.public_key()
    if isinstance(key, rsa.RSAPublicKey):
        return "RSA", key.key_size
    if isinstance(key, ec.EllipticCurvePublicKey):
        return f"EC ({key.curve.name})", key.key_size
    if isinstance(key, ed25519.Ed25519PublicKey):
        return "Ed25519", 256
    if isinstance(key, ed448.Ed448PublicKey):
        return "Ed448", 456
    return type(key).__name__, None


def _cert_record(cert: x509.Certificate) -> dict:
    not_before = cert.not_valid_before_utc
    not_after = cert.not_valid_after_utc
    now = datetime.now(timezone.utc)
    sans: list[str] = []
    try:
        san_ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        sans = san_ext.value.get_values_for_type(x509.DNSName)
    except x509.ExtensionNotFound:
        pass
    try:
        basic = cert.extensions.get_extension_for_class(x509.BasicConstraints)
        is_ca = bool(basic.value.ca)
    except x509.ExtensionNotFound:
        is_ca = False
    key_type, key_bits = _public_key_details(cert)
    days_remaining = (not_after - now).days
    return {
        "subject": _name_to_text(cert.subject),
        "issuer": _name_to_text(cert.issuer),
        "issuer_organization": next(
            (str(a.value) for a in cert.issuer if a.oid == NameOID.ORGANIZATION_NAME), ""
        ),
        "serial_number": format(cert.serial_number, "x"),
        "not_before": not_before.isoformat(),
        "not_after": not_after.isoformat(),
        "days_remaining": days_remaining,
        "expired": not_after < now,
        "not_yet_valid": not_before > now,
        "san": sans[:50],
        "is_ca": is_ca,
        "signature_algorithm": cert.signature_algorithm_oid._name,
        "public_key_type": key_type,
        "public_key_bits": key_bits,
        "fingerprint_sha256": cert.fingerprint(hashes.SHA256()).hex(),
    }


def hostname_matches(host: str, sans: list[str], common_name: str) -> bool:
    host = host.lower().rstrip(".")
    names = [name.lower().rstrip(".") for name in sans] or [common_name.lower().strip()]
    for name in names:
        if not name:
            continue
        if name == host:
            return True
        if name.startswith("*."):
            suffix = name[1:]
            if host.endswith(suffix) and host.count(".") == name.count("."):
                return True
    return False


def _handshake(host: str, port: int, ip: str, verify: bool) -> dict:
    context = build_ssl_context(verify=verify)

    destination = (ip, port, 0, 0) if ":" in ip else (ip, port)
    family = socket.AF_INET6 if ":" in ip else socket.AF_INET
    with socket.socket(family, socket.SOCK_STREAM) as raw:
        raw.settimeout(6.0)
        raw.connect(destination)
        with context.wrap_socket(raw, server_hostname=host) as tls:
            der = tls.getpeercert(binary_form=True)
            chain_objects = []
            if hasattr(tls, "get_verified_chain") and verify:
                chain_objects = list(tls.get_verified_chain() or [])
            elif hasattr(tls, "get_unverified_chain"):
                chain_objects = list(tls.get_unverified_chain() or [])
            chain_ders: list[bytes] = []
            for item in chain_objects:
                if isinstance(item, bytes):
                    chain_ders.append(item)
                elif hasattr(item, "public_bytes"):
                    chain_ders.append(item.public_bytes(ssl._ssl.Encoding.DER))  # type: ignore[attr-defined]
            return {
                "der": der,
                "chain_ders": chain_ders,
                "protocol": tls.version(),
                "cipher": tls.cipher()[0] if tls.cipher() else None,
                "verified": verify,
            }


def analyse_tls(host: str, port: int = 443, ip: str | None = None) -> dict:
    started = time.monotonic()
    target = resolve_public(host, port)
    address = ip or target.ip
    limitations = [
        "Revocation (OCSP/CRL) is not checked by Python's default TLS verification.",
        "Certificate Transparency data is queried separately and may lag behind issuance.",
        "TrustLens cannot infer a certificate authority's private-key generation weakness from a public certificate.",
        "A valid certificate does not prove that the website is safe or honest.",
    ]
    try:
        handshake = _handshake(host, port, address, verify=True)
        verify_error = None
    except ssl.SSLCertVerificationError as exc:
        verify_error = str(exc.verify_message or exc)
        try:
            handshake = _handshake(host, port, address, verify=False)
        except (ssl.SSLError, OSError, socket.timeout) as inner:
            return {
                "status": "unavailable",
                "severity": "info",
                "summary": f"TLS handshake failed: {inner.__class__.__name__}.",
                "evidence": {"host": host, "error": str(inner)[:200]},
                "findings": [],
                "limitations": limitations,
                "elapsed_ms": int((time.monotonic() - started) * 1000),
            }
    except (ssl.SSLError, OSError, socket.timeout) as exc:
        return {
            "status": "unavailable",
            "severity": "info",
            "summary": f"TLS handshake failed: {exc.__class__.__name__}.",
            "evidence": {"host": host, "error": str(exc)[:200]},
            "findings": [],
            "limitations": limitations,
            "elapsed_ms": int((time.monotonic() - started) * 1000),
        }

    ders = handshake["chain_ders"] or ([handshake["der"]] if handshake["der"] else [])
    certificates: list[dict] = []
    for der in ders:
        try:
            certificates.append(_cert_record(x509.load_der_x509_certificate(der)))
        except ValueError:
            continue
    leaf = certificates[0] if certificates else {}
    trusted = handshake["verified"]
    findings: list[dict] = []

    def add(rule_id, severity, title, summary, impact, remediation, evidence=None):
        findings.append(
            {
                "rule_id": rule_id,
                "severity": severity,
                "title": title,
                "summary": summary,
                "impact": impact,
                "remediation": remediation,
                "evidence": evidence or {},
                "limitations": limitations,
                "authoritative": False,
            }
        )

    if not trusted:
        add(
            "tls.untrusted_chain",
            "high",
            "Certificate chain is not trusted",
            verify_error or "The presented certificate did not validate against the system trust store.",
            "An untrusted certificate allows a third party to impersonate the site or intercept traffic.",
            "Do not enter credentials or payment details. Verify the site through an official channel.",
            {"host": host, "verify_error": verify_error},
        )

    if leaf:
        hostname_ok = hostname_matches(host, leaf.get("san", []), leaf.get("subject", "").split(",")[0])
        if not hostname_ok:
            add(
                "tls.hostname_mismatch",
                "high",
                "Certificate does not match the hostname",
                f"The certificate is not valid for '{host}'.",
                "The encrypted connection may terminate at a different site than the one requested.",
                "Do not trust the page identity; re-check the URL and reach the organisation directly.",
                {"host": host, "san": leaf.get("san", [])},
            )
        if leaf.get("expired"):
            add(
                "tls.expired",
                "high",
                "TLS certificate has expired",
                f"The certificate expired on {leaf.get('not_after')}.",
                "Expired certificates break the trust guarantee and can indicate an abandoned or neglected service.",
                "Avoid submitting personal data; contact the operator through a known channel.",
                {"not_after": leaf.get("not_after")},
            )
        elif leaf.get("days_remaining", 999) <= 14:
            add(
                "tls.expiring_soon",
                "medium",
                "TLS certificate expires soon",
                f"The certificate expires in {leaf.get('days_remaining')} day(s).",
                "Renewal failures commonly produce browser warnings and service disruption.",
                "Inform the site operator if you trust them; avoid sensitive transactions meanwhile.",
                {"not_after": leaf.get("not_after")},
            )
        if leaf.get("not_yet_valid"):
            add(
                "tls.not_yet_valid",
                "high",
                "Certificate is not yet valid",
                "The certificate's validity period starts in the future.",
                "A future-dated certificate indicates a misconfigured or forged trust chain.",
                "Do not trust the connection.",
                {"not_before": leaf.get("not_before")},
            )

        signature = (leaf.get("signature_algorithm") or "").lower()
        if "md5" in signature or "sha1" in signature:
            add(
                "tls.weak_signature",
                "high",
                "Weak certificate signature algorithm",
                f"The certificate uses {leaf.get('signature_algorithm')}, which is obsolete.",
                "Weak signatures make certificate forgery more feasible.",
                "Treat the certificate as untrusted.",
                {"signature_algorithm": leaf.get("signature_algorithm")},
            )
        key_bits = leaf.get("public_key_bits") or 0
        key_type = leaf.get("public_key_type") or ""
        if (key_type == "RSA" and key_bits < 2048) or (key_type.startswith("EC") and key_bits < 224):
            add(
                "tls.weak_key",
                "medium",
                "Certificate key is below current guidance",
                f"The certificate uses a {key_bits}-bit {key_type} key.",
                "Short keys are more exposed to cryptanalytic and brute-force attacks.",
                "The operator should rotate to a modern key size.",
                {"public_key_type": key_type, "public_key_bits": key_bits},
            )

        issuer_text = f"{leaf.get('issuer', '')} {leaf.get('issuer_organization', '')}".lower()
        for name, reason in DISTRUSTED_ISSUERS:
            if name in issuer_text:
                add(
                    "tls.distrusted_ca",
                    "critical",
                    f"Certificate chains to distrusted CA: {name}",
                    reason,
                    "Certificates from a distrusted authority can no longer be relied upon for identity.",
                    "Do not trust the site's identity; validate it through an official channel.",
                    {"issuer": leaf.get("issuer"), "ca": name, "reason": reason},
                )
                break
        if "emudhra" in issuer_text:
            limitations.append(
                "eMudhra is not currently on TrustLens's distrusted-CA list. The 2024 eMudhra reporting concerned a CA key-generation weakness, which cannot be inferred from a public certificate."
            )

    protocol = handshake.get("protocol") or ""
    if protocol in {"TLSv1", "TLSv1.1", "SSLv3", "SSLv2"}:
        add(
            "tls.legacy_protocol",
            "high",
            "Legacy TLS protocol negotiated",
            f"The connection negotiated {protocol}.",
            "Legacy protocol versions have known cryptographic weaknesses.",
            "The operator should disable TLS 1.0/1.1.",
            {"protocol": protocol},
        )

    severity_rank = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
    severity = max((f["severity"] for f in findings), key=lambda s: severity_rank[s], default="info")
    summary = (
        "TLS trust chain is valid, but this does not prove the site is safe."
        if trusted and not findings
        else f"{len(findings)} TLS finding(s) identified."
    )
    return {
        "status": "completed",
        "severity": severity,
        "summary": summary,
        "evidence": {
            "host": host,
            "ip": address,
            "protocol": protocol,
            "cipher": handshake.get("cipher"),
            "trusted": trusted,
            "verify_error": verify_error,
            "leaf": leaf,
            "chain": certificates,
        },
        "findings": findings,
        "limitations": limitations,
        "elapsed_ms": int((time.monotonic() - started) * 1000),
    }
