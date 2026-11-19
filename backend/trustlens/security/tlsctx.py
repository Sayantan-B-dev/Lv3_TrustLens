"""TLS contexts with a portable public root bundle.

Using certifi's Mozilla-derived roots avoids platform trust-store gaps (common
on Windows and in containers) while keeping full hostname and chain checks.
Certificate *trust* findings are still reported honestly when verification
fails.
"""

from __future__ import annotations

import ssl

try:  # certifi ships with httpx, but keep the fallback for minimal installs
    import certifi
except ModuleNotFoundError:  # pragma: no cover
    certifi = None


def build_ssl_context(verify: bool = True, *, minimum_tls: bool = True) -> ssl.SSLContext:
    if certifi is not None:
        context = ssl.create_default_context(cafile=certifi.where())
    else:  # pragma: no cover
        context = ssl.create_default_context()
    if minimum_tls:
        context.minimum_version = ssl.TLSVersion.TLSv1_2
    if not verify:
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
    return context
