"""Phishing-domain heuristics: IDN/homograph, typosquatting, impersonation.

Every heuristic is explainable and paired with explicit false-positive
limitations. A similarity match is a prompt to investigate, not proof.
"""

from __future__ import annotations

import re
import unicodedata

from .normalize import URLInfo

# Canonical domains for well-known brands used in similarity checks.
BRAND_DOMAINS: dict[str, tuple[str, ...]] = {
    "google": ("google.com", "google.co.in", "google.co.uk", "gmail.com", "googleusercontent.com"),
    "microsoft": ("microsoft.com", "live.com", "outlook.com", "office.com", "office365.com"),
    "apple": ("apple.com", "icloud.com"),
    "amazon": ("amazon.com", "amazon.in", "amazon.co.uk", "aws.amazon.com"),
    "paypal": ("paypal.com", "paypal.me"),
    "facebook": ("facebook.com", "fb.com", "messenger.com"),
    "instagram": ("instagram.com",),
    "whatsapp": ("whatsapp.com",),
    "netflix": ("netflix.com",),
    "linkedin": ("linkedin.com",),
    "dropbox": ("dropbox.com",),
    "adobe": ("adobe.com",),
    "coinbase": ("coinbase.com",),
    "binance": ("binance.com",),
    "metamask": ("metamask.io",),
    "telegram": ("telegram.org", "t.me"),
    "steam": ("steampowered.com", "steamcommunity.com"),
    "dhl": ("dhl.com",),
    "fedex": ("fedex.com",),
    "ups": ("ups.com",),
    "usps": ("usps.com",),
    "visa": ("visa.com",),
    "mastercard": ("mastercard.com",),
    "hdfc": ("hdfcbank.com",),
    "sbi": ("onlinesbi.sbi", "sbi.co.in"),
    "icici": ("icicibank.com",),
    "axis": ("axisbank.com",),
    "kotak": ("kotak.com",),
    "chase": ("chase.com",),
    "wellsfargo": ("wellsfargo.com",),
    "bankofamerica": ("bankofamerica.com",),
    "irs": ("irs.gov",),
    "govuk": ("gov.uk",),
    "aadhaar": ("uidai.gov.in",),
}

SUSPICIOUS_KEYWORDS = (
    "login",
    "signin",
    "verify",
    "verification",
    "secure",
    "security",
    "account",
    "update",
    "wallet",
    "kyc",
    "otp",
    "gift",
    "prize",
    "claim",
    "refund",
    "support",
    "billing",
    "confirm",
    "unlock",
    "recovery",
    "invoice",
    "payment",
)

SHORTENER_DOMAINS = {
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "goo.gl",
    "ow.ly",
    "is.gd",
    "buff.ly",
    "cutt.ly",
    "rb.gy",
    "shorturl.at",
    "rebrand.ly",
    "tiny.cc",
    "s.id",
    "t.ly",
    "clck.ru",
    "v.gd",
    "shorte.st",
}

SUSPICIOUS_TLDS = {
    "tk",
    "ml",
    "ga",
    "cf",
    "gq",
    "work",
    "click",
    "link",
    "rest",
    "buzz",
    "cam",
    "monster",
    "top",
    "zip",
    "mov",
}

CONFUSABLES = str.maketrans(
    {
        "а": "a",
        "е": "e",
        "о": "o",
        "р": "p",
        "с": "c",
        "у": "y",
        "х": "x",
        "і": "i",
        "ј": "j",
        "ѕ": "s",
        "ԁ": "d",
        "ɡ": "g",
        "ο": "o",
        "α": "a",
        "ε": "e",
        "ι": "i",
        "κ": "k",
        "ν": "v",
        "ρ": "p",
        "τ": "t",
        "υ": "u",
        "χ": "x",
        "ӏ": "l",
        "ı": "i",
        "ℓ": "l",
    }
)

_MULTI_PART_SUFFIXES = {
    "co.uk",
    "org.uk",
    "ac.uk",
    "gov.uk",
    "co.in",
    "net.in",
    "org.in",
    "ac.in",
    "gov.in",
    "co.jp",
    "co.kr",
    "com.au",
    "net.au",
    "org.au",
    "com.br",
    "com.mx",
    "com.sg",
    "com.hk",
    "com.pk",
    "co.za",
    "com.ng",
    "com.tr",
}


def registrable_domain(host: str) -> str:
    host = host.lower().rstrip(".")
    labels = host.split(".")
    if len(labels) <= 2:
        return host
    last_two = ".".join(labels[-2:])
    if last_two in _MULTI_PART_SUFFIXES and len(labels) >= 3:
        return ".".join(labels[-3:])
    return last_two


def _levenshtein(left: str, right: str) -> int:
    if left == right:
        return 0
    if not left:
        return len(right)
    if not right:
        return len(left)
    previous = list(range(len(right) + 1))
    for i, lchar in enumerate(left, start=1):
        current = [i]
        for j, rchar in enumerate(right, start=1):
            cost = 0 if lchar == rchar else 1
            current.append(min(current[j - 1] + 1, previous[j] + 1, previous[j - 1] + cost))
        previous = current
    return previous[-1]


def _script_of(char: str) -> str:
    try:
        return unicodedata.name(char).split(" ")[0]
    except ValueError:
        return "UNKNOWN"


def _finding(rule_id: str, severity: str, title: str, summary: str, evidence: dict, remediation: str, impact: str, limitations: list[str]) -> dict:
    return {
        "rule_id": rule_id,
        "severity": severity,
        "title": title,
        "summary": summary,
        "evidence": evidence,
        "impact": impact,
        "remediation": remediation,
        "limitations": limitations,
        "authoritative": False,
    }


def analyse_domain(info: URLInfo) -> dict:
    findings: list[dict] = []
    facts: dict = {
        "host": info.host,
        "unicode_host": info.unicode_host,
        "registrable_domain": registrable_domain(info.host),
        "is_ip_literal": info.is_ip_literal,
        "is_shortener": registrable_domain(info.host) in SHORTENER_DOMAINS,
        "suspicious_keywords": [],
        "brand_matches": [],
        "known_brand_domain": False,
    }
    label_host = info.unicode_host.lower()

    if info.had_credentials:
        findings.append(
            _finding(
                "url.embedded_credentials",
                "high",
                "URL embeds credentials",
                "The URL contains a username or password before the hostname, a technique used to disguise the real destination.",
                {"url": info.display},
                "Do not open this link. Navigate to the organisation's site directly.",
                "Users may believe they are visiting a trusted site while the browser connects elsewhere.",
                ["TrustLens did not fetch this URL because embedded credentials are rejected."],
            )
        )

    if info.is_ip_literal:
        findings.append(
            _finding(
                "url.ip_literal_host",
                "medium",
                "IP address used instead of a domain",
                "The link points to a raw IP address, so there is no domain or certificate identity to inspect.",
                {"host": info.host},
                "Treat with caution; verify who operates the address before sharing information.",
                "IP-hosted pages bypass domain reputation and are common in short-lived phishing kits.",
                ["Some legitimate services expose IP-only endpoints; this is not proof of malice."],
            )
        )

    if not info.port_allowed:
        findings.append(
            _finding(
                "url.unusual_port",
                "medium",
                "Non-standard network port",
                f"The URL explicitly uses port {info.port}; TrustLens only fetches 80/443.",
                {"port": info.port},
                "Avoid entering credentials on services served from unusual ports.",
                "Alternate ports can bypass network monitoring that only inspects normal web traffic.",
                ["TrustLens did not connect to this port."],
            )
        )

    # --- IDN / homograph -------------------------------------------------
    has_non_ascii = any(ord(ch) > 127 for ch in info.unicode_host)
    has_punycode = "xn--" in info.host
    if has_non_ascii:
        scripts = {_script_of(ch) for ch in info.unicode_host if ch.isalpha()}
        ascii_equivalent = info.unicode_host.translate(CONFUSABLES)
        facts["ascii_confusable_equivalent"] = ascii_equivalent
        brand_hit = None
        for brand in BRAND_DOMAINS:
            if brand in ascii_equivalent.lower().replace("-", ""):
                brand_hit = brand
                break
        severity = "high" if brand_hit or len(scripts) > 1 else "medium"
        if brand_hit:
            facts["brand_matches"].append(
                {"brand": brand_hit, "technique": "homograph", "normalised_ascii": ascii_equivalent}
            )
        findings.append(
            _finding(
                "domain.idn_homograph",
                severity,
                "Internationalised domain needs scrutiny",
                "The hostname contains non-ASCII characters that can visually resemble Latin letters."
                + (f" After normalising lookalike characters it contains the brand '{brand_hit}'." if brand_hit else ""),
                {
                    "unicode_host": info.unicode_host,
                    "punycode_host": info.host,
                    "scripts": sorted(scripts),
                    "normalised_ascii": ascii_equivalent,
                },
                "Do not trust the visual spelling. Verify the punycode form and reach the organisation through a known address.",
                "Homograph domains let attackers register visually identical names for impersonation.",
                ["Not every IDN is malicious; legitimate sites use internationalised domains."],
            )
        )
    elif has_punycode:
        findings.append(
            _finding(
                "domain.punycode_unverified",
                "low",
                "Punycode hostname",
                "The hostname uses punycode but was supplied in ASCII form, so the visible spelling may differ from what the browser displays.",
                {"punycode_host": info.host, "decoded": info.unicode_host},
                "Check the browser's displayed domain carefully before entering data.",
                "Punycode is normal for international domains but is also used by lookalike domains.",
                ["Punycode alone is not evidence of malicious intent."],
            )
        )

    # --- typosquatting ---------------------------------------------------
    sld = facts["registrable_domain"].split(".")[0]
    compact_sld = sld.replace("-", "")
    for brand, canonical in BRAND_DOMAINS.items():
        if facts["registrable_domain"] in canonical:
            facts["known_brand_domain"] = True
            continue
        distance = _levenshtein(compact_sld, brand)
        if len(brand) >= 5 and 1 <= distance <= 2:
            findings.append(
                _finding(
                    "domain.typosquatting",
                    "medium",
                    f"Lookalike spelling of '{brand}'",
                    f"The registrable domain '{facts['registrable_domain']}' differs from '{brand}' by {distance} character(s).",
                    {"host": info.host, "brand": brand, "edit_distance": distance},
                    "Reach the organisation by typing its known address rather than following this link.",
                    "Typosquatted domains intercept users who mistype or misread an address.",
                    ["Short or generic names can be within two edits of a brand by coincidence."],
                )
            )
            facts["brand_matches"].append(
                {"brand": brand, "technique": "typosquatting", "distance": distance}
            )
            break

    # --- brand impersonation --------------------------------------------
    if not facts["known_brand_domain"]:
        host_tokens = re.split(r"[.\-]", label_host)
        for brand, canonical in BRAND_DOMAINS.items():
            if brand in host_tokens or brand in compact_sld:
                if facts["registrable_domain"] in canonical:
                    continue
                has_keyword = any(keyword in info.url.lower() for keyword in SUSPICIOUS_KEYWORDS)
                hyphenated = "-" in sld
                severity = "high" if has_keyword or hyphenated else "medium"
                findings.append(
                    _finding(
                        "domain.brand_impersonation",
                        severity,
                        f"Brand name '{brand}' on an unrelated domain",
                        f"The hostname mentions '{brand}', but the registrable domain '{facts['registrable_domain']}' is not operated by that brand.",
                        {
                            "host": info.host,
                            "brand": brand,
                            "canonical_domains": list(canonical),
                            "registrable_domain": facts["registrable_domain"],
                        },
                        "Verify the domain against the organisation's official website before sharing credentials.",
                        "Attackers place trusted brand names in subdomains or hyphenated domains to appear legitimate.",
                        ["Brands use many domains; confirm through official channels before concluding impersonation."],
                    )
                )
                facts["brand_matches"].append(
                    {"brand": brand, "technique": "brand-token", "registrable_domain": facts["registrable_domain"]}
                )
                break

    # --- shortener --------------------------------------------------------
    if facts["is_shortener"]:
        findings.append(
            _finding(
                "url.shortener",
                "medium",
                "Link-shortening service",
                "The URL uses a shortening service, which hides the final destination until it is followed.",
                {"host": info.host},
                "Expand the link with a trusted tool and inspect the destination before opening it.",
                "Shorteners are routinely used to disguise phishing destinations.",
                ["Shorteners are also widely used for legitimate tracking and sharing."],
            )
        )

    # --- keywords, structure ---------------------------------------------
    haystack = f"{info.path} {info.query}".lower()
    keywords = sorted({word for word in SUSPICIOUS_KEYWORDS if word in haystack})
    if keywords:
        facts["suspicious_keywords"] = keywords
        findings.append(
            _finding(
                "url.suspicious_keywords",
                "low",
                "Sensitive wording in the URL",
                "The path or query contains wording commonly used to pressure users into logging in or paying.",
                {"keywords": keywords},
                "Treat login or payment prompts reached through this link with suspicion.",
                "Credential-harvesting pages frequently reuse these keywords in their URLs.",
                ["Legitimate login and billing pages also use these words."],
            )
        )

    host_labels = info.host.split(".")
    if len(host_labels) >= 5:
        findings.append(
            _finding(
                "url.excessive_subdomains",
                "low",
                "Deep subdomain nesting",
                f"The hostname has {len(host_labels)} labels, which makes the true registrable domain harder to see.",
                {"host": info.host, "labels": len(host_labels)},
                "Read the hostname from the right to find the real registrable domain.",
                "Long subdomain chains push the real domain out of view on small screens.",
                ["Enterprise services legitimately use deeply nested subdomains."],
            )
        )

    tld = info.host.rsplit(".", 1)[-1]
    if tld in SUSPICIOUS_TLDS:
        findings.append(
            _finding(
                "url.high_abuse_tld",
                "low",
                "Frequently abused top-level domain",
                f"'.{tld}' has a comparatively high rate of abuse reports.",
                {"tld": tld},
                "Apply extra scrutiny, especially if the page requests credentials or payment.",
                "Some TLDs offer cheap or free registration, which attracts abuse.",
                ["Many legitimate sites use these TLDs; this is a weak signal on its own."],
            )
        )

    return {"findings": findings, "facts": facts}
