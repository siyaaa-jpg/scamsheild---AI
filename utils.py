"""Shared helpers for ScamShield AI.

Lightweight, dependency-free text utilities used by the heuristic detector and
the UI layer: text normalization, URL / phone / email / money extraction, and
small formatting helpers. Keeping these pure-Python means the core analysis
always runs — even on a Hugging Face Space with no model token configured.
"""

from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass

# --- Regexes -----------------------------------------------------------------

URL_RE = re.compile(
    r"""(?xi)
    \b(
        (?:https?://|www\.)              # scheme or www
        [^\s<>"')\]]+                     # the rest of the URL
    )
    """,
)

# Bare domains like "sbi-verify.xyz/login" without scheme.
BARE_DOMAIN_RE = re.compile(
    r"(?i)\b((?:[a-z0-9-]+\.)+[a-z]{2,})(/[^\s<>\"')\]]*)?"
)

EMAIL_RE = re.compile(r"(?i)\b[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}\b")

# Indian + generic phone numbers (10-13 digits, optional +, spaces, dashes).
PHONE_RE = re.compile(
    r"(?<!\d)(?:\+?\d{1,3}[\s-]?)?(?:\d[\s-]?){9,12}\d(?!\d)"
)

# Money amounts: ₹, Rs, INR, lakh/crore, or $.
MONEY_RE = re.compile(
    r"(?i)(?:₹|rs\.?|inr|usd|\$)\s?[\d,]+(?:\.\d+)?(?:\s?(?:lakh|lakhs|crore|crores|k|million|cr|l))?"
    r"|[\d,]+(?:\.\d+)?\s?(?:lakh|lakhs|crore|crores)\b"
)

OTP_RE = re.compile(r"(?<!\d)\d{4,8}(?!\d)")


# --- URL shorteners & official domains ---------------------------------------

URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly",
    "cutt.ly", "rb.gy", "rebrand.ly", "shorturl.at", "t.ly", "tiny.cc",
    "bitly.com", "shorte.st", "adf.ly", "v.gd", "lnkd.in", "wa.me", "surl.li",
}

# A non-exhaustive list of brands commonly impersonated in Indian scams, with
# their legitimate domains. Used to spot look-alike / impostor domains.
BRAND_OFFICIAL_DOMAINS = {
    "sbi": {"onlinesbi.sbi", "sbi.co.in", "onlinesbi.com"},
    "hdfc": {"hdfcbank.com"},
    "icici": {"icicibank.com"},
    "axis": {"axisbank.com"},
    "kotak": {"kotak.com"},
    "paytm": {"paytm.com", "paytmbank.com"},
    "phonepe": {"phonepe.com"},
    "gpay": {"pay.google.com"},
    "amazon": {"amazon.in", "amazon.com"},
    "flipkart": {"flipkart.com"},
    "irctc": {"irctc.co.in"},
    "epfo": {"epfindia.gov.in"},
    "income tax": {"incometax.gov.in"},
    "aadhaar": {"uidai.gov.in"},
    "uidai": {"uidai.gov.in"},
    "fedex": {"fedex.com"},
    "dhl": {"dhl.com"},
    "bluedart": {"bluedart.com"},
    "indiapost": {"indiapost.gov.in"},
    "netflix": {"netflix.com"},
}

SUSPICIOUS_TLDS = {
    "xyz", "top", "club", "online", "site", "info", "buzz", "click", "link",
    "live", "icu", "cyou", "rest", "fit", "shop", "monster", "work", "country",
    "loan", "win", "review", "gq", "ml", "cf", "tk", "ga",
}


@dataclass
class ExtractedEntities:
    urls: list[str]
    domains: list[str]
    emails: list[str]
    phones: list[str]
    amounts: list[str]


def normalize_text(text: str) -> str:
    """Unicode-normalize and collapse whitespace without losing meaning."""
    if not text:
        return ""
    text = unicodedata.normalize("NFKC", text)
    text = text.replace("\u200b", "").replace("\ufeff", "")
    text = re.sub(r"[ \t]+", " ", text)
    text = re.sub(r"\n{3,}", "\n\n", text)
    return text.strip()


def _registered_domain(host: str) -> str:
    """Best-effort eTLD+1 (handles common two-part TLDs like co.in)."""
    host = host.lower().strip(".")
    parts = host.split(".")
    if len(parts) <= 2:
        return host
    two_part = {"co", "gov", "net", "org", "ac", "edu", "nic", "res", "gen", "ind"}
    if parts[-2] in two_part:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def get_domain(url: str) -> str:
    """Extract a lowercase host from a URL or bare domain string."""
    u = url.strip()
    u = re.sub(r"(?i)^https?://", "", u)
    u = re.sub(r"(?i)^www\.", "", u)
    u = u.split("/")[0].split("?")[0].split("#")[0]
    u = u.split("@")[-1]  # strip userinfo
    u = u.split(":")[0]   # strip port
    return u.lower()


def extract_entities(text: str) -> ExtractedEntities:
    """Pull URLs, domains, emails, phone numbers and money amounts from text."""
    urls = [m.group(1) for m in URL_RE.finditer(text)]
    scheme_domains = {get_domain(u) for u in urls}

    # Capture bare domains (no scheme) that look like links, excluding emails.
    emails = EMAIL_RE.findall(text)
    email_domains = {get_domain(e.split("@")[-1]) for e in emails}

    bare = []
    for m in BARE_DOMAIN_RE.finditer(text):
        full = m.group(0)
        dom = get_domain(full)
        if dom in email_domains or dom in scheme_domains:
            continue  # already captured via an email or a scheme URL
        # Only treat as a link if it has a path or a known/suspicious TLD shape.
        tld = dom.split(".")[-1] if "." in dom else ""
        if (m.group(2) or tld) and not full.lower().startswith(("http", "www")):
            bare.append(full)

    all_url_strings = urls + bare
    domains = []
    seen = set()
    for u in all_url_strings:
        d = get_domain(u)
        if d and d not in seen:
            seen.add(d)
            domains.append(d)

    phones = [p.strip() for p in PHONE_RE.findall(text) if len(re.sub(r"\D", "", p)) >= 10]
    amounts = [m.group(0).strip() for m in MONEY_RE.finditer(text)]

    return ExtractedEntities(
        urls=all_url_strings,
        domains=domains,
        emails=emails,
        phones=phones,
        amounts=amounts,
    )


def looks_like_ip(host: str) -> bool:
    return bool(re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", host))


def clamp(value: float, low: float = 0, high: float = 100) -> float:
    return max(low, min(high, value))


def highlight_phrases(text: str, phrases: list[str]) -> str:
    """Return HTML with each phrase wrapped in a <mark> tag (case-insensitive).

    Longer phrases are highlighted first to avoid partial-overlap clobbering.
    The output is HTML-escaped before marking so it is safe to render.
    """
    import html

    escaped = html.escape(text)
    unique = sorted({p for p in phrases if p and p.strip()}, key=len, reverse=True)
    for phrase in unique:
        esc_phrase = html.escape(phrase)
        pattern = re.compile(re.escape(esc_phrase), re.IGNORECASE)
        escaped = pattern.sub(
            lambda m: f"<mark class='flag'>{m.group(0)}</mark>", escaped
        )
    return escaped.replace("\n", "<br>")
