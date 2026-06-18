"""Rule-based scam-detection engine for ScamShield AI.

This module is the deterministic backbone of the product. It scores a message
for fraud risk using transparent, explainable heuristics:

- Suspicious-URL analysis (shorteners, look-alike brand domains, raw IPs,
  punycode, risky TLDs, credential-in-URL tricks).
- Weighted keyword/pattern signals across many Indian scam playbooks
  (OTP/UPI, KYC, lottery, job, loan, courier, electricity, digital arrest,
  investment/crypto, refund, advance-fee, etc.) in English, Hindi (Devanagari)
  and Hinglish.
- Urgency / pressure tactics, money/OTP requests, and known scam combos.

It runs with NO external dependencies or API token, so the deployed demo always
produces a useful verdict. The LLM layer (see ``llm.py``) only *enriches* this.
"""

from __future__ import annotations

import re
from collections import defaultdict
from dataclasses import dataclass, field

from utils import (
    BRAND_OFFICIAL_DOMAINS,
    SUSPICIOUS_TLDS,
    URL_SHORTENERS,
    ExtractedEntities,
    clamp,
    extract_entities,
    get_domain,
    looks_like_ip,
    normalize_text,
)

# Verdict thresholds (tuned so unambiguous scams land in SCAM while genuine
# messages stay SAFE; borderline single-signal cases become SUSPICIOUS).
SCAM_THRESHOLD = 50
SUSPICIOUS_THRESHOLD = 22

# Diminishing returns for repeated signals within the same category.
_DAMP = [1.0, 0.7, 0.5, 0.35, 0.25]
_DAMP_TAIL = 0.2

# Categories that are "amplifiers" rather than scam families of their own.
_GENERIC_CATEGORIES = {"urgency", "contact"}


@dataclass
class RedFlag:
    phrase: str          # the exact text snippet that triggered the flag
    reason: str          # human-readable explanation of why it is suspicious
    category: str        # signal family (used for scam-type classification)
    weight: int          # contribution to the risk score


@dataclass
class DetectionResult:
    risk_score: int
    verdict: str                       # "SCAM" | "SUSPICIOUS" | "LIKELY SAFE"
    scam_type: str
    red_flags: list[RedFlag]
    entities: ExtractedEntities
    rationale: list[str] = field(default_factory=list)

    @property
    def flagged_phrases(self) -> list[str]:
        return [f.phrase for f in self.red_flags]


# --- Signal definitions -------------------------------------------------------
# Each entry: (regex, weight, category, reason). Patterns are case-insensitive
# and cover English / Hindi (Devanagari) / Hinglish (romanized) variants.

KEYWORD_SIGNALS: list[tuple[str, int, str, str]] = [
    # --- OTP / UPI / banking credential theft -------------------------------
    (r"\b(share|send|tell|enter|provide|forward)\s+(me\s+)?(your\s+|the\s+)?(otp|pin|cvv|password|code)\b"
     r"|\b(otp|pin|cvv|password)\s+(batao|bataye|bhejo|do)\b", 28, "otp_upi",
     "Directly asks you to share a secret OTP/PIN/CVV — no genuine entity ever does this."),
    (r"\b(otp|one[\s-]?time[\s-]?password|o\.?t\.?p\.?)\b|ओटीपी|वन\s*टाइम\s*पासवर्ड", 16, "otp_upi",
     "Mentions an OTP — banks never ask you to share OTPs."),
    (r"\b(cvv|atm[\s-]?pin|debit[\s-]?card|credit[\s-]?card|card[\s-]?number|expiry\s+date)\b", 16,
     "otp_upi", "References card/PIN/CVV details — a classic credential-theft tactic."),
    (r"\b(upi[\s-]?pin|upi[\s-]?id|enter\s+upi|upi\s+collect\s+request)\b", 14, "otp_upi",
     "Mentions UPI credentials/collect requests, commonly abused in payment fraud."),
    (r"\b(\d\s*digit\s*(code|otp|pin)|verification\s+code|security\s+code|one\s+time\s+code)\b", 14,
     "otp_upi", "Asks for a verification/one-time code used to take over your account."),
    # --- KYC / account-block phishing ---------------------------------------
    (r"\b(kyc|k\.?y\.?c\.?|re[\s-]?kyc|update\s+kyc|kyc\s+update|kyc\s+verif\w*)\b|केवाईसी", 16, "kyc",
     "KYC-update lure — a very common bank/wallet impersonation scam."),
    (r"\b(account|a/c|khata)\s+(will\s+be\s+)?(block|suspend|freeze|deactivat|band|hold)\w*"
     r"|खाता\s*(ब्लॉक|बंद|फ्रीज|होल्ड)", 16, "kyc",
     "Threatens that your account will be blocked/suspended to create panic."),
    (r"\b(suspend\w*|suspension|deactivat\w*|blocked\s+today|will\s+be\s+blocked)\b", 11, "kyc",
     "Threatens suspension/deactivation/blocking to pressure you."),
    (r"\b(pan\s*card|aadhaar|aadhar)\b.{0,40}\b(update|verify|link|expire|block)\b|पैन\s*कार्ड|आधार", 13,
     "kyc", "Pressures you to 'update/verify' PAN/Aadhaar — identity-theft bait."),
    # --- Lottery / prize / reward -------------------------------------------
    (r"\b(congratulations|congrats|you\s+have\s+won|you\s*'?re\s+a\s+winner|lucky\s+winner"
     r"|jackpot|lottery|lucky\s+draw|won\s+(rs|₹|inr|\d))\b"
     r"|बधाई|जीत[ेा]|लॉटरी|लकी\s*ड्रॉ|इनाम|पुरस्कार", 18, "lottery",
     "Announces a prize/lottery win you never entered — classic advance-fee bait."),
    (r"\b(claim\s+your\s+(prize|reward|gift|cashback)|gift\s+card|free\s+recharge|free\s+gift|kbc)\b", 13,
     "lottery", "Promises a free prize/reward to bait a click."),
    # --- Advance-fee / upfront payment (its own family on purpose) ----------
    (r"\b(registration\s+fee|joining\s+fee|security\s+deposit|processing\s+fee|clearance\s+fee"
     r"|customs\s+(duty|fee)|service\s+charge|refundable\s+deposit)\b"
     r"|रजिस्ट्रेशन\s*फीस|शुल्क\s*भेज|फीस\s*भेज|पैसे\s*भेज", 18, "advance_fee",
     "Demands an upfront fee/deposit to release a job, prize, parcel or loan — a hallmark of fraud."),
    # --- Fake job / task ----------------------------------------------------
    (r"\b(work\s+from\s+home|part[\s-]?time\s+job|earn\s+(money|daily|upto|₹|rs)"
     r"|daily\s+income|job\s+offer|hiring\s+now)\b|naukri|ghar\s+baithe|घर\s*बैठे|कमाओ", 14,
     "job", "Too-good-to-be-true work-from-home / easy-money job offer."),
    # --- Loan ----------------------------------------------------------------
    (r"\b(instant\s+loan|pre[\s-]?approved\s+loan|loan\s+approved|low\s+interest\s+loan"
     r"|personal\s+loan\s+offer)\b|turant\s+loan|तुरंत\s*लोन", 13,
     "loan", "Unsolicited instant-loan offer, often a data-harvesting trap."),
    # --- Courier / parcel / customs -----------------------------------------
    (r"\b(parcel|courier|consignment|shipment|package)\b.{0,60}\b(hold|stuck|seized|pending|on\s+hold"
     r"|clear|deliver|customs|illegal)\b|पार्सल|कूरियर", 15,
     "courier", "Parcel-held / customs-fee scam impersonating delivery firms."),
    (r"\b(fedex|dhl|bluedart|india\s*post|dtdc)\b", 6, "courier",
     "Impersonates a courier brand."),
    # --- Electricity / utility disconnection --------------------------------
    (r"\b(electricity|power|bijli)\b.{0,50}\b(disconnect\w*|cut\s+off|tonight|9[:.]?30"
     r"|bill\s+(was\s+)?not\s+updated|connection\s+will)\b|बिजली.{0,20}(कट|काट|डिस्कनेक्ट)", 18,
     "electricity", "Electricity-disconnection-tonight scam — a trending SMS fraud."),
    # --- Digital arrest / law-enforcement impersonation ---------------------
    (r"\b(digital\s+arrest|cbi|narcotics|ncb|enforcement\s+directorate|customs\s+department"
     r"|police\s+case|fir\s+(against|registered|lodged)|arrest\s+warrant|money\s+laundering"
     r"|court\s+notice|cyber\s+cell)\b|डिजिटल\s*अरेस्ट|गिरफ्तार|सीबीआई", 22,
     "digital_arrest", "Law-enforcement impersonation / 'digital arrest' — a high-harm scam."),
    (r"\b(your\s+(number|sim|mobile)\s+will\s+be\s+(disconnect\w*|block\w*)|sim\s+block|trai)\b", 14,
     "digital_arrest", "Threatens SIM/number disconnection to impersonate authorities (TRAI/DoT)."),
    # --- Investment / crypto -------------------------------------------------
    (r"\b(guaranteed\s+returns?|double\s+your\s+money|crypto|bitcoin|trading\s+tips|stock\s+tips"
     r"|investment\s+plan|profit\s+daily|high\s+returns?|sure\s+shot)\b", 15, "investment",
     "Guaranteed-return / crypto-investment lure — classic Ponzi bait."),
    (r"\b(telegram|whatsapp)\b.{0,30}\b(group|task|invest|earn|rating\s+job)\b", 10, "investment",
     "Pushes you into a Telegram/WhatsApp 'earning' or 'task' group."),
    # --- Refund / overpayment ------------------------------------------------
    (r"\b(refund|cashback|reversal|amount\s+credited|tax\s+refund|gst\s+refund|income\s+tax\s+refund)\b",
     9, "refund", "Unexpected refund/cashback lure used to capture bank details."),
    # --- Urgency / pressure (amplifier) -------------------------------------
    (r"\b(urgent\w*|immediately|right\s+now|within\s+\d+\s*(hours?|hrs?|minutes?|mins?)"
     r"|expire?s?\s+(today|soon)|last\s+chance|act\s+now)\b"
     r"|turant|jaldi|abhi|aaj\s+hi|तुरंत|जल्दी|अभी|आज\s*ही|24\s*घंटे", 10,
     "urgency", "Artificial urgency / deadline pressure to stop you thinking."),
    (r"\b(verify\s+now|click\s+(here|below|the\s+link|on\s+the\s+link)|update\s+now|complete\s+now"
     r"|pay\s+now|release\s+your)\b|लिंक\s*पर\s*क्लिक|क्लिक\s*कर", 12,
     "urgency", "Pushes an immediate click/payment on a link."),
    # --- Contact-channel red flags (amplifier) ------------------------------
    (r"\b(call\s+(immediately|now|on|our|the\s+officer)|whatsapp\s+(me|us|on|number)"
     r"|reply\s+(yes|stop)|press\s+\d)\b", 8, "contact",
     "Pushes you to call/WhatsApp an unknown number quickly."),
]

# Brand mention regex built from the impersonation list, for look-alike checks.
_BRAND_MENTION_RE = re.compile(
    r"\b(" + "|".join(re.escape(b) for b in BRAND_OFFICIAL_DOMAINS) + r")\b",
    re.IGNORECASE,
)

CATEGORY_LABELS = {
    "otp_upi": "OTP / UPI / Banking fraud",
    "kyc": "KYC / Account-update phishing",
    "lottery": "Lottery / Prize / Reward scam",
    "advance_fee": "Advance-fee / Upfront-payment scam",
    "job": "Fake job / Task scam",
    "loan": "Instant-loan scam",
    "courier": "Courier / Parcel / Customs scam",
    "electricity": "Electricity-bill disconnection scam",
    "digital_arrest": "Digital arrest / Authority impersonation",
    "investment": "Investment / Crypto fraud",
    "refund": "Refund / Cashback bait",
    "phishing": "Phishing link",
    "urgency": "Urgency / Pressure tactic",
    "contact": "Suspicious contact request",
}


def _analyze_urls(entities: ExtractedEntities) -> list[RedFlag]:
    flags: list[RedFlag] = []
    for raw in entities.urls:
        host = get_domain(raw)
        if not host:
            continue
        if host in URL_SHORTENERS:
            flags.append(RedFlag(raw, "Uses a URL shortener that hides the real destination.",
                                 "phishing", 16))
        if looks_like_ip(host):
            flags.append(RedFlag(raw, "Link points to a raw IP address instead of a domain.",
                                 "phishing", 18))
        if raw.lower().startswith("http://"):
            flags.append(RedFlag(raw, "Uses insecure http:// (no TLS) for a sensitive action.",
                                 "phishing", 8))
        if "xn--" in host:
            flags.append(RedFlag(raw, "Punycode domain — can disguise look-alike characters.",
                                 "phishing", 14))
        host_part = raw.split("//")[-1].split("/")[0]
        if "@" in host_part:
            flags.append(RedFlag(raw, "Credentials embedded in the URL host (the @ trick).",
                                 "phishing", 14))
        tld = host.split(".")[-1]
        if tld in SUSPICIOUS_TLDS:
            flags.append(RedFlag(raw, f"Unusual top-level domain '.{tld}' rarely used by real brands.",
                                 "phishing", 10))
        if host.count("-") >= 2 or host.count(".") >= 3:
            flags.append(RedFlag(raw, "Long/obfuscated host with many dashes or subdomains.",
                                 "phishing", 7))
    return flags


def _analyze_brand_lookalikes(text: str, entities: ExtractedEntities) -> list[RedFlag]:
    flags: list[RedFlag] = []
    mentioned = {m.group(1).lower() for m in _BRAND_MENTION_RE.finditer(text)}
    if not mentioned or not entities.domains:
        return flags
    for brand in mentioned:
        official = BRAND_OFFICIAL_DOMAINS.get(brand, set())
        for dom in entities.domains:
            base = dom.lower()
            if any(base == o or base.endswith("." + o) for o in official):
                continue  # legitimate official domain
            squashed = base.replace("-", "").replace(".", "")
            if brand.replace(" ", "") in squashed:
                flags.append(RedFlag(
                    dom,
                    f"Domain imitates '{brand}' but is not its official site "
                    f"({', '.join(sorted(official)) or 'unknown'}).",
                    "phishing", 20,
                ))
            elif official:
                flags.append(RedFlag(
                    dom,
                    f"Message names '{brand}' but links to an unrelated domain.",
                    "phishing", 9,
                ))
    return flags


def _verdict_for(score: int) -> str:
    if score >= SCAM_THRESHOLD:
        return "SCAM"
    if score >= SUSPICIOUS_THRESHOLD:
        return "SUSPICIOUS"
    return "LIKELY SAFE"


def detect(message: str) -> DetectionResult:
    """Run the full heuristic analysis and return a structured result."""
    text = normalize_text(message)
    entities = extract_entities(text)
    flags: list[RedFlag] = []

    for pattern, weight, category, reason in KEYWORD_SIGNALS:
        for match in re.finditer(pattern, text, flags=re.IGNORECASE):
            phrase = match.group(0).strip()
            if phrase:
                flags.append(RedFlag(phrase, reason, category, weight))

    flags.extend(_analyze_urls(entities))
    flags.extend(_analyze_brand_lookalikes(text, entities))

    score = _score(flags, entities)
    verdict = _verdict_for(score)
    scam_type = _classify(flags)
    rationale = _build_rationale(verdict, flags, entities)

    # De-duplicate flags (same phrase+reason) for display while keeping order.
    seen: set[tuple[str, str]] = set()
    deduped: list[RedFlag] = []
    for f in flags:
        key = (f.phrase.lower(), f.reason)
        if key not in seen:
            seen.add(key)
            deduped.append(f)

    return DetectionResult(
        risk_score=score,
        verdict=verdict,
        scam_type=scam_type,
        red_flags=deduped,
        entities=entities,
        rationale=rationale,
    )


def _score(flags: list[RedFlag], entities: ExtractedEntities) -> int:
    """Aggregate flags into a 0-100 risk score.

    Distinct signals within a category get diminishing weight (so ten urgency
    words don't dominate), while multiple independent scam *families* compound.
    """
    by_cat: dict[str, list[int]] = defaultdict(list)
    seen: set[tuple[str, str, str]] = set()
    for f in flags:
        # Collapse only exact duplicates (same phrase AND same reason); distinct
        # phrases from one signal (e.g. "CBI" + "digital arrest") still compound,
        # and distinct reasons on one URL (bad TLD + http) still both count.
        key = (f.category, f.phrase.lower(), f.reason)
        if key in seen:
            continue
        seen.add(key)
        by_cat[f.category].append(f.weight)

    score = 0.0
    for weights in by_cat.values():
        for i, w in enumerate(sorted(weights, reverse=True)):
            damp = _DAMP[i] if i < len(_DAMP) else _DAMP_TAIL
            score += w * damp

    families = [c for c in by_cat if c not in _GENERIC_CATEGORIES]
    if len(families) >= 2:
        score += 8 * (len(families) - 1)

    # Known high-confidence combinations.
    if "electricity" in by_cat and entities.phones:
        score += 15  # "your power will be cut, call this number" is textbook
    if entities.amounts and ({"otp_upi", "lottery", "refund", "advance_fee"} & set(by_cat)):
        score += 6

    return int(round(clamp(score)))


def _classify(flags: list[RedFlag]) -> str:
    """Pick the dominant scam family by summed weight (ignore generic signals)."""
    weight_by_cat: dict[str, int] = defaultdict(int)
    for f in flags:
        weight_by_cat[f.category] += f.weight

    candidates = {c: w for c, w in weight_by_cat.items() if c not in _GENERIC_CATEGORIES}
    if not candidates:
        return "No specific scam pattern detected"
    best = max(candidates, key=candidates.get)
    return CATEGORY_LABELS.get(best, best)


def _build_rationale(
    verdict: str,
    flags: list[RedFlag],
    entities: ExtractedEntities,
) -> list[str]:
    points: list[str] = []
    if verdict == "LIKELY SAFE" and not flags:
        points.append("No known scam patterns, suspicious links, or pressure tactics were found.")
        return points
    if entities.urls:
        points.append(
            f"Contains {len(entities.urls)} link(s): {', '.join(entities.domains[:3])}."
        )
    families = sorted({f.category for f in flags})
    if families:
        points.append(
            "Triggered signal families: "
            + ", ".join(CATEGORY_LABELS.get(c, c) for c in families)
            + "."
        )
    return points
