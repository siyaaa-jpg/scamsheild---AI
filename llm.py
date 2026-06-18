"""LLM enrichment for ScamShield AI.

The heuristic detector (``detector.py``) always produces a verdict. This layer
*optionally* enriches that verdict with a nuanced natural-language explanation,
a refined scam-type label, a safe suggested reply and an awareness tip — using
a hosted open model via the Hugging Face ``InferenceClient``.

Design goals:
- Zero hard dependency on a token. If ``HF_TOKEN`` is missing or the call
  fails, fall back to deterministic, template-based guidance built from the
  heuristic result. The app must NEVER crash because of the model.
- Strict-ish JSON contract with tolerant parsing.
"""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass

from detector import DetectionResult

DEFAULT_MODEL = os.getenv("MODEL_ID", "Qwen/Qwen2.5-7B-Instruct")
HF_TOKEN = os.getenv("HF_TOKEN") or os.getenv("HUGGINGFACEHUB_API_TOKEN")

SYSTEM_PROMPT = (
    "You are ScamShield AI, an expert fraud analyst specializing in Indian "
    "digital scams (SMS, email, WhatsApp, calls). You understand English, Hindi "
    "and Hinglish. You are given a suspicious message plus the output of a "
    "deterministic heuristic detector. Produce a careful, calm, non-alarmist "
    "analysis that helps an ordinary person stay safe. Never ask for or repeat "
    "the victim's secrets. Reply ONLY with a single valid JSON object — no "
    "markdown, no preamble."
)

JSON_INSTRUCTIONS = """\
Return a JSON object with EXACTLY these keys:
{
  "scam_type": "<short specific label>",
  "explanation": "<2-4 sentence plain-language explanation of why this is or isn't a scam, mirroring the user's language (English/Hindi/Hinglish)>",
  "safe_reply": "<one short safe response the user could send, OR explicit 'Do not reply — block and report' guidance>",
  "awareness_tip": "<one concise, memorable prevention tip>"
}
"""


@dataclass
class Enrichment:
    scam_type: str
    explanation: str
    safe_reply: str
    awareness_tip: str
    source: str  # "model" or "heuristic"


def _build_user_prompt(message: str, result: DetectionResult) -> str:
    flags = "\n".join(
        f"- [{f.category}] {f.reason} (matched: \"{f.phrase}\")"
        for f in result.red_flags[:12]
    ) or "- (none)"
    domains = ", ".join(result.entities.domains) or "none"
    return (
        f"SUSPICIOUS MESSAGE:\n\"\"\"\n{message}\n\"\"\"\n\n"
        f"HEURISTIC DETECTOR OUTPUT:\n"
        f"- Verdict: {result.verdict}\n"
        f"- Risk score: {result.risk_score}/100\n"
        f"- Detected scam type: {result.scam_type}\n"
        f"- Links/domains: {domains}\n"
        f"- Red flags:\n{flags}\n\n"
        f"{JSON_INSTRUCTIONS}"
    )


def _extract_json(raw: str) -> dict | None:
    """Tolerantly pull the first JSON object out of a model response."""
    if not raw:
        return None
    # Strip code fences if present.
    raw = re.sub(r"^```(?:json)?|```$", "", raw.strip(), flags=re.MULTILINE).strip()
    start = raw.find("{")
    end = raw.rfind("}")
    if start == -1 or end == -1 or end <= start:
        return None
    candidate = raw[start : end + 1]
    try:
        return json.loads(candidate)
    except json.JSONDecodeError:
        # Last resort: tidy trailing commas.
        cleaned = re.sub(r",\s*([}\]])", r"\1", candidate)
        try:
            return json.loads(cleaned)
        except json.JSONDecodeError:
            return None


class ScamAnalyzer:
    """LLM-backed enrichment with a deterministic fallback."""

    def __init__(self, model: str = DEFAULT_MODEL, token: str | None = HF_TOKEN):
        self.model = model
        self.token = token
        self._client = None
        if token:
            try:
                from huggingface_hub import InferenceClient

                self._client = InferenceClient(model=model, token=token)
            except Exception:
                self._client = None

    @property
    def online(self) -> bool:
        return self._client is not None

    def status(self) -> str:
        if self.online:
            return f"AI analysis active · model `{self.model}`"
        return "Heuristic mode · set HF_TOKEN secret for AI-written explanations"

    def enrich(self, message: str, result: DetectionResult) -> Enrichment:
        if self.online:
            try:
                response = self._client.chat_completion(
                    messages=[
                        {"role": "system", "content": SYSTEM_PROMPT},
                        {"role": "user", "content": _build_user_prompt(message, result)},
                    ],
                    max_tokens=500,
                    temperature=0.2,
                )
                content = response.choices[0].message.content
                data = _extract_json(content)
                if data:
                    return Enrichment(
                        scam_type=str(data.get("scam_type") or result.scam_type),
                        explanation=str(data.get("explanation") or "").strip()
                        or self._fallback_explanation(result),
                        safe_reply=str(data.get("safe_reply") or "").strip()
                        or self._fallback_reply(result),
                        awareness_tip=str(data.get("awareness_tip") or "").strip()
                        or self._fallback_tip(result),
                        source="model",
                    )
            except Exception:
                pass  # fall through to heuristic enrichment

        return self._heuristic_enrichment(result)

    # --- Deterministic fallbacks ---------------------------------------------

    def _heuristic_enrichment(self, result: DetectionResult) -> Enrichment:
        return Enrichment(
            scam_type=result.scam_type,
            explanation=self._fallback_explanation(result),
            safe_reply=self._fallback_reply(result),
            awareness_tip=self._fallback_tip(result),
            source="heuristic",
        )

    @staticmethod
    def _fallback_explanation(result: DetectionResult) -> str:
        if result.verdict == "LIKELY SAFE":
            return (
                "No strong scam indicators were detected. Still, stay cautious if "
                "the sender is unknown or asks for money, OTPs or personal details."
            )
        top = result.red_flags[:3]
        reasons = " ".join(f"{i+1}) {f.reason}" for i, f in enumerate(top))
        return (
            f"This message shows hallmarks of a {result.scam_type.lower()}. "
            f"Key reasons: {reasons} "
            "Genuine banks/companies/government bodies never ask for OTPs, PINs or "
            "urgent payments over SMS/WhatsApp."
        )

    @staticmethod
    def _fallback_reply(result: DetectionResult) -> str:
        if result.verdict == "SCAM":
            return (
                "Do NOT reply, click any link, or call back. Block the sender and "
                "report it (details below). If you already shared details or money, "
                "call 1930 immediately."
            )
        if result.verdict == "SUSPICIOUS":
            return (
                "Do not act on this message. Independently verify by contacting the "
                "company/bank via their official app or printed customer-care number "
                "— never the number in this message."
            )
        return (
            "Looks low-risk, but if it asks for money, OTPs or personal info, verify "
            "through official channels before responding."
        )

    @staticmethod
    def _fallback_tip(result: DetectionResult) -> str:
        tips = {
            "OTP / UPI / Banking fraud": "Your OTP/PIN is a secret. No real bank employee will ever ask for it.",
            "KYC / Account-update phishing": "Banks don't update KYC via SMS links. Use the official app/branch only.",
            "Lottery / Prize / Reward scam": "You can't win a lottery you never entered. Prizes never need an upfront fee.",
            "Digital arrest / Authority impersonation": "No real police/CBI conducts 'arrests' over video call or demands money to settle.",
            "Electricity-bill disconnection scam": "Electricity boards don't disconnect via random SMS. Check your official provider app.",
            "Courier / Parcel / Customs scam": "Real couriers don't ask for 'customs fees' through random links.",
            "Instant-loan scam": "Avoid loan apps asking for fees/permissions upfront; use RBI-regulated lenders.",
            "Investment / Crypto fraud": "Guaranteed high returns = guaranteed red flag. No investment is risk-free.",
        }
        return tips.get(
            result.scam_type,
            "When in doubt, slow down. Urgency is the scammer's favourite weapon.",
        )
