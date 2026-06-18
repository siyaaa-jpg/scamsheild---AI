---
title: ScamShield AI
emoji: 🛡️
colorFrom: indigo
colorTo: blue
sdk: gradio
sdk_version: 4.44.1
app_file: app.py
pinned: false
license: mit
python_version: 3.11
---
# 🛡️ ScamShield AI

**Paste any suspicious SMS, email, WhatsApp message, or call transcript — in English, Hindi, or Hinglish — and instantly find out if it's a scam, *why*, and *what to do about it*.**

ScamShield AI is a daily-life fraud-protection assistant built for the Indian threat landscape (but useful globally). It combines a **transparent rule-based detection engine** with an **optional LLM layer** for nuanced, human-friendly explanations — so it always gives a useful answer, even with no API token configured.

---

## Why it's different

Most "scam detector" demos are a thin wrapper around a chatbot prompt. ScamShield AI is a **hybrid system**:

- **Deterministic detector (`detector.py`)** — explainable heuristics that score risk from suspicious URLs (shorteners, look-alike brand domains, raw IPs, punycode, risky TLDs), urgency tactics, and weighted keyword signals across **10+ Indian scam playbooks**. This runs with **zero dependencies on any API token**, so the public demo never breaks.
- **LLM enrichment (`llm.py`)** — a hosted open model (via `huggingface_hub.InferenceClient`) adds a nuanced explanation, refined scam-type label, a safe suggested reply, and an awareness tip. If there's no token or the call fails, it **gracefully falls back** to deterministic guidance.
- **The app never crashes on the model path** — the heuristic result is the source of truth; the model only *enriches* it.

## What you get for every message

1. **Verdict** — `SCAM` / `SUSPICIOUS` / `LIKELY SAFE`
2. **Risk score (0–100)** shown as a colour-coded gauge
3. **Scam-type classification** — OTP/UPI, KYC phishing, lottery/prize, fake job, instant loan, courier/customs, electricity disconnection, **digital arrest**, investment/crypto, refund bait, and more
4. **Red flags** — the *exact* suspicious phrases and links are highlighted, each with a plain-language reason
5. **A safe suggested reply** (or "do not reply — block & report" guidance)
6. **Real Indian reporting steps** — Cyber Crime Helpline **1930**, [cybercrime.gov.in](https://cybercrime.gov.in), and **Sanchar Saathi / Chakshu** ([sancharsaathi.gov.in](https://sancharsaathi.gov.in))
7. **A short awareness tip** tailored to the scam type

Built-in **multilingual sample messages** (English / Hindi / Hinglish) let anyone try it in one click.

---

## File layout

```
scamshield-ai/
├── app.py            # Gradio UI — Hugging Face Spaces entrypoint
├── detector.py       # Rule-based hybrid detection engine (no token needed)
├── llm.py            # InferenceClient enrichment + graceful fallback
├── utils.py          # Text cleaning, URL/phone/money extraction, highlighting
├── examples.py       # Built-in multilingual sample messages
├── requirements.txt
├── .gitignore
└── README.md
```

---

## Run locally

> Requires Python 3.10+.

```bash
# 1. Clone (after you push it to GitHub) or cd into the project
cd scamshield-ai

# 2. Create a virtual environment
python -m venv .venv
# Windows:
.venv\Scripts\activate
# macOS/Linux:
source .venv/bin/activate

# 3. Install dependencies
pip install -r requirements.txt

# 4. (Optional) enable AI-written explanations
#    Windows PowerShell:
$env:HF_TOKEN="hf_xxx_your_token"
#    macOS/Linux:
export HF_TOKEN="hf_xxx_your_token"

# 5. Launch
python app.py
```

Open the printed local URL (usually `http://127.0.0.1:7860`). Without `HF_TOKEN`, the app runs in **Heuristic mode** — fully functional, just without the AI-written prose.

You can also pick a different model:

```bash
export MODEL_ID="meta-llama/Llama-3.1-8B-Instruct"   # any chat model on HF Inference
```

---

## Push to GitHub

```bash
cd scamshield-ai
git init
git add .
git commit -m "ScamShield AI: hybrid scam detector"
git branch -M main
git remote add origin https://github.com/<your-username>/scamshield-ai.git
git push -u origin main
```

---

## Deploy to Hugging Face Spaces

1. Go to **https://huggingface.co/new-space** → choose **SDK: Gradio**, name it `scamshield-ai`, set visibility, and create it.
2. Push the code to the Space (the YAML header at the top of this README is what configures the Space):

   ```bash
   git remote add space https://huggingface.co/spaces/<your-username>/scamshield-ai
   git push space main
   ```

   *(Or, on the Space page, choose “link to a GitHub repo” / drag-and-drop the files.)*
3. **Add your token as a secret (optional but recommended):** open the Space → **Settings → Variables and secrets → New secret** → name it **`HF_TOKEN`**, paste a token from <https://huggingface.co/settings/tokens> (a read token is enough). The Space rebuilds and AI explanations turn on automatically.
4. The Space builds from `requirements.txt` and launches `app.py`. Done.

> The header fields (`sdk: gradio`, `sdk_version`, `app_file: app.py`) are read by Hugging Face Spaces — keep them at the very top of this file.

---

## How the risk score works

The detector assigns weighted scores to each matched signal, applies **diminishing returns** within a signal family (so ten urgency words don't dominate), and **compounds** when multiple independent scam families appear together. Thresholds: **≥ 65 → SCAM**, **30–64 → SUSPICIOUS**, **< 30 → LIKELY SAFE**. Every contributing signal is surfaced in the “Why it was flagged” panel, so the verdict is always explainable.

---

## Disclaimer

ScamShield AI is an **assistive tool**, not legal or financial advice, and can produce false positives/negatives. Always verify through official channels and report fraud via the resources above.

## License

MIT
