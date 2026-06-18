"""ScamShield AI — Gradio app (Hugging Face Spaces entrypoint).

Paste a suspicious SMS / email / WhatsApp / call transcript (English, Hindi or
Hinglish) and get an explainable fraud verdict: risk score, scam type, exact
red flags, a safe reply, and real Indian reporting steps.

Run locally:   python app.py
Deploy:        push to a Hugging Face Space (sdk: gradio, app_file: app.py)
"""

from __future__ import annotations

import html

import gradio as gr

from detector import CATEGORY_LABELS, DetectionResult, detect
from examples import EXAMPLE_MESSAGES
from llm import ScamAnalyzer
from utils import highlight_phrases

analyzer = ScamAnalyzer()

VERDICT_STYLE = {
    "SCAM": ("#ef4444", "#7f1d1d", "🚨", "High risk — treat as fraud"),
    "SUSPICIOUS": ("#f59e0b", "#78350f", "⚠️", "Be careful — verify independently"),
    "LIKELY SAFE": ("#22c55e", "#14532d", "✅", "No strong scam signals found"),
}


# --- HTML renderers -----------------------------------------------------------

def _verdict_card(result: DetectionResult, scam_type: str, status: str) -> str:
    color, deep, icon, tagline = VERDICT_STYLE.get(
        result.verdict, ("#64748b", "#1e293b", "•", "")
    )
    score = result.risk_score
    return f"""
    <div class="ss-card verdict" style="--accent:{color};--accent-deep:{deep}">
      <div class="verdict-head">
        <div class="verdict-badge" style="background:{color}">
          <span class="vb-icon">{icon}</span>
          <span class="vb-text">{result.verdict}</span>
        </div>
        <div class="verdict-tag">{tagline}</div>
      </div>
      <div class="gauge-row">
        <div class="gauge-score" style="color:{color}">{score}<span>/100</span></div>
        <div class="gauge-wrap">
          <div class="gauge-track">
            <div class="gauge-fill" style="width:{score}%;background:{color}"></div>
          </div>
          <div class="gauge-labels"><span>Safe</span><span>Risky</span></div>
        </div>
      </div>
      <div class="scam-type">
        <span class="st-label">Likely category</span>
        <span class="st-value" style="border-color:{color};color:{deep}">{html.escape(scam_type)}</span>
      </div>
      <div class="ss-status">{html.escape(status)}</div>
    </div>
    """


def _flags_card(message: str, result: DetectionResult) -> str:
    highlighted = highlight_phrases(message, result.flagged_phrases)
    if not result.red_flags:
        rows = "<div class='no-flags'>No specific red flags detected.</div>"
    else:
        items = []
        for f in result.red_flags:
            label = CATEGORY_LABELS.get(f.category, f.category)
            items.append(f"""
              <li class="flag-item">
                <div class="flag-top">
                  <span class="flag-chip">{html.escape(label)}</span>
                  <code class="flag-phrase">{html.escape(f.phrase[:80])}</code>
                </div>
                <div class="flag-reason">{html.escape(f.reason)}</div>
              </li>""")
        rows = "<ul class='flag-list'>" + "".join(items) + "</ul>"

    return f"""
    <div class="ss-card">
      <h3>Highlighted message</h3>
      <div class="msg-preview">{highlighted}</div>
      <h3>Why it was flagged <span class="count">{len(result.red_flags)}</span></h3>
      {rows}
    </div>
    """


def _reply_card(explanation: str, safe_reply: str, tip: str, source: str) -> str:
    badge = "AI-written" if source == "model" else "Heuristic"
    return f"""
    <div class="ss-card">
      <h3>What's going on <span class="src-badge">{badge}</span></h3>
      <p class="explain">{html.escape(explanation)}</p>
      <h3>Suggested response</h3>
      <div class="safe-reply">{html.escape(safe_reply)}</div>
      <div class="awareness"><strong>Awareness tip:</strong> {html.escape(tip)}</div>
    </div>
    """


REPORTING_HTML = """
<div class="ss-card reporting">
  <h3>How to report (India)</h3>
  <ul class="report-list">
    <li><span class="r-key">Cyber Crime Helpline</span>
        Call <a href="tel:1930"><strong>1930</strong></a> immediately if you lost money.</li>
    <li><span class="r-key">National Cyber Crime Portal</span>
        File a complaint at <a href="https://cybercrime.gov.in" target="_blank" rel="noopener">cybercrime.gov.in</a>.</li>
    <li><span class="r-key">Sanchar Saathi · Chakshu</span>
        Report fraud SMS/calls at <a href="https://sancharsaathi.gov.in" target="_blank" rel="noopener">sancharsaathi.gov.in</a>
        (Chakshu facility).</li>
    <li><span class="r-key">Block & don't engage</span>
        Don't click links, call back, or share OTP/PIN/UPI. Block the sender.</li>
  </ul>
  <div class="disclaimer">ScamShield AI is an assistive tool, not legal or financial advice.
  Always verify through official channels.</div>
</div>
"""

WELCOME_HTML = """
<div class="ss-card welcome">
  <h3>Paste a message to begin</h3>
  <p>ScamShield AI checks SMS, email, WhatsApp texts and call transcripts in
  English, Hindi and Hinglish. Try one of the sample messages below, or paste
  your own. Your text is analysed in-session and not stored.</p>
</div>
"""


def analyze(message: str):
    if not message or not message.strip():
        return WELCOME_HTML, "", "", REPORTING_HTML
    result = detect(message)
    enrichment = analyzer.enrich(message, result)
    return (
        _verdict_card(result, enrichment.scam_type, analyzer.status()),
        _flags_card(message, result),
        _reply_card(enrichment.explanation, enrichment.safe_reply,
                    enrichment.awareness_tip, enrichment.source),
        REPORTING_HTML,
    )


# --- Theme & CSS --------------------------------------------------------------

THEME = gr.themes.Soft(
    primary_hue=gr.themes.colors.indigo,
    secondary_hue=gr.themes.colors.blue,
    neutral_hue=gr.themes.colors.slate,
    font=[gr.themes.GoogleFont("Inter"), "system-ui", "sans-serif"],
)

CSS = """
.gradio-container {max-width: 1180px !important; margin: auto;}
#hero {text-align:center; padding: 26px 18px 8px;}
#hero h1 {font-size: 2.5rem; font-weight: 800; margin: 0;
  background: linear-gradient(90deg,#6366f1,#06b6d4);
  -webkit-background-clip:text; -webkit-text-fill-color:transparent;}
#hero p {color: var(--body-text-color-subdued); margin-top: 6px; font-size: 1.05rem;}
.ss-card {background: var(--background-fill-primary); border: 1px solid var(--border-color-primary);
  border-radius: 16px; padding: 18px 20px; margin-bottom: 16px;
  box-shadow: 0 4px 18px rgba(2,6,23,0.06);}
.ss-card h3 {margin: 6px 0 10px; font-size: 1.05rem; display:flex; align-items:center; gap:8px;}
.verdict {border-top: 4px solid var(--accent);}
.verdict-head {display:flex; align-items:center; gap:14px; flex-wrap:wrap;}
.verdict-badge {display:inline-flex; align-items:center; gap:8px; color:#fff;
  padding: 8px 16px; border-radius: 999px; font-weight:800; letter-spacing:.04em;
  box-shadow: 0 6px 16px color-mix(in srgb, var(--accent) 45%, transparent);}
.vb-icon {font-size: 1.1rem;}
.verdict-tag {color: var(--body-text-color-subdued); font-weight:600;}
.gauge-row {display:flex; align-items:center; gap:18px; margin:18px 0 6px;}
.gauge-score {font-size: 2.6rem; font-weight:800; line-height:1;}
.gauge-score span {font-size: 1rem; color: var(--body-text-color-subdued); font-weight:600;}
.gauge-wrap {flex:1;}
.gauge-track {height: 14px; border-radius: 999px; overflow:hidden;
  background: linear-gradient(90deg,#22c55e22,#f59e0b22,#ef444422);}
.gauge-fill {height:100%; border-radius:999px; transition: width .6s ease;}
.gauge-labels {display:flex; justify-content:space-between; font-size:.78rem;
  color: var(--body-text-color-subdued); margin-top:4px;}
.scam-type {display:flex; align-items:center; gap:12px; margin-top:8px;}
.st-label {color: var(--body-text-color-subdued); font-size:.85rem;}
.st-value {border:1.5px solid; padding:4px 12px; border-radius:999px; font-weight:700; font-size:.9rem;}
.ss-status {margin-top:12px; font-size:.8rem; color: var(--body-text-color-subdued);
  border-top:1px dashed var(--border-color-primary); padding-top:10px;}
.msg-preview {background: var(--background-fill-secondary); border-radius:12px;
  padding:14px; line-height:1.6; font-size:.95rem; border:1px solid var(--border-color-primary);}
mark.flag {background: #fde68a; color:#7c2d12; padding:1px 4px; border-radius:5px; font-weight:600;}
.count, .flag-chip, .src-badge {font-size:.72rem;}
.count {background: var(--primary-500); color:#fff; border-radius:999px; padding:2px 9px;}
.flag-list {list-style:none; padding:0; margin:6px 0 0; display:flex; flex-direction:column; gap:10px;}
.flag-item {border:1px solid var(--border-color-primary); border-radius:12px; padding:12px 14px;
  background: var(--background-fill-secondary);}
.flag-top {display:flex; align-items:center; gap:10px; flex-wrap:wrap; margin-bottom:4px;}
.flag-chip {background:#ef444418; color:#b91c1c; border:1px solid #ef444433;
  padding:2px 10px; border-radius:999px; font-weight:700; text-transform:uppercase; letter-spacing:.03em;}
.flag-phrase {background: var(--background-fill-primary); padding:2px 8px; border-radius:6px;
  font-size:.8rem; border:1px solid var(--border-color-primary);}
.flag-reason {color: var(--body-text-color); font-size:.9rem;}
.no-flags {color: var(--body-text-color-subdued); padding:8px 0;}
.src-badge {background:#6366f118; color:#4338ca; border:1px solid #6366f133;
  padding:2px 9px; border-radius:999px; font-weight:700;}
.explain {line-height:1.6;}
.safe-reply {background:#06b6d412; border-left:4px solid #06b6d4; padding:12px 14px;
  border-radius:8px; line-height:1.55;}
.awareness {margin-top:12px; background:#22c55e12; border-radius:10px; padding:10px 14px; font-size:.92rem;}
.reporting .report-list {list-style:none; padding:0; margin:0; display:flex; flex-direction:column; gap:10px;}
.report-list li {display:flex; flex-direction:column; gap:2px; font-size:.92rem;}
.r-key {font-weight:700; color: var(--primary-600);}
.disclaimer {margin-top:14px; font-size:.78rem; color: var(--body-text-color-subdued); font-style:italic;}
.welcome p {color: var(--body-text-color-subdued); line-height:1.6;}
"""


def build_demo() -> gr.Blocks:
    with gr.Blocks(theme=THEME, css=CSS, title="ScamShield AI") as demo:
        gr.HTML(
            """
            <div id="hero">
              <h1>🛡️ ScamShield AI</h1>
              <p>Paste any suspicious SMS, email, WhatsApp message or call transcript —
              in English, Hindi or Hinglish — and find out if it's a scam, why, and what to do.</p>
            </div>
            """
        )
        with gr.Row(equal_height=False):
            with gr.Column(scale=5):
                inp = gr.Textbox(
                    label="Suspicious message",
                    placeholder="Paste the SMS / email / WhatsApp text / call transcript here…",
                    lines=10,
                    autofocus=True,
                )
                with gr.Row():
                    analyze_btn = gr.Button("Analyze message", variant="primary", scale=3)
                    clear_btn = gr.ClearButton(value="Clear", scale=1)
                gr.Markdown("#### Try a sample message")
                gr.Examples(
                    examples=[[m] for m in EXAMPLE_MESSAGES],
                    inputs=[inp],
                    label="",
                    examples_per_page=8,
                )
            with gr.Column(scale=6):
                verdict_out = gr.HTML(WELCOME_HTML)
                flags_out = gr.HTML("")
                reply_out = gr.HTML("")
                reporting_out = gr.HTML(REPORTING_HTML)

        outputs = [verdict_out, flags_out, reply_out, reporting_out]
        analyze_btn.click(analyze, inputs=[inp], outputs=outputs)
        inp.submit(analyze, inputs=[inp], outputs=outputs)
        clear_btn.add([inp])

    return demo


demo = build_demo()

if __name__ == "__main__":
    demo.queue().launch()
