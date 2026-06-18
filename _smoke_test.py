"""Quick smoke test: verify imports and detector verdicts on the examples."""
from detector import detect
from examples import EXAMPLE_MESSAGES
from llm import ScamAnalyzer

analyzer = ScamAnalyzer()
print("LLM status:", analyzer.status())
for i, msg in enumerate(EXAMPLE_MESSAGES):
    r = detect(msg)
    enr = analyzer.enrich(msg, r)
    print(f"\n[{i}] verdict={r.verdict} score={r.risk_score} type={r.scam_type}")
    print("    flags:", len(r.red_flags), "| reply:", enr.safe_reply[:50])
print("\nOK: imports + detector + enrichment ran without error.")
