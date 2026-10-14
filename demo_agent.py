#!/usr/bin/env python3
"""Prove the agent machinery works end to end -- WITHOUT a real model.

A scripted MockModel walks the IDOR fixture: it greps for object access, greps
for an ownership check, finds none, and reports the IDOR. Then the mechanical
verifier confirms the cited line is real.

This demonstrates PLUMBING, not reasoning quality. The mock is told what to do;
a real model would have to figure it out. Swap OllamaAdapter in (see README) to
get a real result. Run:

    python3 demo_agent.py
"""

from pathlib import Path

from seceval.agent import AgentDetector, MockModel

HERE = Path(__file__).parent
IDOR = HERE / "fixtures" / "php" / "idor_vulnerable.php"

# A scripted "reasoning" trace: two investigative greps, then the finding.
SCRIPT = [
    # Step 0: locate direct object access by id.
    '{"thought": "Find where records are fetched by id.",'
    ' "action": "tool", "tool": "grep", "args": {"pattern": "findOrFail"}}',
    # Step 1: look for an ownership/authorization scope near that access.
    '{"thought": "Check whether the query is scoped to the current user.",'
    ' "action": "tool", "tool": "grep", "args": {"pattern": "user\\\\(\\\\)->"}}',
    # Step 2: no ownership check in the vulnerable file -> report IDOR.
    '{"thought": "Invoice is fetched by id with no ownership check.",'
    ' "action": "final", "findings": [{"cwe": "CWE-639", "line": 13,'
    ' "message": "Invoice fetched by id with no check that it belongs to the'
    ' current user (broken object-level authorization).",'
    ' "evidence": "Invoice::findOrFail($id)", "confidence": 0.8}]}',
]


def main():
    model = MockModel(SCRIPT)
    # verify_semantic=False: the mock has no verifier responses scripted, and the
    # mechanical check alone is enough to prove the finding is grounded in real code.
    agent = AgentDetector(model, max_steps=6, verify=True,
                          verify_semantic=False, trace=True)

    code = IDOR.read_text()
    print("=" * 72)
    print("Agent trace on idor_vulnerable.php (mock-driven)")
    print("=" * 72)
    findings = agent.analyze(str(IDOR), code)

    print("=" * 72)
    print(f"Findings after verification: {len(findings)}")
    for f in findings:
        print(f"  {f.cwe} line {f.line} (conf {f.confidence}) -- {f.message}")
    print("=" * 72)
    assert findings and findings[0].cwe == "CWE-639", "agent should catch the IDOR"
    print("OK: the loop investigated, reported, and verified the IDOR end to end.")


if __name__ == "__main__":
    main()
