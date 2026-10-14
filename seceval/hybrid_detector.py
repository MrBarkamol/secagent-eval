"""The hybrid: static analyzer for pattern bugs, LLM agent for the rest.

The whole project's thesis in one class. The agent-only result showed that a
small local model is unreliable at the easy, pattern-matchable bugs that Semgrep
nails every time -- and worse than Semgrep overall. So don't make the model
compete with the scanner; make it do only what the scanner CANNOT: find the
missing-check bugs (IDOR and friends) that have no pattern.

Strategy:
  1. Run the static detector (Semgrep). These findings are high-precision and
     deterministic -- trust them for the pattern classes.
  2. Run the agent. Keep only its findings that the scanner did NOT already
     report (same CWE family + nearby line = duplicate), so the agent's
     contribution is the reasoning bugs, not a noisy re-run of the scanner.
  3. The agent's own verifier has already pruned its additions.

The result should inherit Semgrep's recall on pattern bugs AND add the IDOR,
while keeping precision high because the unreliable model is no longer the one
responsible for the easy cases.
"""

from __future__ import annotations

import re

from .detector import Detector, Finding


def _num(cwe: str) -> str:
    m = re.search(r"\d+", str(cwe))
    return m.group(0) if m else str(cwe).strip().upper()


class HybridDetector(Detector):
    name = "hybrid"

    def __init__(self, static: Detector, agent: Detector, line_window: int = 3):
        self.static = static
        self.agent = agent
        self.line_window = line_window

    def analyze(self, path: str, code: str) -> list[Finding]:
        static_findings = self.static.analyze(path, code)
        agent_findings = self.agent.analyze(path, code)

        merged = list(static_findings)
        for af in agent_findings:
            duplicate = any(
                _num(af.cwe) == _num(sf.cwe)
                and abs(af.line - sf.line) <= self.line_window
                for sf in static_findings
            )
            if not duplicate:
                af.source = "hybrid:agent"
                merged.append(af)
        return merged
