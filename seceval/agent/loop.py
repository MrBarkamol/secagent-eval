"""The agent: a reason -> act -> observe loop, wrapped as a Detector.

This is the piece that is supposed to catch what the static tools cannot -- the
IDOR, where the bug is a MISSING ownership check. It does that not by matching a
pattern but by investigating the code with tools and reasoning about what SHOULD
be there and isn't.

Flow:
  1. Show the model the file (with line numbers).
  2. Loop up to max_steps: the model either calls a tool (we run it, feed back
     the observation) or returns final findings.
  3. Verify every finding (mechanical always; semantic if enabled).
  4. Return the survivors as Findings, scored by the same harness as every other
     detector.

A step limit is essential: without it a confused model can loop forever. When
the limit is hit with no final answer, we return nothing rather than guess.
"""

from __future__ import annotations

from pathlib import Path

from ..detector import Detector, Finding
from .adapter import ModelAdapter
from .parsing import extract_json
from .prompts import FOCUS_AUTHZ, HINT_IDOR, SYSTEM_PROMPT
from .tools import ToolContext, dispatch
from .verifier import verify_finding


def _numbered(code: str) -> str:
    return "\n".join(f"{i:>4} | {ln}" for i, ln in enumerate(code.splitlines(), 1))


class AgentDetector(Detector):
    name = "agent"

    def __init__(self, model: ModelAdapter, root: str | Path | None = None,
                 max_steps: int = 6, verify: bool = True,
                 verify_semantic: bool = True, trace: bool = False,
                 focus: str | None = None, isolate: bool = False,
                 hint: bool = True, retriever=None):
        self.model = model
        self.root = root
        self.max_steps = max_steps
        self.verify = verify
        self.verify_semantic = verify_semantic
        self.trace = trace
        self.focus = focus  # None = general review; "authz" = authorization only
        # isolate=True: the tools only see a private copy of the file under review.
        # In the eval this matters: the fixtures folder holds each vulnerable file
        # next to its FIXED twin, so a shared root lets the agent "find" a bug by
        # diffing against the answer.
        self.isolate = isolate
        self.hint = hint          # include the specific IDOR example in the prompt
        self.retriever = retriever  # if set, inject retrieved knowledge (RAG)

    def _log(self, *a):
        if self.trace:
            print(*a)

    def analyze(self, path: str, code: str) -> list[Finding]:
        if self.isolate:
            import tempfile
            with tempfile.TemporaryDirectory() as tmp:
                name = Path(path).name
                (Path(tmp) / name).write_text(code)
                return self._analyze(name, code, ToolContext(tmp))
        return self._analyze(path, code, ToolContext(self.root or Path(path).parent))

    def _analyze(self, path: str, code: str, ctx: ToolContext) -> list[Finding]:
        system = SYSTEM_PROMPT
        if self.hint:
            system += HINT_IDOR
        if self.focus == "authz":
            system += FOCUS_AUTHZ
        if self.retriever is not None:
            knowledge = self.retriever.retrieve(code)
            if knowledge:
                system += ("\n\nRetrieved security knowledge (use only if relevant):\n"
                           + knowledge)
        messages = [
            {"role": "system", "content": system},
            {"role": "user",
             "content": f"Review this file: {path}\n\n{_numbered(code)}"},
        ]

        raw_findings: list[dict] = []
        for step in range(self.max_steps):
            raw = self.model.complete(messages)
            messages.append({"role": "assistant", "content": raw})
            msg = extract_json(raw) or {}
            self._log(f"[step {step}] {msg.get('action')} {msg.get('thought','')}")

            if msg.get("action") == "tool":
                obs = dispatch(ctx, msg.get("tool", ""), msg.get("args", {}))
                self._log(f"  tool={msg.get('tool')} args={msg.get('args')}")
                self._log(f"  observation:\n{obs}")
                messages.append({"role": "user", "content": f"Observation:\n{obs}"})
                continue

            if msg.get("action") == "final":
                raw_findings = msg.get("findings", [])
                if not isinstance(raw_findings, list):
                    raw_findings = []
                break
            # Unparseable / unknown: nudge once, then let the loop end.
            self._log(f"  [unparsed/unknown action] raw: {raw[:400]!r}")
            messages.append({"role": "user",
                             "content": "Respond with one valid JSON object."})

        findings: list[Finding] = []
        for f in raw_findings:
            if not isinstance(f, dict):
                continue
            try:
                line = int(f.get("line", 0))
            except (TypeError, ValueError):
                line = 0
            try:
                conf = float(f.get("confidence", 0.5))
            except (TypeError, ValueError):
                conf = 0.5
            finding = Finding(
                cwe=str(f.get("cwe", "")), line=line,
                message=str(f.get("message", "")), evidence=str(f.get("evidence", "")),
                confidence=conf, source=self.name,
            )
            if self.verify:
                ok, reason = verify_finding(
                    finding, code, self.model, use_semantic=self.verify_semantic)
                self._log(f"  verify {finding.cwe} L{finding.line}: {ok} ({reason})")
                if not ok:
                    continue
            findings.append(finding)
        return findings
