"""The verifier: make each finding survive an attempt to knock it down.

Two layers, cheapest first:

  mechanical_check -- pure code, no model. Does the cited line exist, and does
    the quoted evidence actually appear there? This is a hallucination guard: if
    the model says "SQLi at line 42" but line 42 is blank or says something else,
    the finding is dropped. This single check removes a whole class of confident
    nonsense for free.

  semantic_check -- a second model pass (the VERIFIER_PROMPT) that argues the
    finding is NOT exploitable. Only findings that survive are kept. This is the
    defense against the characteristic LLM failure mode: confident false
    positives on code that is actually safe.
"""

from __future__ import annotations

import json
import re

from ..detector import Finding
from .adapter import ModelAdapter
from .prompts import VERIFIER_PROMPT
from .parsing import extract_json


def mechanical_check(finding: Finding, code: str) -> tuple[bool, str]:
    lines = code.splitlines()
    if not (1 <= finding.line <= len(lines)):
        return False, f"cited line {finding.line} is out of range (1..{len(lines)})"
    actual = lines[finding.line - 1]
    if finding.evidence:
        tokens = [t for t in re.findall(r"\w+", finding.evidence) if len(t) > 3]
        if tokens and not any(t in actual for t in tokens):
            return False, "quoted evidence does not appear on the cited line"
    return True, "line exists and evidence matches"


def semantic_check(finding: Finding, code: str, model: ModelAdapter) -> tuple[bool, str]:
    user = (
        f"Finding: {finding.cwe} at line {finding.line}: {finding.message}\n"
        f"Evidence: {finding.evidence}\n\nFull file:\n{code}"
    )
    raw = model.complete([
        {"role": "system", "content": VERIFIER_PROMPT},
        {"role": "user", "content": user},
    ])
    obj = extract_json(raw) or {}
    exploitable = bool(obj.get("exploitable", True))
    return exploitable, obj.get("reason", "")


def verify_finding(
    finding: Finding, code: str, model: ModelAdapter | None,
    use_semantic: bool = True,
) -> tuple[bool, str]:
    ok, reason = mechanical_check(finding, code)
    if not ok:
        return False, f"mechanical: {reason}"
    if use_semantic and model is not None:
        ok, reason = semantic_check(finding, code, model)
        if not ok:
            return False, f"semantic: {reason}"
    return True, "verified"
