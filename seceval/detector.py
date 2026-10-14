"""Core types: a Finding, and the Detector interface everything plugs into.

The whole harness is built around one contract: a Detector takes a file's path
and its source code, and returns a list of Findings. The naive regex baseline,
a Semgrep wrapper, and the full LLM agent are all just different Detectors.
That means you can score any of them with the exact same runner and compare
them fairly -- which is the entire point of an eval harness.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class Finding:
    """One reported vulnerability.

    cwe is the thing we score on: a finding only counts as correct if its CWE
    matches the ground-truth CWE for that file. line and evidence are what make
    a finding *verifiable* -- the verifier (built later) checks that the cited
    line actually exists and contains what `evidence` claims.
    """

    cwe: str
    line: int
    message: str = ""
    evidence: str = ""
    confidence: float = 1.0
    source: str = ""  # which detector/tool produced it, for provenance


class Detector:
    """Base class. A detector is anything that can look at code and report findings."""

    name: str = "base"

    def analyze(self, path: str, code: str) -> list[Finding]:
        raise NotImplementedError

    # Convenience so a detector can be called like a function.
    def __call__(self, path: str, code: str) -> list[Finding]:
        return self.analyze(path, code)
