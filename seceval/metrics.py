"""Scoring.

The scoring rules ARE a design decision, so they are written down explicitly
here rather than hidden in the runner. For each paired sample we run the
detector twice -- once on the vulnerable file, once on the fixed file -- and
classify the outcome:

  On the VULNERABLE file:
    - If at least one finding has the expected CWE  -> 1 true positive (TP).
    - Otherwise                                     -> 1 false negative (FN).
    - Every finding whose CWE is NOT the expected one is noise -> 1 FP each.

  On the FIXED file:
    - Every finding is a false positive (FP). A correct detector is SILENT here.

From these counts:
    precision = TP / (TP + FP)      "of what I flagged, how much was real"
    recall    = TP / (TP + FN)      "of the real bugs, how many I caught"
    fp_per_kloc = FP / (total_lines / 1000)
    silent_on_fix_rate = (fixed files with zero findings) / (number of samples)

Why this scheme and not accuracy:
  Accuracy is meaningless for an imbalanced, open-ended task where "no finding"
  is almost always the right answer for most lines. Precision and recall each
  tell half the story; the fixed-file FP count is what catches a detector that
  "finds" a bug that a human already patched -- the single most damaging
  failure mode for a security tool, because it destroys trust.

Line tolerance: we DON'T require the reported line to match exactly, only the
CWE, because a reasonable tool may point at the sink line or the source line.
`line_match_within` reports how often the line was close, as a secondary stat,
without gating correctness on it.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from .dataset import Sample
from .detector import Detector, Finding


@dataclass
class SampleResult:
    sample_id: str
    cwe: str
    llm_value: str
    tp: int = 0
    fn: int = 0
    fp: int = 0
    caught: bool = False          # did we flag the vuln file with the right CWE
    silent_on_fix: bool = True    # were we correctly silent on the fixed file
    line_close: bool = False      # was a correct finding within the line window
    vuln_findings: list[Finding] = field(default_factory=list)
    fixed_findings: list[Finding] = field(default_factory=list)


@dataclass
class Report:
    detector_name: str
    results: list[SampleResult]
    total_lines: int

    @property
    def tp(self) -> int:
        return sum(r.tp for r in self.results)

    @property
    def fn(self) -> int:
        return sum(r.fn for r in self.results)

    @property
    def fp(self) -> int:
        return sum(r.fp for r in self.results)

    @property
    def precision(self) -> float:
        denom = self.tp + self.fp
        return self.tp / denom if denom else 0.0

    @property
    def recall(self) -> float:
        denom = self.tp + self.fn
        return self.tp / denom if denom else 0.0

    @property
    def f1(self) -> float:
        p, r = self.precision, self.recall
        return 2 * p * r / (p + r) if (p + r) else 0.0

    @property
    def fp_per_kloc(self) -> float:
        return self.fp / (self.total_lines / 1000) if self.total_lines else 0.0

    @property
    def silent_on_fix_rate(self) -> float:
        n = len(self.results)
        return sum(1 for r in self.results if r.silent_on_fix) / n if n else 0.0


def _count_lines(code: str) -> int:
    return code.count("\n") + 1


def _norm_cwe(c: str) -> str:
    """Compare CWEs by their number, so 'CWE-863', '863', 'cwe 863' all match."""
    m = re.search(r"\d+", str(c))
    return m.group(0) if m else str(c).strip().upper()


def score_sample(
    detector: Detector, sample: Sample, line_match_within: int = 3
) -> tuple[SampleResult, int]:
    """Score one sample. Returns (result, lines_of_code_analyzed)."""
    res = SampleResult(sample_id=sample.id, cwe=sample.cwe, llm_value=sample.llm_value)

    vuln_code = sample.vulnerable_code()
    fixed_code = sample.fixed_code()
    lines = _count_lines(vuln_code) + _count_lines(fixed_code)

    # --- vulnerable file ---
    accepted = {_norm_cwe(c) for c in sample.accept_cwes}
    res.vuln_findings = detector(str(sample.vulnerable_path), vuln_code)
    correct = [f for f in res.vuln_findings if _norm_cwe(f.cwe) in accepted]
    noise = [f for f in res.vuln_findings if _norm_cwe(f.cwe) not in accepted]

    if correct:
        res.tp = 1
        res.caught = True
        res.line_close = any(
            abs(f.line - sample.vuln_line) <= line_match_within for f in correct
        )
    else:
        res.fn = 1

    res.fp += len(noise)

    # --- fixed file (should be silent) ---
    res.fixed_findings = detector(str(sample.fixed_path), fixed_code)
    if res.fixed_findings:
        res.silent_on_fix = False
        res.fp += len(res.fixed_findings)

    return res, lines


def evaluate(detector: Detector, samples: list[Sample]) -> Report:
    results: list[SampleResult] = []
    total_lines = 0
    for s in samples:
        r, lines = score_sample(detector, s)
        results.append(r)
        total_lines += lines
    return Report(detector_name=detector.name, results=results, total_lines=total_lines)
