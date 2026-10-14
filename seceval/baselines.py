"""A deliberately naive pattern-matching detector.

This is the baseline the real agent must beat. It is intentionally shallow so
that running the harness MAKES VISIBLE the two failure modes the whole project
is about:

  1. Sanitizer-blindness -> false positives. It flags any dangerous sink that
     is built with string concatenation, so it fires on BOTH the vulnerable
     cmd-injection/path-traversal code AND the FIXED versions (which still
     concatenate, just safely). A regex cannot tell that escapeshellarg() or
     basename() neutralized the input.

  2. Blindness to missing-check bugs -> false negatives. The IDOR case has no
     dangerous function call at all; the bug is the ABSENCE of an ownership
     check. There is no string to match, so the baseline misses it entirely.

Those two gaps are exactly where an LLM reasoner is supposed to earn its place.
Reporting the baseline's numbers honestly is the motivation section of the
write-up.
"""

from __future__ import annotations

import re

from .detector import Detector, Finding

# A line "concatenates a string" if a quote is followed by the PHP `.` operator.
_CONCAT = re.compile(r"""['"]\s*\.""")

# Dangerous sinks, mapped to the CWE a match should be reported as.
_SINKS = [
    (re.compile(r"DB::(select|statement|insert|update|raw)\s*\("), "CWE-89",
     "SQL query built by string concatenation"),
    (re.compile(r"\b(shell_exec|exec|system|passthru|popen|proc_open)\s*\("), "CWE-78",
     "OS command built by string concatenation"),
    (re.compile(r"\b(storage_path|file_get_contents|fopen|readfile)\s*\("), "CWE-22",
     "File path built from concatenation"),
]

# Mass assignment has a recognizable shape, so the baseline CAN catch it.
_MASS_ASSIGN = re.compile(r"::(create|fill|update)\s*\(\s*\$request->all\(\)")


class NaiveRegexDetector(Detector):
    name = "naive-regex"

    def analyze(self, path: str, code: str) -> list[Finding]:
        findings: list[Finding] = []
        for i, line in enumerate(code.splitlines(), start=1):
            stripped = line.strip()

            if _MASS_ASSIGN.search(line):
                findings.append(Finding(
                    cwe="CWE-915", line=i,
                    message="Mass assignment from request->all()",
                    evidence=stripped, confidence=0.6, source=self.name,
                ))
                continue

            if _CONCAT.search(line):
                for pat, cwe, msg in _SINKS:
                    if pat.search(line):
                        findings.append(Finding(
                            cwe=cwe, line=i, message=msg,
                            evidence=stripped, confidence=0.5, source=self.name,
                        ))
                        break
        return findings
