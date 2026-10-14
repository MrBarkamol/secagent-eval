"""A Detector that wraps Semgrep, an industry-standard static-analysis tool.

This is the serious non-LLM baseline. Where the regex baseline matches raw
text, Semgrep parses the code into a syntax tree and matches structure, which
lets it do two things regex cannot:

  - `pattern-not` to EXCLUDE a sanitized call (e.g. ignore a shell command when
    its argument is wrapped in escapeshellarg()). This is how it kills the
    false positive the regex produced on fixed command-injection code.

  - match by shape rather than exact characters, so formatting changes don't
    fool it.

What it still CANNOT do, by design of the rules here:
  - catch the IDOR, because that bug is a *missing* ownership check and there is
    no structure to match;
  - see the fixed path-traversal as safe, because basename() is applied on a
    previous line and plain pattern mode reasons one statement at a time
    (Semgrep's taint mode could fix this -- a documented possible improvement).

Those two gaps are precisely what the LLM agent must close to justify itself.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
from pathlib import Path

from .detector import Detector, Finding


class SemgrepDetector(Detector):
    name = "semgrep"

    def __init__(self, rules_path: str | Path, semgrep_bin: str | None = None,
                 name: str | None = None):
        self.rules_path = str(rules_path)
        if name:
            self.name = name
        self.semgrep_bin = semgrep_bin or shutil.which("semgrep")
        if not self.semgrep_bin:
            raise RuntimeError(
                "semgrep not found on PATH. Install it with `pip install semgrep` "
                "(ideally in a virtualenv)."
            )

    def analyze(self, path: str, code: str) -> list[Finding]:
        suffix = Path(path).suffix or ".php"
        tmp = None
        proc = None
        try:
            with tempfile.NamedTemporaryFile("w", suffix=suffix, delete=False) as tf:
                tf.write(code)
                tmp = tf.name

            proc = subprocess.run(
                [
                    self.semgrep_bin,
                    "--config", self.rules_path,
                    tmp,
                    "--json", "--quiet",
                    "--disable-version-check",
                    "--metrics", "off",
                ],
                capture_output=True, text=True,
            )
            data = json.loads(proc.stdout or "{}")
        except (json.JSONDecodeError, OSError) as e:
            # Never fail silently: an empty result here would look like
            # "Semgrep found nothing" and corrupt the comparison.
            detail = proc.stderr[-500:] if proc is not None else ""
            raise RuntimeError(f"semgrep produced no usable output: {e}\n{detail}")
        finally:
            if tmp and os.path.exists(tmp):
                os.unlink(tmp)

        fatal = [e for e in data.get("errors", [])
                 if str(e.get("level", "")).lower() == "error"
                 and "rule" in str(e.get("type", "")).lower() + str(e.get("message", "")).lower()]
        if proc.returncode >= 2 or fatal:
            raise RuntimeError(
                f"semgrep failed (exit {proc.returncode}) with rules {self.rules_path}: "
                f"{(fatal[0].get('message') if fatal else proc.stderr)[:500]}")

        findings: list[Finding] = []
        for r in data.get("results", []):
            cwe = r.get("extra", {}).get("metadata", {}).get("cwe", "")
            if isinstance(cwe, list):
                cwe = cwe[0] if cwe else ""
            findings.append(
                Finding(
                    cwe=cwe,
                    line=r["start"]["line"],
                    message=r.get("extra", {}).get("message", "").strip(),
                    evidence=r.get("extra", {}).get("lines", "").strip(),
                    confidence=0.9,
                    source=self.name,
                )
            )
        return findings
