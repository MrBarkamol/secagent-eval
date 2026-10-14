#!/usr/bin/env python3
"""Watch the real agent think on ONE vulnerable fixture, step by step.

Use this to see WHY a case is missed: does the model never propose the finding,
or does it propose one that the verifier then kills? The trace prints every
step's action, each tool call and its observation, the raw model text when it
can't be parsed, and each verify decision with its reason.

    python3 debug_agent.py                 # defaults to php_idor
    python3 debug_agent.py php_cmdi        # any sample id from labels.json
    python3 debug_agent.py php_idor --no-verify   # skip verification entirely

Sample ids: php_sqli php_cmdi php_pathtraversal php_massassign php_idor
"""

import sys
from pathlib import Path

from seceval.agent import AgentDetector, OllamaAdapter
from seceval.dataset import load_dataset

HERE = Path(__file__).parent


def main():
    args = [a for a in sys.argv[1:]]
    no_verify = "--no-verify" in args
    args = [a for a in args if not a.startswith("--")]
    sid = args[0] if args else "php_idor"

    samples = {s.id: s for s in load_dataset(HERE / "fixtures")}
    if sid not in samples:
        print(f"unknown sample '{sid}'. choices: {', '.join(samples)}")
        return
    s = samples[sid]

    model = OllamaAdapter(model="qwen2.5:7b-instruct")
    agent = AgentDetector(
        model, isolate=True,
        verify=not no_verify, verify_semantic=not no_verify, trace=True,
    )

    print("=" * 72)
    print(f"{s.id}  expected {s.cwe} at line {s.vuln_line}  "
          f"(verify={'off' if no_verify else 'on'})")
    print("=" * 72)
    findings = agent.analyze(str(s.vulnerable_path), s.vulnerable_code())
    print("-" * 72)
    print(f"RESULT: {len(findings)} finding(s) survived")
    for f in findings:
        print(f"  {f.cwe} line {f.line} (conf {f.confidence}) -- {f.message}")


if __name__ == "__main__":
    main()
