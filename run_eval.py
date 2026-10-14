#!/usr/bin/env python3
"""Run a detector over the fixture set and print a scored report.

Usage:
    python run_eval.py                 # runs the naive-regex baseline
    python run_eval.py --detector naive-regex

As you add detectors (a Semgrep wrapper, the LLM agent), register them in
DETECTORS below and compare them on identical data. The point of the harness
is that this command is the single source of truth for "is the new thing
actually better than the old thing."
"""

from __future__ import annotations

import argparse
from pathlib import Path

from seceval.agent import AgentDetector, OllamaAdapter
from seceval.agent.retrieval import BM25Retriever
from seceval.baselines import NaiveRegexDetector
from seceval.dataset import load_dataset
from seceval.hybrid_detector import HybridDetector
from seceval.metrics import Report, evaluate
from seceval.semgrep_detector import SemgrepDetector

HERE = Path(__file__).parent
FIXTURES = HERE / "fixtures"
DATASETS = {"main": HERE / "fixtures", "heldout": HERE / "fixtures_heldout",
            "main-nocomments": HERE / "fixtures_nocomments"}
SEMGREP_RULES = HERE / "semgrep_rules" / "php-security.yml"
KB_PATH = HERE / "fixtures" / "knowledge" / "security_kb.json"

# Register detectors here by name. Each entry is a zero-arg factory.
# The agent is NOT here by default because it needs a running local model; add
# it with --with-agent MODELSPEC once you have one (see build_agent).
COMMUNITY_RULES = HERE / "semgrep_rules" / "community-php.yml"

DETECTORS = {
    "naive-regex": NaiveRegexDetector,
    "semgrep": lambda: SemgrepDetector(SEMGREP_RULES),
}
# Semgrep's public PHP ruleset, if downloaded (see README). It was not written by
# me and has never seen these fixtures, so it is a fair, untailored static
# baseline -- unlike my own five rules above.
if COMMUNITY_RULES.exists():
    DETECTORS["semgrep-community"] = lambda: SemgrepDetector(
        COMMUNITY_RULES, name="semgrep-community")


def build_agent(spec: str, verify_semantic: bool = True,
                temperature: float = 0.2, hint: bool = True,
                rag: bool = False) -> AgentDetector:
    """Build the agent from a model spec. Currently supports 'ollama:<model>',
    e.g. --with-agent ollama:qwen2.5:7b-instruct"""
    if spec.startswith("ollama:"):
        model = spec.split(":", 1)[1]
        retriever = BM25Retriever(KB_PATH) if rag else None
        return AgentDetector(
            OllamaAdapter(model=model, temperature=temperature),
            verify_semantic=verify_semantic, isolate=True,
            hint=hint, retriever=retriever)
    raise SystemExit(f"unknown model spec '{spec}'. Try ollama:<model-name>.")


def build_hybrid(spec: str, verify_semantic: bool = True,
                 temperature: float = 0.2) -> HybridDetector:
    """Semgrep for pattern bugs + a RETRIEVAL-grounded agent for what Semgrep
    misses.

    Earlier the hybrid used a hint-only agent and underperformed. The standalone
    experiment showed the retrieval (RAG) agent was by far the strongest
    configuration, so the hybrid now uses it: Semgrep handles the pattern
    classes, and the grounded agent adds the missing-check bugs (IDOR) that no
    static rule can match. Duplicates are removed by the hybrid, so the agent's
    overlap with Semgrep is dropped."""
    if not spec.startswith("ollama:"):
        raise SystemExit(f"unknown model spec '{spec}'. Try ollama:<model-name>.")
    model = spec.split(":", 1)[1]
    agent = AgentDetector(
        OllamaAdapter(model=model, temperature=temperature),
        verify_semantic=verify_semantic, isolate=True,
        hint=False, retriever=BM25Retriever(KB_PATH))
    return HybridDetector(SemgrepDetector(SEMGREP_RULES), agent)


def print_report(report: Report) -> None:
    line = "=" * 72
    print(line)
    print(f"Detector: {report.detector_name}")
    print(line)

    header = f"{'sample':<18}{'CWE':<10}{'llm_value':<11}{'caught':<8}{'silent_fix':<12}{'fp':<4}"
    print(header)
    print("-" * 72)
    for r in report.results:
        print(
            f"{r.sample_id:<18}{r.cwe:<10}{r.llm_value:<11}"
            f"{('yes' if r.caught else 'NO'):<8}"
            f"{('yes' if r.silent_on_fix else 'NO'):<12}{r.fp:<4}"
        )

    print(line)
    print("Aggregate")
    print("-" * 72)
    print(f"  true positives : {report.tp}")
    print(f"  false negatives: {report.fn}")
    print(f"  false positives: {report.fp}")
    print(f"  precision      : {report.precision:.3f}   (of flagged, how much was real)")
    print(f"  recall         : {report.recall:.3f}   (of real bugs, how many caught)")
    print(f"  f1             : {report.f1:.3f}")
    print(f"  FP per KLOC    : {report.fp_per_kloc:.2f}")
    print(f"  silent-on-fix  : {report.silent_on_fix_rate:.3f}   (fraction of fixes left alone)")
    print(line)


def print_comparison(reports: list[Report]) -> None:
    line = "=" * 72
    print(line)
    print("Detector comparison (same fixtures, same scoring)")
    print(line)
    print(f"{'detector':<16}{'precision':<11}{'recall':<9}{'f1':<8}{'FP/KLOC':<10}{'silent-fix':<11}")
    print("-" * 72)
    for r in reports:
        print(
            f"{r.detector_name:<16}{r.precision:<11.3f}{r.recall:<9.3f}"
            f"{r.f1:<8.3f}{r.fp_per_kloc:<10.2f}{r.silent_on_fix_rate:<11.3f}"
        )
    print(line)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--detector", default="naive-regex", choices=list(DETECTORS))
    ap.add_argument("--compare", action="store_true",
                    help="run every registered detector and print a comparison table")
    ap.add_argument("--with-agent", metavar="MODELSPEC", default=None,
                    help="add the LLM agent using a local model, e.g. ollama:qwen2.5:7b-instruct")
    ap.add_argument("--agent-no-semantic", action="store_true",
                    help="run the agent with the semantic verifier OFF (mechanical check only)")
    ap.add_argument("--agent-temp", type=float, default=0.2,
                    help="agent model temperature; use 0 for reproducible runs (default 0.2)")
    ap.add_argument("--agent-no-hint", action="store_true",
                    help="remove the specific IDOR example from the agent prompt")
    ap.add_argument("--agent-rag", action="store_true",
                    help="give the agent retrieval over the local security knowledge base")
    ap.add_argument("--dataset", choices=list(DATASETS), default="main",
                    help="'main' (5 pairs), 'heldout' (4 unseen pairs), or 'main-nocomments' "
                         "(main set with code comments removed)")
    args = ap.parse_args()

    samples = load_dataset(DATASETS[args.dataset])
    verify_semantic = not args.agent_no_semantic
    temp = args.agent_temp
    hint = not args.agent_no_hint
    rag = args.agent_rag

    if args.compare:
        factories = dict(DETECTORS)
        if args.with_agent:
            factories["agent"] = lambda: build_agent(args.with_agent, verify_semantic, temp, hint, rag)
            factories["hybrid"] = lambda: build_hybrid(args.with_agent, verify_semantic, temp)
        reports = [evaluate(f(), samples) for f in factories.values()]
        print_comparison(reports)
        return

    detector = (build_agent(args.with_agent, verify_semantic, temp, hint, rag)
                if args.with_agent else DETECTORS[args.detector]())
    report = evaluate(detector, samples)
    print_report(report)


if __name__ == "__main__":
    main()
