# seceval — evaluation harness for a code-security agent

This is the **measurement layer** of the security-agent project, built first and
on purpose. A security tool that cannot be measured is a demo, not an
engineering result. Everything else — the LLM agent, scanner integration,
retrieval — plugs into this harness as a `Detector` and is scored the same way,
so claims like "the agent beats the baseline" become numbers instead of
opinions.

## Why evaluation first

The characteristic failure of LLM security tools is **confident false
positives**. You cannot see that failure by counting how many bugs a tool
"finds"; you can only see it by also checking how often it cries wolf on code
that is already safe. So the harness is built around **paired data**: every
test case has a `*_vulnerable` file and a `*_fixed` file. A good detector flags
the vulnerable one with the right CWE and stays **silent** on the fix. The
silent-on-fix rate is the headline trust metric.

## What's here

```
fixtures/
  labels.json                 ground truth: each sample's CWE, files, vuln line
  php/*_vulnerable.php         textbook-vulnerable Laravel snippets
  php/*_fixed.php              their patched counterparts
seceval/
  detector.py                 Finding + Detector interface (the plug point)
  dataset.py                  loads fixtures + labels
  metrics.py                  scoring rules, written out explicitly
  baselines.py                a deliberately naive regex detector
  semgrep_detector.py         wraps Semgrep (real static-analysis baseline)
  hybrid_detector.py          Semgrep + the retrieval-grounded agent
  agent/                      the LLM security agent
    adapter.py                model seam: ModelAdapter, MockModel, OllamaAdapter
    tools.py                  read-only investigation tools (read_file/grep/...)
    loop.py                   the reason->act->observe loop + AgentDetector
    verifier.py               mechanical + semantic checks on findings
    prompts.py                system + verifier prompts
    parsing.py                tolerant JSON extraction
    retrieval.py              BM25 retriever over the security knowledge base (RAG)
semgrep_rules/
  php-security.yml            custom Semgrep rules for the fixture classes
fixtures/knowledge/
  security_kb.json            ~18 weakness classes for retrieval (RAG)
fixtures_heldout/             4 unseen pairs, written after everything was frozen
fixtures_nocomments/         the main set with code comments removed
run_eval.py                   runs a detector (or --compare), prints the report
demo_agent.py                 drives the agent over the IDOR case with a mock
debug_agent.py                full step-by-step trace of the real agent on one case
WRITEUP.md                    decisions, results, diagnosis, limitations
```

## Run it

```bash
python3 run_eval.py                      # naive-regex baseline
python3 run_eval.py --detector semgrep   # Semgrep baseline (needs semgrep installed)
python3 run_eval.py --compare            # all detectors, side by side
```

The Semgrep detector needs the tool installed. A virtualenv keeps it off your
system Python:

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install semgrep
```

The rules in `semgrep_rules/` are custom and local, so no registry/network is
needed to reproduce the results.

## The fixtures, and why these five

| sample | CWE | LLM value | why it's in the set |
|---|---|---|---|
| SQL injection | CWE-89 | low | clean source→sink flow; static tools already do this well |
| Command injection | CWE-78 | medium | the *fix* still concatenates (`escapeshellarg`), so naive tools false-positive on safe code |
| Path traversal | CWE-22 | medium | same trap: `basename()` neutralizes it, but there's no new pattern to see |
| Mass assignment | CWE-915 | high | exploitability depends on `$fillable`/`$guarded` in *another file* — needs cross-file context |
| IDOR / broken access control | CWE-639 | high | the bug is a **missing** ownership check; there is no string to match at all |

The `LLM value` column is a claim the harness is designed to test: the baseline
should handle the "low" rows and fail the "high" rows, and the agent should
close that gap. The fixtures are intentionally small and hand-written rather
than drawn from a famous benchmark (Juice Shop, DVWA, etc.) to avoid **training
-data contamination** — if the test code is in the model's training set, a good
score may be memorization, not reasoning.

## Scoring (see `metrics.py` for the exact rules)

- **Precision** — of what you flagged, how much was real.
- **Recall** — of the real bugs, how many you caught.
- **FP per KLOC** — false positives normalized by code size; a proxy for alert
  fatigue, the thing that gets security tools uninstalled.
- **Silent-on-fix rate** — fraction of patched files left correctly untouched.

Correctness is gated on the **CWE matching**, not on an exact line number (a
reasonable tool may point at the source line or the sink line); line proximity
is reported as a secondary stat.

## Results

All rows are scored on the same fixtures by the same code. Agent and hybrid use a
local `qwen2.5:7b-instruct` at temperature 0 (`--agent-temp 0`) so runs repeat.

```
detector        precision  recall   f1      FP/KLOC   silent-fix
naive-regex     0.667      0.800    0.727   10.87     0.600
semgrep         0.800      0.800    0.800   5.43      0.800
agent (hint)    0.500      0.600    0.545   16.30     0.600
agent + RAG     1.000      0.800    0.889    0.00     1.000
hybrid (hint)   0.500      0.800    0.615   21.74     0.800
hybrid (RAG)    0.833      1.000    0.909    5.43     0.800
```

What each row teaches:

- **naive-regex** false-positives on the fixed command-injection and
  path-traversal files: it sees concatenation and is blind to the sanitizer.
- **semgrep** matches structure, so `pattern-not` ignores the
  `escapeshellarg()`-wrapped command and precision climbs. It still flags the
  fixed path traversal, because `basename()` is applied on a previous line.
- **Both static tools miss the IDOR**: a *missing* ownership check has nothing
  to match.
- **The 7B agent** depends on grounding: told what IDOR looks like it catches 3
  of 5; with retrieval (RAG) it reaches 4 of 5 at perfect precision, the best row.
- **The hybrid** is only as good as its agent: with the hint agent it scored
  f1 0.615; with the retrieval agent it is the best configuration (recall 1.0,
  f1 0.909), adding the IDOR with no new false positives. See `WRITEUP.md` for
  the caveats: tiny dataset, one run, and rules/KB written for these classes.

## The agent

The agent is a reason→act→observe loop (`agent/loop.py`) with read-only tools
(`agent/tools.py`) and a verifier (`agent/verifier.py`), all written against one
model interface (`agent/adapter.py`) so the model is swappable. It is designed to
catch exactly what the static tools cannot: the IDOR, a *missing* ownership check
that has no pattern to match.

Key design decisions (defensible talking points):
- **Read-only tools.** The agent reviews untrusted code, so it can never write,
  execute, or reach the network. A review agent that could edit or run code would
  itself be an attack surface (prompt injection → tool abuse). The file tool even
  guards against path traversal — the thing that hunts CWE-22 must not be
  vulnerable to CWE-22.
- **A verifier that tries to disprove each finding.** Mechanical first (does the
  cited line exist and match the quoted evidence? — a free hallucination guard),
  then semantic (a second model pass arguing the finding is *not* exploitable).
  This targets the characteristic LLM failure: confident false positives.
- **A step limit.** Without it a confused model loops forever; on timeout the
  agent returns nothing rather than guess.

### Prove the machinery (no model needed)

```bash
python3 demo_agent.py
```

A scripted `MockModel` walks the IDOR case — grep, grep, report, verify. This
proves the loop/tools/verifier work end to end. It is PLUMBING, not reasoning:
the mock is told what to do, so it produces no meaningful score.

### Run it for real (needs a local model)

The reasoning must run on a local model to satisfy the brief. Easiest path is
Ollama:

```bash
# install ollama from https://ollama.com, then:
ollama pull qwen2.5:7b-instruct
python3 run_eval.py --compare --with-agent ollama:qwen2.5:7b-instruct --agent-temp 0
```

Useful extras:

```bash
python3 debug_agent.py php_idor            # watch the agent reason on one case
python3 debug_agent.py php_idor --no-verify
python3 run_eval.py --compare --with-agent ollama:qwen2.5:7b-instruct \
    --agent-temp 0 --agent-no-semantic    # ablation: semantic verifier off

# RAG experiment: can the agent learn instead of being told?
python3 run_eval.py --with-agent ollama:qwen2.5:7b-instruct --agent-temp 0 --agent-no-hint
python3 run_eval.py --with-agent ollama:qwen2.5:7b-instruct --agent-temp 0 --agent-no-hint --agent-rag
```

This adds the `agent` and `hybrid` rows to the comparison. Numbers only count
when they come from the real model; the mock proves plumbing, not reasoning.

## Held-out test

Four extra pairs in `fixtures_heldout/` were written after the rules, prompts and
knowledge base were frozen, in different code shapes and with no comments.

```bash
python3 run_eval.py --compare --dataset heldout --with-agent ollama:qwen2.5:7b-instruct --agent-temp 0
```

Both static tools score 0 there; the best agent configurations catch 2 of 4. The
main-set numbers above are therefore optimistic. See `WRITEUP.md` section 8.

## Extra checks

```bash
# A fair static baseline: Semgrep's public PHP ruleset (not written by me).
curl -sL https://semgrep.dev/c/p/php -o semgrep_rules/community-php.yml
python3 run_eval.py --compare                    # adds a semgrep-community row
python3 run_eval.py --compare --dataset heldout

# Comment leak: the main set with all code comments removed.
python3 run_eval.py --dataset main-nocomments --with-agent ollama:qwen2.5:7b-instruct \
    --agent-temp 0 --agent-no-hint --agent-rag

# Verifier ablation: the RAG agent with the semantic verifier switched off.
python3 run_eval.py --with-agent ollama:qwen2.5:7b-instruct \
    --agent-temp 0 --agent-no-hint --agent-rag --agent-no-semantic
```

Results: the public `p/php` ruleset found nothing on either set (it does flag a
raw `$_GET` SQL injection, so it works; it just does not recognise Laravel
idioms). Removing comments and switching off the semantic verifier both left the
RAG agent's result unchanged (f1 0.889). Details in `WRITEUP.md` section 9.

## Possible next steps

1. A **held-out fixture set**, written after the rules and prompts are frozen,
   to remove the optimism in the current numbers.
2. **Retrieval** over CWE / OWASP guidance, to ground the agent's reasoning.
3. A **larger model** (14B–32B) on hardware with more memory.
4. **Semgrep taint mode** for path traversal.
5. **Multiple runs per configuration**, reporting mean and spread.

### Hardware note

Results above were produced on a MacBook with 8 GB RAM, which is enough for a
7B model through Ollama but not for 14B or larger. The first request after the
model loads can be slow; the adapter retries on transient server errors.
