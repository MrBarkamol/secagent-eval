# Build a local AI security agent — decisions & findings

*Submission for the Safia ML Engineer case study.*

**Author:** Ismailov Barkamol
**Year of study:** 4th year (final year), Economics and Data Science, New Uzbekistan University
**Run instructions:** see `README.md`.

---

## TL;DR (the honest version)

I built a local code-security agent and, more importantly, a harness to measure
whether it actually works, then tested it on cases it had never seen.

| detector                     | main set f1 (5 pairs, seen) | held-out f1 (4 pairs, unseen) |
|------------------------------|-----------------------------|-------------------------------|
| naive-regex                  | 0.727                       | 0.000                         |
| semgrep (my rules)           | 0.800                       | 0.000                         |
| semgrep (public `p/php` rules) | 0.000                     | 0.000                         |
| agent, hint                  | 0.545                       | 0.333                         |
| agent + RAG                  | 0.889                       | 0.571                         |
| **hybrid (Semgrep + RAG agent)** | **0.909**               | 0.571                         |

*(local `qwen2.5:7b-instruct`, temperature 0, one run per configuration; full
tables in sections 5, 7, 8 and 9.)*

**The main-set numbers look excellent and are mostly tailoring.** On the five
fixtures I had seen, the hybrid caught all five bugs. On four new fixtures written
after everything was frozen, it caught two, and my Semgrep rules caught none.
Semgrep's public PHP ruleset, which was never tailored to anything here, caught
none on either set: it does not recognise Laravel idioms at all.

**What holds up is narrower but real.** The LLM generalises better than
hand-written rules, catches bug shapes the rules never anticipated, and never
flagged a fixed file. Grounding it with retrieved security knowledge helps when
retrieval picks the right entry and hurts when it doesn't, so retrieval quality
is the next thing to improve. Nine fixture pairs in total is small; treat this as
evidence for the approach, not proof.

---

## 1. How I read the task

The brief left five things deliberately open, and I treated answering them as the
real work:

1. what "agent" means,
2. how it learns / what knowledge it uses,
3. what it is allowed to do,
4. how it verifies a finding,
5. how it explains a result.

I organised the whole project around those five decisions.

## 2. The core design principle

The weak version of this task is "paste code into an LLM and ask what's
vulnerable." I rejected that early, for concrete reasons: a model can't hold a
real codebase in context, it hallucinates findings and line numbers, it floods
you with false positives (which is what gets security tools uninstalled), and if
the test code is famous it may be *remembering* bugs rather than reasoning.

So my principle is: **the deterministic tools do the broad, reliable work; the
LLM does only the judgement the tools are bad at.** Static analysers are fast,
reproducible, and don't hallucinate — but they're blind to context. The LLM's
job is to reason about the context they can't see: above all, *missing* checks
like broken object-level authorization (IDOR), which have no pattern to match.

## 3. Architecture

**The agent (`seceval/agent/`).** A reason→act→observe loop (ReAct). The model
investigates with read-only tools (`read_file`, `grep`, `find_callers`) before
concluding, then reports findings. A step limit prevents infinite loops.

**What it's allowed to do.** The tools are strictly read-only. The agent reviews
*untrusted* code, so if it could write files, run commands, or reach the network,
the code under review could turn it into an attack vector (prompt injection →
tool abuse). The file tool even guards against path traversal — the thing that
hunts CWE-22 must not itself be vulnerable to CWE-22. Auto-exploitation is an
explicit non-goal: this is a review agent, and exploitation adds risk without
improving the findings.

**How it verifies.** A two-layer verifier. First a *mechanical* check (pure code,
no model): does the cited line exist and contain the quoted evidence? This is a
free hallucination guard. Then a *semantic* check: a second model pass that tries
to *disprove* the finding, judging only on visible code. Only survivors are
reported.

**How it explains.** Every finding carries a CWE, the exact file:line evidence, a
short message, and a confidence score.

**The model seam (`adapter.py`).** The whole agent is written against one tiny
interface, so the model is swappable. I run a local model via Ollama to satisfy
the "local model" requirement; a mock model lets me test all the machinery
without a real model.

**The hybrid (`hybrid_detector.py`).** Semgrep for the pattern bugs it nails, the
retrieval-grounded agent for what Semgrep misses, merged and deduped. (An earlier
version used a hint-only agent focused on authorization bugs; it was weaker, see
section 5.)

## 4. Evaluation — the part I'm most deliberate about

I built the measurement layer *first*, on purpose. A security tool you can't
measure is a demo, not an engineering result, and "it found some bugs" is not
evidence.

- **Paired data.** Every test case has a vulnerable file *and* its patched twin.
  A good detector flags the vulnerable one with the right CWE and stays *silent*
  on the fix. The silent-on-fix rate is the headline trust metric, because
  confident false positives are the characteristic failure of LLM security tools.
- **Contamination control.** The fixtures are small and hand-written rather than
  drawn from a famous benchmark (Juice Shop, DVWA), because those are almost
  certainly in a model's training data — a high score there could be memorisation,
  not reasoning.
- **Metrics with a reason:** precision, recall, FP/KLOC (a proxy for alert
  fatigue), and silent-on-fix. Accuracy is meaningless on an imbalanced task
  where "no finding" is usually correct.
- **Honest scoring rules.** Correctness is gated on the CWE matching a per-case
  *accepted set* (authorization bugs are legitimately labelled 639/863/862/285),
  not an exact code, because tools and humans disagree on the exact CWE.

## 5. Results, read honestly

The regex baseline false-positives on *fixed* command-injection and
path-traversal code: it sees concatenation and is blind to the sanitiser.
Semgrep parses structure, so `pattern-not` lets it ignore the
`escapeshellarg()`-wrapped command and its precision climbs. Both static tools
are stuck at recall 0.8 because neither can see the IDOR, a *missing* ownership
check. That is the one case the LLM is supposed to win.

**The agent's quality depends heavily on grounding** (full data in section 7).
Told what an IDOR looks like, the standalone agent caught 3 of 5 (sqli, path
traversal, idor) with some false positives. Given retrieval instead of a hint it
reached 4 of 5 with none. The classes it struggles with are command injection
(retrieval ranks it poorly) and, without help, mass assignment.

**The hybrid is only as good as the agent inside it.** With the focused hint
agent, the hybrid gave recall 0.8 and precision 0.5 (f1 0.615), below Semgrep,
because that agent added false positives without landing the IDOR. Swapping in
the retrieval agent changed this completely: recall 1.0, precision 0.833, f1
0.909, the best result in the project. The two halves cover each other's gaps.
The RAG agent missed command injection, which Semgrep catches; Semgrep misses the
IDOR, which the RAG agent catches. FP/KLOC (5.43) is identical to Semgrep's, so
the agent added no new false alarms; the one false positive left is Semgrep
flagging the fixed path traversal.

## 6. The most useful part: a diagnosis, not a number

The agent's first run scored **recall 0.2**. Rather than guess, I instrumented the
loop (`debug_agent.py`) to print every step, tool call, observation, and verifier
decision. Two distinct bugs fell out:

1. **The semantic verifier was over-suppressing.** It killed a correct IDOR
   finding by *inventing a mitigation it could not see* — "the route is likely
   protected by authentication middleware." I rewrote the verifier prompt to
   judge only on visible code and never assume unseen protections. The finding
   then survived.
2. **CWE mismatch.** The model reported `CWE-863` (Incorrect Authorization); the
   label expected `CWE-639` (IDOR). These are the same bug. I added a per-case
   accepted-CWE set so equivalent authorization codes count.

After both fixes the IDOR case passed when I ran it on its own, but full-set recall
stayed at 0.2 and false positives appeared: the less suspicious verifier now let
more weak findings through. Setting temperature to 0 made runs reproducible. I
then built the hybrid and gave its agent a narrow job: report only authorization
flaws, because Semgrep already covers the injection classes.

Reviewing my own harness afterwards, I found two flaws that could have flattered
the agent, and fixed both:

1. **The `grep` tool could leave the project root** with a pattern like `../*`,
   which could even reach `labels.json`, the answer key. `read_file` was guarded
   but `grep` was not. It now rejects `..` and skips any file outside the root.
2. **The agent could see the fixed twin of each file.** All fixtures share one
   folder, so while reviewing `idor_vulnerable.php` the agent's searches also
   returned lines from `idor_fixed.php`, letting it "find" the bug by comparing
   with the answer. Each file is now reviewed in an isolated copy, and all
   numbers in this document come from runs after this fix.

The hint-based hybrid also turned out to be fragile. Right after these fixes its
focused agent caught the IDOR (recall 1.0); after a later, small rewording of the
base prompt it no longer did (recall 0.8, f1 0.615). A result that flips with
prompt wording is not one to rely on, which is part of why I moved the hybrid to
the retrieval agent.

This diagnosis arc — measure, instrument, find the real cause, fix it, re-measure,
and keep being honest when it still isn't enough — is the part of the project I'd
most want to be judged on.

## 7. Extra experiment: can it learn instead of being told?

The brief asks how the agent *learns*. The main agent is simply **told** what an
IDOR looks like, in its prompt (a hint). To test whether it can instead pick up
the relevant knowledge at run time, I added a small local **knowledge base** of
~18 weakness classes and a **BM25 retriever** (`seceval/agent/retrieval.py`).
Before reviewing a file, the agent retrieves the most relevant entries and puts
them in the prompt — this is the RAG ("retrieval-augmented generation") step. No
embedding model or network is needed, which suits 8 GB RAM.

The knowledge base deliberately covers far more classes than the five tested, so
retrieval has to *select* the right guidance rather than be handed the answer.
For the IDOR file it returns the IDOR entry first; across the five fixtures it
returns the correct class in the top 3 for **4 of 5** — command injection is
outranked by entries sharing generic tokens like "request"/"host", a real
limitation of keyword retrieval.

Three configurations of the standalone agent (temperature 0, isolated files):

| configuration            | recall | precision | f1    | notes |
|--------------------------|--------|-----------|-------|-------|
| no hint, no RAG          | 0.400  | 0.500     | 0.444 | the model's own knowledge only (caught cmdi, path) |
| hint (prompt names IDOR) | 0.600  | 0.500     | 0.545 | current default (caught sqli, path, idor) |
| **RAG, no hint**         | **0.800** | **1.000** | **0.889** | retrieves guidance instead of being told (caught sqli, path, mass-assignment, idor; 0 false positives) |

Reproduce with:

```bash
python3 run_eval.py --with-agent ollama:qwen2.5:7b-instruct --agent-temp 0 --agent-no-hint
python3 run_eval.py --with-agent ollama:qwen2.5:7b-instruct --agent-temp 0
python3 run_eval.py --with-agent ollama:qwen2.5:7b-instruct --agent-temp 0 --agent-no-hint --agent-rag
```

Retrieval helped more than the hint. With no help the agent caught 2 of 5; told
what an IDOR looks like it caught 3 of 5; given retrieval over the knowledge base
it caught 4 of 5 with **zero false positives** — including the IDOR and the mass
assignment it was never told about. The only miss was command injection, which
the retriever ranked poorly (it shares generic tokens like "request"/"host" with
other entries), so the result is consistent with the retrieval limitation noted
above. This is concrete evidence that the agent can pick up the relevant
knowledge at run time rather than needing it hard-coded in the prompt — and on
this small set the retrieval-grounded agent (f1 0.889) even edged the Semgrep
baseline (0.800). Caveats remain: five fixtures, one run, and a knowledge base
that does contain descriptions of these weakness classes (as any security
reference would).

## 8. Held-out test: does any of this generalise?

Everything above was measured on five fixtures that I had seen while writing the
Semgrep rules, the prompts and the knowledge base. Two of them (IDOR and mass
assignment) even contain comments that describe the bug. So I wrote a
**held-out set** of four new vulnerable/fixed pairs (`fixtures_heldout/`) after
freezing all rules, prompts and knowledge-base entries, in code shapes different
from the main set and with no comments: SQL injection through Eloquent
`whereRaw`, command injection through `exec(sprintf(...))`, a missing
`authorize()` on a route-model-bound update, and an open redirect (a class not in
the main set at all). I changed nothing after seeing the results.

| detector (held-out, 4 pairs) | precision | recall | f1    | caught |
|------------------------------|-----------|--------|-------|--------|
| naive-regex                  | 0.000     | 0.000  | 0.000 | none |
| semgrep                      | 0.000     | 0.000  | 0.000 | none |
| agent, no help               | 1.000     | 0.500  | 0.667 | cmdi, redirect |
| agent, hint                  | 0.500     | 0.250  | 0.333 | one of four |
| agent + RAG                  | 0.667     | 0.500  | 0.571 | idor, redirect |
| hybrid (Semgrep + RAG agent) | 0.667     | 0.500  | 0.571 | idor, redirect |

What this shows:

- **The static rules did not generalise at all.** Semgrep went from 0.8 recall
  on the main set to 0 here. Its main-set score came entirely from rules written
  for those exact files; a different call (`whereRaw`, `sprintf`) defeats them.
- **The LLM generalises better than the rules, but not well.** Every agent
  configuration caught something the rules missed, and none raised an alarm on a
  fixed file. But the best held-out recall is 0.5, far below the main-set
  numbers, which confirms those numbers were optimistic.
- **Retrieval helps only when it retrieves the right thing.** Before running the
  model I checked the retriever on these files: it chose the right knowledge for
  the IDOR and redirect cases, but not for SQL injection or command injection.
  The RAG agent's results follow that exactly: it caught the IDOR and the
  redirect, and missed the other two. On command injection, misleading
  retrieved text even made it worse than the agent with no help, which caught
  it. Bad retrieval is not neutral; it can steer the model wrong.
- **Nothing caught the `whereRaw` SQL injection**, the simplest bug in the set.
- **The hybrid adds nothing here** because Semgrep found nothing, so it equals
  the RAG agent.

With only four pairs, each case is worth 25 points of recall, so these numbers
are noisy. But the direction is clear and consistent.

## 9. Robustness checks

Three quick checks on claims the earlier results depend on.

**An untailored static baseline.** My "Semgrep" row uses five rules I wrote with
the main fixtures in view, so its held-out zero only proves *my* rules overfit.
To test static analysis fairly, I ran Semgrep's public `p/php` ruleset (24 rules,
not written by me). It found **nothing on either set**: f1 0 on the main set and 0
on the held-out set. To make sure this was not a setup problem, I ran the same
rules on a three-line raw-PHP file with a textbook `$_GET` → `mysqli_query` SQL
injection, and they flagged it correctly. So the ruleset works; it just does not
recognise Laravel idioms such as `$request->input()`, Eloquent and route model
binding. Static analysis is only as good as its fit to the framework: generic
rules miss everything here, and framework-specific rules written for one shape
miss the next shape.

**Comment leak.** Two main fixtures contain comments describing the bug. I
re-ran the RAG agent on a copy of the main set with every comment removed
(`fixtures_nocomments/`). The result was identical: the same four bugs, f1
0.889. For this configuration, the catches came from the code and the retrieved
knowledge, not from the comments.

**Verifier ablation.** I re-ran the RAG agent with the semantic verifier (the
second "try to disprove it" model pass) switched off. The result was identical:
f1 0.889. For this configuration the semantic verifier never rejected a finding,
so it cost an extra model call per finding with no measured benefit. Earlier in
the project it was actively harmful until I fixed its prompt (section 6). Its
value is therefore unproven by my data; it may help noisier configurations, such
as the hint agent that produced false positives, but I have not measured that.
The cheap mechanical check (does the cited line exist and match?) stays on in
every configuration.

## 10. Honest conclusion

On the fixtures I had seen, the best design scored very well: Semgrep plus a
retrieval-grounded agent caught all five bugs (f1 0.909). On fixtures I had not
seen, that dropped to half the bugs (f1 0.571), and the hand-written rules
dropped to zero. That gap is the most important result in this project: most of
the main-set performance came from tailoring, not from general capability.

What survives the held-out test is narrower but real. A small local LLM
generalises better than hand-written rules, catches bug shapes the rules never
anticipated, and stayed quiet on every fixed file. Static analysis, by contrast,
was all-or-nothing: generic public rules found nothing in Laravel code, and my
framework-specific rules found only the exact shapes they were written for. Grounding it with retrieved
security knowledge helps when retrieval finds the right entry and hurts when it
does not, so retrieval quality, not just the model, is what to improve next.

The design I would stand behind: a static analyzer for well-understood
patterns, a retrieval-grounded LLM pass for authorization and logic flaws, a
verifier between them, and a human triaging the output, judged only on data the
system was not built against. This is evidence for the design, not proof: nine
fixture pairs in total, one run per configuration, a 7B model.

## 11. Limitations (stated plainly)

- **Tiny dataset.** Five fixture pairs demonstrate the method but are far too few
  for statistically meaningful numbers. Treat the table as illustrative.
- **Test-set leakage on the main set.** The Semgrep rules, prompts and knowledge
  base were written with the main fixtures in view, and two main fixtures contain
  comments describing the bug. The held-out set (section 8) shows how much this
  inflated the main-set scores.
- **The held-out set is small and has the same author.** Four pairs, written by
  the same person who wrote the rules and prompts, even though nothing was changed
  after seeing the results.
- **The semantic verifier's value is unproven.** Switching it off changed
  nothing for the best configuration (section 9).
- **Keyword retrieval.** BM25 ranked command injection poorly; an embedding-based
  retriever or richer knowledge-base entries might fix that.
- **One language/framework.** PHP/Laravel only (chosen because it's likely close
  to what Safia runs, and underserved by existing benchmarks).
- **Model ceiling.** I have 8 GB RAM, so I could not test a 14B/32B model. The
  7B was already straining the machine. I also used the general Qwen2.5 model
  and did not compare it with the code-specialised Qwen2.5-Coder variant.
- **Not built:** a LoRA fine-tune experiment, a true black-box mode, and
  multi-run variance measurement. All are scoped below.

## 12. What I'd do next (in priority order)

1. **Better retrieval** — the held-out failures track retrieval failures. Split
   identifiers like `whereRaw` into words, enrich knowledge-base entries, and try
   embeddings alongside BM25. Measure retrieval accuracy separately from the agent.
2. **A larger held-out dataset written by someone else** — more classes, more
   languages, and real CVE fixes, so the author cannot tailor anything to it.
3. **Measure the verifier where it should matter** — on the noisier hint agent
   and on the held-out set, to decide whether the extra model call earns its cost.
4. **Variance measurement** — run each configuration N times and report mean ±
   std, since the model is non-deterministic.
5. **Semgrep taint mode** for path traversal, which removes the one false
   positive left in the best configuration.
6. **A bigger or code-specialised model** (Qwen2.5-Coder, 14B–32B) on hardware
   with more memory.
7. **A black-box mode** (reason over HTTP responses, headers, the client bundle),
   which the brief hinted at with "find vulnerabilities without accessing source
   code."

## 13. On the optional security assessment

I treated the live-app assessment as the optional, secondary challenge the email
described, and did not let it crowd out the primary task. I kept strictly within
the authorised scope and the confidentiality rules, and prioritised building a
sound, measurable agent over opportunistic testing. I did not run any tests
against Safia's applications.

## 14. Tools, model, and methodology

- **Language/stack:** Python 3; Semgrep (custom local rules); Ollama serving
  `qwen2.5:7b-instruct` locally; macOS, 8 GB RAM.
- **AI tools:** I used AI tools for writing the code.
- **Methodology:** measurement-first. Build the eval harness, establish baselines,
  add the LLM only where baselines are blind, and judge every change by the same
  `run_eval.py --compare` rather than by impression.
