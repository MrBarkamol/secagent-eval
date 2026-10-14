"""The agent's tools. All read-only, on purpose.

The agent can look at code but can never modify it, execute it, or reach the
network. That is a deliberate security decision worth stating in the write-up:
a review agent is pointed at UNTRUSTED code, so if it could write files or run
commands, the code under review could turn the agent into an attack vector
(prompt injection -> tool abuse). Read-only tools make that class of attack
impossible by construction.

Note the path-traversal guard in _resolve(): the agent reviews untrusted input,
so even its own file-reading tool refuses to escape the project root. The tool
that hunts for CWE-22 must not itself be vulnerable to CWE-22.
"""

from __future__ import annotations

import re
from pathlib import Path


class ToolContext:
    def __init__(self, root: str | Path, max_hits: int = 100):
        self.root = Path(root).resolve()
        self.max_hits = max_hits

    def _resolve(self, rel: str) -> Path:
        p = (self.root / rel).resolve()
        if self.root not in p.parents and p != self.root:
            raise ValueError(f"path escapes root: {rel}")
        return p

    def read_file(self, path: str, start: int | None = None,
                  end: int | None = None) -> str:
        """Return a file (or a line range) with line numbers, so the model can
        cite exact lines."""
        try:
            p = self._resolve(path)
        except ValueError as e:
            return f"[error: {e}]"
        if not p.is_file():
            return f"[error: no such file: {path}]"
        lines = p.read_text(errors="replace").splitlines()
        if start is None:
            selected, base = lines, 1
        else:
            s = max(1, start)
            e = end or len(lines)
            selected, base = lines[s - 1:e], s
        return "\n".join(f"{base + i:>4} | {ln}" for i, ln in enumerate(selected))

    def _normalize_glob(self, glob: str) -> str:
        """Models often pass an absolute path or a leading-slash path as the
        search scope. pathlib.glob rejects those, so coerce to a relative glob."""
        if not glob:
            return "**/*"
        p = Path(glob)
        if p.is_absolute():
            try:
                return str(p.relative_to(self.root))
            except ValueError:
                return p.name  # outside root -> fall back to the bare filename
        return glob.lstrip("/") or "**/*"

    def grep(self, pattern: str, glob: str = "**/*") -> str:
        """Search the codebase for a regex. Returns file:line: text hits."""
        try:
            rx = re.compile(pattern)
        except re.error as e:
            return f"[error: bad regex: {e}]"
        glob = self._normalize_glob(glob)
        if ".." in Path(glob).parts:
            return "[error: glob may not contain '..']"
        hits: list[str] = []
        for f in sorted(self.root.glob(glob)):
            if not f.is_file():
                continue
            # Same guard as read_file: never read outside the review root
            # (this also keeps the agent away from the answer key in labels.json).
            resolved = f.resolve()
            if self.root not in resolved.parents:
                continue
            try:
                for i, line in enumerate(f.read_text(errors="replace").splitlines(), 1):
                    if rx.search(line):
                        hits.append(f"{f.relative_to(self.root)}:{i}: {line.strip()}")
                        if len(hits) >= self.max_hits:
                            hits.append("[truncated]")
                            return "\n".join(hits)
            except OSError:
                continue
        return "\n".join(hits) if hits else "[no matches]"

    def find_callers(self, symbol: str, glob: str = "**/*") -> str:
        """Find where a function/method is CALLED (symbol followed by '(').
        Useful for tracing whether user input reaches a dangerous sink."""
        return self.grep(rf"{re.escape(symbol)}\s*\(", glob)


import inspect

# Real models are sloppy with argument names. Rather than demand perfection, we
# accept common synonyms and map them to the real parameter name.
_ALIASES = {
    "grep": {"query": "pattern", "regex": "pattern", "search": "pattern",
             "term": "pattern", "path": "glob", "file": "glob",
             "filename": "glob", "dir": "glob"},
    "read_file": {"file": "path", "filename": "path", "filepath": "path"},
    "find_callers": {"name": "symbol", "function": "symbol", "method": "symbol",
                     "func": "symbol"},
}


def dispatch(ctx: ToolContext, tool: str, args: dict) -> str:
    """Run a tool by name with a dict of args, returning the observation text.

    Robustness is the whole point here: a malformed tool call from the model
    must become an *observation* the model can learn from, never an exception
    that kills the run. We (1) map synonym arg names to the real ones, (2) drop
    unknown args with a note, and (3) turn any remaining TypeError (e.g. a
    missing required arg) into an error string the loop feeds back.
    """
    fn = getattr(ctx, tool, None)
    if tool not in _ALIASES or fn is None:
        return (f"[error: unknown tool '{tool}'. "
                f"available: read_file, grep, find_callers]")

    args = dict(args or {})
    # 1. normalize synonyms
    for syn, real in _ALIASES[tool].items():
        if syn in args and real not in args:
            args[real] = args.pop(syn)

    # 2. drop anything the function doesn't accept
    accepted = set(inspect.signature(fn).parameters)
    dropped = [k for k in list(args) if k not in accepted]
    for k in dropped:
        args.pop(k)

    # 3. call, turning ANY error into an observation (never a crash)
    try:
        result = fn(**args)
    except TypeError as e:
        return (f"[error calling {tool}: {e}. "
                f"accepted args: {sorted(accepted)}]")
    except Exception as e:  # noqa: BLE001 - a tool must not kill the run
        return f"[error calling {tool}: {type(e).__name__}: {e}]"
    if dropped:
        result = f"[note: ignored unexpected args {dropped}]\n{result}"
    return result
