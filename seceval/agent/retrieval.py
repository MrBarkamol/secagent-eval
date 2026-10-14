"""Retrieval over a local security knowledge base (the "learning" step).

This is the RAG component. Before the agent reviews a file, it retrieves the few
most relevant weakness descriptions from a local knowledge base and puts them in
the prompt, so the model reasons with grounded, citable guidance instead of only
its own memory.

Retrieval is plain BM25 over the knowledge base — no embedding model, no network,
no extra memory, which suits an 8 GB machine. The knowledge base covers ~18
weakness classes, far more than the five we test, so retrieval has to actually
SELECT the right guidance; it is not handed the answer.
"""

from __future__ import annotations

import json
import math
import re
from collections import Counter
from pathlib import Path


def _tokens(text: str) -> list[str]:
    return re.findall(r"[a-zA-Z_][a-zA-Z0-9_]+", text.lower())


class BM25Retriever:
    def __init__(self, kb_path: str | Path, k: int = 3, k1: float = 1.5, b: float = 0.75):
        data = json.loads(Path(kb_path).read_text())
        self.entries = data["entries"]
        self.docs = [
            _tokens(" ".join([e["name"], e.get("keywords", ""),
                              e["description"], e.get("fix", "")]))
            for e in self.entries
        ]
        self.N = len(self.docs)
        self.avgdl = sum(len(d) for d in self.docs) / self.N
        self.df: dict[str, int] = {}
        for d in self.docs:
            for w in set(d):
                self.df[w] = self.df.get(w, 0) + 1
        self.k, self.k1, self.b = k, k1, b

    def _idf(self, w: str) -> float:
        n = self.df.get(w, 0)
        return math.log(1 + (self.N - n + 0.5) / (n + 0.5))

    def _score(self, query: list[str], doc: list[str]) -> float:
        tf = Counter(doc)
        dl = len(doc)
        s = 0.0
        for w in query:
            if w not in tf:
                continue
            f = tf[w]
            s += self._idf(w) * (f * (self.k1 + 1)) / (
                f + self.k1 * (1 - self.b + self.b * dl / self.avgdl))
        return s

    def top(self, code: str) -> list[dict]:
        q = _tokens(code)
        ranked = sorted(range(self.N), key=lambda i: self._score(q, self.docs[i]),
                        reverse=True)
        return [self.entries[i] for i in ranked[:self.k]
                if self._score(q, self.docs[i]) > 0]

    def retrieve(self, code: str) -> str:
        """Return the top-k entries formatted for the prompt (or '' if none)."""
        entries = self.top(code)
        if not entries:
            return ""
        return "\n".join(
            f"- {e['cwe']} {e['name']}: {e['description']} Fix: {e.get('fix', '')}"
            for e in entries
        )
