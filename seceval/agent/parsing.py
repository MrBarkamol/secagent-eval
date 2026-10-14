"""Pull a JSON object out of a model's reply.

Even with format=json set, models sometimes wrap output in ```json fences or add
a stray sentence. This extractor is deliberately forgiving: strip fences, try a
straight parse, and if that fails, grab the first balanced {...} block. Robust
parsing here saves the loop from dying on cosmetic noise.
"""

from __future__ import annotations

import json


def extract_json(text: str) -> dict | None:
    if not text:
        return None
    t = text.strip()
    if t.startswith("```"):
        t = t.strip("`")
        if t[:4].lower() == "json":
            t = t[4:]
        t = t.strip()
    try:
        return json.loads(t)
    except json.JSONDecodeError:
        pass
    # Fall back to the first balanced brace block.
    start = t.find("{")
    while start != -1:
        depth = 0
        for i in range(start, len(t)):
            if t[i] == "{":
                depth += 1
            elif t[i] == "}":
                depth -= 1
                if depth == 0:
                    try:
                        return json.loads(t[start:i + 1])
                    except json.JSONDecodeError:
                        break
        start = t.find("{", start + 1)
    return None
