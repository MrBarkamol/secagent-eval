"""The model seam.

The entire agent is written against ONE tiny interface -- `ModelAdapter.complete`
-- so the loop, the tools, and the verifier never know or care which model is
behind it. That is the design decision that lets you develop and test today with
a mock, and swap in a real local model later by changing a single line.

Three implementations:
  - ModelAdapter : the interface.
  - MockModel    : a scripted test double. Proves the machinery works WITHOUT a
                   real model. It does not reason, so any eval number produced
                   with it is meaningless -- real numbers need a real model.
  - OllamaAdapter: runs a LOCAL model via Ollama. This is the real path. It is
                   left untested in this repo because it needs a running Ollama
                   and a pulled model; wire it up once you know your hardware.
"""

from __future__ import annotations


class ModelAdapter:
    name = "base"

    def complete(self, messages: list[dict]) -> str:
        """Take chat messages [{role, content}, ...], return the model's text."""
        raise NotImplementedError


class MockModel(ModelAdapter):
    """Returns pre-written responses in order. For testing the agent machinery.

    Give it a `script` of JSON strings; each call to complete() returns the next
    one. Once the script runs out it returns an empty-findings 'final' so the
    loop always terminates.
    """

    name = "mock"

    def __init__(self, script: list[str]):
        self.script = list(script)
        self.i = 0

    def complete(self, messages: list[dict]) -> str:
        if self.i >= len(self.script):
            return '{"action": "final", "findings": []}'
        out = self.script[self.i]
        self.i += 1
        return out


class OllamaAdapter(ModelAdapter):
    """Runs a local model served by Ollama (https://ollama.com).

    UNTESTED here -- needs `ollama serve` running and a model pulled, e.g.:
        ollama pull qwen2.5:7b-instruct
    Then:
        AgentDetector(OllamaAdapter(model="qwen2.5:7b-instruct"))

    `format="json"` asks Ollama to constrain output to valid JSON, which makes
    the loop's parsing far more reliable. temperature 0 keeps runs reproducible.
    """

    name = "ollama"

    def __init__(self, model: str = "qwen2.5:7b-instruct",
                 host: str = "http://localhost:11434",
                 json_mode: bool = False, temperature: float = 0.2,
                 num_predict: int = 1024, repeat_penalty: float = 1.2):
        self.model = model
        self.host = host.rstrip("/")
        # json_mode OFF by default: Ollama's JSON grammar + greedy decoding can
        # make small models loop until the server aborts with a 500 ("token
        # repeat limit reached"). Free-form generation plus our tolerant JSON
        # parser avoids that. A little temperature breaks deterministic loops;
        # num_predict caps runaway output; repeat_penalty discourages repetition.
        self.json_mode = json_mode
        self.temperature = temperature
        self.num_predict = num_predict
        self.repeat_penalty = repeat_penalty

    def complete(self, messages: list[dict]) -> str:
        import json
        import time
        import urllib.error
        import urllib.request

        payload = {
            "model": self.model,
            "messages": messages,
            "stream": False,
            "options": {
                "temperature": self.temperature,
                "num_predict": self.num_predict,
                "repeat_penalty": self.repeat_penalty,
            },
        }
        if self.json_mode:
            payload["format"] = "json"
        body = json.dumps(payload).encode()

        # The first call to a cold model can 500 while it loads into memory, and
        # a long eval shouldn't die on one transient hiccup. Retry with growing
        # backoff that comfortably covers a model load (~15s), then give a clear
        # message rather than a raw traceback.
        backoffs = [3, 8, 20]
        last = ""
        for attempt in range(len(backoffs) + 1):
            try:
                req = urllib.request.Request(
                    self.host + "/api/chat", data=body,
                    headers={"Content-Type": "application/json"},
                )
                with urllib.request.urlopen(req, timeout=180) as resp:
                    return json.loads(resp.read())["message"]["content"]
            except urllib.error.HTTPError as e:
                detail = ""
                try:
                    detail = e.read().decode()[:200]
                except Exception:
                    pass
                last = f"HTTP {e.code}: {detail}"
                if e.code >= 500 and attempt < len(backoffs):
                    time.sleep(backoffs[attempt])
                    continue
                raise RuntimeError(
                    f"Ollama returned {last}. Check that `ollama serve` is running "
                    f"and '{self.model}' is pulled (`ollama list`)."
                ) from e
            except urllib.error.URLError as e:
                last = str(e)
                if attempt < len(backoffs):
                    time.sleep(backoffs[attempt])
                    continue
                raise RuntimeError(
                    f"Could not reach Ollama at {self.host} ({last}). "
                    f"Start it with `brew services start ollama`."
                ) from e
