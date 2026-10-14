"""Load the paired vulnerable/fixed fixtures and their ground-truth labels."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path


@dataclass
class Sample:
    id: str
    cwe: str
    name: str
    vulnerable_path: Path
    fixed_path: Path
    vuln_line: int
    llm_value: str
    note: str
    accept_cwes: list[str]  # CWEs that count as a correct match for this bug

    def vulnerable_code(self) -> str:
        return self.vulnerable_path.read_text()

    def fixed_code(self) -> str:
        return self.fixed_path.read_text()


def load_dataset(fixtures_dir: str | Path) -> list[Sample]:
    fixtures_dir = Path(fixtures_dir)
    labels = json.loads((fixtures_dir / "labels.json").read_text())

    samples: list[Sample] = []
    for s in labels["samples"]:
        samples.append(
            Sample(
                id=s["id"],
                cwe=s["cwe"],
                name=s["name"],
                vulnerable_path=fixtures_dir / s["vulnerable_file"],
                fixed_path=fixtures_dir / s["fixed_file"],
                vuln_line=s["vuln_line"],
                llm_value=s["llm_value"],
                note=s["note"],
                accept_cwes=s.get("accept_cwes", [s["cwe"]]),
            )
        )
    return samples
