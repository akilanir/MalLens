"""Loads the sensitive-API CSV and matches Stage-1 api_calls signatures
against it (longest-prefix wins). Data-driven so PScout/Axplorer merges
never require code changes."""
from __future__ import annotations

import csv
from dataclasses import dataclass
from pathlib import Path

from loguru import logger


@dataclass(frozen=True)
class ApiRule:
    pattern: str
    category: str
    weight: float
    permission: str | None


class ApiTaxonomy:
    def __init__(self, rules: list[ApiRule]):
        # longest pattern first -> most specific rule wins
        self.rules = sorted(rules, key=lambda r: len(r.pattern), reverse=True)
        self.categories = sorted({r.category for r in rules})

    @classmethod
    def load(cls, csv_path: str | Path) -> "ApiTaxonomy":
        rules: list[ApiRule] = []
        logger.info(f"Loading CSV drom : {csv_path}")
        with open(csv_path, newline="", encoding="utf-8") as fh:
            for i, row in enumerate(csv.DictReader(fh), start=2):
                try:
                    rules.append(ApiRule(
                        pattern=row["pattern"].strip(),
                        category=row["category"].strip(),
                        weight=float(row["weight"]),
                        permission=(row.get("permission") or "").strip() or None,
                    ))
                except (KeyError, ValueError) as exc:
                    logger.warning(f"{csv_path}:{i} skipped bad row: {exc}")
        if not rules:
            logger.info("NO VALUES IN CSV")
            raise ValueError(f"no valid rules in {csv_path}")
        logger.info(f"taxonomy: {len(rules)} rules, "f"{len({r.category for r in rules})} categories")
        return cls(rules)

    def match(self, signature: str) -> ApiRule | None:
        for r in self.rules:
            if signature.startswith(r.pattern):
                return r
        return None
