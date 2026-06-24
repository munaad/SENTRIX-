from __future__ import annotations

from dataclasses import dataclass
from typing import Literal, Optional

Severity = Literal["critical", "high", "medium", "low"]


@dataclass(frozen=True)
class Finding:
    title: str
    severity: Severity
    cwe: str
    line: Optional[int]
    description: str
    fix: str
    rule_id: str

