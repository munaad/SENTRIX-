from __future__ import annotations

from .types import Finding


_SEVERITY_WEIGHTS = {
    "critical": 30,
    "high": 20,
    "medium": 10,
    "low": 5,
}


def risk_score(findings: list[Finding]) -> int:
    score = 0
    for f in findings:
        score += _SEVERITY_WEIGHTS.get(f.severity, 0)

    
    if len(findings) >= 6:
        score = int(score * 0.85)
    if len(findings) >= 12:
        score = int(score * 0.75)

    return max(0, min(100, score))

