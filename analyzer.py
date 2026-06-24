from __future__ import annotations

from dataclasses import asdict
from typing import Any

from .python_ast import analyze_python
from .regex_rules import scan_regex
from .scoring import risk_score
from .types import Finding


def analyze(code: str, language: str) -> dict[str, Any]:
    lang = (language or "python").lower()

    findings: list[Finding] = []

    if lang in {"py", "python"}:
        py_findings, _err = analyze_python(code)
        findings.extend(py_findings)
        # supplement with regex for additional signal
        findings.extend(scan_regex(code, "python"))
    else:
        findings.extend(scan_regex(code, lang))


    sev_rank = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    by_loc: dict[tuple[Any, str, str], Finding] = {}
    for f in findings:
        key = (f.line, f.cwe, f.title)
        cur = by_loc.get(key)
        if cur is None:
            by_loc[key] = f
            continue

        if sev_rank.get(f.severity, 99) < sev_rank.get(cur.severity, 99):
            by_loc[key] = f
            continue
        if sev_rank.get(f.severity, 99) == sev_rank.get(cur.severity, 99):
            if len(f.description) > len(cur.description):
                by_loc[key] = f

    deduped = list(by_loc.values())

    
    deduped.sort(key=lambda f: (sev_rank.get(f.severity, 99), f.line or 10**9, f.title))

    score = risk_score(deduped)
    return {
        "risk_score": score,
        "findings": [asdict(f) for f in deduped],
    }

