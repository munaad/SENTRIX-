from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Optional

from .types import Finding, Severity


@dataclass(frozen=True)
class RegexRule:
    rule_id: str
    title: str
    severity: Severity
    cwe: str
    pattern: re.Pattern[str]
    description: str
    fix: str


def _line_for_index(code: str, idx: int) -> int:
    return code.count("\n", 0, idx) + 1


def scan_regex(code: str, language: str) -> list[Finding]:
    # this is for regex pattern matching
    lang = (language or "").lower()

    rules: list[RegexRule] = [
        RegexRule(
            rule_id="REGEX-SQLI-001",
            title="Possible SQL Injection",
            severity="high",
            cwe="CWE-89",
            pattern=re.compile(
                r"(?:\bf[\"']\s*(?:SELECT|UPDATE|DELETE|INSERT)\b|\b(?:SELECT|UPDATE|DELETE|INSERT)\b[\s\S]{0,200}(?:[\"']\s*\+|[\"']\s*%|\$\{|\bformat\s*\(|\.format\s*\())",
                re.IGNORECASE,
            ),
            description="SQL built via string concatenation/interpolation can allow attackers to change the query.",
            fix="Use parameterized queries / prepared statements (placeholders) and pass parameters separately. Never concatenate untrusted input into SQL.",
        ),
        RegexRule(
            rule_id="REGEX-SECRET-001",
            title="Hardcoded secret (pattern match)",
            severity="high",
            cwe="CWE-798",
            pattern=re.compile(r"(?i)\b(password|passwd|secret|api[_-]?key|token)\b\s*[:=]\s*['\"][^'\"]{6,}['\"]"),
            description="Hardcoding secrets in source code risks accidental leaks via git, logs, or artifact distribution.",
            fix="Move secrets to environment variables or a secrets manager; rotate exposed credentials.",
        ),
        RegexRule(
            rule_id="REGEX-XSS-001",
            title="Possible XSS sink (DOM injection)",
            severity="low",
            cwe="CWE-79",
            pattern=re.compile(r"\b(innerHTML|outerHTML|document\.write)\s*=", re.IGNORECASE),
            description="Writing attacker-controlled content into the DOM as HTML can execute scripts in the victim's browser.",
            fix="Use textContent/innerText, sanitize HTML, and apply templating auto-escaping and CSP.",
        ),
        RegexRule(
            rule_id="REGEX-PATH-001",
            title="Possible path traversal",
            severity="high",
            cwe="CWE-22",
            pattern=re.compile(r"(\.\./|\.\.\\\\)"),
            description="Path traversal lets attackers access files outside the intended directory by using '..' segments.",
            fix="Normalize paths, enforce an allowed base directory, and reject traversal sequences; use safe path join + validation.",
        ),
        RegexRule(
            rule_id="REGEX-EVAL-001",
            title="Possible dynamic code execution via eval or exec",
            severity="critical",
            cwe="CWE-95",
            pattern=re.compile(r"\b(eval|exec)\s*\(", re.IGNORECASE),
            description="Dynamic code execution can allow attackers to run arbitrary code if any part is attacker-controlled.",
            fix="Remove eval/exec; use safe parsers, explicit mappings, or restricted interpreters.",
        ),
        RegexRule(
            rule_id="REGEX-RAND-001",
            title="Insecure randomness (non-crypto RNG)",
            severity="medium",
            cwe="CWE-338",
            pattern=re.compile(r"\b(Math\.random\(\)|random\.(random|randint|choice)\()", re.IGNORECASE),
            description="Non-cryptographic PRNGs are predictable and unsafe for tokens, passwords, or security decisions.",
            fix="Use a cryptographically secure RNG (Python: secrets; JS: crypto.getRandomValues / crypto.randomUUID).",
        ),
        RegexRule(
            rule_id="REGEX-CRYPTO-001",
            title="Weak cryptography (MD5/SHA1)",
            severity="medium",
            cwe="CWE-328",
            pattern=re.compile(r"\b(md5|sha1)\b", re.IGNORECASE),
            description="MD5 and SHA-1 are considered broken/weak and enable collision attacks in many contexts.",
            fix="Use SHA-256/512 for hashing, and modern constructions for passwords (bcrypt/scrypt/Argon2) and HMAC where appropriate.",
        ),
    ]

    findings: list[Finding] = []
    for rule in rules:
        for m in rule.pattern.finditer(code):
            line = _line_for_index(code, m.start())
            findings.append(
                Finding(
                    title=rule.title,
                    severity=rule.severity,
                    cwe=rule.cwe,
                    line=line,
                    description=rule.description,
                    fix=rule.fix,
                    rule_id=rule.rule_id + f":{lang or 'text'}",
                )
            )

    # this is for local regex dedupe
    seen: set[tuple[str, Optional[int]]] = set()
    out: list[Finding] = []
    for f in findings:
        key = (f.rule_id, f.line)
        if key in seen:
            continue
        seen.add(key)
        out.append(f)

    return out

