from __future__ import annotations

import ast
import re
from typing import Optional

from .types import Finding


_SECRET_NAME_RE = re.compile(r"(?i)\b(pass(word)?|passwd|secret|token|api[_-]?key|private[_-]?key)\b")
_SECRET_VALUE_RE = re.compile(
    r"(?i)(AKIA[0-9A-Z]{16}|AIza[0-9A-Za-z\-_]{35}|xox[baprs]-[0-9A-Za-z-]{10,}|-----BEGIN (RSA|EC|OPENSSH) PRIVATE KEY-----)"
)


def _attr_to_str(node: ast.AST) -> Optional[str]:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = _attr_to_str(node.value)
        if not base:
            return None
        return f"{base}.{node.attr}"
    return None


def _const_str(node: ast.AST) -> Optional[str]:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None


def _get_call_kw_bool(call: ast.Call, kw_name: str) -> Optional[bool]:
    for kw in call.keywords or []:
        if kw.arg == kw_name and isinstance(kw.value, ast.Constant) and isinstance(kw.value.value, bool):
            return kw.value.value
    return None


class _Taint:
    def __init__(self) -> None:
        self.tainted_names: set[str] = set()

    def is_tainted(self, expr: ast.AST) -> bool:
        if isinstance(expr, ast.Name):
            return expr.id in self.tainted_names
        if isinstance(expr, ast.Constant):
            return False
        if isinstance(expr, ast.JoinedStr):
            return any(self.is_tainted(v.value) for v in expr.values if isinstance(v, ast.FormattedValue))
        if isinstance(expr, ast.BinOp) and isinstance(expr.op, (ast.Add, ast.Mod)):
            return self.is_tainted(expr.left) or self.is_tainted(expr.right)
        if isinstance(expr, ast.Call):
            callee = _attr_to_str(expr.func)
            if callee in {
                "input",
                "sys.argv.__getitem__",
            }:
                return True

            if callee and callee.endswith(".get"):
                base = callee[: -len(".get")]
                if base in {
                    "request.args",
                    "request.form",
                    "request.values",
                    "request.headers",
                    "request.cookies",
                    "request.json",
                    "request.view_args",
                }:
                    return True

            if callee == "os.environ.get":
                return True

            if callee in {"str", "format"}:
                return any(self.is_tainted(a) for a in expr.args)

        if isinstance(expr, ast.Subscript):
            base = _attr_to_str(expr.value)
            if base in {
                "request.args",
                "request.form",
                "request.values",
                "request.headers",
                "request.cookies",
                "request.json",
                "request.view_args",
                "os.environ",
            }:
                return True
        if isinstance(expr, ast.Attribute):
            return self.is_tainted(expr.value)
        return False

    def taint_assign(self, target: ast.AST, value: ast.AST) -> None:
        if not self.is_tainted(value):
            return
        if isinstance(target, ast.Name):
            self.tainted_names.add(target.id)
        elif isinstance(target, (ast.Tuple, ast.List)):
            for elt in target.elts:
                self.taint_assign(elt, value)


def _is_string_interpolated(expr: ast.AST) -> bool:
    if isinstance(expr, ast.JoinedStr):
        return True
    if isinstance(expr, ast.BinOp) and isinstance(expr.op, (ast.Add, ast.Mod)):
        return True
    if isinstance(expr, ast.Call):
        if isinstance(expr.func, ast.Attribute) and expr.func.attr == "format":
            return True
        callee = _attr_to_str(expr.func) or ""
        if callee.endswith(".format"):
            return True
    return False


def analyze_python(code: str) -> tuple[list[Finding], Optional[str]]:
    try:
        tree = ast.parse(code)
    except SyntaxError as e:
        return (
            [
                Finding(
                    title="Python syntax error",
                    severity="low",
                    cwe="N/A",
                    line=getattr(e, "lineno", None),
                    description="The code could not be parsed as Python, so AST-based checks did not run.",
                    fix="Fix the syntax error and re-run analysis.",
                    rule_id="PY-PARSE-001",
                )
            ],
            "syntax_error",
        )

    findings: list[Finding] = []
    taint = _Taint()

    for node in ast.walk(tree):
        if isinstance(node, ast.Assign):
            for tgt in node.targets:
                taint.taint_assign(tgt, node.value)
        elif isinstance(node, ast.AnnAssign) and node.value is not None:
            taint.taint_assign(node.target, node.value)

    # this is for running AST security checks
    for node in ast.walk(tree):
        if isinstance(node, (ast.Assign, ast.AnnAssign)):
            targets = []
            value = None
            if isinstance(node, ast.Assign):
                targets = node.targets
                value = node.value
            else:
                targets = [node.target]
                value = node.value

            if value is not None:
                s = _const_str(value)
                if s is not None:
                    for t in targets:
                        if isinstance(t, ast.Name) and _SECRET_NAME_RE.search(t.id) and len(s) >= 6:
                            findings.append(
                                Finding(
                                    title="Hardcoded secret",
                                    severity="high",
                                    cwe="CWE-798",
                                    line=getattr(node, "lineno", None),
                                    description="A secret-like value is assigned directly in code, which risks leaking credentials via source control or logs.",
                                    fix="Move the secret to an environment variable or secret manager, and rotate the credential if it was ever committed.",
                                    rule_id="PY-SECRET-001",
                                )
                            )
                            break

                    if _SECRET_VALUE_RE.search(s):
                        findings.append(
                            Finding(
                                title="Hardcoded secret (signature match)",
                                severity="high",
                                cwe="CWE-798",
                                line=getattr(node, "lineno", None),
                                description="This string matches the signature of a real credential/key format and should be treated as compromised if committed.",
                                fix="Remove it from source history if possible, rotate the credential/key, and load secrets from a secure runtime source.",
                                rule_id="PY-SECRET-002",
                            )
                        )

        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id in {"eval", "exec"}:
            findings.append(
                Finding(
                    title=f"Use of dangerous function: {node.func.id}",
                    severity="critical",
                    cwe="CWE-95",
                    line=getattr(node, "lineno", None),
                    description="Dynamic code execution is extremely dangerous if any part of the executed string can be influenced by an attacker.",
                    fix="Remove eval/exec. Use safe parsers (e.g., json), explicit mappings/dispatch tables, or validate and parse input without executing code.",
                    rule_id="PY-EVAL-001",
                )
            )

        if isinstance(node, ast.Call):
            callee = _attr_to_str(node.func) or ""

            if callee == "os.system":
                if node.args and taint.is_tainted(node.args[0]):
                    sev = "critical"
                else:
                    sev = "low"
                findings.append(
                    Finding(
                        title="Possible command injection via os.system",
                        severity=sev,
                        cwe="CWE-78",
                        line=getattr(node, "lineno", None),
                        description="Passing attacker-controlled data to a shell command can lead to arbitrary command execution.",
                        fix="Avoid shell execution. Use `subprocess.run([...], shell=False)` with a fixed argument list; validate/allowlist any user-controlled values.",
                        rule_id="PY-CMDI-001",
                    )
                )

            if callee.startswith("subprocess.") and callee.split(".", 1)[1] in {"run", "call", "check_call", "check_output", "Popen"}:
                shell = _get_call_kw_bool(node, "shell")
                arg0 = node.args[0] if node.args else None
                tainted = arg0 is not None and taint.is_tainted(arg0)
                if shell is True or (isinstance(arg0, ast.Constant) and isinstance(arg0.value, str)):
                    sev = "critical" if (shell is True and tainted) else "low"
                    findings.append(
                        Finding(
                            title="Possible command injection via subprocess",
                            severity=sev,
                            cwe="CWE-78",
                            line=getattr(node, "lineno", None),
                            description="Using subprocess with `shell=True` or building command strings can allow injection if inputs are attacker-controlled.",
                            fix="Prefer `subprocess.run([prog, arg1, ...], shell=False)`; avoid `shell=True`; validate/allowlist user input.",
                            rule_id="PY-CMDI-002",
                        )
                    )

            if callee.endswith(".execute") or callee.endswith(".executemany"):
                if node.args:
                    q = node.args[0]
                    unsafe = taint.is_tainted(q) or _is_string_interpolated(q)
                    if unsafe:
                        findings.append(
                            Finding(
                                title="Possible SQL Injection in database execute()",
                                severity="high",
                                cwe="CWE-89",
                                line=getattr(node, "lineno", None),
                                description="Building SQL with string interpolation/concatenation can let attackers alter the query structure.",
                                fix="Use parameterized queries: `cursor.execute('... WHERE id = %s', (id,))` (placeholder style depends on your DB driver).",
                                rule_id="PY-SQLI-001",
                            )
                        )

            if callee in {"flask.render_template_string", "render_template_string"}:
                if any(taint.is_tainted(a) for a in node.args) or any(taint.is_tainted(kw.value) for kw in node.keywords or [] if kw.value):
                    findings.append(
                        Finding(
                            title="Possible server-side template injection via render_template_string",
                            severity="medium",
                            cwe="CWE-94",
                            line=getattr(node, "lineno", None),
                            description="Passing user-controlled input into `render_template_string` can allow an attacker to inject template directives and execute arbitrary code on the server.",
                            fix="Avoid `render_template_string` with untrusted input; use `render_template` with auto-escaping, or strictly sanitize/escape user data.",
                            rule_id="PY-XSS-001",
                        )
                    )

            if callee.endswith("Markup"):
                if node.args and taint.is_tainted(node.args[0]):
                    findings.append(
                        Finding(
                            title="Possible XSS via Markup() of untrusted input",
                            severity="low",
                            cwe="CWE-79",
                            line=getattr(node, "lineno", None),
                            description="Marking attacker-controlled content as 'safe' disables escaping and can introduce XSS.",
                            fix="Do not wrap untrusted input in Markup. Keep auto-escaping enabled and sanitize only known-safe HTML fragments.",
                            rule_id="PY-XSS-002",
                        )
                    )

            if callee in {"open", "pathlib.Path", "send_file", "flask.send_file", "send_from_directory", "flask.send_from_directory"}:
                if node.args and taint.is_tainted(node.args[0]):
                    findings.append(
                        Finding(
                            title="Possible path traversal",
                            severity="high",
                            cwe="CWE-22",
                            line=getattr(node, "lineno", None),
                            description="Using attacker-controlled paths may allow reading/writing files outside intended directories via '..' or absolute paths.",
                            fix="Constrain paths to a base directory (realpath/resolve), reject traversal, and use allowlists for filenames.",
                            rule_id="PY-PATH-001",
                        )
                    )

            if callee.startswith("random.") and callee.split(".", 1)[1] in {"random", "randint", "choice", "choices", "randrange"}:
                findings.append(
                    Finding(
                        title="Insecure random number generation",
                        severity="medium",
                        cwe="CWE-338",
                        line=getattr(node, "lineno", None),
                        description="The `random` module is not suitable for security-sensitive values (tokens, session IDs, password resets).",
                        fix="Use `secrets` (e.g., `secrets.token_urlsafe`, `secrets.randbelow`) for security-sensitive randomness.",
                        rule_id="PY-RAND-001",
                    )
                )

            if callee.startswith("hashlib.") and callee.split(".", 1)[1] in {"md5", "sha1"}:
                findings.append(
                    Finding(
                        title=f"Weak cryptography: {callee}",
                        severity="medium",
                        cwe="CWE-328",
                        line=getattr(node, "lineno", None),
                        description="MD5 and SHA-1 are weak and should not be used for security-sensitive hashing.",
                        fix="Use SHA-256/512 where appropriate; for password hashing use a dedicated password hashing algorithm (bcrypt/scrypt/Argon2).",
                        rule_id="PY-CRYPTO-001",
                    )
                )

        if isinstance(node, ast.ImportFrom) and node.module == "hashlib":
            for alias in node.names:
                if alias.name in {"md5", "sha1"}:
                    findings.append(
                        Finding(
                            title=f"Weak cryptography import: hashlib.{alias.name}",
                            severity="medium",
                            cwe="CWE-328",
                            line=getattr(node, "lineno", None),
                            description="Importing MD5/SHA-1 often indicates use of weak hashes in security contexts.",
                            fix="Prefer SHA-256/512; avoid MD5/SHA-1 for integrity/security. Use modern password hashing for passwords.",
                            rule_id="PY-CRYPTO-002",
                        )
                    )

    # this is for local AST dedupe
    seen: set[tuple[str, Optional[int]]] = set()
    out: list[Finding] = []
    for f in findings:
        key = (f.rule_id, f.line)
        if key in seen:
            continue
        seen.add(key)
        out.append(f)

    return out, None

