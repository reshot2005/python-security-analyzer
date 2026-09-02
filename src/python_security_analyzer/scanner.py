"""AST-based Python security pattern detection."""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass
from pathlib import Path

from secintel_core.security import bounded_read_file

_SECRET_ASSIGN = re.compile(r"(api[_-]?key|password|secret|token|aws_)", re.I)
_DANGEROUS_CALLS = {
    "eval": ("dangerous_eval", "high", 0.95),
    "exec": ("dangerous_exec", "high", 0.95),
    "pickle.loads": ("insecure_deserialization", "high", 0.92),
    "pickle.load": ("insecure_deserialization", "high", 0.92),
    "yaml.load": ("insecure_deserialization", "high", 0.90),
    "subprocess.call": ("shell_injection_risk", "medium", 0.80),
    "subprocess.run": ("shell_injection_risk", "medium", 0.80),
    "os.system": ("shell_injection_risk", "high", 0.93),
}


@dataclass(frozen=True)
class PyIssue:
    file: str
    line: int
    issue: str
    severity: str
    confidence_score: float
    detail: str
    excerpt: str


def _call_name(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = _call_name(node.value)
        return f"{base}.{node.attr}" if base else node.attr
    return ""


def scan_python(path: Path) -> list[PyIssue]:
    raw = bounded_read_file(path, max_bytes=5 * 1024 * 1024)
    text = raw.decode("utf-8", errors="replace") if isinstance(raw, bytes) else raw
    issues: list[PyIssue] = []
    try:
        tree = ast.parse(text, filename=str(path))
    except SyntaxError as exc:
        issues.append(
            PyIssue(
                file=str(path),
                line=exc.lineno or 1,
                issue="parse_error",
                severity="low",
                confidence_score=1.0,
                detail=f"SyntaxError: {exc.msg}",
                excerpt="",
            )
        )
        return issues

    lines = text.splitlines()

    class Visitor(ast.NodeVisitor):
        def visit_Call(self, node: ast.Call) -> None:
            name = _call_name(node.func)
            short = name.split(".")[-1] if name else ""
            meta = _DANGEROUS_CALLS.get(name) or _DANGEROUS_CALLS.get(short)
            if meta:
                issue, sev, conf = meta
                # shell=True elevates subprocess
                if short in {"call", "run", "Popen"}:
                    for kw in node.keywords:
                        if kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True:
                            issue, sev, conf = "shell_true", "high", 0.94
                line = getattr(node, "lineno", 1)
                excerpt = lines[line - 1].strip() if 0 < line <= len(lines) else ""
                issues.append(
                    PyIssue(
                        file=str(path),
                        line=line,
                        issue=issue,
                        severity=sev,
                        confidence_score=conf,
                        detail=f"Call to {name}",
                        excerpt=excerpt[:120],
                    )
                )
            self.generic_visit(node)

        def visit_Assign(self, node: ast.Assign) -> None:
            for target in node.targets:
                if isinstance(target, ast.Name) and _SECRET_ASSIGN.search(target.id):
                    if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
                        line = getattr(node, "lineno", 1)
                        excerpt = lines[line - 1].strip() if 0 < line <= len(lines) else ""
                        issues.append(
                            PyIssue(
                                file=str(path),
                                line=line,
                                issue="hardcoded_secret",
                                severity="high",
                                confidence_score=0.88,
                                detail=f"Hardcoded secret in {target.id}",
                                excerpt=excerpt[:80],
                            )
                        )
            self.generic_visit(node)

        def visit_BinOp(self, node: ast.BinOp) -> None:
            # SQL-ish string formatting: "SELECT ... %s" % var
            if isinstance(node.op, ast.Mod) and isinstance(node.left, ast.Constant):
                left = str(node.left.value).upper()
                if "SELECT" in left or "INSERT" in left or "UPDATE" in left:
                    line = getattr(node, "lineno", 1)
                    excerpt = lines[line - 1].strip() if 0 < line <= len(lines) else ""
                    issues.append(
                        PyIssue(
                            file=str(path),
                            line=line,
                            issue="sql_injection_pattern",
                            severity="high",
                            confidence_score=0.82,
                            detail="String-formatted SQL query",
                            excerpt=excerpt[:120],
                        )
                    )
            self.generic_visit(node)

    Visitor().visit(tree)
    return issues
