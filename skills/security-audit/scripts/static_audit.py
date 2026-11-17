#!/usr/bin/env python3
"""Deterministic static security and reliability scanner for Code Reviewer."""

import ast
import json
import os
import re
import sys
from pathlib import Path

SKIP_DIRS = {".git", "node_modules", ".venv", "venv", "__pycache__", ".kiro", "dist", "build"}
SCAN_EXTS = {".py", ".js", ".ts", ".jsx", ".tsx", ".mjs", ".cjs"}

TOKEN_REGEX = re.compile(
    r"(sk-live-[A-Za-z0-9_-]{8,}|sk-proj-[A-Za-z0-9_-]{8,}|AKIA[0-9A-Z]{16}|ghp_[A-Za-z0-9]{20,}|AIza[0-9A-Za-z_-]{20,})"
)
SECRET_ASSIGN_REGEX = re.compile(
    r"""(?i)\b(api_key|secret_key|password|passwd|access_token|auth_token|private_key)\b\s*[:=]\s*["']([^"'\r\n]{6,})["']"""
)
SQL_KEYWORD_REGEX = re.compile(r"(?i)\b(SELECT|INSERT|UPDATE|DELETE)\b.*\b(FROM|INTO|SET|WHERE)\b")
JS_UNSAFE_REGEX = re.compile(r"(\beval\s*\(|dangerouslySetInnerHTML|\.innerHTML\s*=)")
PLACEHOLDER_HINTS = ("your_", "example", "changeme", "placeholder", "xxxx", "<")


def is_dynamic_sql_expr(node: ast.AST) -> bool:
    if isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Add, ast.Mod)):
        return True
    if isinstance(node, ast.JoinedStr):
        return True
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "format":
        return True
    return False


def expr_contains_sql(node: ast.AST) -> bool:
    for sub in ast.walk(node):
        if isinstance(sub, ast.Constant) and isinstance(sub.value, str):
            if SQL_KEYWORD_REGEX.search(sub.value):
                return True
    return False


def scan_python_ast(path: Path, source: str, findings: list) -> None:
    try:
        tree = ast.parse(source, filename=str(path))
    except SyntaxError as exc:
        findings.append({
            "rule_id": "SYNTAX-001",
            "severity": "Critical",
            "file": str(path),
            "line": exc.lineno or 1,
            "message": f"Python syntax error: {exc.msg}",
        })
        return

    for node in ast.walk(tree):
        if isinstance(node, ast.Assign) and is_dynamic_sql_expr(node.value) and expr_contains_sql(node.value):
            findings.append({
                "rule_id": "SEC-SQLI-001",
                "severity": "Critical",
                "file": str(path),
                "line": node.lineno,
                "message": "Dynamic SQL string construction detected (use parameterized queries instead).",
            })

        elif isinstance(node, ast.Call):
            if isinstance(node.func, ast.Attribute) and node.func.attr in {"execute", "executemany"}:
                if node.args and is_dynamic_sql_expr(node.args[0]):
                    findings.append({
                        "rule_id": "SEC-SQLI-002",
                        "severity": "Critical",
                        "file": str(path),
                        "line": node.lineno,
                        "message": f"Dynamic query passed directly to .{node.func.attr}().",
                    })
            elif isinstance(node.func, ast.Name) and node.func.id in {"eval", "exec"}:
                findings.append({
                    "rule_id": "SEC-EVAL-001",
                    "severity": "High",
                    "file": str(path),
                    "line": node.lineno,
                    "message": f"Unsafe dynamic code execution via {node.func.id}().",
                })
            elif isinstance(node.func, ast.Attribute) and node.func.attr == "system":
                if isinstance(node.func.value, ast.Name) and node.func.value.id == "os":
                    findings.append({
                        "rule_id": "SEC-CMD-001",
                        "severity": "High",
                        "file": str(path),
                        "line": node.lineno,
                        "message": "Shell command execution via os.system().",
                    })
            for kw in node.keywords:
                if kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True:
                    findings.append({
                        "rule_id": "SEC-CMD-002",
                        "severity": "High",
                        "file": str(path),
                        "line": node.lineno,
                        "message": "Subprocess invoked with shell=True.",
                    })

        elif isinstance(node, ast.ExceptHandler):
            if node.type is None:
                findings.append({
                    "rule_id": "REL-BARE-EXCEPT",
                    "severity": "Medium",
                    "file": str(path),
                    "line": node.lineno,
                    "message": "Bare except: clause catches system exits and hides real errors.",
                })
            elif isinstance(node.type, ast.Name) and node.type.id == "Exception":
                findings.append({
                    "rule_id": "REL-BROAD-EXCEPT",
                    "severity": "Low",
                    "file": str(path),
                    "line": node.lineno,
                    "message": "Broad except Exception: handler; prefer specific exception classes.",
                })


def scan_file(path: Path, findings: list) -> None:
    text = path.read_text(encoding="utf-8", errors="replace")
    lines = text.splitlines()

    for idx, line in enumerate(lines, start=1):
        if TOKEN_REGEX.search(line):
            findings.append({
                "rule_id": "SEC-SECRET-001",
                "severity": "Critical",
                "file": str(path),
                "line": idx,
                "message": "Hardcoded API key or credential token pattern detected.",
            })
        else:
            m = SECRET_ASSIGN_REGEX.search(line)
            if m and not any(h in m.group(2).lower() for h in PLACEHOLDER_HINTS):
                findings.append({
                    "rule_id": "SEC-SECRET-002",
                    "severity": "Critical",
                    "file": str(path),
                    "line": idx,
                    "message": f"Possible hardcoded credential assigned to '{m.group(1)}'.",
                })

        if path.suffix.lower() in {".js", ".ts", ".jsx", ".tsx", ".mjs", ".cjs"} and JS_UNSAFE_REGEX.search(line):
            findings.append({
                "rule_id": "SEC-XSS-001",
                "severity": "High",
                "file": str(path),
                "line": idx,
                "message": "Potentially unsafe DOM/eval sink detected.",
            })

    if path.suffix.lower() == ".py":
        scan_python_ast(path, text, findings)


def collect_targets(target: Path) -> list:
    if target.is_file():
        return [target]
    files = []
    for root, dirs, names in os.walk(target):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
        for name in names:
            p = Path(root) / name
            if p.suffix.lower() in SCAN_EXTS:
                files.append(p)
    return files


def main() -> int:
    if len(sys.argv) < 2:
        print(json.dumps({"error": "Usage: static_audit.py <file_or_directory>"}))
        return 0

    target = Path(sys.argv[1])
    if not target.exists():
        print(json.dumps({"error": f"Path not found: {target}"}))
        return 0

    files = collect_targets(target)
    findings = []
    for f in files:
        scan_file(f, findings)

    summary = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
    for item in findings:
        sev = item.get("severity", "Low")
        if sev in summary:
            summary[sev] += 1

    print(json.dumps({
        "tool": "code-reviewer/static_audit.py",
        "files_scanned": len(files),
        "summary": summary,
        "findings": findings,
    }, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())