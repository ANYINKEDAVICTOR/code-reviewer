#!/usr/bin/env python3
"""Portable, zero-dependency stdio MCP server for Code Reviewer."""

import importlib.util
import json
import sys
from pathlib import Path

if hasattr(sys.stdin, "reconfigure"):
    sys.stdin.reconfigure(encoding="utf-8")
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")

ROOT_DIR = Path(__file__).resolve().parent.parent
STATIC_AUDIT_PATH = ROOT_DIR / "skills" / "security-audit" / "scripts" / "static_audit.py"
RUBRIC_PATH = ROOT_DIR / "skills" / "security-audit" / "references" / "rubric.md"

_spec = importlib.util.spec_from_file_location("static_audit", STATIC_AUDIT_PATH)
static_audit = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(static_audit)

TOOLS = [
    {
        "name": "run_static_audit",
        "description": "Run deterministic AST, syntax, hardcoded-secret, and injection checks on a file or directory.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "target_path": {
                    "type": "string",
                    "description": "Absolute or workspace-relative path to the file or folder to scan."
                }
            },
            "required": ["target_path"]
        }
    },
    {
        "name": "get_review_rubric",
        "description": "Load the 100-point project and coursework evaluation rubric.",
        "inputSchema": {
            "type": "object",
            "properties": {}
        }
    },
    {
        "name": "calculate_rubric_score",
        "description": "Deterministically compute the 100-point rubric breakdown and official verdict.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "security_deductions": {"type": "integer", "minimum": 0, "maximum": 30},
                "correctness_deductions": {"type": "integer", "minimum": 0, "maximum": 30},
                "reliability_deductions": {"type": "integer", "minimum": 0, "maximum": 20},
                "structure_deductions": {"type": "integer", "minimum": 0, "maximum": 20},
                "has_critical": {"type": "boolean"}
            },
            "required": [
                "security_deductions",
                "correctness_deductions",
                "reliability_deductions",
                "structure_deductions",
                "has_critical"
            ]
        }
    }
]


def call_tool(name: str, args: dict) -> dict:
    if name == "run_static_audit":
        target = Path(args.get("target_path", ""))
        if not target.exists():
            return {"error": f"Path not found: {target}"}
        files = static_audit.collect_targets(target)
        findings = []
        for f in files:
            static_audit.scan_file(f, findings)
        summary = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
        for item in findings:
            sev = item.get("severity", "Low")
            if sev in summary:
                summary[sev] += 1
        return {
            "tool": "code-reviewer-mcp/run_static_audit",
            "files_scanned": len(files),
            "summary": summary,
            "findings": findings,
        }

    if name == "get_review_rubric":
        if not RUBRIC_PATH.exists():
            return {"error": "rubric.md not found"}
        return {"rubric_markdown": RUBRIC_PATH.read_text(encoding="utf-8")}

    if name == "calculate_rubric_score":
        sec = max(0, 30 - int(args.get("security_deductions", 0)))
        cor = max(0, 30 - int(args.get("correctness_deductions", 0)))
        rel = max(0, 20 - int(args.get("reliability_deductions", 0)))
        strc = max(0, 20 - int(args.get("structure_deductions", 0)))
        total = sec + cor + rel + strc
        has_critical = bool(args.get("has_critical", False))
        if has_critical or total < 70:
            verdict = "Revision Required"
        elif total < 90:
            verdict = "Pass with Minor Fixes"
        else:
            verdict = "Approved / Production-Ready"
        return {
            "scores": {
                "security": f"{sec}/30",
                "correctness": f"{cor}/30",
                "reliability": f"{rel}/20",
                "structure": f"{strc}/20",
            },
            "total": f"{total}/100",
            "has_critical": has_critical,
            "verdict": verdict,
        }

    raise ValueError(f"Unknown tool: {name}")


def send(obj: dict) -> None:
    sys.stdout.write(json.dumps(obj) + "\n")
    sys.stdout.flush()


def main() -> None:
    supported_versions = {"2024-11-05", "2025-03-26", "2025-06-18"}
    for raw in sys.stdin:
        line = raw.strip()
        if not line:
            continue
        try:
            msg = json.loads(line)
        except json.JSONDecodeError:
            continue

        req_id = msg.get("id")
        method = msg.get("method")
        params = msg.get("params") or {}

        # Notifications have no id; do not reply
        if req_id is None:
            continue

        if method == "initialize":
            client_ver = params.get("protocolVersion", "2024-11-05")
            proto = client_ver if client_ver in supported_versions else "2024-11-05"
            send({
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {
                    "protocolVersion": proto,
                    "capabilities": {"tools": {}},
                    "serverInfo": {"name": "code-reviewer-mcp", "version": "1.3.0"},
                },
            })
        elif method == "ping":
            send({"jsonrpc": "2.0", "id": req_id, "result": {}})
        elif method == "tools/list":
            send({"jsonrpc": "2.0", "id": req_id, "result": {"tools": TOOLS}})
        elif method == "tools/call":
            try:
                result = call_tool(params.get("name", ""), params.get("arguments") or {})
                send({
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "result": {
                        "content": [{"type": "text", "text": json.dumps(result, indent=2)}],
                        "isError": False,
                    },
                })
            except Exception as exc:
                send({
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "result": {
                        "content": [{"type": "text", "text": str(exc)}],
                        "isError": True,
                    },
                })
        else:
            send({
                "jsonrpc": "2.0",
                "id": req_id,
                "error": {"code": -32601, "message": f"Method not found: {method}"},
            })


if __name__ == "__main__":
    main()