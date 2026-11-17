---
name: security-audit
description: Perform an autonomous, read-only security, reliability, and 100-point domain rubric audit using code-reviewer-mcp tools, static_audit.py, and visual Markdown/Mermaid reports.
---

# Autonomous Code & Security Audit Playbook

## Evaluation Workflow
1. **Load Rubric & Run Deterministic Scan:**
   - Call the `get_review_rubric` MCP tool (or read `references/rubric.md`).
   - Call the `run_static_audit` MCP tool on the target path (or run `python scripts/static_audit.py <target_path>` if calling via CLI).
2. **Verify All Lines Directly:** Read every target file completely before reporting. Quote exact file paths, line numbers, and code snippets.
3. **Compute Exact Verdict:** Call `calculate_rubric_score` with your category deductions and `has_critical` boolean so the `/100` score and Verdict are mathematically exact.

## Output Format & Consistency Rules
- **Executive Summary Table:** Exact severity counts (`Critical`, `High`, `Medium`, `Low`). Verify the counts match the exact findings listed below before finishing.
- **Rubric Scorecard Table:** Score breakdown per category + total `/100` + final Verdict from `calculate_rubric_score`.
- **Threat-Flow Diagram:** Include a Mermaid diagram when untrusted inputs reach sensitive sinks.
- **Detailed Findings:** Include **Rule ID**, **Severity**, **Confidence**, **File & Line**, **Vulnerable Code**, and **Fixed Code** (always using specific exception classes rather than bare `except Exception`).
- **Action Checklist:** Prioritized checklist of concrete fixes.