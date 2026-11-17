---
name: security-audit
description: Perform an autonomous, read-only security, reliability, and 100-point domain rubric audit using deterministic static_audit.py analysis plus visual Markdown/Mermaid reports.
---

# Autonomous Code & Security Audit Playbook

Before scoring, read `references/rubric.md` completely.

## Evaluation Workflow
1. **Run Deterministic Scanner First (if shell access is available):**
   Execute `python scripts/static_audit.py <target_path>` (or run the `static_audit.py` script in this skill folder) to collect verified AST, syntax, secret, and sink findings in JSON. Treat script findings as ground-truth evidence alongside your own full-file inspection.
2. **Verify All Lines Directly:** Read every target file completely before reporting. Quote exact file paths, line numbers, and code snippets.
3. **Score Against Rubric:** Calculate points strictly using `references/rubric.md` (Security 30, Correctness 30, Reliability 20, Structure 20). Any Critical finding forces the verdict to **Revision Required**.

## Output Format & Consistency Rules
- **Executive Summary Table:** Exact severity counts (`Critical`, `High`, `Medium`, `Low`). Verify the counts equal the exact findings listed below before finishing.
- **Rubric Scorecard Table:** Score breakdown per category + total `/100` + final Verdict.
- **Threat-Flow Diagram:** Include a Mermaid diagram when untrusted inputs reach sensitive sinks.
- **Detailed Findings:** Include **Rule ID** (when detected by `static_audit.py`), **Severity**, **Confidence**, **File & Line**, **Vulnerable Code**, and **Fixed Code** (always using specific exception classes rather than bare `except Exception`).
- **Action Checklist:** Prioritized checklist of concrete fixes.