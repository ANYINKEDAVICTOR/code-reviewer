---
name: security-audit
description: Perform an autonomous, read-only security, reliability, and 100-point domain rubric audit on codebases or course submissions with visual Markdown/Mermaid reports.
---

# Autonomous Code & Security Audit Playbook

Before scoring, read `references/rubric.md` completely and inspect every target file thoroughly.

## Evaluation Workflow
1. **Verify Facts First:** Read the actual file(s) completely before reporting any issue. Quote exact file paths, line numbers, and code snippets.
2. **Audit Security & Logic:** Check secrets, injection vectors, input validation, edge cases, resource leaks, and exception specificity.
3. **Score Against Rubric:** Calculate points strictly using `references/rubric.md` (Security 30, Correctness 30, Reliability 20, Structure 20). Note that any Critical security issue forces the verdict to **Revision Required** regardless of total score.

## Output Format & Consistency Rules
- **Executive Summary Table:** Exact severity counts (`Critical`, `High`, `Medium`, `Low`). Verify the counts equal the exact findings listed below before finishing.
- **Rubric Scorecard Table:** Score breakdown per category + total `/100` + final Verdict.
- **Threat-Flow Diagram:** Include a Mermaid diagram when untrusted inputs reach sensitive sinks (DB, shell, filesystem, network).
- **Detailed Findings:** Include **Severity**, **Confidence**, **File & Line**, **Vulnerable Code**, and **Fixed Code** (always using specific exception classes rather than bare `except Exception`).
- **Action Checklist:** Prioritized checklist of concrete fixes.