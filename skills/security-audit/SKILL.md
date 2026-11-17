---
name: security-audit
description: Perform a thorough security, reliability, and domain-rubric audit on code or student/team projects. Use when reviewing code, auditing files, or grading project submissions.
---

# Security & Domain Audit Playbook

Before scoring, read `references/rubric.md` and evaluate every target file against:
1. **Secrets & Credentials:** Hardcoded API keys, tokens, DB URIs, weak defaults.
2. **Injection & Input Validation:** SQL injection, command injection, path traversal, XSS.
3. **Error Handling & Reliability:** Unhandled errors, resource leaks, overly broad `except Exception` catches.
4. **Domain Rubric Criteria:** All requirements defined in `references/rubric.md`.

## Output Format & Consistency Rules
- Present an **Executive Summary** table with exact counts by severity (`Critical`, `High`, `Medium`, `Low`).
- **Consistency check:** Count every finding below and verify the Executive Summary numbers equal the exact severity totals before finishing.
- For each finding, include **File & Line**, **Confidence**, **Risk**, **Vulnerable Code**, and **Fixed Code** (using specific exception classes, not bare `except Exception`).
- Include a **Mermaid diagram** tracing untrusted input to sensitive sinks when data-flow risks exist.