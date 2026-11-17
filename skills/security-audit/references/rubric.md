# Code & Project Evaluation Rubric (100 Points)

Score every reviewed codebase or coursework submission objectively against these four weighted categories. Deduct points only for verified issues observed directly in the files read.

## 1. Security & Safety (30 Points)
- **No Hardcoded Secrets (10 pts):** No API keys, tokens, passwords, or private credentials in source files.
- **Injection & Input Protection (12 pts):** Parameterized database queries, sanitized shell/file/HTML inputs, and validated user input.
- **Safe Defaults (8 pts):** Fail-fast when required environment variables are missing; no debug/insecure bypass flags left enabled.

## 2. Correctness & Edge Cases (30 Points)
- **Functional Logic (15 pts):** Code fulfills its stated purpose without logic bugs, off-by-one errors, or unreachable branches.
- **Boundary & Null Handling (15 pts):** Handles `None`/`null`, empty strings/lists, invalid types, and missing records gracefully.

## 3. Error Handling & Reliability (20 Points)
- **Specific Exception Handling (10 pts):** Catches specific exceptions (e.g., `sqlite3.Error`, `ValueError`, `OSError`) instead of swallowing everything with bare `except:` or broad `except Exception:` without re-raising.
- **Resource & State Safety (10 pts):** Closes DB connections/files safely (e.g., `with` context managers) and logs failures without leaking secrets or raw stack traces to end users.

## 4. Structure, Maintainability & Readiness (20 Points)
- **Clarity & Modularity (10 pts):** Descriptive names, focused functions, and minimal duplication.
- **Reproducibility & Docs (10 pts):** Clear setup instructions, dependencies, and environment variable requirements.

## Verdict Thresholds
- **90-100:** Approved / Production-Ready
- **70-89:** Pass with Minor Fixes
- **Below 70 (or ANY Critical security issue):** Revision Required