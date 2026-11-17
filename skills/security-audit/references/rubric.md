# Domain Evaluation Rubric

Customize these criteria for your target course, stack, or project type:

## 1. Correctness & Requirements
- Does the code fulfill its core function cleanly?
- Are edge cases handled (empty inputs, null/None, invalid types, boundary values)?

## 2. Security & Safety
- No hardcoded API keys, passwords, or tokens.
- Parameterized queries / safe escaping for database, shell, and web inputs.
- Specific exception handling (catch driver/domain exceptions like `sqlite3.Error` or `ValueError`—never swallow unknown bugs with bare `except Exception` without re-raising or narrow scoping).

## 3. Structure & Readability (Project / Course Standards)
- Clear function/variable naming and single-responsibility functions.
- Reproducible setup (dependencies listed, environment variables documented).