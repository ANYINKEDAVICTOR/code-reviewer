<p align="center">
  <img src="./assets/logo.svg" alt="Code Reviewer by Anyinkeda Victor" width="160" />
</p>

# Code Reviewer

**Created by Anyinkeda Victor**

A read-only, autonomous **Code Reviewer** built as a **Kiro Power** (Agent Plugins 1.0.0) combining deterministic Python AST scanning, a 100-point weighted evaluation rubric, an embedded zero-dependency MCP server, and visual Markdown/Mermaid audit reports.

## Key Capabilities
- **Deterministic Static Analysis (`code-reviewer-mcp` / `static_audit.py`):** Detects hardcoded secrets, SQL injection vectors, unsafe `eval`/`exec`/`shell=True` calls, syntax errors, and broad exception handlers.
- **100-Point Domain Rubric:** Scores **Security (30)**, **Correctness (30)**, **Reliability (20)**, and **Structure (20)** with automatic verdict thresholds.
- **Visual IDE Reports:** Generates structured Executive Summary tables, Scorecard tables, Mermaid threat-flow diagrams, and copy-pasteable fixes.

## Installation in Kiro IDE
1. Open **Kiro IDE** and click the **Powers** icon in the left sidebar.
2. Click **Add Custom Power -> Import power from GitHub**.
3. Paste: `https://github.com/ANYINKEDAVICTOR/code-reviewer`
4. Click **Install** *(Requires Python 3 on PATH for `code-reviewer-mcp`)*.

## Usage
- **Kiro IDE / Kiro CLI:** Open any project and ask:
  - `/security-audit Review @<filename>`
  - `Run a code review and rubric check on @<filename>`
- **ACP Clients (JetBrains IDEs, Zed, etc.):** Connect your ACP client using `kiro-cli acp` (`kiro-cli acp --help` for flags).

## Support & Feedback
- **Bug Reports & Feature Requests:** [GitHub Issues](https://github.com/ANYINKEDAVICTOR/code-reviewer/issues)
- **Repository:** https://github.com/ANYINKEDAVICTOR/code-reviewer

## Privacy & License
- **Privacy Policy:** [PRIVACY.md](https://github.com/ANYINKEDAVICTOR/code-reviewer/blob/main/PRIVACY.md)
- **License:** [MIT License](./LICENSE)