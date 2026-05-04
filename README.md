# MCP Trust Evaluation Framework

A security scanner that evaluates the trustworthiness of MCP (Model Context Protocol) servers before you connect them to your AI agent. Paste a GitHub URL, get a full threat report in seconds.

## Why This Exists

The MCP ecosystem is growing fast and most teams connect MCP servers to their agents without any security vetting. A malicious or poorly secured MCP server can compromise your entire agent pipeline through tool poisoning, prompt injection via tool outputs, credential theft, or confused deputy attacks.

This tool runs four security checks against any public MCP server and generates an AI powered threat brief grounded in current MCP attack research.

## What It Checks

**Secret Scanning** — Detects hardcoded API keys, tokens, credentials, and private keys across the entire codebase. A server with embedded credentials is an immediate critical risk.

**Dependency Vulnerability Scanning** — Queries the OSV database for known CVEs in all Python and Node dependencies. Vulnerable dependencies in a server you connect to your agent can be exploited transitively.

**MCP Tool Definition Analysis** — The most MCP specific check. Scans every tool name, description, and parameter definition for prompt injection patterns, instruction override attempts, data exfiltration patterns, SSRF vectors, and dangerous function usage. This is where tool poisoning attacks hide.

**Trust Signal Analysis** — Evaluates repository health signals including maintenance status, security policy presence, license, community vetting, and archival status.

## Trust Score

Each check contributes to a score out of 100:

| Score | Verdict | Meaning |
|---|---|---|
| 75-100 | LOW RISK | Safe to evaluate further |
| 45-74 | MEDIUM RISK | Proceed with caution, fix HIGH findings first |
| 0-44 | HIGH RISK | Do not connect to your agent |

## Setup

```bash
git clone https://github.com/yourusername/mcp-trust-eval
cd mcp-trust-eval
pip install -r requirements.txt
cp .env.example .env
```

Edit `.env` and add your keys:
```
GEMINI_API_KEY=your_gemini_api_key
GITHUB_TOKEN=your_github_token
```

Get a free Gemini API key at aistudio.google.com
Get a GitHub token at github.com/settings/tokens (read only repo scope)

## Usage

```bash
python main.py https://github.com/owner/mcp-server-name
```

The tool outputs a color coded terminal report and saves a full JSON report locally.

## Example Output

```
TRUST SCORE
47/100  [█████████░░░░░░░░░░░]  MEDIUM RISK

SECRET SCANNING (1 findings)
  [CRITICAL] Google API Key — Possible Google API Key found at line 23
             File: src/client.py

DEPENDENCY VULNERABILITIES (2 findings)
  [HIGH] Vulnerable Dependency — requests 2.28.0 — GHSA-j8r2-6x86-q33q
  [MEDIUM] Vulnerable Dependency — urllib3 1.26.0 — CVE-2023-43804

TOOL DEFINITION ANALYSIS (1 findings)
  [HIGH] Dangerous Function Usage — Arbitrary Code Execution
         File: tools/executor.py

AI GENERATED THREAT BRIEF
...
```

## Attack Classes Detected

The tool specifically looks for MCP attack patterns documented in recent security research:

**Tool Poisoning** — Hidden instructions embedded in tool descriptions that hijack agent behavior when the tool is called.

**Confused Deputy** — A server that requests permissions beyond its stated purpose and uses them on behalf of a higher privileged caller.

**Indirect Prompt Injection** — Malicious instructions delivered through tool return values rather than user input.

**Rug Pull** — A server that behaves safely during evaluation but changes behavior in production.

**Credential Harvesting** — Tools designed to extract API keys, tokens, or credentials from the agent context.

## Background

Built by Pranav Walgude, MS Cybersecurity candidate at Northeastern University. Informed by hands on offensive testing of MCP servers during a security internship where critical tool poisoning and prompt injection vulnerabilities were discovered across production AI agent infrastructure.

## License

MIT
