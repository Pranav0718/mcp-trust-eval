import json
from datetime import datetime


RED = "\033[91m"
YELLOW = "\033[93m"
GREEN = "\033[92m"
BLUE = "\033[94m"
BOLD = "\033[1m"
RESET = "\033[0m"
DIM = "\033[2m"


def severity_color(severity: str) -> str:
    return {
        "CRITICAL": RED,
        "HIGH": YELLOW,
        "MEDIUM": BLUE,
        "LOW": DIM
    }.get(severity, RESET)


def print_banner():
    print(f"""
{BOLD}╔══════════════════════════════════════════════════════════╗
║          MCP TRUST EVALUATION FRAMEWORK                  ║
║          AI Agent Security Scanner                       ║
╚══════════════════════════════════════════════════════════╝{RESET}
""")


def print_score(score_result: dict):
    score = score_result["score"]
    verdict = score_result["verdict"]
    color = RED if verdict == "HIGH RISK" else (YELLOW if verdict == "MEDIUM RISK" else GREEN)

    bar_filled = int(score / 5)
    bar = "█" * bar_filled + "░" * (20 - bar_filled)

    print(f"\n{BOLD}TRUST SCORE{RESET}")
    print(f"{color}{BOLD}{score}/100  [{bar}]  {verdict}{RESET}")
    print(f"\n{score_result['recommendation']}\n")
    print(f"{DIM}{'─' * 60}{RESET}")


def print_findings_section(title: str, findings: list):
    if not findings:
        print(f"\n{GREEN}✓ {title}: No issues found{RESET}")
        return

    print(f"\n{BOLD}{title} ({len(findings)} findings){RESET}")
    for f in findings:
        sev = f.get("severity", "LOW")
        color = severity_color(sev)
        print(f"  {color}[{sev}]{RESET} {f.get('type', '')} — {f.get('subtype', f.get('detail', ''))[:80]}")
        if f.get("file"):
            print(f"         {DIM}File: {f['file']}{RESET}")
        if f.get("package"):
            print(f"         {DIM}Package: {f['package']} {f.get('version', '')} — {f.get('vuln_id', '')}{RESET}")


def print_threat_brief(brief: str):
    print(f"\n{BOLD}{'═' * 60}{RESET}")
    print(f"{BOLD}  AI GENERATED THREAT BRIEF{RESET}")
    print(f"{BOLD}{'═' * 60}{RESET}\n")
    for line in brief.split("\n"):
        print(line)
    print(f"\n{BOLD}{'═' * 60}{RESET}\n")


def print_tools_found(tools: list):
    if not tools:
        return
    print(f"\n{BOLD}MCP TOOLS DISCOVERED ({len(tools)} tools){RESET}")
    for tool in tools:
        print(f"  {BLUE}•{RESET} {tool.get('name', 'unknown')} {DIM}({tool.get('source_file', '')}){RESET}")


def save_json_report(github_url: str, score_result: dict, all_findings: list, threat_brief: str, tools: list, metadata: dict):
    report = {
        "evaluated_at": datetime.utcnow().isoformat() + "Z",
        "repository": github_url,
        "metadata": metadata,
        "score": score_result,
        "tools_discovered": tools,
        "findings": all_findings,
        "threat_brief": threat_brief
    }
    filename = f"mcp_trust_report_{metadata.get('repo', 'unknown')}_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.json"
    with open(filename, "w") as f:
        json.dump(report, f, indent=2)
    return filename


def display_full_report(github_url, score_result, secret_findings, dep_findings, tool_findings, trust_findings, tools, threat_brief, metadata):
    print_banner()
    print(f"{BOLD}Repository:{RESET} {github_url}")
    print(f"{BOLD}Language:{RESET}   {metadata.get('language', 'Unknown')}")
    print(f"{BOLD}Last Push:{RESET}  {metadata.get('last_pushed', 'Unknown')[:10]}")
    print(f"{BOLD}License:{RESET}    {metadata.get('license', 'None')}")

    print_score(score_result)
    print_tools_found(tools)
    print_findings_section("SECRET SCANNING", secret_findings)
    print_findings_section("DEPENDENCY VULNERABILITIES", dep_findings)
    print_findings_section("TOOL DEFINITION ANALYSIS", tool_findings)
    print_findings_section("TRUST SIGNALS", trust_findings)
    print_threat_brief(threat_brief)

    all_findings = secret_findings + dep_findings + tool_findings + trust_findings
    filename = save_json_report(github_url, score_result, all_findings, threat_brief, tools, metadata)
    print(f"{GREEN}Report saved:{RESET} {filename}\n")
