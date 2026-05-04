import os
import sys
from dotenv import load_dotenv

load_dotenv()

from analyzer.repo_fetcher import fetch_repo
from analyzer.secret_scanner import scan_secrets
from analyzer.dependency_scanner import scan_dependencies
from analyzer.tool_analyzer import analyze_tool_definitions
from analyzer.trust_signals import analyze_trust_signals
from scoring.trust_scorer import score_findings
from intelligence.report_generator import generate_threat_brief
from output.formatter import display_full_report


def main():
    if len(sys.argv) < 2:
        print("Usage: python main.py <github_url>")
        print("Example: python main.py https://github.com/owner/mcp-server")
        sys.exit(1)

    github_url = sys.argv[1].strip()

    if not os.getenv("GEMINI_API_KEY"):
        print("ERROR: GEMINI_API_KEY not set in .env file")
        sys.exit(1)

    if not os.getenv("GITHUB_TOKEN"):
        print("ERROR: GITHUB_TOKEN not set in .env file")
        sys.exit(1)

    print(f"\nFetching repository: {github_url}")
    try:
        repo_data = fetch_repo(github_url)
    except Exception as e:
        print(f"ERROR: Could not fetch repository: {e}")
        sys.exit(1)

    files = repo_data["files"]
    metadata = repo_data["metadata"]
    repo_name = f"{repo_data['owner']}/{repo_data['repo']}"

    print(f"Fetched {len(files)} files from {repo_name}")

    print("Running secret scan...")
    secret_findings = scan_secrets(files)

    print("Running dependency vulnerability scan...")
    dep_findings = scan_dependencies(files)

    print("Analyzing MCP tool definitions...")
    tool_findings, tools = analyze_tool_definitions(files)

    print("Analyzing trust signals...")
    trust_findings = analyze_trust_signals(metadata)

    score_result = score_findings(secret_findings, dep_findings, tool_findings, trust_findings)

    print("Generating AI threat brief...")
    all_findings = secret_findings + dep_findings + tool_findings + trust_findings
    threat_brief = generate_threat_brief(repo_name, score_result, all_findings, metadata)

    display_full_report(
        github_url,
        score_result,
        secret_findings,
        dep_findings,
        tool_findings,
        trust_findings,
        tools,
        threat_brief,
        metadata
    )


if __name__ == "__main__":
    main()
