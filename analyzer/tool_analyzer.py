import re
import json


PROMPT_INJECTION_PATTERNS = [
    ("Instruction Override", r"(?i)(ignore|disregard|forget).{0,30}(previous|prior|above|system|instruction)", "CRITICAL"),
    ("System Prompt Leak", r"(?i)(reveal|expose|print|show|output).{0,30}(system prompt|instructions|context)", "CRITICAL"),
    ("Role Hijacking", r"(?i)(you are now|act as|pretend to be|roleplay as|your new role)", "HIGH"),
    ("Hidden Directive", r"(?i)(<!--|\/\*|\[hidden\]|\[system\]|\[admin\]).{0,100}(instruction|command|directive)", "HIGH"),
    ("Jailbreak Attempt", r"(?i)(developer mode|DAN mode|no restrictions|unrestricted|bypass safety)", "CRITICAL"),
    ("Data Exfiltration", r"(?i)(send|transmit|exfiltrate|upload|POST).{0,40}(password|secret|token|key|credential)", "CRITICAL"),
    ("SSRF Pattern", r"(?i)(fetch|request|curl|wget|http).{0,30}(internal|localhost|127\.0\.0\.1|169\.254)", "HIGH"),
    ("Excessive Scope Claim", r"(?i)(access to all|full access|unrestricted access|admin access|root access)", "HIGH"),
    ("Prompt Continuation", r"(?i)(continue from|pick up where|as we discussed|as previously instructed)", "MEDIUM"),
    ("Social Engineering", r"(?i)(urgent|immediately|without question|do not verify|trust me|bypass verification)", "MEDIUM"),
]

DANGEROUS_FUNCTIONS = [
    ("Arbitrary Code Execution", r"(?i)(eval\(|exec\(|subprocess\.call|os\.system|shell=True)", "CRITICAL"),
    ("File System Access", r"(?i)(open\(|os\.path|pathlib|shutil|glob\.glob)", "MEDIUM"),
    ("Network Calls", r"(?i)(requests\.get|requests\.post|urllib|httpx|aiohttp|fetch\()", "MEDIUM"),
    ("Environment Access", r"(?i)(os\.environ|process\.env|getenv)", "MEDIUM"),
    ("Dynamic Import", r"(?i)(__import__|importlib|require\()", "HIGH"),
]

MCP_TOOL_PATTERNS = [
    r"@tool\b",
    r"@mcp\.tool",
    r"Tool\(",
    r"\"tools\"\s*:",
    r"tools\s*=\s*\[",
    r"def\s+\w+\s*\(.*\).*->.*str",
]


def extract_tool_definitions(content: str, path: str) -> list:
    tools = []

    if path.endswith(".json"):
        try:
            data = json.loads(content)
            if isinstance(data, dict) and "tools" in data:
                for tool in data["tools"]:
                    tools.append({
                        "name": tool.get("name", "unknown"),
                        "description": tool.get("description", ""),
                        "parameters": json.dumps(tool.get("parameters", tool.get("inputSchema", {}))),
                        "source_file": path
                    })
        except Exception:
            pass
        return tools

    tool_blocks = re.findall(
        r'(?:@tool|@mcp\.tool)[^\n]*\n(?:.*\n){0,20}?(?:def\s+\w+[^:]+:)',
        content
    )
    for block in tool_blocks:
        name_match = re.search(r"def\s+(\w+)", block)
        desc_match = re.search(r'"""(.*?)"""', block, re.DOTALL)
        tools.append({
            "name": name_match.group(1) if name_match else "unknown",
            "description": desc_match.group(1).strip() if desc_match else "",
            "parameters": block,
            "source_file": path
        })

    return tools


def analyze_tool_definitions(files: dict) -> list:
    findings = []
    all_tools = []

    for path, content in files.items():
        is_mcp_file = any(re.search(p, content) for p in MCP_TOOL_PATTERNS)
        if is_mcp_file or path.endswith(".json"):
            tools = extract_tool_definitions(content, path)
            all_tools.extend(tools)

        for pattern_name, pattern, severity in PROMPT_INJECTION_PATTERNS:
            matches = re.findall(pattern, content)
            if matches:
                findings.append({
                    "type": "Prompt Injection Surface",
                    "subtype": pattern_name,
                    "file": path,
                    "severity": severity,
                    "detail": f"{pattern_name} pattern detected in tool definition or handler",
                    "match_count": len(matches)
                })

        for func_name, pattern, severity in DANGEROUS_FUNCTIONS:
            matches = re.findall(pattern, content)
            if matches:
                findings.append({
                    "type": "Dangerous Function Usage",
                    "subtype": func_name,
                    "file": path,
                    "severity": severity,
                    "detail": f"{func_name} usage detected, could be exploited via prompt injection",
                    "match_count": len(matches)
                })

    for tool in all_tools:
        desc = tool["description"].lower()
        params = tool["parameters"].lower()
        combined = desc + " " + params

        for pattern_name, pattern, severity in PROMPT_INJECTION_PATTERNS:
            if re.search(pattern, combined):
                findings.append({
                    "type": "Malicious Tool Description",
                    "subtype": pattern_name,
                    "tool_name": tool["name"],
                    "file": tool["source_file"],
                    "severity": severity,
                    "detail": f"Tool '{tool['name']}' description contains {pattern_name} pattern, possible tool poisoning attempt",
                })

    return findings, all_tools
