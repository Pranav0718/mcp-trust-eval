import re

SECRET_PATTERNS = [
    ("AWS Access Key", r"AKIA[0-9A-Z]{16}"),
    ("AWS Secret Key", r"(?i)aws.{0,20}secret.{0,20}['\"][0-9a-zA-Z/+]{40}['\"]"),
    ("GitHub Token", r"ghp_[a-zA-Z0-9]{36}|github_pat_[a-zA-Z0-9_]{82}"),
    ("Google API Key", r"AIza[0-9A-Za-z\-_]{35}"),
    ("OpenAI API Key", r"sk-[a-zA-Z0-9]{48}"),
    ("Anthropic API Key", r"sk-ant-[a-zA-Z0-9\-_]{90,}"),
    ("Slack Token", r"xox[baprs]-[0-9a-zA-Z]{10,48}"),
    ("Stripe Secret Key", r"sk_live_[0-9a-zA-Z]{24,}"),
    ("Generic Secret", r"(?i)(secret|password|passwd|api_key|apikey|token|auth)['\"]?\s*[:=]\s*['\"][a-zA-Z0-9+/=_\-]{16,}['\"]"),
    ("Private Key Header", r"-----BEGIN (RSA|EC|DSA|OPENSSH) PRIVATE KEY-----"),
    ("Bearer Token", r"(?i)bearer\s+[a-zA-Z0-9\-_\.]{20,}"),
    ("Database URL", r"(?i)(mongodb|postgres|mysql|redis|postgresql)://[^\s'\"]{10,}"),
]

SKIP_EXTENSIONS = {".md", ".txt", ".example", ".sample"}
SKIP_PATHS = {"test", "mock", "fixture", "example", "sample", "fake"}


def is_likely_false_positive(path: str, match: str) -> bool:
    path_lower = path.lower()
    for skip in SKIP_PATHS:
        if skip in path_lower:
            return True
    placeholders = {"your_", "xxx", "example", "placeholder", "dummy", "insert", "changeme", "xxxxxxxx"}
    match_lower = match.lower()
    for p in placeholders:
        if p in match_lower:
            return True
    return False


def scan_secrets(files: dict) -> list:
    findings = []

    for path, content in files.items():
        ext = "." + path.split(".")[-1] if "." in path else ""
        if ext in SKIP_EXTENSIONS:
            continue

        lines = content.split("\n")
        for line_num, line in enumerate(lines, 1):
            if line.strip().startswith("#") or line.strip().startswith("//"):
                continue
            for pattern_name, pattern in SECRET_PATTERNS:
                matches = re.findall(pattern, line)
                for match in matches:
                    match_str = match if isinstance(match, str) else match[0]
                    if is_likely_false_positive(path, match_str):
                        continue
                    findings.append({
                        "type": pattern_name,
                        "file": path,
                        "line": line_num,
                        "severity": "CRITICAL",
                        "detail": f"Possible {pattern_name} found at line {line_num}",
                        "snippet": line.strip()[:120]
                    })

    return findings
