import re
import json
import requests


OSV_API = "https://api.osv.dev/v1/query"


def extract_python_deps(content: str) -> list:
    deps = []
    lines = content.strip().split("\n")
    for line in lines:
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        match = re.match(r"^([a-zA-Z0-9_\-\.]+)([>=<!~^]+.*)?$", line)
        if match:
            name = match.group(1)
            version_spec = match.group(2) or ""
            version = re.findall(r"[\d\.]+", version_spec)
            deps.append({
                "name": name,
                "version": version[0] if version else None,
                "ecosystem": "PyPI"
            })
    return deps


def extract_node_deps(content: str) -> list:
    deps = []
    try:
        data = json.loads(content)
        all_deps = {}
        all_deps.update(data.get("dependencies", {}))
        all_deps.update(data.get("devDependencies", {}))
        for name, version_spec in all_deps.items():
            version = re.findall(r"[\d\.]+", version_spec)
            deps.append({
                "name": name,
                "version": version[0] if version else None,
                "ecosystem": "npm"
            })
    except Exception:
        pass
    return deps


def query_osv(name: str, version: str, ecosystem: str) -> list:
    if not version:
        payload = {"package": {"name": name, "ecosystem": ecosystem}}
    else:
        payload = {"version": version, "package": {"name": name, "ecosystem": ecosystem}}

    try:
        resp = requests.post(OSV_API, json=payload, timeout=10)
        if resp.status_code == 200:
            data = resp.json()
            return data.get("vulns", [])
    except Exception:
        pass
    return []


def scan_dependencies(files: dict) -> list:
    findings = []
    deps = []

    for path, content in files.items():
        filename = path.split("/")[-1].lower()
        if filename == "requirements.txt":
            deps.extend(extract_python_deps(content))
        elif filename == "package.json":
            deps.extend(extract_node_deps(content))

    seen = set()
    for dep in deps:
        key = f"{dep['name']}:{dep['ecosystem']}"
        if key in seen:
            continue
        seen.add(key)

        vulns = query_osv(dep["name"], dep["version"], dep["ecosystem"])
        for vuln in vulns[:3]:
            severity = "HIGH"
            cvss = vuln.get("database_specific", {}).get("cvss", "")
            if cvss:
                try:
                    score = float(re.findall(r"[\d\.]+", str(cvss))[0])
                    if score >= 9.0:
                        severity = "CRITICAL"
                    elif score >= 7.0:
                        severity = "HIGH"
                    elif score >= 4.0:
                        severity = "MEDIUM"
                    else:
                        severity = "LOW"
                except Exception:
                    pass

            findings.append({
                "type": "Vulnerable Dependency",
                "package": dep["name"],
                "version": dep["version"],
                "ecosystem": dep["ecosystem"],
                "vuln_id": vuln.get("id", "Unknown"),
                "severity": severity,
                "detail": vuln.get("summary", "Known vulnerability found"),
                "references": [r.get("url") for r in vuln.get("references", [])[:2]]
            })

    return findings
