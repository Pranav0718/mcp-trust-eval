from datetime import datetime, timezone


def analyze_trust_signals(metadata: dict) -> list:
    findings = []
    now = datetime.now(timezone.utc)

    last_pushed = metadata.get("last_pushed")
    if last_pushed:
        try:
            pushed_dt = datetime.fromisoformat(last_pushed.replace("Z", "+00:00"))
            days_since = (now - pushed_dt).days
            if days_since > 365:
                findings.append({
                    "type": "Trust Signal",
                    "subtype": "Abandoned Repository",
                    "severity": "MEDIUM",
                    "detail": f"Repository has not been updated in {days_since} days, security patches may be missing"
                })
        except Exception:
            pass

    if not metadata.get("has_security_policy"):
        findings.append({
            "type": "Trust Signal",
            "subtype": "No Security Policy",
            "severity": "LOW",
            "detail": "Repository has no SECURITY.md, no responsible disclosure process defined"
        })

    if metadata.get("archived"):
        findings.append({
            "type": "Trust Signal",
            "subtype": "Archived Repository",
            "severity": "HIGH",
            "detail": "Repository is archived and will no longer receive security updates"
        })

    if not metadata.get("license"):
        findings.append({
            "type": "Trust Signal",
            "subtype": "No License",
            "severity": "LOW",
            "detail": "No license found, unclear usage rights and maintenance commitment"
        })

    if metadata.get("owner_type") == "User" and metadata.get("stars", 0) < 5:
        findings.append({
            "type": "Trust Signal",
            "subtype": "Low Community Trust",
            "severity": "MEDIUM",
            "detail": "Repository owned by individual user with very few stars, limited community vetting"
        })

    if metadata.get("open_issues", 0) > 50:
        findings.append({
            "type": "Trust Signal",
            "subtype": "High Open Issues",
            "severity": "LOW",
            "detail": f"{metadata['open_issues']} open issues may indicate maintenance backlog or known unresolved bugs"
        })

    return findings
