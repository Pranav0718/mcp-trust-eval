def score_findings(secret_findings, dependency_findings, tool_findings, trust_findings):
    score = 100
    breakdown = {}

    severity_weights = {
        "CRITICAL": 20,
        "HIGH": 10,
        "MEDIUM": 5,
        "LOW": 2
    }

    secret_deduction = 0
    for f in secret_findings:
        secret_deduction += severity_weights.get(f.get("severity", "HIGH"), 10)
    secret_deduction = min(secret_deduction, 40)
    score -= secret_deduction
    breakdown["secrets"] = {"findings": len(secret_findings), "deduction": secret_deduction}

    dep_deduction = 0
    for f in dependency_findings:
        dep_deduction += severity_weights.get(f.get("severity", "HIGH"), 10)
    dep_deduction = min(dep_deduction, 25)
    score -= dep_deduction
    breakdown["dependencies"] = {"findings": len(dependency_findings), "deduction": dep_deduction}

    tool_deduction = 0
    for f in tool_findings:
        tool_deduction += severity_weights.get(f.get("severity", "HIGH"), 10)
    tool_deduction = min(tool_deduction, 25)
    score -= tool_deduction
    breakdown["tool_analysis"] = {"findings": len(tool_findings), "deduction": tool_deduction}

    trust_deduction = 0
    for f in trust_findings:
        trust_deduction += severity_weights.get(f.get("severity", "LOW"), 2)
    trust_deduction = min(trust_deduction, 10)
    score -= trust_deduction
    breakdown["trust_signals"] = {"findings": len(trust_findings), "deduction": trust_deduction}

    score = max(0, score)

    if score >= 75:
        verdict = "LOW RISK"
        verdict_color = "GREEN"
        recommendation = "This server appears relatively safe to connect. Review individual findings before deploying in production."
    elif score >= 45:
        verdict = "MEDIUM RISK"
        verdict_color = "YELLOW"
        recommendation = "Proceed with caution. Address HIGH and CRITICAL findings before connecting to any production agent."
    else:
        verdict = "HIGH RISK"
        verdict_color = "RED"
        recommendation = "Do not connect this server to your agent. Critical security issues detected that could compromise your entire pipeline."

    return {
        "score": score,
        "verdict": verdict,
        "verdict_color": verdict_color,
        "recommendation": recommendation,
        "breakdown": breakdown,
        "total_findings": len(secret_findings) + len(dependency_findings) + len(tool_findings) + len(trust_findings)
    }
