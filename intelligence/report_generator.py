import os
import time
import json
import requests


def generate_threat_brief(repo_name: str, score_result: dict, all_findings: list, metadata: dict) -> str:
    api_key = os.getenv("GEMINI_API_KEY")
    if not api_key:
        return "GEMINI_API_KEY not set in .env file."

    models_to_try = [
    "gemini-2.0-flash-lite",
    "gemini-2.0-flash-001",
    "gemini-2.5-flash",
    ]

    critical = [f for f in all_findings if f.get("severity") == "CRITICAL"]
    high = [f for f in all_findings if f.get("severity") == "HIGH"]

    findings_summary = json.dumps({
        "score": score_result["score"],
        "verdict": score_result["verdict"],
        "critical_findings": critical[:5],
        "high_findings": high[:5],
        "breakdown": score_result["breakdown"]
    }, indent=2)

    prompt = f"""You are an expert AI security researcher specializing in MCP (Model Context Protocol) server security and LLM agent safety.

A security evaluation was run on the MCP server: {repo_name}
Language: {metadata.get('language', 'Unknown')}
Last updated: {metadata.get('last_pushed', 'Unknown')}
Trust Score: {score_result['score']}/100 ({score_result['verdict']})

Security Findings Summary:
{findings_summary}

Provide a structured threat brief with exactly these four sections:

1. THREAT SUMMARY
A 3-4 sentence plain English summary of the overall risk this MCP server poses to an AI agent that connects to it.

2. ATTACK SCENARIOS
List 2-3 specific realistic attack scenarios an adversary could execute using this server against an agent.

3. CURRENT THREAT CONTEXT
How do these findings relate to known MCP attack patterns like tool poisoning, confused deputy, indirect prompt injection, or rug pull attacks.

4. SAFE USAGE RECOMMENDATIONS
4-5 specific actionable recommendations to reduce risk if someone must use this server.

Keep the entire response under 600 words. Be direct and technical."""

    payload = {
        "contents": [{"parts": [{"text": prompt}]}],
        "generationConfig": {
            "temperature": 0.3,
            "maxOutputTokens": 800
        }
    }

    for model in models_to_try:
        url = f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent?key={api_key}"
        print(f"Trying model: {model}")
        try:
            resp = requests.post(url, json=payload, timeout=30)
            print(f"Status: {resp.status_code}")
            if resp.status_code == 429:
                print("Rate limited on this model, trying next...")
                time.sleep(10)
                continue
            if resp.status_code == 404:
                print("Model not found, trying next...")
                continue
            resp.raise_for_status()
            data = resp.json()
            return data["candidates"][0]["content"]["parts"][0]["text"]
        except Exception as e:
            print(f"Error with {model}: {e}")
            time.sleep(5)
            continue

    return f"All models failed. Manual summary: {score_result['recommendation']}"