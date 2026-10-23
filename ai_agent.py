import os
import json
from dotenv import load_dotenv
from google import genai
from analyzer import analyze_logs

# Load API key from .env file automatically
load_dotenv()

def generate_soc_report(incidents):
    api_key = os.environ.get("GEMINI_API_KEY")
    if not api_key:
        print("[!] Error: GEMINI_API_KEY environment variable set kora nei!")
        return None

    # Initialize Gemini Client
    client = genai.Client(api_key=api_key)

    prompt = f"""
    You are an elite Autonomous Tier-3 SOC Analyst. 
    Analyze the following security incidents detected from our web server logs and generate a professional Incident Response Report in Markdown format.

    Detected Incidents (JSON):
    {json.dumps(incidents, indent=2)}

    Your report MUST include:
    1. **Executive Summary**: Brief overview of the attack campaign and critical risks (highlight successful HTTP 200 attacks vs blocked attempts).
    2. **Attacker Profiling (By IP)**: Group activities by IP address, explain what payloads they used, and whether the attack succeeded.
    3. **Immediate Containment (Firewall Rules)**: Exact Linux `ufw` and `iptables` commands to block the malicious IPs immediately.
    4. **Code & WAF Remediation**: Specific fixes (e.g., Parameterized Queries, Input Sanitization, Rate Limiting, CSP headers) for the engineering team.
    """

    print("[*] Sending threat telemetry to SentinelAI SOC Engine (Gemini 3.8 Flash)...")
    response = client.models.generate_content(
        model="gemini-3.8-flash",
        contents=prompt,
    )
    return response.text

if __name__ == "__main__":
    print("[*] Running Step 1: Scanning access.log...")
    incidents = analyze_logs("access.log")
    print(f"[+] Found {len(incidents)} threats.")

    if incidents:
        report = generate_soc_report(incidents)
        if report:
            report_file = "incident_report.md"
            with open(report_file, "w", encoding="utf-8") as f:
                f.write(report)
            print(f"\n[SUCCESS] Full AI Incident Response Report saved to '{report_file}'!")
            print("-" * 60)
            print(report[:800] + "\n...\n[Open incident_report.md to view the full report]")