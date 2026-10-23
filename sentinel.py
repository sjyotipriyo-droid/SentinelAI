import os
import sys
import argparse
from dotenv import load_dotenv
from analyzer import analyze_logs
from ai_agent import generate_soc_report

load_dotenv()

RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
MAGENTA = "\033[95m"
RESET = "\033[0m"

def print_banner():
    banner = f"""
{CYAN}  ███████╗███████╗███╗   ██╗████████╗██╗███╗   ██╗███████╗ █████╗ ██╗
  ██╔════╝██╔════╝████╗  ██║╚══██╔══╝██║████╗  ██║██╔════╝██╔══██╗██║
  ███████╗█████╗  ██╔██╗ ██║   ██║   ██║██╔██╗ ██║█████╗  ███████║██║
  ╚════██║██╔══╝  ██║╚██╗██║   ██║   ██║██║╚██╗██║██╔══╝  ██╔══██║██║
  ███████║███████╗██║ ╚████║   ██║   ██║██║ ╚████║███████╗██║  ██║██║
  ╚══════╝╚══════╝╚═╝  ╚═══╝   ╚═╝   ╚═╝╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝╚═╝
        [ Autonomous Tier-3 SOC Threat Hunter + Live OSINT ]
{RESET}"""
    print(banner)

def main():
    parser = argparse.ArgumentParser(description="SentinelAI - Autonomous SOC Log Threat Hunter")
    parser.add_argument("--log", type=str, default="access.log", help="Path to the server log file")
    parser.add_argument("--output", type=str, default="incident_report.md", help="Path to save the AI report")
    args = parser.parse_args()

    print_banner()

    log_path = args.log
    if not os.path.exists(log_path):
        print(f"{RED}[!] Error: Log file '{log_path}' pawa gelo na!{RESET}")
        sys.exit(1)

    print(f"{YELLOW}[*] Scanning target log file & querying Live OSINT: {log_path}...{RESET}")
    incidents = analyze_logs(log_path)
    
    print(f"{GREEN}[+] Scan complete! Total threats detected: {len(incidents)}{RESET}\n")

    if not incidents:
        print(f"{GREEN}[✓] No security threats found. System is clean!{RESET}")
        return

    # Display enriched summary in terminal
    for idx, inc in enumerate(incidents, 1):
        sev_color = RED if inc['severity'] in ['CRITICAL', 'HIGH'] else YELLOW
        osint = inc.get('osint', {})
        print(f"  {sev_color}[{idx}] {inc['threat_type']} [{inc['severity']}]{RESET}")
        print(f"      {MAGENTA}MITRE ATT&CK:{RESET} {inc.get('mitre_attack')}")
        print(f"      {CYAN}Attacker IP :{RESET} {inc['ip']} ({osint.get('country')} | ISP: {osint.get('isp')})")
        print(f"      {YELLOW}Payload     :{RESET} {inc['payload']} (HTTP {inc['status_code']})\n")

    choice = input(f"{CYAN}[?] Do you want SentinelAI Engine to generate an Incident Response Report? (y/n): {RESET}").strip().lower()
    
    if choice == 'y':
        report = generate_soc_report(incidents)
        if report:
            with open(args.output, "w", encoding="utf-8") as f:
                f.write(report)
            print(f"\n{GREEN}[SUCCESS] Enriched IR Report saved to '{args.output}'!{RESET}")
    else:
        print(f"{YELLOW}[*] Report generation skipped by user.{RESET}")

if __name__ == "__main__":
    main()