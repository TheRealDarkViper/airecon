import re
import socket
import json
import shodan
import whois
import subprocess
from openai import OpenAI

client = OpenAI(api_key="")  # or use transformers-based model
from selenium import webdriver
from github import Github

# Set your OpenAI API Key

################################
# 1. Auto-Detect Available Model
################################
def get_available_openai_model():
    """Force usage of GPT-4o model with no fallback."""
    return "gpt-4o"

MODEL_NAME = get_available_openai_model()

########################################################
# 2. WHOIS Lookup + AI Analysis
########################################################

def perform_whois_lookup(target: str):
    """Performs WHOIS lookup and just prints the raw data, without sending it to AI."""
    try:
        # Strip http:// or https:// from the target if present, plus any trailing slashes
        target_domain = re.sub(r'^https?://', '', target).rstrip('/')
        print(f"[DEBUG] WHOIS target domain: {target_domain}")

        domain_info_dict = whois.whois(target_domain)

        # Print the raw WHOIS data in JSON format
        domain_info_json = json.dumps(domain_info_dict, default=str, indent=2)
        print("WHOIS Raw Data:")
        print(domain_info_json)

        return domain_info_dict
    except Exception as e:
        return f"WHOIS lookup failed: {e}"


########################################################
# 3. Google Dorking
########################################################
def google_dorking(target: str):
    """Generates and prints AI-suggested Google Dorks based on the target."""
    prompt = (
        f"Generate Google Dorks for reconnaissance on {target}, focusing on "
        f"security vulnerabilities and pentesting insights. Output only the queries, one per line, no descriptions."
    )
    try:
        response = client.chat.completions.create(model=MODEL_NAME,
        messages=[
            {
                "role": "system",
                "content": (
                    "You are an AI designed to assist in pentesting reconnaissance. "
                    "Generate effective Google Dorks to discover sensitive information and potential vulnerabilities."
                ),
            },
            {"role": "user", "content": prompt},
        ])
        dorks = response.choices[0].message.content.split("\n")
        print("\n[+] AI-Suggested Google Dorks:")
        for dork in dorks:
            print(f"  - {dork}")
        return dorks
    except Exception as e:
        print(f"[-] Google Dorking failed: {e}")
        return []

########################################################
# 4. GitHub Dorks
########################################################
def search_github(target: str):
    """Generates GitHub search queries (dorks) for finding sensitive info."""
    prompt = (
        f"Generate the top 10 GitHub search queries for finding sensitive information "
        f"related to {target}. Output only the queries, one per line, no descriptions."
    )
    try:
        response = client.chat.completions.create(model=MODEL_NAME,
        messages=[
            {
                "role": "system",
                "content": (
                    "You are an AI designed for cybersecurity reconnaissance. "
                    "Generate GitHub search queries for finding sensitive information."
                ),
            },
            {"role": "user", "content": prompt},
        ])
        dorks = response.choices[0].message.content.split("\n")
        print("\n[+] AI-Suggested GitHub Search Queries:")
        for dork in dorks:
            print(f"  - {dork}")
        return dorks
    except Exception as e:
        print(f"[-] GitHub search failed: {e}")
        return []

########################################################
# 5. Shodan Port Scan
########################################################
def check_open_ports(target: str):
    """Resolves the domain, then queries Shodan for open ports."""
    SHODAN_API_KEY = ""
    api = shodan.Shodan(SHODAN_API_KEY)

    try:
        # Remove http/https if present
        target_domain = re.sub(r'^https?://', '', target)
        ip_address = socket.gethostbyname(target_domain)
        print(f"[+] Resolved {target_domain} to IP: {ip_address}")
        result = api.host(ip_address)
        print("\n[+] Open Ports Found:")
        for port in result.get('ports', []):
            print(f"  - Port {port}")
        return result.get('ports', [])
    except socket.gaierror:
        print(f"[-] Could not resolve domain: {target}")
    except shodan.APIError as e:
        print(f"[-] Shodan API Error: {e}")
    return []

########################################################
# 6. Screenshot Capture
########################################################
def capture_screenshot(target: str):
    """Captures a screenshot of the target website using Selenium."""
    options = webdriver.ChromeOptions()
    options.headless = True
    try:
        driver = webdriver.Chrome(options=options)
        driver.get(target)
        driver.save_screenshot("screenshot.png")
        driver.quit()
        print("[+] Screenshot saved as screenshot.png")
    except Exception as e:
        print(f"[-] Error capturing screenshot: {e}")

########################################################
# 7. Webanalyze + AI Wordlist
########################################################
def find_versions_and_generate_wordlist(target: str):
    """Uses Webanalyze to detect technologies and generate a custom wordlist."""
    try:
        print("[+] Running Webanalyze to detect website technologies...")
        result = subprocess.run(
            ["/home/user/go/bin/webanalyze", "-host", target, "-output", "json"],
            capture_output=True,
            text=True
        )
        if result.returncode != 0:
            print(f"[-] Webanalyze execution failed: {result.stderr}")
            return []

        analysis_data = json.loads(result.stdout)
        versions = []
        for match in analysis_data.get("matches", []):
            tech_name = match.get("app_name", "Unknown")
            tech_version = match.get("version", "").strip()
            if tech_version:
                versions.append(f"{tech_name} {tech_version}")
            else:
                versions.append(tech_name)

        unique_versions = list(set(versions))
        if unique_versions:
            print("\n[+] Detected Technologies and Versions:")
            for version in unique_versions:
                print(f"  - {version}")
        else:
            print("[-] No technologies detected.")
            return []

        # Format technologies for AI
        formatted_versions = "\n".join(unique_versions)
        prompt = (
            f"Generate a custom wordlist for brute forcing directories or subdomains "
            f"based on these detected technologies:\n{formatted_versions}. "
            "Output only the words themselves, one per line, with no extra descriptions. "
            "I am wanting to use this list for a tool such as gobuster or dirbbuster."
        )
        response = client.chat.completions.create(model=MODEL_NAME,
        messages=[
            {
                "role": "system",
                "content": (
                    "You are an AI designed for cybersecurity pentesting. "
                    "Analyze the detected technologies and create a list "
                    "of potential directories/subdomains."
                ),
            },
            {"role": "user", "content": prompt},
        ])
        wordlist = response.choices[0].message.content.split("\n")
        with open("custom_wordlist.txt", "w") as f:
            for word in wordlist:
                f.write(word.strip() + "\n")

        print("\n[+] Custom Wordlist Saved: custom_wordlist.txt")
        return wordlist

    except Exception as e:
        print(f"[-] Error fetching version info: {e}")
    return []

########################################################
# 8. Main
########################################################
def print_usage():
    """Displays usage information and available options."""
    usage_text = """
AiRecon - Automated Pentesting Reconnaissance Tool
--------------------------------------------------
Usage:
  python script.py [options] <target1> <target2> ...

Options:
  -whois        Perform WHOIS lookup
  -dorks        Perform Google Dorking & GitHub Dorks
  -ports        Perform Shodan open port scan
  -screenshot   Capture a screenshot of the target
  -makelist     Run Webanalyze & generate custom wordlist
  -all          Perform all available checks
  -h, --help    Show this help message and exit

Example:
  python script.py -all example.com testsite.org
  python script.py -whois -ports -screenshot example.com subdomain.test.com
"""
    print(usage_text)

def main():
    import sys

    if len(sys.argv) < 2:
        print_usage()
        sys.exit(1)

    # Check for help
    if '-h' in sys.argv or '--help' in sys.argv:
        print_usage()
        sys.exit(0)

    # Separate flags from domains
    flags = []
    domains = []

    # skip the script name itself, start from sys.argv[1]
    for arg in sys.argv[1:]:
        if arg.startswith('-'):
            flags.append(arg)
        else:
            domains.append(arg)

    # If no domains, print usage
    if not domains:
        print_usage()
        sys.exit(1)

    # If user gave no flags, print usage
    if not flags:
        print_usage()
        sys.exit(1)

    # -all overrides everything
    if '-all' in flags:
        for domain in domains:
            print(f"\n=== Running ALL checks for: {domain} ===")
            print("[+] Performing WHOIS Lookup...")
            perform_whois_lookup(domain)

            print("[+] Performing Google Dorking...")
            google_dorking(domain)

            print("[+] Generating GitHub Dorks...")
            search_github(domain)

            print("[+] Checking Open Ports...")
            check_open_ports(domain)

            print("[+] Capturing Screenshot...")
            capture_screenshot(domain)

            print("[+] Finding Versions and Generating Wordlist...")
            find_versions_and_generate_wordlist(domain)
        sys.exit(0)

    # Otherwise, perform actions per flag for each domain
    for domain in domains:
        print(f"\n=== Running checks for: {domain} ===")

        if '-whois' in flags:
            print("[+] Performing WHOIS Lookup...")
            perform_whois_lookup(domain)

        if '-dorks' in flags:
            print("[+] Performing Google Dorking...")
            google_dorking(domain)
            print("[+] Generating GitHub Dorks...")
            search_github(domain)

        if '-ports' in flags:
            print("[+] Checking Open Ports...")
            check_open_ports(domain)

        if '-screenshot' in flags:
            print("[+] Capturing Screenshot...")
            capture_screenshot(domain)

        if '-makelist' in flags:
            print("[+] Finding Versions and Generating Wordlist...")
            find_versions_and_generate_wordlist(domain)

########################################################
# 9. Script Entry Point
########################################################
if __name__ == "__main__":
    main()
