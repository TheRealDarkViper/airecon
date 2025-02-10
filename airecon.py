import requests
from bs4 import BeautifulSoup
import re
import os
import openai  # or use transformers-based model
import whois
import socket
from googlesearch import search
from github import Github
import shodan
from selenium import webdriver
import subprocess
import json

# Set OpenAI API Key
openai.api_key = "Your-OpenAI-API-Key"

def get_available_openai_model():
    """Detects the best available OpenAI model for the user's API key."""
    try:
        available_models = [model.id for model in openai.models.list().data]
        for preferred_model in ["gpt-4o"]:
            if preferred_model in available_models:
                return preferred_model
    except Exception as e:
        print(f"[!] Error retrieving OpenAI models: {e}")
    return "gpt-3.5-turbo"  # Default to a widely available model

MODEL_NAME = get_available_openai_model()

def perform_whois_lookup(target):
    try:
        domain_info = whois.whois(target)
        prompt = f"Analyze this WHOIS data and identify any interesting findings for pentesting reconnaissance: {domain_info}"
        response = openai.chat.completions.create(
            model=MODEL_NAME,
            messages=[{"role": "system", "content": "You are an AI designed to assist in pentesting reconnaissance. Your task is to analyze WHOIS data to find useful insights for security testing."},
                      {"role": "user", "content": prompt}]
        )
        print("\n[+] WHOIS Analysis:")
        print(response.choices[0].message.content)
        return domain_info
    except Exception as e:
        return f"WHOIS lookup failed: {e}"

def main():
    target_url = input("Enter the target website: ")
    print("[+] Performing WHOIS Lookup...")
    perform_whois_lookup(target_url)
    
    print("[+] Checking Open Ports...")
    check_open_ports(target_url)
    
    print("[+] Capturing Screenshot...")
    capture_screenshot(target_url)
    
    print("[+] Finding Versions and Generating Wordlist...")
    find_versions_and_generate_wordlist(target_url)

def check_open_ports(target):
    """Resolves the target domain to an IP address and performs a Shodan lookup."""
    SHODAN_API_KEY = "Your-Shodan-API-Key"
    api = shodan.Shodan(SHODAN_API_KEY)
    
    try:
        # Strip http:// or https:// from the target if present
        target = re.sub(r'^https?://', '', target)
        ip_address = socket.gethostbyname(target)
        print(f"[+] Resolved {target} to IP: {ip_address}")
        result = api.host(ip_address)
        print("\n[+] Open Ports Found:")
        for port in result['ports']:
            print(f"  - Port {port}: {result['data'][0]['transport']}")
        return result['ports']
    except socket.gaierror:
        print(f"[-] Could not resolve domain: {target}")
    except shodan.APIError as e:
        print(f"[-] Shodan API Error: {e}")
    return []

def capture_screenshot(target):
    options = webdriver.ChromeOptions()
    options.headless = True
    driver = webdriver.Chrome(options=options)
    driver.get(target)
    driver.save_screenshot("screenshot.png")
    driver.quit()
    print("[+] Screenshot saved as screenshot.png")

def find_versions_and_generate_wordlist(target):
    """Uses Webanalyze to find version information from the target website and generates a custom wordlist for reconnaissance."""
    try:
        print("[+] Running Webanalyze to detect website technologies...")
        result = subprocess.run(
            ["webanalyze", "-host", target, "-output", "json"],
            capture_output=True,
            text=True
        )

        if result.returncode != 0:
            print(f"[-] Webanalyze execution failed: {result.stderr}")
            return []

        # Parse JSON output
        analysis_data = json.loads(result.stdout)
        versions = []

        for match in analysis_data.get("matches", []):  # Adjusting for "matches"
            tech_name = match.get("app_name", "Unknown")
            tech_version = match.get("version", "").strip()  # Some versions might be empty
            
            if tech_version:
                versions.append(f"{tech_name} {tech_version}")
            else:
                versions.append(f"{tech_name}")  # Include tech name even if no version found

        unique_versions = list(set(versions))

        if unique_versions:
            print("\n[+] Detected Technologies and Versions:")
            for version in unique_versions:
                print(f"  - {version}")
        else:
            print("[-] No technologies detected.")

        if not unique_versions:
            return []

        # Properly format detected versions for OpenAI prompt
        formatted_versions = "\n".join(unique_versions)

        # Use AI to generate a custom wordlist
        prompt = f"Generate a custom wordlist for brute forcing directories or subdomains based on these detected technologies:\n{formatted_versions}"
        response = openai.chat.completions.create(
            model=MODEL_NAME,
            messages=[{"role": "system", "content": "You are an AI designed for cybersecurity pentesting. Your goal is to analyze detected software versions from a website and create a list of potential directories and subdomains that could be useful in security testing."},
                      {"role": "user", "content": prompt}]
        )
        wordlist = response.choices[0].message.content.split("\n")

        with open("custom_wordlist.txt", "w") as f:
            for word in wordlist:
                f.write(word + "\n")

        print("\n[+] Custom Wordlist Saved: custom_wordlist.txt")
        return wordlist
    except Exception as e:
        print(f"[-] Error fetching version info: {e}")
    return []

if __name__ == "__main__":
    main()
