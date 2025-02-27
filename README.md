# AiRecon

[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](#license)
[![Python Version](https://img.shields.io/badge/Python-3.7%2B-blue.svg)](#requirements)

**AiRecon** is an automated pentesting reconnaissance tool. It consolidates multiple recon steps—WHOIS lookup, Google Dorks, GitHub Dorks, Shodan port scanning, screenshot capture, and technology fingerprinting (with Webanalyze + AI-driven wordlist)—into a single script.

## Table of Contents
- [Features](#features)
- [Demo / Preview](#demo--preview)
- [Installation](#installation)
- [Usage](#usage)
  - [CLI Flags](#cli-flags)
  - [Examples](#examples)
- [Outputs](#outputs)
- [Troubleshooting](#troubleshooting)
- [License](#license)

---

## Features

| Feature                            | Description                                                       |
|------------------------------------|-------------------------------------------------------------------|
| **WHOIS**                          | Fetch domain registration data and print raw JSON.               |
| **Google/GitHub Dorks**           | AI-generated queries for searching sensitive data online.         |
| **Shodan Port Scan**              | Query Shodan for open ports and services.                         |
| **Screenshot Capture**            | Take a screenshot of a target using Selenium & headless Chrome.   |
| **Webanalyze + Wordlist**         | Identify site technologies and create a custom wordlist with AI.  |
| **Multiple Domains**              | Provide any number of domains in one command.                     |

---
## Installation
**Clone the Repository**  
   ```bash
   git clone https://github.com/YourUser/AiRecon.git
   cd AiRecon
```

## Demo / Preview

<details>
  <summary>Show CLI Demo</summary>

```bash
$ python airecon.py -all example.com testsite.org

=== Running ALL checks for: example.com ===
[+] Performing WHOIS Lookup...
[DEBUG] WHOIS target domain: example.com
[+] WHOIS Raw Data:
{
  "domain_name": "EXAMPLE.COM",
  "registrar": "XYZ Registrar",
  ...
}

[+] Performing Google Dorking...
[+] AI-Suggested Google Dorks:
  - site:example.com intitle:index.of
  - site:example.com filetype:env

...

[+] Capturing Screenshot...
[+] Screenshot saved as screenshot.png

[+] Finding Versions and Generating Wordlist...
[+] Detected Technologies and Versions:
  - Apache 2.4
[+] Custom Wordlist Saved: custom_wordlist.txt
