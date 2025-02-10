import requests
from bs4 import BeautifulSoup
import re
import os
import openai  # or use transformers-based model
from googlesearch import search
from github import Github
import subprocess

# Set OpenAI API Key
openai.api_key = "your_openai_api_key"  # Replace with your actual API key

def install_dependencies():
    """Installs required dependencies automatically."""
    dependencies = [
        "requests", "beautifulsoup4", "openai", "google-search-results", "PyGithub"
    ]
    for package in dependencies:
        subprocess.run(["pip", "install", package], check=True)

install_dependencies()

def crawl_website(url):
    """Extracts keywords, paths, and potential directories from a given URL."""
    response = requests.get(url)
    soup = BeautifulSoup(response.text, 'html.parser')
    
    words = set()
    
    # Extract from meta tags, headings, links, and JavaScript variables
    for tag in soup.find_all(['meta', 'h1', 'h2', 'h3', 'a', 'script']):
        content = tag.get('content') or tag.text or tag.get('src')
        words.update(re.findall(r'\b\w{3,}\b', content))
    
    # Extract from URLs in href attributes
    for link in soup.find_all('a', href=True):
        words.update(re.findall(r'\b\w{3,}\b', link['href']))
    
    return list(words)

def ai_generate_wordlist(words):
    """Uses AI to generate probable directory names based on expanded keyword extraction."""
    prompt = f"Predict common directory names from these words: {', '.join(words)}"
    
    response = openai.ChatCompletion.create(
        model="gpt-4",
        messages=[{"role": "system", "content": "Generate common directory names from given keywords and URL paths."},
                  {"role": "user", "content": prompt}]
    )
    
    return response['choices'][0]['message']['content'].split('\n')

def search_github(target):
    """Searches GitHub for public repos related to the target domain without authentication."""
    g = Github()  # No token required for public searches
    repos = g.search_repositories(query=target)
    
    results = [repo.clone_url for repo in repos[:5]]
    return results

def google_dorking(target):
    """Performs Google dorking to find exposed directories."""
    queries = [
        f"site:{target} intitle:index.of",
        f"site:{target} ext:txt | ext:log | ext:bak",
        f"site:{target} inurl:config",
        f"site:{target} inurl:admin",
        f"site:{target} filetype:pdf",
        f"site:{target} inurl:login",
        f"site:{target} intext:'password'",
        f"site:{target} inurl:wp-content",
        f"site:{target} inurl:backup",
        f"site:{target} inurl:database",
        f"site:{target} ext:sql | ext:db | ext:mdb",
        f"site:{target} inurl:api",
        f"site:{target} inurl:upload",
        f"site:{target} inurl:logs",
    ]
    
    results = []
    for query in queries:
        for result in search(query, num_results=5):
            results.append(result)
    
    return results

def save_wordlist(wordlist, filename="wordlist.txt"):
    """Saves the generated wordlist to a file."""
    with open(filename, "w") as f:
        for word in wordlist:
            f.write(word + "\n")

def main():
    target_url = input("Enter the target website: ")
    
    print("[+] Crawling website...")
    words = crawl_website(target_url)
    
    print("[+] Generating AI-based wordlist...")
    ai_words = ai_generate_wordlist(words)
    
    print("[+] Searching GitHub...")
    github_results = search_github(target_url)
    
    print("[+] Performing Google dorking...")
    google_results = google_dorking(target_url)
    
    final_wordlist = set(ai_words + github_results + google_results)
    save_wordlist(final_wordlist)
    
    print(f"[+] Wordlist saved to wordlist.txt ({len(final_wordlist)} entries)")

if __name__ == "__main__":
    main()
