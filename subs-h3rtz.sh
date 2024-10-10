#!/bin/bash
set -euo pipefail

# Define colors
GREEN='\e[32m'
BLUE='\e[34m'
RED='\e[31m'
YELLOW='\e[33m'
NC='\e[0m' # No Color

# Define file names
DOMAINS_FILE="domains"
GIT_TOKEN_FILE="$HOME/.git/git-token.txt"

# Read GitHub token from file
GITHUB_TOKEN=$(<"$GIT_TOKEN_FILE")

# Print ASCII Art
cat << "EOF"
          ______   _______ _________ _______ 
|\     /|/ ___  \ (  ____ )\__   __// ___   )
| )   ( |\/   \  \| (    )|   ) (   \/   )  |
| (___) |   ___) /| (____)|   | |       /   )
|  ___  |  (___ ( |     __)   | |      /   / 
| (   ) |      ) \| (\ (      | |     /   /  
| )   ( |/\___/  /| ) \ \__   | |    /   (_/\\
|/     \|\______/ |/   \__/   )_(   (_______/
\tinstagram: @givarirmdn - Happy Hacking ^_^
EOF

# Run subfinder
run_subfinder() {
    echo -e "\e[94m[$(date '+%Y-%m-%d %H:%M:%S')] [+] Running tool: subfinder...\e[0m"
    subfinder -dL "$DOMAINS_FILE" | tee subs_subfinder.txt
}

# Run assetfinder
run_assetfinder() {
    echo -e "\e[94m[$(date '+%Y-%m-%d %H:%M:%S')] [+] Running tool: assetfinder...\e[0m"
    assetfinder -subs-only < "$DOMAINS_FILE" | tee subs_assetfinder.txt
}

# Scrape GitHub for subdomains
run_github_subdomains() {
    echo -e "\e[94m[$(date '+%Y-%m-%d %H:%M:%S')] [+] Running tool: github-subdomains...\e[0m"
    while IFS= read -r DOMAIN; do
        github-subdomains -d "$DOMAIN" -t "$GITHUB_TOKEN" >> subs_github.txt
    done < "$DOMAINS_FILE"
}

# Use crt.sh to get subdomains from Certificate Transparency Logs
run_crtsh() {
    echo -e "\e[94m[$(date '+%Y-%m-%d %H:%M:%S')] [+] Running crt.sh...\e[0m"
    while IFS= read -r DOMAIN; do
        curl -s "https://crt.sh/?q=%25.$DOMAIN&output=json" | jq -r '.[].name_value' | sort -u >> subs_crtsh.txt
    done < "$DOMAINS_FILE"
}

# Combine results from different tools
combine_results() {
    echo -e "\e[94m[$(date '+%Y-%m-%d %H:%M:%S')] [+] Combining subdomains from various sources...\e[0m"
    cat subs_subfinder.txt subs_assetfinder.txt subs_github.txt subs_crtsh.txt | sort -u > allSubs.txt
}

# Run dnsx to filter out non-resolving subdomains
run_dnsx() {
    echo -e "\e[94m[$(date '+%Y-%m-%d %H:%M:%S')] [+] Running tool: dnsx...\e[0m"
    dnsx -silent < allSubs.txt | tee resolved_subs.txt
}

# Run HTTPX with concurrency and categorize subdomains
run_httpx() {
    echo -e "\e[94m[$(date '+%Y-%m-%d %H:%M:%S')] [+] Running tool: httpx...\e[0m"
    httpx -l resolved_subs.txt -mc 200 -threads 100 | tee active_subs.txt
    httpx -l resolved_subs.txt -mc 301,302,303 -threads 100 | tee redirect_subs.txt
    httpx -l resolved_subs.txt -mc 401,403,405 -threads 100 | tee forbidden_subs.txt
    httpx -l resolved_subs.txt -mc 404,500 -threads 100 | tee takeovers_subs.txt
}

# Output results with colors
output_results() {
    echo -e "${GREEN}[+] Active Subdomains saved to active_subs.txt${NC}"
    echo -e "${BLUE}[+] Redirect Subdomains saved to redirect_subs.txt${NC}"
    echo -e "${RED}[-] Forbidden Subdomains saved to forbidden_subs.txt${NC}"
    echo -e "${YELLOW}[*] Takeover Subdomains saved to takeovers_subs.txt${NC}"
}

# Main execution flow
run_subfinder
run_assetfinder
run_github_subdomains
run_crtsh
combine_results
run_dnsx
run_httpx
output_results
