#!/bin/bash
set -euo pipefail

# Define colors
GREEN=$'\033[32m'
BLUE=$'\033[34m'
RED=$'\033[31m'
YELLOW=$'\033[33m'
NC=$'\033[0m' # No Color

# Define file names
DOMAINS_FILE="domains"

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
    echo -e "${BLUE}[$(date '+%Y-%m-%d %H:%M:%S')] [+] Running tool: subfinder...${NC}"
    subfinder -dL "$DOMAINS_FILE" | tee subs_subfinder.txt
}

# Run assetfinder
run_assetfinder() {
    echo -e "${BLUE}[$(date '+%Y-%m-%d %H:%M:%S')] [+] Running tool: assetfinder...${NC}"
    assetfinder -subs-only < "$DOMAINS_FILE" | tee subs_assetfinder.txt
}

# Run crtsh
run_crtsh() {
    echo -e "${BLUE}[$(date '+%Y-%m-%d %H:%M:%S')] [+] Running tool: crtsh...${NC}"
    # Create an empty file to avoid "No such file or directory" error later
    : > subs_crtsh.txt

    while read -r domain; do
        # Run crtsh only if the domain is non-empty
        if [[ -n "$domain" ]]; then
            python3 /usr/local/bin/crtsh -d "$domain" >> subs_crtsh.txt || echo "[ERR] Failed to retrieve data for $domain" >&2
        fi
    done < "$DOMAINS_FILE"
}

# Combine results from different tools
combine_results() {
    echo -e "${BLUE}[$(date '+%Y-%m-%d %H:%M:%S')] [+] Combining subdomains from various sources...${NC}"
    cat subs_subfinder.txt subs_assetfinder.txt subs_crtsh.txt | sort -u > allSubs.txt
}

# Run dnsx to filter out non-resolving subdomains
run_dnsx() {
    echo -e "${BLUE}[$(date '+%Y-%m-%d %H:%M:%S')] [+] Running tool: dnsx...${NC}"
    dnsx -silent < allSubs.txt | tee resolved_subs.txt
}

# Run HTTPX with concurrency and categorize subdomains
run_httpx() {
    echo -e "${BLUE}[$(date '+%Y-%m-%d %H:%M:%S')] [+] Running tool: httpx...${NC}"
    httpx-toolkit -l resolved_subs.txt -mc 200,201,202,204,301 -threads 100 -silent | tee active_subs.txt
    httpx-toolkit -l resolved_subs.txt -mc 300,303,307,308 -threads 100 | tee redirect_subs.txt
    httpx-toolkit -l resolved_subs.txt -mc 401,402,403,405,407,408 -threads 100 | tee forbidden_subs.txt
    httpx-toolkit -l resolved_subs.txt -mc 404,500,503 -threads 100 | tee takeovers_subs.txt
}

# Run Subjack for subdomain takeover detection on potential takeover subdomains
run_subjack() {
    echo -e "${BLUE}[$(date '+%Y-%m-%d %H:%M:%S')] [+] Running tool: subjack...${NC}"
    subjack -w takeovers_subs.txt -o potential_takeovers.txt -c /Users/h3rtz/Tools/fingerprints.json -ssl -v
}

# Output results with colors
output_results() {
    echo -e "${GREEN}[+] Active Subdomains saved to active_subs.txt${NC}"
    echo -e "${BLUE}[+] Redirect Subdomains saved to redirect_subs.txt${NC}"
    echo -e "${RED}[-] Forbidden Subdomains saved to forbidden_subs.txt${NC}"
    echo -e "${YELLOW}[*] Takeover Subdomains saved to takeovers_subs.txt${NC}"
    echo -e "${YELLOW}[!] Potential Takeover Subdomains saved to potential_takeovers.txt${NC}"
}

# Main execution flow
run_subfinder
run_assetfinder
run_crtsh
combine_results
run_dnsx
run_httpx
run_subjack
output_results
