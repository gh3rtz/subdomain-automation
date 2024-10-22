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

# Run sublist3r
run_sublist3r() {
    echo -e "\e[94m[$(date '+%Y-%m-%d %H:%M:%S')] [+] Running tool: sublist3r...\e[0m"
    while IFS= read -r DOMAIN; do
        sublist3r -d "$DOMAIN" -o subs_sublist3r.txt
    done < "$DOMAINS_FILE"
}

# Use crt.sh to get subdomains from Certificate Transparency Logs
run_crtsh() {
    echo -e "\e[94m[$(date '+%Y-%m-%d %H:%M:%S')] [+] Running crt.sh...\e[0m"
    while IFS= read -r DOMAIN; do
        RESPONSE=$(curl -s "https://crt.sh/?q=%25.$DOMAIN&output=json")
        if echo "$RESPONSE" | jq . >/dev/null 2>&1; then
            echo "$RESPONSE" | jq -r '.[].name_value' | sort -u >> subs_crtsh.txt
        else
            echo -e "${RED}[-] Invalid response from crt.sh for $DOMAIN${NC}" >&2
        fi
        sleep 1 # Delay to avoid hitting rate limits
    done < "$DOMAINS_FILE"
}

# Combine results from different tools
combine_results() {
    echo -e "\e[94m[$(date '+%Y-%m-%d %H:%M:%S')] [+] Combining subdomains from various sources...\e[0m"
    cat subs_subfinder.txt subs_assetfinder.txt subs_sublist3r.txt subs_crtsh.txt | sort -u > allSubs.txt
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
run_sublist3r
run_crtsh
combine_results
run_dnsx
run_httpx
output_results
