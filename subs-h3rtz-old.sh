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
\tinstagram: @givarirmdn \tlinkedin: @givarirmdn - Happy Hacking ^_^
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

# Combine results from different tools
combine_results() {
    echo -e "${BLUE}[$(date '+%Y-%m-%d %H:%M:%S')] [+] Combining subdomains from various sources...${NC}"
    cat subs_subfinder.txt subs_assetfinder.txt | sort -u > allSubs.txt
}

# Run dnsx to filter out non-resolving subdomains
run_dnsx() {
    echo -e "${BLUE}[$(date '+%Y-%m-%d %H:%M:%S')] [+] Running tool: dnsx...${NC}"
    dnsx -silent < allSubs.txt | tee resolved_subs.txt
}

# Run HTTPX with concurrency and categorize subdomains
run_httpx() {
    echo -e "${BLUE}[$(date '+%Y-%m-%d %H:%M:%S')] [+] Running tool: httpx...${NC}"
    httpx-toolkit -l allSubs.txt -sc -title -cl -wc -td | tee uniq_subs_temp.txt
    
    # Use awk to filter unique entries
    echo -e "${BLUE}[$(date '+%Y-%m-%d %H:%M:%S')] [+] Filtering unique subdomains...${NC}"
    cat uniq_subs_temp.txt | awk -F"[" '!seen[$2, $3, $4, $5]++' | tee uniq_subs.txt

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
    UNIQUE_COUNT=$(wc -l < uniq_subs.txt)

    echo -e "${GREEN}[+] ${UNIQUE_COUNT} Unique Subdomains saved to uniq_subs.txt${NC}"
    echo -e "${GREEN}[+] Active Subdomains saved to active_subs.txt${NC}"
    echo -e "${BLUE}[+] Redirect Subdomains saved to redirect_subs.txt${NC}"
    echo -e "${RED}[-] Forbidden Subdomains saved to forbidden_subs.txt${NC}"
    echo -e "${YELLOW}[*] Takeover Subdomains saved to takeovers_subs.txt${NC}"
    echo -e "${YELLOW}[!] Potential Takeover Subdomains saved to potential_takeovers.txt${NC}"
}


# Main execution flow
run_subfinder
run_assetfinder
combine_results
run_dnsx
run_httpx
run_subjack
output_results
