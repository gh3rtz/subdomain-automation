#!/bin/bash

# Define file names
DOMAINS_FILE="domains"
GIT_TOKEN_FILE="$HOME/.git/git-token.txt"

# Read GitHub token from file
GITHUB_TOKEN=$(cat $GIT_TOKEN_FILE)

# Print ASCII Art
echo -e "
          ______   _______ _________ _______ 
|\     /|/ ___  \ (  ____ )\__   __// ___   )
| )   ( |\/   \  \| (    )|   ) (   \/   )  |
| (___) |   ___) /| (____)|   | |       /   )
|  ___  |  (___ ( |     __)   | |      /   / 
| (   ) |      ) \| (\ (      | |     /   /  
| )   ( |/\___/  /| ) \ \__   | |    /   (_/\\
|/     \|\______/ |/   \__/   )_(   (_______/

\tinstagram: @givarirmdn - Happy Hacking ^_^
"

# Run subdomain enumeration tools
echo -e "\e[94m[$(date '+%Y-%m-%d %H:%M:%S')] [+] Running tool: subfinder...\e[0m"
subfinder -dL $DOMAINS_FILE | tee subs_subfinder.txt

echo -e "\e[94m[$(date '+%Y-%m-%d %H:%M:%S')] [+] Running tool: assetfinder...\e[0m"
cat $DOMAINS_FILE | assetfinder -subs-only | tee subs_assetfinder.txt

# Scrape GitHub for subdomains
echo -e "\e[94m[$(date '+%Y-%m-%d %H:%M:%S')] [+] Running tool: github-subdomains...\e[0m"
while read DOMAIN; do
  github-subdomains -d $DOMAIN -t $GITHUB_TOKEN -o subs_github.txt
done < $DOMAINS_FILE

# Use crt.sh to get subdomains from Certificate Transparency Logs
echo -e "\e[94m[$(date '+%Y-%m-%d %H:%M:%S')] [+] Running crt.sh...\e[0m"
for DOMAIN in $(cat $DOMAINS_FILE); do
  curl -s "https://crt.sh/?q=%25.$DOMAIN&output=json" | jq -r '.[].name_value' | sort -u | tee -a subs_crtsh.txt
done

# Use CertSpotter to gather more subdomains
echo -e "\e[94m[$(date '+%Y-%m-%d %H:%M:%S')] [+] Running CertSpotter...\e[0m"
for DOMAIN in $(cat $DOMAINS_FILE); do
  certspotter $DOMAIN | jq -r '.dns_names[]' | sort -u | tee -a subs_certspotter.txt
done

# Combine results from different tools
echo -e "\e[94m[$(date '+%Y-%m-%d %H:%M:%S')] [+] Combining subdomains from various sources...\e[0m"
cat subs_subfinder.txt subs_assetfinder.txt subs_github.txt subs_crtsh.txt subs_certspotter.txt | sort -u > allSubs.txt

# Run dnsx to filter out non-resolving subdomains
echo -e "\e[94m[$(date '+%Y-%m-%d %H:%M:%S')] [+] Running tool: dnsx...\e[0m"
cat allSubs.txt | dnsx -silent | tee resolved_subs.txt

# Run HTTPX with concurrency and categorize subdomains
echo -e "\e[94m[$(date '+%Y-%m-%d %H:%M:%S')] [+] Running tool: httpx...\e[0m"
httpx -l resolved_subs.txt -mc 200 -threads 100 | tee active_subs.txt
httpx -l resolved_subs.txt -mc 301,302,303 -threads 100 | tee redirect_subs.txt
httpx -l resolved_subs.txt -mc 401,403,405 -threads 100 | tee forbidden_subs.txt
httpx -l resolved_subs.txt -mc 404,500 -threads 100 | tee takeovers_subs.txt

# Output results with colors
echo -e "\e[32m[+] Active Subdomains saved to active_subs.txt\e[0m"
echo -e "\e[34m[+] Redirect Subdomains saved to redirect_subs.txt\e[0m"
echo -e "\e[31m[-] Forbidden Subdomains saved to forbidden_subs.txt\e[0m"
echo -e "\e[33m[*] Takeover Subdomains saved to takeovers_subs.txt\e[0m"
