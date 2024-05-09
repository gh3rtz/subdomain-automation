#!/bin/bash

# Define file names
DOMAINS_FILE="domains"


"""
          ______   _______ _________ _______ 
|\     /|/ ___  \ (  ____ )\__   __// ___   )
| )   ( |\/   \  \| (    )|   ) (   \/   )  |
| (___) |   ___) /| (____)|   | |       /   )
|  ___  |  (___ ( |     __)   | |      /   / 
| (   ) |      ) \| (\ (      | |     /   /  
| )   ( |/\___/  /| ) \ \__   | |    /   (_/\
|/     \|\______/ |/   \__/   )_(   (_______/

	instagram: @givarirmdn - Happy Hacking ^_^
"""
# Run subdomain enumeration tools
echo -e "\e[94m[+] Running tool: subfinder...\e[0m"
subfinder -dL $DOMAINS_FILE | tee subs_subfinder.txt

echo -e "\e[94m[+] Running tool: assetfinder...\e[0m"
cat $DOMAINS_FILE | assetfinder -subs-only | tee subs_assetfinder.txt


# Combine results from different tools
echo -e "\e[94m[+] Combining subdomains from various sources...\e[0m"
cat subs_subfinder.txt subs_assetfinder.txt | sort -u > allSubs.txt

# Run HTTPX with concurrency and categorize subdomains
echo -e "\e[94m[+] Running tool: httpx\e[0m"
httpx -l allSubs.txt -mc 200 | tee active_subs.txt
httpx -l allSubs.txt -mc 301,302,303 | tee redirect_subs.txt
httpx -l allSubs.txt -mc 401,403,405 | tee forbidden_subs.txt
httpx -l allSubs.txt -mc 404,500 | tee takeovers_subs.txt

# Output colorful
echo -e "\e[32m[+] Active Subdomains saved to active_subs.txt\e[0m"
echo -e "\e[30m[+] Redirect Subdomains saved to redirect_subs.txt\e[0m"
echo -e "\e[31m[-] Forbidden Subdomains saved to forbidden_subs.txt\e[0m"
echo -e "\e[33m[*] Takeover Subdomains saved to takeovers_subs.txt\e[0m"
