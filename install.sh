#!/bin/bash

echo -e "\e[94m[+] Updating package list...\e[0m"
sudo apt update

# Install basic dependencies
echo -e "\e[94m[+] Installing basic dependencies...\e[0m"
sudo apt install -y curl git jq python3 python3-pip

# Install Golang if not already installed
if ! command -v go &> /dev/null; then
    echo -e "\e[94m[+] Installing Golang...\e[0m"
    sudo apt install -y golang-go
fi

# Install subfinder
echo -e "\e[94m[+] Installing subfinder...\e[0m"
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest

# Install assetfinder
echo -e "\e[94m[+] Installing assetfinder...\e[0m"
go install github.com/tomnomnom/assetfinder@latest

# Install github-subdomains
echo -e "\e[94m[+] Installing github-subdomains...\e[0m"
go install github.com/gwen001/github-subdomains@latest

# Install httpx
echo -e "\e[94m[+] Installing httpx...\e[0m"
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest

# Install dnsx
echo -e "\e[94m[+] Installing dnsx...\e[0m"
go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest

# Move Go binaries to /usr/local/bin
echo -e "\e[94m[+] Moving Go binaries to /usr/local/bin...\e[0m"
sudo mv ~/go/bin/* /usr/local/bin/

echo -e "\e[92m[+] Installation complete! All tools are installed and available in /usr/local/bin.\e[0m"
