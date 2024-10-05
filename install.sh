#!/bin/bash

echo -e "\e[94m[+] Updating package list...\e[0m"
sudo apt update

# Install basic dependencies
echo -e "\e[94m[+] Installing basic dependencies...\e[0m"
sudo apt install -y curl git jq python3 python3-pip

# Install subfinder
echo -e "\e[94m[+] Installing subfinder...\e[0m"
GO111MODULE=on go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
export PATH=$PATH:$(go env GOPATH)/bin

# Install assetfinder
echo -e "\e[94m[+] Installing assetfinder...\e[0m"
go install github.com/tomnomnom/assetfinder@latest
export PATH=$PATH:$(go env GOPATH)/bin

# Install github-subdomains
echo -e "\e[94m[+] Installing github-subdomains...\e[0m"
git clone https://github.com/gwen001/github-subdomains
cd github-subdomains
pip3 install -r requirements.txt --break-system-packages
cd ..

# Install httpx
echo -e "\e[94m[+] Installing httpx...\e[0m"
GO111MODULE=on go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
export PATH=$PATH:$(go env GOPATH)/bin

# Install dnsx
echo -e "\e[94m[+] Installing dnsx...\e[0m"
GO111MODULE=on go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest
export PATH=$PATH:$(go env GOPATH)/bin

# Install certspotter
echo -e "\e[94m[+] Installing certspotter...\e[0m"
go install github.com/SSLMate/certspotter@latest
export PATH=$PATH:$(go env GOPATH)/bin

# Install Golang if not already installed (for subfinder, shuffledns, httpx, dnsx)
if ! command -v go &> /dev/null
then
    echo -e "\e[94m[+] Installing Golang...\e[0m"
    sudo apt install -y golang-go
fi

# Export Go binaries to PATH in .bashrc
if ! grep -q 'export PATH=$PATH:$(go env GOPATH)/bin' ~/.bashrc; then
    echo 'export PATH=$PATH:$(go env GOPATH)/bin' >> ~/.bashrc
    source ~/.bashrc
fi

echo -e "\e[92m[+] Installation complete! All tools are installed.\e[0m"
