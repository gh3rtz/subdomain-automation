#!/bin/bash
set -euo pipefail

# Function to print messages with colors
print_message() {
    local color="$1"
    shift
    echo -e "${color}[+] $*${NC}"
}

# Define color codes
NC='\e[0m' # No Color
BLUE='\e[94m'
GREEN='\e[92m'

# Update package list
print_message "$BLUE" "Updating package list..."
sudo apt update

# Install basic dependencies
print_message "$BLUE" "Installing basic dependencies..."
sudo apt install -y curl git jq python3 python3-pip

# Install Golang if not already installed
if ! command -v go &> /dev/null; then
    print_message "$BLUE" "Installing Golang..."
    sudo apt install -y golang-go
else
    print_message "$BLUE" "Golang is already installed."
fi

# Function to install a Go tool
install_go_tool() {
    local tool_name="$1"
    local tool_repo="$2"
    
    print_message "$BLUE" "Installing $tool_name..."
    go install "$tool_repo"@latest
}

# Install tools
install_go_tool "Subfinder" "github.com/projectdiscovery/subfinder/v2/cmd/subfinder"
install_go_tool "Assetfinder" "github.com/tomnomnom/assetfinder"
install_go_tool "GitHub Subdomains" "github.com/gwen001/github-subdomains"
install_go_tool "HTTPX" "github.com/projectdiscovery/httpx/cmd/httpx"
install_go_tool "DNSX" "github.com/projectdiscovery/dnsx/cmd/dnsx"

# Move Go binaries to /usr/local/bin
print_message "$BLUE" "Moving Go binaries to /usr/local/bin..."
sudo mv ~/go/bin/* /usr/local/bin/

print_message "$GREEN" "Installation complete! All tools are installed and available in /usr/local/bin."
