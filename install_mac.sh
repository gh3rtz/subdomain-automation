#!/bin/bash
set -euo pipefail

# Colors
NC='\e[0m'
BLUE='\e[94m'
GREEN='\e[92m'
YELLOW='\e[93m'

print_message() {
    local color="$1"; shift
    echo -e "${color}[+] $*${NC}"
}

# Update Homebrew
print_message "$BLUE" "Updating Homebrew..."
brew update

# Install dependencies
print_message "$BLUE" "Installing required packages..."
brew install curl git jq python3 unzip

# Install Golang if missing
if ! command -v go &>/dev/null; then
    print_message "$BLUE" "Installing Golang..."
    brew install go
else
    print_message "$GREEN" "Golang already installed."
fi

# Ensure Go environment
export GOPATH=$HOME/go
export PATH=$PATH:$GOPATH/bin

# Function to install Go tools
install_go_tool() {
    local tool_name="$1"
    local tool_repo="$2"

    if ! command -v "${tool_name,,}" &>/dev/null; then
        print_message "$YELLOW" "Installing $tool_name..."
        go install "$tool_repo"@latest
    else
        print_message "$GREEN" "$tool_name already installed."
    fi
}

# Install all required tools
print_message "$BLUE" "Installing reconnaissance tools..."
install_go_tool "Subfinder" "github.com/projectdiscovery/subfinder/v2/cmd/subfinder"
install_go_tool "Assetfinder" "github.com/tomnomnom/assetfinder"
install_go_tool "GAU" "github.com/lc/gau/v2/cmd/gau"
install_go_tool "DNSX" "github.com/projectdiscovery/dnsx/cmd/dnsx"
install_go_tool "Shuffledns" "github.com/projectdiscovery/shuffledns/cmd/shuffledns"
install_go_tool "Naabu" "github.com/projectdiscovery/naabu/v2/cmd/naabu"
install_go_tool "HTTPX" "github.com/projectdiscovery/httpx/cmd/httpx"
install_go_tool "Nuclei" "github.com/projectdiscovery/nuclei/v3/cmd/nuclei"
install_go_tool "Katana" "github.com/projectdiscovery/katana/cmd/katana"

# Move Go binaries to /usr/local/bin
print_message "$BLUE" "Moving Go binaries to /usr/local/bin..."
sudo mv -f ~/go/bin/* /usr/local/bin/ 2>/dev/null || true

# Update Nuclei templates
print_message "$BLUE" "Setting up Nuclei templates..."
mkdir -p ~/nuclei-templates
nuclei -update-templates || true

# Prepare directory structure
mkdir -p ~/Tools ~/myWordlists/fuzz4bounty/DNS ~/myWordlists/resolvers

print_message "$GREEN" "✅ Installation complete!"
print_message "$GREEN" "All tools are ready under /usr/local/bin."
print_message "$GREEN" "You can now run: ./h3rtzv13 -d target.com"
