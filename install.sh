#!/bin/bash

# Install Golang
echo "Installing Golang..."
sudo apt update
sudo apt install -y golang

# Install subfinder
echo "Installing subfinder..."
GO111MODULE=on go get -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
sudo cp $HOME/go/bin/subfinder /usr/local/bin/

# Install assetfinder
echo "Installing assetfinder..."
GO111MODULE=on go get -v github.com/tomnomnom/assetfinder@latest
sudo cp $HOME/go/bin/assetfinder /usr/local/bin/

# Install httpx
echo "Installing httpx..."
GO111MODULE=on go get -v github.com/projectdiscovery/httpx/cmd/httpx@latest
sudo cp $HOME/go/bin/httpx /usr/local/bin/

# Set permissions and symbolic link for subs_h3rtz.sh
echo "Setting up h3rtz..."
sudo cp subs_h3rtz.sh /usr/local/bin/h3rtz
sudo chmod +x /usr/local/bin/h3rtz

echo "Installation complete."
