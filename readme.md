## Installation

Run the appropriate installer for your operating system:

- **Linux:** `chmod +x install.sh && ./install.sh`
- **macOS:** `chmod +x install_mac.sh && ./install_mac.sh`

This will install all the necessary Go tools and other dependencies required by the automation script.

## Basic Usage

1.  Create a file named `domains` in the same directory.
2.  Add your target root domains to this file, one domain per line.
3.  Run the script by typing `h3rtz` in your terminal.

---

## Subdomain Automation Script (`subs-h3rtz.sh`)

This is a comprehensive and robust automation script for subdomain enumeration and initial vulnerability reconnaissance. It chains together a series of popular open-source tools to create a powerful and efficient workflow.

### Main Purpose

The primary goal of this script is to automate the tedious process of discovering, resolving, and performing initial scans on the subdomains of a given target. It takes one or more root domains as input and produces a structured set of output files containing discovered assets, live hosts, potential vulnerabilities, and other valuable information.

### Key Features

- **Multi-faceted Discovery:** Uses both passive (OSINT) and active (brute-force) methods to discover a wide range of subdomains.
- **Robust and Resilient:** The script is designed to handle errors gracefully. A failure in one tool will not stop the entire process. It includes retry logic for network-intensive tasks.
- **Organized Output:** Creates a unique, timestamped directory for each run, with results neatly organized into subdirectories for discovery, live hosts, and potential vulnerabilities.
- **Comprehensive Scanning:** Goes beyond simple discovery to perform port scanning, web service probing, screenshotting, endpoint crawling, and vulnerability scanning (specifically for subdomain takeovers).
- **Intelligent Identification:** Attempts to identify specific endpoint types, such as APIs, login panels, and internal-facing "colleague" systems, based on common naming conventions.

### Workflow Overview

The script executes the following steps in sequence:

1.  **Passive Discovery:** Gathers subdomains from public sources using `subfinder`, `assetfinder`, `gau` (from web archives), and `crt.sh` (from certificate transparency logs).
2.  **Active Bruteforce:** Uses `shuffledns` with a wordlist to discover additional subdomains that may not be publicly listed.
3.  **Resolution:** Combines all discovered subdomains and uses `dnsx` to identify which ones have valid DNS records.
4.  **Port Scanning:** Scans the resolved hosts for common open web ports using `naabu`.
5.  **HTTP Probing:** Probes the live hosts with open ports using `httpx` to identify running web services, capture titles, detect technologies, and take screenshots.
6.  **Web Crawling:** Uses `katana` to crawl the identified web services and discover additional endpoints and links.
7.  **Vulnerability Scanning:** Runs a `nuclei` scan specifically using takeover templates to identify potential subdomain takeover vulnerabilities.
8.  **Endpoint Identification:** Analyzes domain names to flag potential API endpoints and internal-facing systems.

### Tools Used

The script relies on the following tools being installed and available in your `PATH`:

- `subfinder`
- `assetfinder`
- `gau`
- `dnsx`
- `shuffledns`
- `naabu`
- `httpx`
- `nuclei`
- `katana`
- `jq`
- `curl`

### Command-Line Usage

You can also run the script directly with more specific options:

```bash
./subs-h3rtz.sh [OPTIONS]
```

**Options:**

| Flag | Argument | Description |
| :--- | :--- | :--- |
| `-d` | `<domain.com>` | Specifies a single domain to scan. |
| `-f` | `<domains.txt>` | Specifies a file containing a list of domains to scan. |
| `-o` | `<output_dir>` | Sets a custom base directory for the output. (Default: `./recon_results`) |
| `-P` | `<number>` | Sets the number of top ports for `naabu` to scan. (Default: 100) |
| `-R` | `<number>` | Sets the number of times `naabu` will retry on failure. (Default: 2) |
| `-s` | | Enables silent mode, suppressing console output. |
| `-h` | | Displays the help message. |

### Output Structure

The script will create a directory structure like this for each run:

```
./recon_results/
└── <target_name>_<YYYY-MM-DD_HHMM>/
    ├── 0_discovery/      # Raw results from passive tools
    ├── 1_hosts/          # Resolved, live, and HTTP-probed hosts
    ├── 2_vulns/          # Vulnerability and analysis results (takeovers, etc.)
    ├── 3_screenshots/    # Screenshots of live web services
    ├── scan.log          # A complete log of the script's execution
    └── ...               # Other JSON summary files
```
