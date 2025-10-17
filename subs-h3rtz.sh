#!/bin/bash
#
# h3rtzv13 - Subdomain Recon (full-featured, robust)
#
# Usage:
#   h3rtzv13 -d <domain.com>
#   h3rtzv13 -f <domains_file.txt>
#   h3rtzv13 -d <domain.com> -o /path/to/output -P 200 -R 3 -s
#
# Options:
#   -d <domain>       Single domain to scan
#   -f <file>         File with one domain per line (scans each sequentially)
#   -o <output_dir>   Base output dir (default: ./recon_results)
#   -P <top_ports>    Naabu top ports count (default: 100)
#   -R <retries>      Naabu retry count (default: 2)
#   -s                Silent mode (suppress console output)
#   -h                Help
#
# Notes:
#  - Requires: subfinder, assetfinder, gau, dnsx, shuffledns, naabu, httpx, nuclei,
#              katana, jq, curl
#  - This script is defensive: missing tools or partial failures won't kill the whole run.


set -euo pipefail

# --- Configuration ---
readonly TOOLS=( "subfinder" "assetfinder" "gau" "dnsx" "naabu" "httpx" "nuclei" "shuffledns" "katana" "jq" "curl" )
readonly PORTS="80,443,8000,8080,8443,3000,5000,9000"
readonly FINGERPRINTS_JSON="${HOME}/Tools/fingerprints.json"
readonly NUCLEI_TEMPLATES="${HOME}/nuclei-templates"

# Bruteforce config
readonly BRUTEFORCE_WORDLIST="${HOME}/myWordlists/fuzz4bounty/DNS/subdomains.txt"
readonly RESOLVERS_FILE="${HOME}/myWordlists/resolvers/resolvers.txt"

# Katana
readonly KATANA_DEPTH=2
readonly KATANA_TIMEOUT=30

# Naabu defaults (can be overridden via flags)
TOP_PORTS_COUNT=100
NAABU_RETRY_COUNT=2
NAABU_TIMEOUT=10       # seconds connection timeout (naabu -timeout)
NAABU_THREADS=50       # -t threads
NAABU_RATE=300         # -rate packets per second

# Colors
readonly NC='\033[0m'
readonly GREEN='\033[0;32m'
readonly BLUE='\033[0;34m'
readonly YELLOW='\033[0;33m'
readonly RED='\033[0;31m'

# Globals (populated in main)
LOG_FILE=""
SILENT_MODE="false"

RUN_DIR=""
DISCOVERY_DIR=""
HOSTS_DIR=""
VULNS_DIR=""
ALL_SUBS_FILE=""
RESOLVED_HOSTS_FILE=""
LIVE_HOSTS_FILE=""
HTTP_PROBE_FILE=""
TAKEOVER_FILE=""
SCREENSHOT_DIR=""
SCREENSHOT_MAP_FILE=""
KATANA_FILE=""
LOGIN_FILE=""
API_ID_FILE=""
COLLEAGUE_ID_FILE=""
HTTP_PROBE_JSON_FILE=""
TAKEOVERS_JSON_FILE=""

# --- Logging (safe) ---
# _log will only attempt to write to LOG_FILE if parent dir exists or LOG_FILE is empty.
_log() {
    local color="$1"; local level="$2"; shift 2
    local message="$*"

    # write to logfile only if LOG_FILE is set and its parent dir exists
    if [[ -n "${LOG_FILE:-}" ]]; then
        local logdir
        logdir=$(dirname "$LOG_FILE")
        if [[ -d "$logdir" ]]; then
            # append; don't exit on failure
            echo "[${level}] $(date "+%Y-%m-%d %H:%M:%S") - ${message}" >> "${LOG_FILE}" 2>/dev/null || true
        fi
    fi

    if [[ "${SILENT_MODE:-false}" == "false" ]]; then
        echo -e "${color}[${level}] $(date "+%H:%M:%S") - ${message}${NC}"
    fi
}

log_info()    { _log "$BLUE" "INFO" "$@"; }
log_success() { _log "$GREEN" "SUCCESS" "$@"; }
log_warn()    { _log "$YELLOW" "WARN" "$@"; }
log_error()   { _log "$RED" "ERROR" "$@"; }
log_fatal()   { _log "$RED" "FATAL" "$@"; exit 1; }

# --- Helpers ---
# portable mktemp wrapper (works on macOS & Linux)
mktemp_file() {
    if tmp=$(mktemp 2>/dev/null); then
        printf '%s' "$tmp"
    else
        # fallback manual
        tmp="/tmp/h3rtz_tmp_$$.$RANDOM"
        : > "$tmp"
        printf '%s' "$tmp"
    fi
}

# Check dependencies; do not auto-fatal on missing tools until after logging init
check_dependencies() {
    log_info "Checking for required tools..."
    local missing_tools=0
    for tool in "${TOOLS[@]}"; do
        if ! command -v "$tool" &>/dev/null; then
            log_error "Required tool '${tool}' is not installed or not in PATH."
            missing_tools=$((missing_tools + 1))
        fi
    done
    if (( missing_tools > 0 )); then
        log_fatal "${missing_tools} required tool(s) are missing. Install them and retry."
    fi
    log_success "All tools are installed."
}

# --- crt.sh (robust) ---
# Usage: run_crtsh <domain> <out_file_optional>
run_crtsh() {
    local target_domain="${1:-}"
    local crt_file="${2:-${DISCOVERY_DIR}/crtsh.txt}"

    if [[ -z "$target_domain" ]]; then
        log_warn "run_crtsh called without a domain; skipping."
        : > "$crt_file"
        return
    fi

    log_info "Running crt.sh search for ${target_domain}..."
    : > "$crt_file"
    local tmp
    tmp=$(mktemp_file)

    # polite UA and try JSON; if not JSON, fallback to regex
    curl -s -A "Mozilla/5.0 (compatible; recon-bot/1.0)" \
        "https://crt.sh/?q=%25.${target_domain}&output=json" -o "$tmp" 2>/dev/null || true

    if command -v jq &>/dev/null && jq -e . "$tmp" >/dev/null 2>&1; then
        jq -r '.[].name_value' "$tmp" 2>/dev/null | sed 's/\*\.//g' >> "$crt_file" || true
    else
        # fallback: extract domain-like tokens containing the target domain
        grep -Eo "([a-zA-Z0-9._-]+\.$target_domain)" "$tmp" 2>/dev/null | sed 's/\*\.//g' >> "$crt_file" || true
    fi

    rm -f "$tmp" 2>/dev/null || true

    if [[ -s "$crt_file" ]]; then
        sort -u -o "$crt_file" "$crt_file" || true
        local count
        count=$(wc -l < "$crt_file" | tr -d ' ')
        log_success "Finished crt.sh search for ${target_domain}, found ${count} subdomains."
    else
        log_warn "crt.sh search for ${target_domain} produced no output (empty/blocked)."
    fi
}

# --- Passive discovery (single-domain) ---
# This function acts on one domain (target_domain) only.
# When running in file mode main() loops over each domain and calls this function.
run_passive_discovery() {
    local target_domain="${1:-}"
    # keep target_file param for compatibility, but we IGNORE iterating it here
    local target_file="${2:-}"

    if [[ -z "$target_domain" ]]; then
        log_warn "run_passive_discovery called without a domain; skipping passive discovery."
        return
    fi

    log_info "Starting passive discovery phase for ${target_domain}..."

    # subfinder (use -d for single domain; -dL is handled by main when iterating)
    (
        log_info "Running subfinder on ${target_domain}..."
        subfinder -d "$target_domain" -all -o "${DISCOVERY_DIR}/subfinder.txt" 2>/dev/null || log_warn "subfinder returned non-zero for ${target_domain}."
        log_success "Finished subfinder for ${target_domain}."
    ) &

    # gau (single domain)
    (
        log_info "Running gau on ${target_domain}..."
        if output=$(gau --subs "$target_domain" 2>/dev/null); then
            printf '%s\n' "$output" | cut -d "/" -f 3 | sort -u > "${DISCOVERY_DIR}/gau.txt" || true
        else
            : > "${DISCOVERY_DIR}/gau.txt"
            log_warn "gau returned no output for ${target_domain} (or failed)."
        fi
        log_success "Finished gau for ${target_domain}."
    ) &

    # assetfinder (single domain)
    (
        log_info "Running assetfinder on ${target_domain}..."
        if output=$(assetfinder --subs-only "$target_domain" 2>/dev/null); then
            printf '%s\n' "$output" | sort -u > "${DISCOVERY_DIR}/assetfinder.txt" || true
        else
            : > "${DISCOVERY_DIR}/assetfinder.txt"
            log_warn "assetfinder returned no output for ${target_domain} (or failed)."
        fi
        log_success "Finished assetfinder for ${target_domain}."
    ) &

    # crt.sh (serial, network call)
    (
        run_crtsh "$target_domain" "${DISCOVERY_DIR}/crtsh.txt"
    ) &

    wait
    log_success "Passive discovery complete for ${target_domain}."

    # combine into all_subdomains for downstream (append unique)
    if compgen -G "${DISCOVERY_DIR}/*.txt" >/dev/null 2>&1; then
        sort -u "${DISCOVERY_DIR}"/*.txt -o "${ALL_SUBS_FILE}" 2>/dev/null || true
        log_info "Combined passive results into ${ALL_SUBS_FILE} (count: $(wc -l < "${ALL_SUBS_FILE}" 2>/dev/null || echo 0))."
    fi
}


# --- Combine results & resolve / bruteforce ---
run_bruteforce_and_resolve() {
    local target_domain="${1:-}"
    local target_file="${2:-}"

    log_info "Combining passive results and preparing for resolution..."

    # Merge any .txt results that exist
    : > "${ALL_SUBS_FILE}"
    if compgen -G "${DISCOVERY_DIR}/*.txt" > /dev/null 2>&1; then
        sort -u -o "${ALL_SUBS_FILE}" "${DISCOVERY_DIR}"/*.txt 2>/dev/null || true
    fi

    local passive_count=0
    if [[ -f "${ALL_SUBS_FILE}" ]]; then
        passive_count=$(wc -l < "${ALL_SUBS_FILE}" | tr -d ' ')
    fi
    log_info "Found ${passive_count} unique subdomains from passive sources."

    # If bruteforce resources missing, just resolve passive list
    if [[ ! -f "$BRUTEFORCE_WORDLIST" || ! -f "$RESOLVERS_FILE" ]]; then
        [[ ! -f "$BRUTEFORCE_WORDLIST" ]] && log_warn "Bruteforce wordlist not found. Skipping bruteforce."
        [[ ! -f "$RESOLVERS_FILE" ]] && log_warn "Resolvers file not found. Skipping bruteforce."

        if [[ -s "${ALL_SUBS_FILE}" ]]; then
            log_info "Resolving passive subdomains only with dnsx..."
            dnsx -l "${ALL_SUBS_FILE}" -o "${RESOLVED_HOSTS_FILE}" -silent || log_warn "dnsx returned non-zero."
        else
            log_warn "No passive subdomains available to resolve."
            : > "${RESOLVED_HOSTS_FILE}"
        fi
        local resolved_count=0
        [[ -f "${RESOLVED_HOSTS_FILE}" ]] && resolved_count=$(wc -l < "${RESOLVED_HOSTS_FILE}" | tr -d ' ')
        log_success "Resolution complete. Found ${resolved_count} resolved hosts."
        return
    fi

    # Use shuffledns to bruteforce (per-domain)
    log_info "Running DNS bruteforce with shuffledns..."
    : > "${RESOLVED_HOSTS_FILE}"

    if [[ -n "$target_domain" ]]; then
        log_info "Bruteforcing domain: ${target_domain}"
        tmpf=$(mktemp_file)
        shuffledns -d "${target_domain}" -w "${BRUTEFORCE_WORDLIST}" -r "${RESOLVERS_FILE}" -mode bruteforce -o "${tmpf}" -silent 2>/dev/null || log_warn "shuffledns failed for ${target_domain}"
        cat "${tmpf}" >> "${RESOLVED_HOSTS_FILE}" || true
        rm -f "${tmpf}" 2>/dev/null || true
    elif [[ -n "$target_file" && -f "$target_file" ]]; then
        log_info "Bruteforcing domains from file: ${target_file}"
        while IFS= read -r d || [[ -n "$d" ]]; do
            d="${d%%[[:space:]]}"
            [[ -z "$d" ]] && continue
            log_info "  -> bruteforcing ${d}"
            tmpf=$(mktemp_file)
            shuffledns -d "${d}" -w "${BRUTEFORCE_WORDLIST}" -r "${RESOLVERS_FILE}" -mode bruteforce -o "${tmpf}" -silent 2>/dev/null || log_warn "shuffledns failed for ${d}"
            cat "${tmpf}" >> "${RESOLVED_HOSTS_FILE}" || true
            rm -f "${tmpf}" 2>/dev/null || true
        done < "${target_file}"
    else
        log_warn "No domain or domain file provided for bruteforce. Skipping."
    fi

    # Add passive entries as well
    if [[ -f "${ALL_SUBS_FILE}" ]]; then
        cat "${ALL_SUBS_FILE}" >> "${RESOLVED_HOSTS_FILE}" || true
    fi
    sort -u -o "${RESOLVED_HOSTS_FILE}" "${RESOLVED_HOSTS_FILE}" || true

    # resolve with dnsx to ensure live records
    if [[ -s "${RESOLVED_HOSTS_FILE}" ]]; then
        log_info "Resolving combined list with dnsx..."
        dnsx -l "${RESOLVED_HOSTS_FILE}" -o "${RESOLVED_HOSTS_FILE}.resolved" -silent 2>/dev/null || log_warn "dnsx returned non-zero."
        if [[ -f "${RESOLVED_HOSTS_FILE}.resolved" ]]; then
            mv -f "${RESOLVED_HOSTS_FILE}.resolved" "${RESOLVED_HOSTS_FILE}" 2>/dev/null || true
        fi
    else
        : > "${RESOLVED_HOSTS_FILE}"
    fi

    local resolved_count=0
    [[ -f "${RESOLVED_HOSTS_FILE}" ]] && resolved_count=$(wc -l < "${RESOLVED_HOSTS_FILE}" | tr -d ' ')
    log_success "Resolution complete. Found ${resolved_count} resolved hosts."
}

# --- Port scan (naabu) with retries and fallback ---
run_portscan() {
    log_info "Running port scan (top ${TOP_PORTS_COUNT} ports) on resolved hosts with naabu..."
    if [[ ! -s "${RESOLVED_HOSTS_FILE}" ]]; then
        log_warn "No resolved hosts to scan. Skipping."
        : > "${LIVE_HOSTS_FILE}"
        return
    fi

    # Detect whether naabu accepts the -t flag (some builds don't)
    local naabu_supports_t=false
    if naabu --help 2>&1 | grep -qiE '\-t[,[:space:]]'; then
        naabu_supports_t=true
        log_info "Detected naabu supports -t (threads)."
    else
        log_info "naabu does not support -t; will run without -t flag."
    fi

    local success=0
    local current_threads=${NAABU_THREADS}
    local current_rate=${NAABU_RATE}
    # loop exactly NAABU_RETRY_COUNT times
    for attempt in $(seq 1 "$NAABU_RETRY_COUNT"); do
        log_info "naabu attempt ${attempt}/${NAABU_RETRY_COUNT} (threads=${current_threads} rate=${current_rate})"
        set +e
        if [[ "$naabu_supports_t" == true ]]; then
            naabu -l "${RESOLVED_HOSTS_FILE}" -top-ports "${TOP_PORTS_COUNT}" -o "${LIVE_HOSTS_FILE}" -silent -t "${current_threads}" -timeout "${NAABU_TIMEOUT}" -rate "${current_rate}" 2> /tmp/naabu_err.log
        else
            # run without -t if not supported
            naabu -l "${RESOLVED_HOSTS_FILE}" -top-ports "${TOP_PORTS_COUNT}" -o "${LIVE_HOSTS_FILE}" -silent -timeout "${NAABU_TIMEOUT}" -rate "${current_rate}" 2> /tmp/naabu_err.log
        fi
        local rc=$?
        set -e

        if [[ $rc -eq 0 && -s "${LIVE_HOSTS_FILE}" ]]; then
            success=1
            log_success "naabu finished successfully on attempt ${attempt}."
            break
        fi

        # If stderr mentions "flag provided but not defined" specifically for -t,
        # switch to running without -t for subsequent attempts (if not already)
        if grep -qi "flag provided but not defined: -t" /tmp/naabu_err.log 2>/dev/null; then
            log_warn "naabu stderr indicates '-t' is not supported. Will retry without -t."
            naabu_supports_t=false
            # Do not count this as an extra attempt beyond loop - next iteration will run without -t.
        else
            log_warn "naabu returned non-zero (rc=${rc}) on attempt ${attempt}. stderr saved to /tmp/naabu_err.log"
            # Backoff: halve threads and rate for next attempt, but keep minimums
            current_threads=$(( current_threads / 2 ))
            (( current_threads < 1 )) && current_threads=1
            current_rate=$(( current_rate / 2 ))
            (( current_rate < 10 )) && current_rate=10
            log_info "Retrying naabu with threads=${current_threads} rate=${current_rate}"
        fi
    done

    if [[ $success -eq 0 ]]; then
        log_warn "naabu failed after ${NAABU_RETRY_COUNT} attempt(s). Falling back to conservative HTTP probe fallback."
        if [[ -s "${RESOLVED_HOSTS_FILE}" ]]; then
            cp -f "${RESOLVED_HOSTS_FILE}" "${LIVE_HOSTS_FILE}" || true
            log_warn "Fallback: copied resolved hosts to ${LIVE_HOSTS_FILE} (httpx will probe these hosts)."
        else
            : > "${LIVE_HOSTS_FILE}"
        fi
    fi

    local live_count=0
    [[ -f "${LIVE_HOSTS_FILE}" ]] && live_count=$(wc -l < "${LIVE_HOSTS_FILE}" | tr -d ' ')
    log_success "Found ${live_count} hosts (post-portscan / fallback)."
}


# --- HTTP probing (httpx) ---
run_http_probe() {
    log_info "Probing live hosts for web services with httpx..."
    if [[ ! -s "${LIVE_HOSTS_FILE}" ]]; then
        log_warn "No live hosts to probe. Skipping."
        : > "${HTTP_PROBE_FILE}"
        : > "${HTTP_PROBE_JSON_FILE}"
        return
    fi

    log_info "Running httpx for standard text output..."
    httpx -l "${LIVE_HOSTS_FILE}" -sc -cl -title -tech-detect -o "${HTTP_PROBE_FILE}" -silent 2>/tmp/httpx_text_err.log || log_warn "httpx (text) returned non-zero."

    log_info "Running httpx for JSON output and screenshots..."
    # httpx supports -json or -j depending on version; try -j then fallback
    set +e
    httpx -l "${LIVE_HOSTS_FILE}" -json -ss -srd "${SCREENSHOT_DIR}" -o "${HTTP_PROBE_JSON_FILE}" -silent 2> /tmp/httpx_json_err.log
    rc=$?
    set -e
    if [[ $rc -ne 0 || ! -s "${HTTP_PROBE_JSON_FILE}" ]]; then
        # try -j flag
        set +e
        httpx -l "${LIVE_HOSTS_FILE}" -j -ss -srd "${SCREENSHOT_DIR}" -o "${HTTP_PROBE_JSON_FILE}" -silent 2> /tmp/httpx_json_err2.log || true
        set -e
    fi

    local http_count=0
    [[ -f "${HTTP_PROBE_FILE}" ]] && http_count=$(wc -l < "${HTTP_PROBE_FILE}" | tr -d ' ')
    log_success "Successfully probed ${http_count} web services."
}

# --- Screenshots map ---
gather_screenshots() {
    log_info "Mapping screenshots..."
    if [[ ! -d "${SCREENSHOT_DIR}" || -z "$(ls -A "${SCREENSHOT_DIR}" 2>/dev/null)" ]]; then
        log_warn "Screenshot directory is empty. Skipping screenshot mapping."
        echo "{}" > "${SCREENSHOT_MAP_FILE}"
        return
    fi

    printf '{\n' > "${SCREENSHOT_MAP_FILE}"
    local sep=""
    local run_dir_path_len=${#RUN_DIR}
    ((run_dir_path_len++))

    for png_file in "${SCREENSHOT_DIR}"/*.png; do
        [ -f "$png_file" ] || continue
        local filename host relpath
        filename=$(basename "$png_file")
        host=$(echo "$filename" | sed -E 's/^[a-z]+-(.*)-[0-9]+\.png$/\1/' | sed 's/-/./g')
        relpath="${png_file:${run_dir_path_len}}"
        printf '%s' "$sep" >> "${SCREENSHOT_MAP_FILE}"
        printf '  "%s": "%s"\n' "$host" "$relpath" >> "${SCREENSHOT_MAP_FILE}"
        sep=","
    done

    printf '}\n' >> "${SCREENSHOT_MAP_FILE}"
    log_success "Screenshot map created at ${SCREENSHOT_MAP_FILE}"
}

# --- Katana crawl ---
run_katana() {
    log_info "Crawling live web services with Katana..."
    if [[ ! -s "$HTTP_PROBE_JSON_FILE" ]]; then
        log_warn "No HTTP JSON data to crawl. Skipping Katana."
        echo "{}" > "$KATANA_FILE"
        return
    fi

    local seeds
    seeds=$(mktemp_file)
    jq -r '.url' "$HTTP_PROBE_JSON_FILE" 2>/dev/null | sort -u > "$seeds" || true

    echo "{" > "$KATANA_FILE"
    local first=true

    while IFS= read -r url; do
        [[ -z "$url" ]] && continue
        log_info "  -> crawling ${url}"
        local tmp
        tmp=$(mktemp_file)
        katana -silent -u "$url" -d "$KATANA_DEPTH" -ct "$KATANA_TIMEOUT" 2>/dev/null | sort -u > "$tmp" || true
        local links_json
        links_json=$(jq -R -s -c 'split("\n") | map(select(length>0))' "$tmp" 2>/dev/null || echo "[]")
        if [ "$first" = true ]; then first=false; else echo "," >> "$KATANA_FILE"; fi
        printf '  "%s": %s\n' "$url" "$links_json" >> "$KATANA_FILE"
        rm -f "$tmp" 2>/dev/null || true
    done < "$seeds"

    echo "}" >> "$KATANA_FILE"
    rm -f "$seeds" 2>/dev/null || true
    log_success "Katana crawling complete. Results in ${KATANA_FILE}"
}

# --- Login detection (same logic but robustified) ---
run_login_detection() {
    log_info "Detecting login panels..."
    if [[ ! -s "$HTTP_PROBE_JSON_FILE" ]]; then
        log_warn "No HTTP JSON data available. Skipping login detection."
        echo "[]" > "$LOGIN_FILE"
        return
    fi

    local urls
    urls=$(jq -r '.url' "$HTTP_PROBE_JSON_FILE" 2>/dev/null || echo "")

    echo "[" > "$LOGIN_FILE"
    local first_entry=true

    detect_login() {
        local headers_file="$1"; local body_file="$2"; local final_url="$3"
        local -a reasons=()
        grep -qiE "<input[^>]*type=(\"|')password(\"|')" "$body_file" && reasons+=("Found password field")
        grep -qiE "<input[^>]*(name|id)=(\"|')?(username|user|email|userid|loginid)(\"|')?" "$body_file" && reasons+=("Found username/email field")
        grep -qiE "<form[^>]*(action|id|name)[[:space:]]*=[[:space:]]*(\"|')?[^\"'>]*(login|log[-]?in|signin|auth|session|user|passwd|pwd|credential|verify|oauth|token|sso)(\"|')?" "$body_file" && reasons+=("Found form with login-related attributes")
        grep -qiE "(forgot[[:space:]]*password|reset[[:space:]]*password|sign[[:space:]]*in|log[[:space:]]*in)" "$body_file" && reasons+=("Found textual indicators for login")
        grep -qiE "<input[^>]*type=(\"|')hidden(\"|')[^>]*(csrf|token|authenticity|nonce|xsrf)" "$body_file" && reasons+=("Found hidden token field")
        grep -qiE "(recaptcha|g-recaptcha|hcaptcha)" "$body_file" && reasons+=("Found CAPTCHA widget")
        grep -qiE "(firebase\.auth|Auth0|passport)" "$body_file" && reasons+=("Found JavaScript auth library reference")

        grep -qiE "^HTTP/.*[[:space:]]+(401|403|407)" "$headers_file" && reasons+=("HTTP header indicates authentication requirement")
        grep -qi 'WWW-Authenticate' "$headers_file" && reasons+=("Found WWW-Authenticate header")
        grep -qiE "Set-Cookie:[[:space:]]*(sessionid|PHPSESSID|JSESSIONID|auth_token|jwt)" "$headers_file" && reasons+=("Found session cookie in headers")
        grep -qiE "Location:.*(login|signin|auth)" "$headers_file" && reasons+=("Found redirection to login in headers")

        echo "$final_url" | grep -qiE '/(login|signin|auth|account|admin|wp-login\.php|wp-admin|users/sign_in|member/login|login\.aspx|signin\.aspx)' && reasons+=("Final URL path suggests login endpoint")

        local login_found="No"
        if [ "${#reasons[@]}" -gt 0 ]; then
            login_found="Yes"
        fi

        local json_details
        json_details=$(printf '%s\n' "${reasons[@]:-}" | jq -R . | jq -s . 2>/dev/null || echo "[]")

        jq -n --arg login_found "$login_found" --argjson details "$json_details" '{login_found: $login_found, login_details: $details}'
    }

    while IFS= read -r url; do
        [[ -z "$url" ]] && continue

        local headers_file body_file curl_err
        headers_file=$(mktemp_file)
        body_file=$(mktemp_file)
        curl_err=$(mktemp_file)

        set +e
        curl -s -S -L -D "$headers_file" -o "$body_file" "$url" 2> "$curl_err"
        local curl_exit=$?
        set -e

        if [ $curl_exit -ne 0 ]; then
            if [ "$first_entry" = true ]; then first_entry=false; else echo "," >> "$LOGIN_FILE"; fi
            local err_msg
            err_msg=$(sed -n '1,10p' "$curl_err" | tr '\n' ' ' | sed 's/"/\\"/g' || true)
            echo "  { \"url\": \"${url}\", \"final_url\": \"\", \"login_detection\": { \"login_found\": \"No\", \"login_details\": [\"curl error: ${err_msg}\"] } }" >> "$LOGIN_FILE"
            rm -f "$headers_file" "$body_file" "$curl_err" 2>/dev/null || true
            continue
        fi
        rm -f "$curl_err" 2>/dev/null || true

        set +e
        local final_url
        final_url=$(grep -i '^location:' "$headers_file" 2>/dev/null | tail -n 1 | awk -F': ' '{print $2}' | tr -d '\r' || true)
        if [[ -z "$final_url" ]]; then final_url="$url"; fi
        set -e

        local detection_json
        detection_json=$(detect_login "$headers_file" "$body_file" "$final_url" 2>/dev/null || echo '{"login_found":"No","login_details":[]}')

        if [ "$first_entry" = true ]; then first_entry=false; else echo "," >> "$LOGIN_FILE"; fi
        echo "  { \"url\": \"${url}\", \"final_url\": \"${final_url}\", \"login_detection\": $detection_json }" >> "$LOGIN_FILE"

        rm -f "$headers_file" "$body_file" 2>/dev/null || true
    done <<< "$urls"

    echo "]" >> "$LOGIN_FILE"
    log_success "Login detection complete. Results in ${LOGIN_FILE}"
}

# --- API identification ---
run_api_identification() {
    log_info "Identifying potential API endpoints..."
    if [[ ! -s "${RESOLVED_HOSTS_FILE}" ]]; then
        log_warn "No resolved hosts to analyze. Skipping API identification."
        echo "[]" > "$API_ID_FILE"
        return
    fi

    echo "[" > "$API_ID_FILE"
    local first_entry=true
    while read -r domain; do
        [[ -z "$domain" ]] && continue
        local api_status="No"
        if echo "$domain" | grep -E -i '(\bapi\b|api\.|-api-|-api\.)' > /dev/null; then
            api_status="Yes"
        fi
        if [ "$first_entry" = true ]; then first_entry=false; else echo "," >> "$API_ID_FILE"; fi
        echo "  { \"domain\": \"${domain}\", \"api_endpoint\": \"${api_status}\" }" >> "$API_ID_FILE"
    done < "${RESOLVED_HOSTS_FILE}"
    echo "]" >> "$API_ID_FILE"
    log_success "API identification complete. Results in ${API_ID_FILE}"
}

# --- Colleague identification (unchanged algorithmically) ---
run_colleague_identification() {
    log_info "Identifying colleague-facing endpoints..."
    if [[ ! -s "${RESOLVED_HOSTS_FILE}" ]]; then
        log_warn "No resolved hosts to analyze. Skipping colleague identification."
        echo "[]" > "$COLLEAGUE_ID_FILE"
        return
    fi

    local tokens=( "qa01" "www-preprod" "uat9" "uat02" "workspace" "staging4" "api-uat" "ngcp-qa2" "webstg" "aem-stage2" "staging3" "canary" "hd-qa74" "uat05" "stgapps" "sit3" "ngcp-prf" "staging-dcm" "stage-mycosta" "edg-stg" "apidev" "uat-aka" "aem-dev2" "aem-qa2" "api-preprod" "shopecomqa" "uat03" "accounts-e2e" "uat7" "test4" "api-qa" "admin-academy" "staging-api" "prodcms" "wiop-stage" "api-stage" "preprod-www" "qa-api" "www-int" "gleague-dev" "prod-qa" "www-uat" "globalstg" "stg1" "pes-preprod" "matrix-preprod" "qa-us" "stage65-engage" "qaperf" "docs-test" "mcprod" "qa02-www" "www-qa2" "cqa" "portalstage" "wiop-qa" "server4" "sit-www" "test-shop" "api-product" "qa-ie" "www-qa3" "cstage" "testint" "perf-www" "mydesk-uat" "wwwdev" "qa5" "qa31" "api-prod" "uat6" "integ" "ux-stage" "aktest-www" "www-stg" "backoffice" "www-qa1" "uat5" "test3" "prodtest" "qa4" "preprod-corporate" "uat8" "emails" "develop" "www-qa" "www-dev" "dev-api" "uat-preview" "wwwtst" "int-www" "www-staging" "uat-www" "api-test" "server3" "homolog" "secure-api" "akamai-staging" "akamai-pat" "stg2" "stagecms" "confluence" "qa-www" "mcstaging" "stage3" "cdev" "cdev2" "dev-www" "cos-internal" "console" "uat3" "stage65" "dev3" "autoconfig" "pilot" "server2" "dashboard" "preview-test" "intranet" "e2e" "uat4" "uat-pdp" "lockerroom" "idp" "staff" "preview-uat-pdp" "upload" "infra" "api1" "lab" "failover" "extranet" "wip" "api3" "dr" "matrix-uat" "sit2" "testing" "jira" "webqa" "preprod2" "storage" "config" "gitlab" "git" "signin" "api-dev" "backend" "shadow" "api" "mail" "svc" "dev" "stage" "staging" "test" "qa" "uat" "stg" "prod" "bastion" "preprod" "login" "admin" "ingress" "preview" "portal" "vpn" "auth" "int" "traefik" "localhost" "remote" "support" "accounts" "developer" "development" "tools" "sandbox" "tst" "demo" "qa2" "perf" "uat2" "control" "sso" "sit" "acc" "dev1" "dev2" "access" "uat1" "internal" "training" "server1" "purge" "edit" "pre" "client" "qa3" "pro" "identity" "ppe" "integration" )

    echo "[" > "$COLLEAGUE_ID_FILE"
    local first_entry=true
    while read -r domain; do
        [[ -z "$domain" ]] && continue
        local lc_domain
        lc_domain=$(echo "$domain" | tr '[:upper:]' '[:lower:]')
        local found="No"
        for token in $(echo "$lc_domain" | tr '.-_' ' '); do
            for t in "${tokens[@]}"; do
                if [ "$token" = "$t" ]; then
                    found="Yes"
                    break 2
                fi
            done
        done
        if [ "$first_entry" = true ]; then first_entry=false; else echo "," >> "$COLLEAGUE_ID_FILE"; fi
        echo "  { \"domain\": \"${domain}\", \"colleague_endpoint\": \"${found}\" }" >> "$COLLEAGUE_ID_FILE"
    done < "${RESOLVED_HOSTS_FILE}"
    echo "]" >> "$COLLEAGUE_ID_FILE"
    log_success "Colleague identification complete. Results in ${COLLEAGUE_ID_FILE}"
}

# --- Robust nuclei runner (takeovers) ---
run_takeover_scan() {
    log_info "Scanning for potential subdomain takeovers using Nuclei..."
    if [[ ! -s "${RESOLVED_HOSTS_FILE}" ]]; then
        log_warn "No resolved hosts available for takeover scan. Skipping."
        : > "${TAKEOVER_FILE}"
        : > "${TAKEOVERS_JSON_FILE}"
        return
    fi

    # Update templates if possible (optional, safe to fail)
    if ! nuclei -update-templates &>/dev/null; then
        log_warn "Failed to update nuclei templates; continuing with existing ones if present."
    else
        log_info "Nuclei templates updated."
    fi

    # Auto-detect takeover template location
    local takeovers_path=""
    for path in \
        "${NUCLEI_TEMPLATES}/takeovers" \
        "${NUCLEI_TEMPLATES}/vulnerabilities/takeovers" \
        "${NUCLEI_TEMPLATES}/default-logins/takeovers" \
        "$(nuclei -ut; nuclei -tl 2>/dev/null | grep -i takeovers | head -n 1)"; do
        if [[ -d "$path" ]]; then
            takeovers_path="$path"
            break
        fi
    done

    if [[ -z "$takeovers_path" ]]; then
        log_warn "Takeover templates not found under ${NUCLEI_TEMPLATES}. Falling back to tag search (-tags takeover)."
    else
        log_info "Using takeover templates from: ${takeovers_path}"
    fi

    # Run nuclei with automatic JSON detection
    local tmp_err tmp_out
    tmp_err=$(mktemp_file)
    tmp_out=$(mktemp_file)
    rm -f "${TAKEOVERS_JSON_FILE}" "${TAKEOVER_FILE}" 2>/dev/null || true

    # Detect supported JSON flag
    local json_flag=""
    if nuclei -h 2>&1 | grep -q "\--json"; then
        json_flag="--json"
    elif nuclei -h 2>&1 | grep -q "\-json"; then
        json_flag="-json"
    elif nuclei -h 2>&1 | grep -q "\-j"; then
        json_flag="-j"
    fi

    if [[ -n "$takeovers_path" ]]; then
        log_info "Running nuclei on ${takeovers_path} with flag: ${json_flag:-none}"
        set +e
        nuclei -l "${RESOLVED_HOSTS_FILE}" -t "${takeovers_path}" ${json_flag:-} -silent -o "${TAKEOVERS_JSON_FILE}" 2> "${tmp_err}"
        rc=$?
        set -e
    else
        log_info "Running nuclei with -tags takeover ${json_flag:-none}"
        set +e
        nuclei -l "${RESOLVED_HOSTS_FILE}" -tags takeover ${json_flag:-} -silent -o "${TAKEOVERS_JSON_FILE}" 2> "${tmp_err}"
        rc=$?
        set -e
    fi

    # If fails, fallback to plain output
    if [[ $rc -ne 0 || ! -s "${TAKEOVERS_JSON_FILE}" ]]; then
        log_warn "nuclei did not produce JSON output; running plain fallback."
        if [[ -n "$takeovers_path" ]]; then
            nuclei -l "${RESOLVED_HOSTS_FILE}" -t "${takeovers_path}" -o "${tmp_out}" -silent 2>> "${tmp_err}" || true
        else
            nuclei -l "${RESOLVED_HOSTS_FILE}" -tags takeover -o "${tmp_out}" -silent 2>> "${tmp_err}" || true
        fi
        cp -f "${tmp_out}" "${TAKEOVERS_JSON_FILE}" || true
    fi

    # Extract potential vulnerable domains
    : > "${TAKEOVER_FILE}"
    if [[ -s "${TAKEOVERS_JSON_FILE}" ]]; then
        if jq -e . "${TAKEOVERS_JSON_FILE}" >/dev/null 2>&1; then
            jq -r '
                if type=="array" then
                    .[] | (.host // .matched // .request?.url // .url // .info?.host // "")
                elif type=="object" then
                    (.host // .matched // .request?.url // .url // "")
                else
                    empty
                end
            ' "${TAKEOVERS_JSON_FILE}" 2>/dev/null |
            sed 's#https\?://##; s#/.*$##' | grep -E '\.' | sort -u > "${TAKEOVER_FILE}" || true
        else
            grep -Eo '([a-zA-Z0-9._-]+\.[a-zA-Z]{2,})' "${TAKEOVERS_JSON_FILE}" | sort -u > "${TAKEOVER_FILE}" || true
        fi
    fi

    rm -f "${tmp_err}" "${tmp_out}" 2>/dev/null || true

    local takeover_count=0
    [[ -f "${TAKEOVER_FILE}" ]] && takeover_count=$(wc -l < "${TAKEOVER_FILE}" | tr -d ' ')
    log_success "Takeover scan complete — found ${takeover_count} potential subdomains (see ${TAKEOVERS_JSON_FILE})."
}

# --- Usage/help ---
usage() {
    echo "Usage: $0 -d <domain.com> | -f <domains_file.txt> [-o <output_dir>] [-s] [-P <top_ports>] [-R <naabu_retries>]"
    echo "  -d <domain>      Single domain to scan."
    echo "  -f <file>        File containing a list of domains."
    echo "  -o <dir>         Base output directory. Default: ./recon_results."
    echo "  -s               Silent mode. Suppress stdout."
    echo "  -P <top_ports>   Top N ports for naabu (default ${TOP_PORTS_COUNT})."
    echo "  -R <retries>     Naabu retry count (default ${NAABU_RETRY_COUNT})."
    echo "  -h               Display this help message."
    exit 1
}

# --- Main driver ---
main() {
    local domain=""
    local domain_file=""
    local output_dir="./recon_results"

    while getopts "d:f:o:shP:R:" opt; do
        case ${opt} in
            d) domain=${OPTARG} ;;
            f) domain_file=${OPTARG} ;;
            o) output_dir=${OPTARG} ;;
            s) SILENT_MODE="true" ;;
            P) TOP_PORTS_COUNT=${OPTARG} ;;
            R) NAABU_RETRY_COUNT=${OPTARG} ;;
            h) usage ;;
            *) usage ;;
        esac
    done

    if [[ -z "$domain" && -z "$domain_file" ]]; then
        echo -e "${RED}[ERROR] You must provide a domain (-d) or a domain file (-f).${NC}" >&2
        usage
    fi

    # Resolve output_dir to absolute if relative
    if ! [[ "$output_dir" =~ ^/ ]]; then
        output_dir="$PWD/$output_dir"
    fi

    local target_name
    if [[ -n "$domain" ]]; then
        target_name="$domain"
    else
        target_name=$(basename "$domain_file" .txt)
    fi

    # create run dir early so logging can write safely
    local run_dir="${output_dir}/${target_name}_$(date "+%Y-%m-%d_%H%M")"
    RUN_DIR="${run_dir}"
    DISCOVERY_DIR="${run_dir}/0_discovery"
    HOSTS_DIR="${run_dir}/1_hosts"
    VULNS_DIR="${run_dir}/2_vulns"
    SCREENSHOT_DIR="${run_dir}/3_screenshots"
    mkdir -p "${DISCOVERY_DIR}" "${HOSTS_DIR}" "${VULNS_DIR}" "${SCREENSHOT_DIR}" || log_warn "Could not create run directories (permission?)."

    LOG_FILE="${run_dir}/scan.log"
    # ensure logfile exists (touch), but be tolerant
    : > "${LOG_FILE}" 2>/dev/null || true

    ALL_SUBS_FILE="${DISCOVERY_DIR}/all_subdomains.txt"
    RESOLVED_HOSTS_FILE="${HOSTS_DIR}/resolved_hosts.txt"
    LIVE_HOSTS_FILE="${HOSTS_DIR}/live_hosts_naabu.txt"
    HTTP_PROBE_FILE="${HOSTS_DIR}/http_probe_httpx.txt"
    HTTP_PROBE_JSON_FILE="${HOSTS_DIR}/http_probe_httpx.json"
    TAKEOVER_FILE="${VULNS_DIR}/potential_takeovers.txt"
    TAKEOVERS_JSON_FILE="${VULNS_DIR}/takeovers.json"
    KATANA_FILE="${VULNS_DIR}/katana_links.json"
    LOGIN_FILE="${VULNS_DIR}/login_detection.json"
    API_ID_FILE="${VULNS_DIR}/api_identification.json"
    COLLEAGUE_ID_FILE="${VULNS_DIR}/colleague_identification.json"
    SCREENSHOT_MAP_FILE="${run_dir}/screenshot_map.json"

    log_info "Output will be saved in: ${run_dir}"
    log_info "naabu: top_ports=${TOP_PORTS_COUNT}, retries=${NAABU_RETRY_COUNT}"

    # --- Run Workflow ---
    check_dependencies

    # support file mode: iterate each domain sequentially
    if [[ -n "$domain_file" && -f "$domain_file" ]]; then
        while IFS= read -r d || [[ -n "$d" ]]; do
            d="${d%%[[:space:]]}"
            [[ -z "$d" ]] && continue
            log_info "=== Processing domain: ${d} ==="
            run_passive_discovery "$d" "$domain_file"
            run_bruteforce_and_resolve "$d" "$domain_file"
            run_portscan
            run_http_probe
            gather_screenshots
            run_katana
            run_login_detection
            run_api_identification
            run_colleague_identification
            run_takeover_scan
        done < "$domain_file"
    else
        run_passive_discovery "$domain" "$domain_file"
        run_bruteforce_and_resolve "$domain" "$domain_file"
        run_portscan
        run_http_probe
        gather_screenshots
        run_katana
        run_login_detection
        run_api_identification
        run_colleague_identification
        run_takeover_scan
    fi

    log_success "Reconnaissance finished for $([[ -n "$domain" ]] && echo "$domain" || echo "$domain_file")."
}

main "$@"
