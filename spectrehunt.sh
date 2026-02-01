#!/bin/bash

# SPECTREHUNT - Bug Bounty Reconnaissance Tool

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
WHITE='\033[1;37m'
BOLD='\033[1m'
RESET='\033[0m'

# ============= GLOBAL VARIABLES (Set after validation) =============
DOMAIN=""
OUTPUT_DIR=""

# ============= LOAD CONFIG AND INITIALIZE =============
# Source config.env file - Load before everything
CONFIG_LOADED=false

# Try multiple locations for config.env
for config_path in "$(dirname "$0")/config.env" "$HOME/SpectreHunt/config.env" "./config.env"; do
    if [ -f "$config_path" ]; then
        # Remove Windows line endings if present (Linux only)
        sed -i 's/\r$//' "$config_path" 2>/dev/null
        source "$config_path"
        CONFIG_LOADED=true
        break
    fi
done

# Start Docker service if installed
if command -v docker &> /dev/null; then
    # Check if Docker daemon is running
    if ! docker info >/dev/null 2>&1; then
        # Try to start Docker service
        sudo systemctl start docker >/dev/null 2>&1 || sudo service docker start >/dev/null 2>&1
    fi
fi

# Initialize Shodan API
if [ -n "$SHODAN_API_KEY" ]; then
    shodan init "$SHODAN_API_KEY" >/dev/null 2>&1
fi

# Display banner
display_banner() {
    clear
    echo -e "${RED}${BOLD}"
    cat << "EOF"
              [ S P E C T R E  H U N T ]
EOF
    echo -e "${CYAN}${BOLD}"
    cat << "EOF"
         Automated Bug Bounty Recon Framework
EOF
    echo -e "${RESET}"
    echo ""
}

# Display help
display_help() {
    display_banner
    echo -e "${CYAN}Usage:${RESET}"
    echo -e "  ./spectrehunt.sh -d <domain>    Run reconnaissance on target domain"
    echo -e "  ./spectrehunt.sh -c             Check if all required tools are installed"
    echo -e "  ./spectrehunt.sh -h             Display this help message"
    echo ""
    echo -e "${CYAN}Examples:${RESET}"
    echo -e "  ./spectrehunt.sh -d example.com"
    echo -e "  ./spectrehunt.sh -c"
    echo ""
    echo -e "${CYAN}Options:${RESET}"
    echo -e "  -d    Specify target domain"
    echo -e "  -c    Check required tools installation"
    echo -e "  -h    Show help menu"
    echo ""
}

# Check required tools
check_tools() {
    display_banner
    echo -e "${YELLOW}[${RESET} ${BOLD}${WHITE}Checking Required Tools${RESET} ${YELLOW}]${RESET}"
    echo ""
    
    local tools=(
        "subfinder"
        "findomain"
        "assetfinder"
        "sublist3r"
        "chaos"
        "crtsh"
        "puredns"
        "httpx"
        "dnsx"
        "katana"
        "gau"
        "ffuf"
        "gf"
        "nuclei"
        "subzy"
        "gowitness"
        "docker"
        "nmap"
        "wafw00f"
    )
    
    local all_installed=true
    local count=1
    
    for tool in "${tools[@]}"; do
        printf "${CYAN}%2d.${RESET} %-15s ${RESET}: " "$count" "$tool"
        if command -v "$tool" &> /dev/null; then
            echo -e "${GREEN}[✓]${RESET}"
        else
            echo -e "${RED}[✗]${RESET}"
            all_installed=false
        fi
        ((count++))
    done
    
    # Check DNS Reaper Docker image
    printf "${CYAN}%2d.${RESET} %-15s ${RESET}: " "$count" "dnsreaper"
    if command -v docker &> /dev/null && docker images punksecurity/dnsreaper -q 2>/dev/null | grep -q .; then
        echo -e "${GREEN}[✓]${RESET}"
    else
        echo -e "${RED}[✗]${RESET}"
        all_installed=false
    fi
    
    echo ""
    if [ "$all_installed" = true ]; then
        echo -e "${GREEN}[✓] All tools are installed!${RESET}"
    else
        echo -e "${RED}[!] Some tools are missing. Please install them before running.${RESET}"
        echo ""
        echo -e "${YELLOW}To install DNS Reaper:${RESET}"
        echo -e "  ${CYAN}docker pull punksecurity/dnsreaper${RESET}"
    fi
    echo ""
}

# Run tool with spinner and timing
run_tool() {
    local tool_name="$1"
    local command="$2"
    local output_file="$3"
    
    local start_time=$(date +%s)
    
    # Run command in background
    eval "$command" >/dev/null 2>&1 &
    local pid=$!
    
    # Show running status with live timer (YELLOW while running)
    while kill -0 $pid 2>/dev/null; do
        local current_time=$(date +%s)
        local elapsed=$((current_time - start_time))
        
        # Format time display
        if [ $elapsed -ge 60 ]; then
            local mins=$((elapsed / 60))
            local secs=$((elapsed % 60))
            echo -ne "${YELLOW}●${RESET} ${CYAN}${tool_name}${RESET} is running... ${CYAN}[${mins}m ${secs}s]${RESET}\r"
        else
            echo -ne "${YELLOW}●${RESET} ${CYAN}${tool_name}${RESET} is running... ${CYAN}[${elapsed}s]${RESET}\r"
        fi
        sleep 1
    done
    
    wait $pid
    local exit_code=$?
    
    local end_time=$(date +%s)
    local duration=$((end_time - start_time))
    
    # Format final time display
    local time_display
    if [ $duration -ge 60 ]; then
        local mins=$((duration / 60))
        local secs=$((duration % 60))
        time_display="${mins}m ${secs}s"
    else
        time_display="${duration}s"
    fi
    
    # Count results
    local count=0
    if [ -f "$output_file" ]; then
        count=$(wc -l < "$output_file" 2>/dev/null || echo 0)
    fi
    
    # Clear line and show result
    echo -ne "\r\033[K"
    
    # GREEN when completed successfully
    if [ $exit_code -eq 0 ] && [ $count -gt 0 ]; then
        echo -e "${GREEN}●${RESET} ${CYAN}${tool_name}${RESET} ${WHITE}${BOLD}${count}${RESET} subdomains found ${CYAN}[${time_display}]${RESET}"
    # GREEN but with 0 results
    elif [ $exit_code -eq 0 ] && [ $count -eq 0 ]; then
        echo -e "${GREEN}●${RESET} ${CYAN}${tool_name}${RESET} ${WHITE}${BOLD}0${RESET} subdomains found ${CYAN}[${time_display}]${RESET}"
    # RED when failed
    else
        echo -e "${RED}●${RESET} ${CYAN}${tool_name}${RESET} ${RED}failed${RESET} ${CYAN}[${time_display}]${RESET}"
    fi
}

# Display target information
display_info() {
    echo -e "${GREEN}➤${RESET}  ${YELLOW}Target:${RESET} ${WHITE}${BOLD}$DOMAIN${RESET}"
    
    # Colorize path separators - split path and add colors
    local path_colored=""
    local IFS='/'
    local parts=($OUTPUT_DIR)
    local first=true
    
    for part in "${parts[@]}"; do
        if [ -z "$part" ]; then
            # Root slash
            path_colored="${CYAN}/${RESET}"
        else
            if [ "$first" = true ]; then
                path_colored="${path_colored}${WHITE}${part}${RESET}"
                first=false
            else
                path_colored="${path_colored}${CYAN}/${RESET}${WHITE}${part}${RESET}"
            fi
        fi
    done
    
    echo -e "${GREEN}➤${RESET}  ${YELLOW}Workspace:${RESET} ${path_colored}"
    echo ""
}

# Subdomain enumeration
subdomain_enumeration() {
    display_info
    echo -e "${YELLOW}[${RESET} ${BOLD}${WHITE}Starting Subdomain Enumeration${RESET} ${YELLOW}]${RESET}"
    echo ""
    
    # Subfinder
    run_tool "subfinder" \
        "subfinder -d '$DOMAIN' -o '$OUTPUT_DIR/subfinder.txt' -rate-limit 30" \
        "$OUTPUT_DIR/subfinder.txt"
    
    # Findomain
    run_tool "findomain" \
        "findomain -t '$DOMAIN' --quiet -u '$OUTPUT_DIR/findomain.txt'" \
        "$OUTPUT_DIR/findomain.txt"
    
    # Assetfinder
    run_tool "assetfinder" \
        "assetfinder -subs-only '$DOMAIN' > '$OUTPUT_DIR/assetfinder.txt'" \
        "$OUTPUT_DIR/assetfinder.txt"
    
    # Sublist3r
    run_tool "sublist3r" \
        "sublist3r -d '$DOMAIN' -e baidu,yahoo,google,bing,ask,netcraft,threatcrowd,ssl,passivedns -o '$OUTPUT_DIR/sublist3r.txt'" \
        "$OUTPUT_DIR/sublist3r.txt"
    
    # Chaos
    if [ -n "$CHAOS_API_KEY" ]; then
        run_tool "chaos" \
            "chaos -key '$CHAOS_API_KEY' -d '$DOMAIN' 2>/dev/null | grep -v '^\[' | grep '\.' > '$OUTPUT_DIR/chaos.txt'" \
            "$OUTPUT_DIR/chaos.txt"
    else
        echo -e "${YELLOW}●${RESET} ${CYAN}chaos${RESET} ${YELLOW}skipped (API key not found)${RESET}"
    fi
    
    # Crtsh
    run_tool "crtsh" \
        "crtsh -d '$DOMAIN' -r > '$OUTPUT_DIR/crtsh.txt' 2>&1" \
        "$OUTPUT_DIR/crtsh.txt"
    
    # Shodan
    if [ -n "$SHODAN_API_KEY" ]; then
        run_tool "shodan" \
            "shodan search --fields hostnames ssl:'$DOMAIN' --limit 0 | tr ';' '\n' > '$OUTPUT_DIR/shodan.txt'" \
            "$OUTPUT_DIR/shodan.txt"
    else
        echo -e "${YELLOW}●${RESET} ${CYAN}shodan${RESET} ${YELLOW}skipped (API key not found)${RESET}"
    fi
    
    # Puredns
    if [ -f "$WORDLISTS" ] && [ -f "$RESOLVERS" ]; then
        run_tool "puredns" \
            "puredns bruteforce '$WORDLISTS' '$DOMAIN' -r '$RESOLVERS' -w '$OUTPUT_DIR/puredns.txt'" \
            "$OUTPUT_DIR/puredns.txt"
    else
        echo -e "${YELLOW}●${RESET} ${CYAN}puredns${RESET} ${YELLOW}skipped (wordlist or resolvers not found)${RESET}"
    fi
    
    # Merge and clean
    merge_subdomains
    
    # Live domain discovery
    live_domain_discovery
    
    # Resolve IPs
    resolve_ips
    
    # URL discovery
    url_discovery
    
    # Secret discovery
    secret_discovery
    
    # Screenshot capture
    screenshot_capture
    
    # Subdomain takeover detection
    subdomain_takeover
    
    # Nuclei vulnerability scanning
    nuclei_scan
    
    # Port scanning
    port_scan
    
    # Directory fuzzing
    directory_fuzz
    
    # WAF detection
    waf_detection
}

# Merge and clean subdomains
merge_subdomains() {
    echo ""
    echo -e "${YELLOW}[${RESET} ${BOLD}${WHITE}Merging and Cleaning Subdomains${RESET} ${YELLOW}]${RESET}"
    echo ""
    
    # Merge all subdomain files
    cat "$OUTPUT_DIR"/*.txt 2>/dev/null | sort > "$OUTPUT_DIR/all_subdomains.txt"
    
    local total=$(wc -l < "$OUTPUT_DIR/all_subdomains.txt" 2>/dev/null || echo 0)
    
    # Remove duplicates
    cat "$OUTPUT_DIR/all_subdomains.txt" | sort -u > "$OUTPUT_DIR/unique_subdomains.txt"
    
    local final=$(wc -l < "$OUTPUT_DIR/unique_subdomains.txt" 2>/dev/null || echo 0)
    local duplicates=$((total - final))
    
    echo -e " ${CYAN}├──${RESET} Total Subdomains Found: ${RED}${total}${RESET}"
    echo -e " ${CYAN}├──${RESET} Removed Duplicates: ${YELLOW}${duplicates}${RESET}"
    echo -e " ${CYAN}└──${RESET} Final Subdomains: ${GREEN}${final}${RESET}"
    echo ""
}

# Live domain discovery
live_domain_discovery() {
    echo ""
    echo -e "${YELLOW}[${RESET} ${BOLD}${WHITE}Discovering Live Domains${RESET} ${YELLOW}]${RESET}"
    echo ""
    
    local start_time=$(date +%s)
    
    # Count subdomains
    local total_subdomains=$(wc -l < "$OUTPUT_DIR/unique_subdomains.txt" 2>/dev/null || echo 0)
    
    # Show running status
    echo -e "${YELLOW}●${RESET} ${CYAN}httpx${RESET} is scanning ${WHITE}${total_subdomains}${RESET} subdomains..."
    echo ""
    
    # Step 1: Run httpx with optimized settings - save output with tee
    httpx -l "$OUTPUT_DIR/unique_subdomains.txt" \
        -sc -cl -ct -td -title -tech-detect -ip -cdn -cname \
        -mc 200,301,302,403,500 \
        -threads 50 \
        -rate-limit 150 \
        -timeout 5 \
        -retries 1 \
        -stats 2>&1 | tee "$OUTPUT_DIR/httpx_full.txt"
    
    # Step 2: Extract only URLs from httpx_full.txt (separate step)
    grep -E "^https?://" "$OUTPUT_DIR/httpx_full.txt" | awk '{print $1}' > "$OUTPUT_DIR/live_urls.txt"
    
    local end_time=$(date +%s)
    local duration=$((end_time - start_time))
    
    # Format time
    local time_display
    if [ $duration -ge 60 ]; then
        local mins=$((duration / 60))
        local secs=$((duration % 60))
        time_display="${mins}m ${secs}s"
    else
        time_display="${duration}s"
    fi
    
    # Count results
    local live_hosts=$(wc -l < "$OUTPUT_DIR/live_urls.txt" 2>/dev/null || echo 0)
    local dead_hosts=$((total_subdomains - live_hosts))
    
    # Display summary
    echo ""
    echo -e "${YELLOW}[${RESET} ${BOLD}${WHITE}Live Domain Summary${RESET} ${YELLOW}]${RESET}"
    echo ""
    echo -e " ${CYAN}├──${RESET} Total Subdomains: ${WHITE}${total_subdomains}${RESET}"
    echo -e " ${CYAN}├──${RESET} Live Hosts: ${GREEN}${live_hosts}${RESET}"
    echo -e " ${CYAN}├──${RESET} Dead Hosts: ${RED}${dead_hosts}${RESET}"
    echo -e " ${CYAN}└──${RESET} Time Taken: ${CYAN}${time_display}${RESET}"
    echo ""
}

# URL discovery with katana and gau
url_discovery() {
    echo ""
    echo -e "${YELLOW}[${RESET} ${BOLD}${WHITE}Discovering URLs${RESET} ${YELLOW}]${RESET}"
    echo ""
    
    # Check if live_urls.txt exists
    if [ ! -f "$OUTPUT_DIR/live_urls.txt" ] || [ ! -s "$OUTPUT_DIR/live_urls.txt" ]; then
        echo -e "${YELLOW}●${RESET} ${CYAN}katana${RESET} ${YELLOW}skipped (no live URLs found)${RESET}"
        echo -e "${YELLOW}●${RESET} ${CYAN}gau${RESET} ${YELLOW}skipped (no live URLs found)${RESET}"
        return
    fi
    
    # Create empty output files first
    touch "$OUTPUT_DIR/katana_urls.txt"
    touch "$OUTPUT_DIR/gau_urls.txt"
    
    # Run both tools in parallel
    local start_time=$(date +%s)
    
    # Katana in background
    (
        katana -list "$OUTPUT_DIR/live_urls.txt" -d 5 -kf all -jc -fx -ef woff,css,png,svg,jpg,woff2,jpeg,gif,ico,ttf,eot,otf,webp,bmp,tiff -rl 200 -c 20 -silent -o "$OUTPUT_DIR/katana_urls.txt" >/dev/null 2>&1
    ) &
    local katana_pid=$!
    
    # GAU in background
    (
        cat "$OUTPUT_DIR/live_urls.txt" | gau --blacklist ttf,woff,woff2,svg,png,jpg,jpeg,gif,ico,css,eot,otf,webp,bmp,tiff --providers wayback,commoncrawl,otx,urlscan --threads 10 --subs --o "$OUTPUT_DIR/gau_urls.txt" >/dev/null 2>&1
    ) &
    local gau_pid=$!
    
    # Monitor both tools
    local katana_done=false
    local gau_done=false
    local last_katana_count=0
    local last_gau_count=0
    
    while [ "$katana_done" = false ] || [ "$gau_done" = false ]; do
        local current_time=$(date +%s)
        local elapsed=$((current_time - start_time))
        
        # Format time
        local time_str
        if [ $elapsed -ge 60 ]; then
            local mins=$((elapsed / 60))
            local secs=$((elapsed % 60))
            time_str="${mins}m ${secs}s"
        else
            time_str="${elapsed}s"
        fi
        
        # Check katana status
        if [ "$katana_done" = false ]; then
            if kill -0 $katana_pid 2>/dev/null; then
                local katana_count=$(wc -l < "$OUTPUT_DIR/katana_urls.txt" 2>/dev/null || echo 0)
                echo -ne "${YELLOW}●${RESET} ${CYAN}katana${RESET} is running... ${WHITE}${katana_count}${RESET} URLs found ${CYAN}[${time_str}]${RESET}    \r"
                last_katana_count=$katana_count
            else
                wait $katana_pid
                local katana_count=$(wc -l < "$OUTPUT_DIR/katana_urls.txt" 2>/dev/null || echo 0)
                echo -e "${GREEN}●${RESET} ${CYAN}katana${RESET} ${WHITE}${BOLD}${katana_count}${RESET} URLs found ${CYAN}[${time_str}]${RESET}                    "
                katana_done=true
            fi
        fi
        
        # Check gau status
        if [ "$gau_done" = false ]; then
            if kill -0 $gau_pid 2>/dev/null; then
                local gau_count=$(wc -l < "$OUTPUT_DIR/gau_urls.txt" 2>/dev/null || echo 0)
                if [ "$katana_done" = true ]; then
                    echo -ne "${YELLOW}●${RESET} ${CYAN}gau${RESET} is running... ${WHITE}${gau_count}${RESET} URLs found ${CYAN}[${time_str}]${RESET}       \r"
                fi
                last_gau_count=$gau_count
            else
                wait $gau_pid
                local gau_count=$(wc -l < "$OUTPUT_DIR/gau_urls.txt" 2>/dev/null || echo 0)
                echo -e "${GREEN}●${RESET} ${CYAN}gau${RESET} ${WHITE}${BOLD}${gau_count}${RESET} URLs found ${CYAN}[${time_str}]${RESET}                       "
                gau_done=true
            fi
        fi
        
        sleep 1
    done
    
    # Merge and deduplicate URLs
    echo ""
    echo -e "${YELLOW}[${RESET} ${BOLD}${WHITE}Merging URLs${RESET} ${YELLOW}]${RESET}"
    echo ""
    
    cat "$OUTPUT_DIR/katana_urls.txt" "$OUTPUT_DIR/gau_urls.txt" 2>/dev/null | sort -u > "$OUTPUT_DIR/all_urls.txt"
    
    local katana_total=$(wc -l < "$OUTPUT_DIR/katana_urls.txt" 2>/dev/null || echo 0)
    local gau_total=$(wc -l < "$OUTPUT_DIR/gau_urls.txt" 2>/dev/null || echo 0)
    local total_urls=$((katana_total + gau_total))
    local unique_urls=$(wc -l < "$OUTPUT_DIR/all_urls.txt" 2>/dev/null || echo 0)
    local duplicates=$((total_urls - unique_urls))
    
    echo -e " ${CYAN}├──${RESET} Total URLs Found: ${RED}${total_urls}${RESET}"
    echo -e " ${CYAN}├──${RESET} Removed Duplicates: ${YELLOW}${duplicates}${RESET}"
    echo -e " ${CYAN}└──${RESET} Unique URLs: ${GREEN}${unique_urls}${RESET}"
    echo ""
    
    # GF Pattern Filtering
    gf_pattern_filter
}

# Merge live URLs with all URLs
merge_all_urls() {
    # Merge live_urls.txt and all_urls.txt silently
    cat "$OUTPUT_DIR/live_urls.txt" "$OUTPUT_DIR/all_urls.txt" 2>/dev/null | sort -u > "$OUTPUT_DIR/combined_urls.txt"
}

# API discovery
api_discovery() {
    echo ""
    echo -e "${YELLOW}[${RESET} ${BOLD}${WHITE}Discovering API Endpoints${RESET} ${YELLOW}]${RESET}"
    echo ""
    
    # Create API directory
    mkdir -p "$OUTPUT_DIR/apis"
    
    # Find API endpoints with better pattern matching
    # Match API indicators but exclude documentation/help pages
    grep -iE "/(api|v[0-9]|graphql|rest|endpoint|service)/|/swagger|/openapi|api\.|graphql\." "$OUTPUT_DIR/combined_urls.txt" \
        | grep -viE "/(help|docs|documentation|guide|tags|blog|news|wiki|support|faq|tutorial|learn)/" \
        > "$OUTPUT_DIR/apis/api_endpoints.txt" 2>/dev/null
    
    local api_count=$(wc -l < "$OUTPUT_DIR/apis/api_endpoints.txt" 2>/dev/null || echo 0)
    
    if [ $api_count -gt 0 ]; then
        echo -e "${GREEN}●${RESET} ${CYAN}API Discovery${RESET} ${WHITE}${BOLD}${api_count}${RESET} API endpoints found"
    else
        echo -e "${YELLOW}●${RESET} ${CYAN}API Discovery${RESET} ${YELLOW}No API endpoints found${RESET}"
    fi
    echo ""
}

# Sensitive file discovery
sensitive_file_discovery() {
    echo ""
    echo -e "${YELLOW}[${RESET} ${BOLD}${WHITE}Discovering Sensitive Files${RESET} ${YELLOW}]${RESET}"
    echo ""
    
    # Create sensitive directory
    mkdir -p "$OUTPUT_DIR/sensitive"
    
    # Use full domain for filtering (handles gre.ac.uk, example.co.uk, etc.)
    local domain_pattern="${DOMAIN}"
    
    # Filter in-scope URLs first
    grep -E "(://|@)([a-zA-Z0-9-]+\.)*${domain_pattern}(/|:|$|\?)" "$OUTPUT_DIR/combined_urls.txt" > "$OUTPUT_DIR/sensitive/temp_in_scope.txt" 2>/dev/null
    
    local start_time=$(date +%s)
    
    # Show running status
    echo -e "${YELLOW}●${RESET} ${CYAN}Sensitive Files${RESET} is scanning..."
    echo ""
    
    # Find sensitive files and show in terminal (from filtered URLs only)
    grep -iE "\.(txt|log|cache|secret|db|backup|yml|json|gz|rar|zip|config|env|crt|ini|pem|bak|swp|key|p12|pfx|ps1|xml|csv|dat|old|tar|tgz|7z|asc|passwd|htpasswd|pgp|ovpn|rc|conf|cert|p7b|bash_history|zsh_history|mysql_history|psql_history|sqlite3|dmp|rdp|sftp|sql|plist|dockerfile|sh|bashrc|zshrc|profile|npmrc|gitconfig|gitignore|aws|pgpass|id_rsa|ppk|openvpn|gpg|csr|cer|apk|mobileprovision|keystore|token|cloud|envrc|bash_aliases|my\.cnf|netrc|enc|ssl)$" "$OUTPUT_DIR/sensitive/temp_in_scope.txt" | tee "$OUTPUT_DIR/sensitive/sensitive_files.txt"
    
    # Cleanup temp file
    rm -f "$OUTPUT_DIR/sensitive/temp_in_scope.txt"
    
    local end_time=$(date +%s)
    local duration=$((end_time - start_time))
    
    # Format time
    local time_display
    if [ $duration -ge 60 ]; then
        local mins=$((duration / 60))
        local secs=$((duration % 60))
        time_display="${mins}m ${secs}s"
    else
        time_display="${duration}s"
    fi
    
    local file_count=$(wc -l < "$OUTPUT_DIR/sensitive/sensitive_files.txt" 2>/dev/null || echo 0)
    
    echo ""
    echo -e "${GREEN}●${RESET} ${CYAN}Sensitive Files${RESET} ${WHITE}${BOLD}${file_count}${RESET} files found ${CYAN}[${time_display}]${RESET}"
    echo ""
    
    # Count files by extension and display
    if [ $file_count -gt 0 ]; then
        echo -e "${YELLOW}[${RESET} ${BOLD}${WHITE}File Type Summary${RESET} ${YELLOW}]${RESET}"
        echo ""
        
        # Extract extensions and count them
        grep -oE "\.[a-z0-9_]+$" "$OUTPUT_DIR/sensitive/sensitive_files.txt" | sort | uniq -c | sort -rn | while read count ext; do
            echo -e " ${CYAN}├──${RESET} ${ext}: ${WHITE}${count}${RESET}"
        done
        
        echo ""
    fi
}

# Extract base domain for filtering
extract_base_domain() {
    echo "$DOMAIN" | awk -F. '{print $(NF-1)"."$NF}'
}

# Advanced sensitive keyword discovery
sensitive_keyword_discovery() {
    echo ""
    echo -e "${YELLOW}[${RESET} ${BOLD}${WHITE}Discovering Sensitive Parameters${RESET} ${YELLOW}]${RESET}"
    echo ""
    
    # Use full domain for filtering (handles gre.ac.uk, example.co.uk, etc.)
    local domain_pattern="${DOMAIN}"
    
    # Create temporary in-scope URLs file with strict domain matching
    # Match: domain.com, *.domain.com but NOT otherdomain.com
    grep -E "(://|@)([a-zA-Z0-9-]+\.)*${domain_pattern}(/|:|$|\?)" "$OUTPUT_DIR/combined_urls.txt" > "$OUTPUT_DIR/sensitive/in_scope_urls.txt" 2>/dev/null
    
    local start_time=$(date +%s)
    
    # 1. URLs with sensitive parameters and values
    grep -iE "(\?|&)(api_key|apikey|secret|token|password|pwd|pass|auth|authorization|access_key|secret_key|private_key|client_secret|api_secret|auth_token|session|session_id|jwt|bearer|oauth|key|access_token|refresh_token)=" "$OUTPUT_DIR/sensitive/in_scope_urls.txt" > "$OUTPUT_DIR/sensitive/sensitive_params.txt" 2>/dev/null
    local params_count=$(wc -l < "$OUTPUT_DIR/sensitive/sensitive_params.txt" 2>/dev/null || echo 0)
    
    # 2. Payment and transaction endpoints
    grep -iE "(payment|checkout|billing|invoice|transaction|order|cart|purchase|pay|stripe|paypal|razorpay|card|credit)" "$OUTPUT_DIR/sensitive/in_scope_urls.txt" | grep -vE "\.(jpg|jpeg|png|gif|svg|css|ico|woff|woff2|ttf)(\?|$)" > "$OUTPUT_DIR/sensitive/payment_endpoints.txt" 2>/dev/null
    local payment_count=$(wc -l < "$OUTPUT_DIR/sensitive/payment_endpoints.txt" 2>/dev/null || echo 0)
    
    # 3. Admin panels and dashboards
    grep -iE "/(admin|administrator|dashboard|panel|cpanel|console|manager|backend|controlpanel)" "$OUTPUT_DIR/sensitive/in_scope_urls.txt" | grep -vE "\.(jpg|jpeg|png|gif|svg|css|ico|woff|woff2|ttf)(\?|$)" > "$OUTPUT_DIR/sensitive/admin_panels.txt" 2>/dev/null
    local admin_count=$(wc -l < "$OUTPUT_DIR/sensitive/admin_panels.txt" 2>/dev/null || echo 0)
    
    # 4. Authentication endpoints (excluding public pages)
    grep -iE "/(signin|signup|register|logout|forgot|reset|verify|authenticate|authorize)" "$OUTPUT_DIR/sensitive/in_scope_urls.txt" | grep -E "(\?|&)" | grep -vE "\.(jpg|jpeg|png|gif|svg|css|ico)(\?|$)" > "$OUTPUT_DIR/sensitive/auth_endpoints.txt" 2>/dev/null
    local auth_count=$(wc -l < "$OUTPUT_DIR/sensitive/auth_endpoints.txt" 2>/dev/null || echo 0)
    
    # 5. Database and backup files
    grep -iE "\.(sql|db|sqlite|sqlite3|mdb|dump|backup|bak)(\?|$)" "$OUTPUT_DIR/sensitive/in_scope_urls.txt" > "$OUTPUT_DIR/sensitive/database_files.txt" 2>/dev/null
    local db_count=$(wc -l < "$OUTPUT_DIR/sensitive/database_files.txt" 2>/dev/null || echo 0)
    
    # 6. Configuration files
    grep -iE "\.(env|config|conf|cfg|ini|yaml|yml|toml|properties)(\?|$)" "$OUTPUT_DIR/sensitive/in_scope_urls.txt" > "$OUTPUT_DIR/sensitive/config_files.txt" 2>/dev/null
    local config_count=$(wc -l < "$OUTPUT_DIR/sensitive/config_files.txt" 2>/dev/null || echo 0)
    
    # 7. Email addresses
    grep -oE "mailto:[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}" "$OUTPUT_DIR/sensitive/in_scope_urls.txt" | sed 's/mailto://' | grep -E "@[a-zA-Z0-9.-]*${domain_pattern}" | sort -u > "$OUTPUT_DIR/sensitive/emails.txt" 2>/dev/null
    local email_count=$(wc -l < "$OUTPUT_DIR/sensitive/emails.txt" 2>/dev/null || echo 0)
    
    # 8. Cloud storage URLs
    grep -iE "(s3\.amazonaws|blob\.core\.windows|storage\.googleapis|cloudfront\.net|digitaloceanspaces|wasabi|backblaze)" "$OUTPUT_DIR/sensitive/in_scope_urls.txt" > "$OUTPUT_DIR/sensitive/cloud_storage.txt" 2>/dev/null
    local cloud_count=$(wc -l < "$OUTPUT_DIR/sensitive/cloud_storage.txt" 2>/dev/null || echo 0)
    
    # 9. Internal IPs and localhost
    grep -E "(://|@)(127\.|10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.|localhost|internal|corp|intranet)" "$OUTPUT_DIR/sensitive/in_scope_urls.txt" > "$OUTPUT_DIR/sensitive/internal_ips.txt" 2>/dev/null
    local ip_count=$(wc -l < "$OUTPUT_DIR/sensitive/internal_ips.txt" 2>/dev/null || echo 0)
    
    # 10. SSH/FTP credentials
    grep -E "^(ssh|ftp|sftp|ftps)://" "$OUTPUT_DIR/sensitive/in_scope_urls.txt" > "$OUTPUT_DIR/sensitive/ssh_ftp_urls.txt" 2>/dev/null
    local ssh_count=$(wc -l < "$OUTPUT_DIR/sensitive/ssh_ftp_urls.txt" 2>/dev/null || echo 0)
    
    # 11. Other sensitive (catch-all for uncategorized items)
    # Find URLs with sensitive keywords not already categorized
    grep -iE "secret|token|password|credential|private|key|api" "$OUTPUT_DIR/sensitive/in_scope_urls.txt" > "$OUTPUT_DIR/sensitive/temp_all_sensitive.txt" 2>/dev/null
    
    # Remove already categorized URLs
    cat "$OUTPUT_DIR/sensitive/sensitive_params.txt" \
        "$OUTPUT_DIR/sensitive/payment_endpoints.txt" \
        "$OUTPUT_DIR/sensitive/admin_panels.txt" \
        "$OUTPUT_DIR/sensitive/auth_endpoints.txt" \
        "$OUTPUT_DIR/sensitive/database_files.txt" \
        "$OUTPUT_DIR/sensitive/config_files.txt" \
        "$OUTPUT_DIR/sensitive/cloud_storage.txt" \
        "$OUTPUT_DIR/sensitive/internal_ips.txt" \
        "$OUTPUT_DIR/sensitive/ssh_ftp_urls.txt" 2>/dev/null | sort -u > "$OUTPUT_DIR/sensitive/temp_categorized.txt"
    
    # Get uncategorized items
    comm -23 <(sort "$OUTPUT_DIR/sensitive/temp_all_sensitive.txt") "$OUTPUT_DIR/sensitive/temp_categorized.txt" > "$OUTPUT_DIR/sensitive/other_sensitive.txt" 2>/dev/null
    
    # Cleanup temp files
    rm -f "$OUTPUT_DIR/sensitive/temp_all_sensitive.txt" "$OUTPUT_DIR/sensitive/temp_categorized.txt" "$OUTPUT_DIR/sensitive/in_scope_urls.txt"
    
    local other_count=$(wc -l < "$OUTPUT_DIR/sensitive/other_sensitive.txt" 2>/dev/null || echo 0)
    
    local end_time=$(date +%s)
    local duration=$((end_time - start_time))
    
    # Format time
    local time_display
    if [ $duration -ge 60 ]; then
        local mins=$((duration / 60))
        local secs=$((duration % 60))
        time_display="${mins}m ${secs}s"
    else
        time_display="${duration}s"
    fi
    
    # Display results in tree format
    echo -e " ${CYAN}├──${RESET} Sensitive Parameters: ${WHITE}${params_count}${RESET}"
    echo -e " ${CYAN}├──${RESET} Payment Endpoints: ${WHITE}${payment_count}${RESET}"
    echo -e " ${CYAN}├──${RESET} Admin Panels: ${WHITE}${admin_count}${RESET}"
    echo -e " ${CYAN}├──${RESET} Auth Endpoints: ${WHITE}${auth_count}${RESET}"
    echo -e " ${CYAN}├──${RESET} Database Files: ${WHITE}${db_count}${RESET}"
    echo -e " ${CYAN}├──${RESET} Config Files: ${WHITE}${config_count}${RESET}"
    echo -e " ${CYAN}├──${RESET} Email Addresses: ${WHITE}${email_count}${RESET}"
    echo -e " ${CYAN}├──${RESET} Cloud Storage: ${WHITE}${cloud_count}${RESET}"
    echo -e " ${CYAN}├──${RESET} Internal IPs: ${WHITE}${ip_count}${RESET}"
    echo -e " ${CYAN}├──${RESET} SSH/FTP URLs: ${WHITE}${ssh_count}${RESET}"
    echo -e " ${CYAN}└──${RESET} Other Sensitive: ${WHITE}${other_count}${RESET}"
    
    echo ""
    echo -e "${CYAN}[✓] Sensitive discovery completed in ${time_display}${RESET}"
    echo ""
}

# JS file discovery
js_file_discovery() {
    echo ""
    echo -e "${YELLOW}[${RESET} ${BOLD}${WHITE}Discovering JavaScript Files${RESET} ${YELLOW}]${RESET}"
    echo ""
    
    # Create JS directory
    mkdir -p "$OUTPUT_DIR/javascript"
    
    # Find JS files
    grep -iE "\.js$|\.jsx$|\.ts$|\.tsx$" "$OUTPUT_DIR/combined_urls.txt" > "$OUTPUT_DIR/javascript/js_files.txt" 2>/dev/null
    
    local js_count=$(wc -l < "$OUTPUT_DIR/javascript/js_files.txt" 2>/dev/null || echo 0)
    
    if [ $js_count -gt 0 ]; then
        echo -e "${GREEN}●${RESET} ${CYAN}JavaScript Files${RESET} ${WHITE}${BOLD}${js_count}${RESET} JS files found"
    else
        echo -e "${YELLOW}●${RESET} ${CYAN}JavaScript Files${RESET} ${YELLOW}No JS files found${RESET}"
        echo ""
        return
    fi
    echo ""
    
    # Run SecretFinder on JS files
    if command -v secretfinder &> /dev/null && [ $js_count -gt 0 ]; then
        echo -e "${YELLOW}[${RESET} ${BOLD}${WHITE}Analyzing JavaScript for Secrets${RESET} ${YELLOW}]${RESET}"
        echo ""
        
        local start_time=$(date +%s)
        echo -e "${YELLOW}●${RESET} ${CYAN}secretfinder${RESET} is analyzing..."
        echo ""
        
        # Run secretfinder with both text and HTML output
        secretfinder -i "$OUTPUT_DIR/javascript/js_files.txt" -o "$OUTPUT_DIR/sensitive/secrets.html" >/dev/null 2>&1
        
        local end_time=$(date +%s)
        local duration=$((end_time - start_time))
        
        # Format time
        local time_display
        if [ $duration -ge 60 ]; then
            local mins=$((duration / 60))
            local secs=$((duration % 60))
            time_display="${mins}m ${secs}s"
        else
            time_display="${duration}s"
        fi
        
        # Count secrets from HTML file
        local secret_count=0
        if [ -f "$OUTPUT_DIR/sensitive/secrets.html" ]; then
            secret_count=$(grep -c "http" "$OUTPUT_DIR/sensitive/secrets.html" 2>/dev/null || echo 0)
        fi
        
        echo -e "${GREEN}●${RESET} ${CYAN}secretfinder${RESET} ${WHITE}${BOLD}${secret_count}${RESET} secrets found ${CYAN}[${time_display}]${RESET}"
        echo ""
    else
        echo -e "${YELLOW}●${RESET} ${CYAN}secretfinder${RESET} ${YELLOW}skipped (tool not installed)${RESET}"
        echo ""
    fi
}

# GF Pattern Filtering
gf_pattern_filter() {
    echo ""
    echo -e "${YELLOW}[${RESET} ${BOLD}${WHITE}Filtering URLs with GF Patterns${RESET} ${YELLOW}]${RESET}"
    echo ""
    
    # Check if gf is installed
    if ! command -v gf &> /dev/null; then
        echo -e "${YELLOW}●${RESET} ${CYAN}gf${RESET} ${YELLOW}skipped (tool not installed)${RESET}"
        echo ""
        return
    fi
    
    # Check if all_urls.txt exists
    if [ ! -f "$OUTPUT_DIR/all_urls.txt" ] || [ ! -s "$OUTPUT_DIR/all_urls.txt" ]; then
        echo -e "${YELLOW}●${RESET} ${CYAN}gf${RESET} ${YELLOW}skipped (no URLs found)${RESET}"
        echo ""
        return
    fi
    
    # Create gf directory
    mkdir -p "$OUTPUT_DIR/gf"
    
    # GF patterns to run
    local patterns=(
        "xss"
        "sqli"
        "ssrf"
        "lfi"
        "rce"
        "redirect"
        "idor"
        "ssti"
        "cors"
        "aws-keys"
        "base64"
        "debug-pages"
        "firebase"
        "s3-buckets"
        "sec"
        "takeovers"
        "upload-fields"
        "interestingEXT"
        "interestingparams"
        "php-errors"
        "php-sinks"
        "json-sec"
        "jsvar"
    )
    
    local start_time=$(date +%s)
    local total_found=0
    
    # Run each pattern
    for pattern in "${patterns[@]}"; do
        cat "$OUTPUT_DIR/all_urls.txt" | gf "$pattern" > "$OUTPUT_DIR/gf/${pattern}.txt" 2>/dev/null
        local count=$(wc -l < "$OUTPUT_DIR/gf/${pattern}.txt" 2>/dev/null || echo 0)
        
        if [ $count -gt 0 ]; then
            echo -e "${GREEN}●${RESET} ${CYAN}${pattern}${RESET} ${WHITE}${count}${RESET} URLs found"
            total_found=$((total_found + count))
        fi
    done
    
    local end_time=$(date +%s)
    local duration=$((end_time - start_time))
    
    # Format time
    local time_display
    if [ $duration -ge 60 ]; then
        local mins=$((duration / 60))
        local secs=$((duration % 60))
        time_display="${mins}m ${secs}s"
    else
        time_display="${duration}s"
    fi
    
    echo ""
    if [ $total_found -gt 0 ]; then
        echo -e "${CYAN}[✓] GF filtering completed - ${WHITE}${total_found}${RESET} interesting URLs found ${CYAN}[${time_display}]${RESET}"
    else
        echo -e "${CYAN}[✓] GF filtering completed - No interesting URLs found ${CYAN}[${time_display}]${RESET}"
    fi
    echo ""
}

# Secret and sensitive discovery wrapper
secret_discovery() {
    merge_all_urls
    api_discovery
    sensitive_file_discovery
    sensitive_keyword_discovery
    js_file_discovery
}

# Screenshot capture with gowitness
screenshot_capture() {
    echo ""
    echo -e "${YELLOW}[${RESET} ${BOLD}${WHITE}Capturing Screenshots${RESET} ${YELLOW}]${RESET}"
    echo ""
    
    # Check if live_urls.txt exists
    if [ ! -f "$OUTPUT_DIR/live_urls.txt" ] || [ ! -s "$OUTPUT_DIR/live_urls.txt" ]; then
        echo -e "${YELLOW}●${RESET} ${CYAN}gowitness${RESET} ${YELLOW}skipped (no live URLs found)${RESET}"
        echo ""
        return
    fi
    
    # Check if gowitness is installed
    if ! command -v gowitness &> /dev/null; then
        echo -e "${YELLOW}●${RESET} ${CYAN}gowitness${RESET} ${YELLOW}skipped (tool not installed)${RESET}"
        echo ""
        return
    fi
    
    # Create screenshots directory
    mkdir -p "$OUTPUT_DIR/screenshots"
    
    local start_time=$(date +%s)
    local live_count=$(wc -l < "$OUTPUT_DIR/live_urls.txt" 2>/dev/null || echo 0)
    
    echo -e "${YELLOW}●${RESET} ${CYAN}gowitness${RESET} is capturing screenshots..."
    echo ""
    
    # Run gowitness - only save screenshots
    gowitness scan file -f "$OUTPUT_DIR/live_urls.txt" \
        --screenshot-path "$OUTPUT_DIR/screenshots" \
        --screenshot-format jpeg \
        --screenshot-jpeg-quality 75 \
        --screenshot-fullpage \
        --chrome-window-x 1920 \
        --chrome-window-y 1080 \
        --threads 10 \
        --timeout 30 \
        --delay 2 \
        --write-none \
        >/dev/null 2>&1
    
    local end_time=$(date +%s)
    local duration=$((end_time - start_time))
    
    # Format time
    local time_display
    if [ $duration -ge 60 ]; then
        local mins=$((duration / 60))
        local secs=$((duration % 60))
        time_display="${mins}m ${secs}s"
    else
        time_display="${duration}s"
    fi
    
    # Count screenshots
    local screenshot_count=$(find "$OUTPUT_DIR/screenshots" -name "*.jpeg" 2>/dev/null | wc -l)
    
    echo -e "${GREEN}●${RESET} ${CYAN}gowitness${RESET} ${WHITE}${BOLD}${screenshot_count}${RESET} screenshots captured ${CYAN}[${time_display}]${RESET}"
    echo ""
}

# Subdomain takeover detection with DNS Reaper
subdomain_takeover() {
    echo ""
    echo -e "${YELLOW}[${RESET} ${BOLD}${WHITE}Detecting Subdomain Takeovers${RESET} ${YELLOW}]${RESET}"
    echo ""
    
    # Check if unique_subdomains.txt exists
    if [ ! -f "$OUTPUT_DIR/unique_subdomains.txt" ] || [ ! -s "$OUTPUT_DIR/unique_subdomains.txt" ]; then
        echo -e "${YELLOW}●${RESET} ${CYAN}DNS Reaper${RESET} ${YELLOW}skipped (no subdomains found)${RESET}"
        echo ""
        return
    fi
    
    # Check if Docker is installed
    if ! command -v docker &> /dev/null; then
        echo -e "${YELLOW}●${RESET} ${CYAN}DNS Reaper${RESET} ${YELLOW}skipped (docker not installed)${RESET}"
        echo ""
        return
    fi
    
    # Check if DNS Reaper image exists
    if ! docker images punksecurity/dnsreaper -q 2>/dev/null | grep -q .; then
        echo -e "${YELLOW}●${RESET} ${CYAN}DNS Reaper${RESET} ${YELLOW}skipped (image not found)${RESET}"
        echo ""
        echo -e "${CYAN}To install DNS Reaper, run:${RESET}"
        echo -e "  ${WHITE}docker pull punksecurity/dnsreaper${RESET}"
        echo ""
        return
    fi
    
    local subdomain_count=$(wc -l < "$OUTPUT_DIR/unique_subdomains.txt" 2>/dev/null || echo 0)
    
    # Ask user if they want to run subdomain takeover scan (can be slow)
    echo -e "${YELLOW}DNS Reaper will scan ${WHITE}${subdomain_count}${RESET}${YELLOW} subdomains (may take 5-15 minutes)${RESET}"
    echo -e "${CYAN}Run subdomain takeover detection? [Y/n]:${RESET} "
    read -r -t 10 response || response="y"
    echo ""
    
    if [[ ! "$response" =~ ^[Yy]$ ]] && [[ -n "$response" ]]; then
        echo -e "${YELLOW}●${RESET} ${CYAN}DNS Reaper${RESET} ${YELLOW}skipped (user choice)${RESET}"
        echo ""
        return
    fi
    
    # Create takeover directory
    mkdir -p "$OUTPUT_DIR/takeover"
    
    local start_time=$(date +%s)
    
    echo -e "${YELLOW}●${RESET} ${CYAN}DNS Reaper${RESET} is scanning ${WHITE}${subdomain_count}${RESET} subdomains..."
    echo ""
    
    # Run DNS Reaper with Docker
    docker run -it --rm \
        -v "$OUTPUT_DIR":/etc/dnsreaper \
        punksecurity/dnsreaper file \
        --filename /etc/dnsreaper/unique_subdomains.txt \
        --out /etc/dnsreaper/takeover/takeover_results \
        --out-format json \
        --parallelism 100 2>&1
    
    local end_time=$(date +%s)
    local duration=$((end_time - start_time))
    
    # Format time
    local time_display
    if [ $duration -ge 60 ]; then
        local mins=$((duration / 60))
        local secs=$((duration % 60))
        time_display="${mins}m ${secs}s"
    else
        time_display="${duration}s"
    fi
    
    # Count vulnerable subdomains from JSON output
    local vulnerable_count=0
    if [ -f "$OUTPUT_DIR/takeover/takeover_results.json" ]; then
        vulnerable_count=$(grep -c '"vulnerable":true' "$OUTPUT_DIR/takeover/takeover_results.json" 2>/dev/null || echo 0)
    fi
    
    echo ""
    if [ $vulnerable_count -gt 0 ]; then
        echo -e "${RED}●${RESET} ${CYAN}DNS Reaper${RESET} ${RED}${BOLD}${vulnerable_count} vulnerable${RESET} subdomains found ${CYAN}[${time_display}]${RESET}"
    else
        echo -e "${GREEN}●${RESET} ${CYAN}DNS Reaper${RESET} ${GREEN}No vulnerabilities${RESET} found ${CYAN}[${time_display}]${RESET}"
    fi
    echo ""
}

# Nuclei vulnerability scanning
nuclei_scan() {
    echo ""
    echo -e "${YELLOW}[${RESET} ${BOLD}${WHITE}Nuclei Vulnerability Scanning${RESET} ${YELLOW}]${RESET}"
    echo ""
    
    # Check if live_urls.txt exists
    if [ ! -f "$OUTPUT_DIR/live_urls.txt" ] || [ ! -s "$OUTPUT_DIR/live_urls.txt" ]; then
        echo -e "${YELLOW}●${RESET} ${CYAN}nuclei${RESET} ${YELLOW}skipped (no live URLs found)${RESET}"
        echo ""
        return
    fi
    
    # Check if nuclei is installed
    if ! command -v nuclei &> /dev/null; then
        echo -e "${YELLOW}●${RESET} ${CYAN}nuclei${RESET} ${YELLOW}skipped (tool not installed)${RESET}"
        echo ""
        return
    fi
    
    # Create nuclei directory
    mkdir -p "$OUTPUT_DIR/nuclei"
    
    local start_time=$(date +%s)
    local url_count=$(wc -l < "$OUTPUT_DIR/live_urls.txt" 2>/dev/null || echo 0)
    
    echo -e "${YELLOW}●${RESET} ${CYAN}nuclei${RESET} is scanning ${WHITE}${url_count}${RESET} URLs with all templates..."
    echo ""
    
    # Run nuclei with all templates from nuclei-templates directory
    nuclei -l "$OUTPUT_DIR/live_urls.txt" \
        ~/nuclei-templates/ \
        -c 200 \
        -rl 200 \
        -o "$OUTPUT_DIR/nuclei/nuclei_results.txt" \
        -json-export "$OUTPUT_DIR/nuclei/nuclei_results.json" 2>&1
    
    local end_time=$(date +%s)
    local duration=$((end_time - start_time))
    
    # Format time
    local time_display
    if [ $duration -ge 60 ]; then
        local mins=$((duration / 60))
        local secs=$((duration % 60))
        time_display="${mins}m ${secs}s"
    else
        time_display="${duration}s"
    fi
    
    # Count findings by severity
    local critical=0
    local high=0
    local medium=0
    local low=0
    local info=0
    
    if [ -f "$OUTPUT_DIR/nuclei/nuclei_results.json" ]; then
        critical=$(grep -c '"severity":"critical"' "$OUTPUT_DIR/nuclei/nuclei_results.json" 2>/dev/null || echo 0)
        high=$(grep -c '"severity":"high"' "$OUTPUT_DIR/nuclei/nuclei_results.json" 2>/dev/null || echo 0)
        medium=$(grep -c '"severity":"medium"' "$OUTPUT_DIR/nuclei/nuclei_results.json" 2>/dev/null || echo 0)
        low=$(grep -c '"severity":"low"' "$OUTPUT_DIR/nuclei/nuclei_results.json" 2>/dev/null || echo 0)
        info=$(grep -c '"severity":"info"' "$OUTPUT_DIR/nuclei/nuclei_results.json" 2>/dev/null || echo 0)
    fi
    
    local total=$((critical + high + medium + low + info))
    
    echo ""
    echo -e "${YELLOW}[${RESET} ${BOLD}${WHITE}Nuclei Scan Summary${RESET} ${YELLOW}]${RESET}"
    echo ""
    
    if [ $total -gt 0 ]; then
        echo -e " ${CYAN}├──${RESET} Critical: ${RED}${critical}${RESET}"
        echo -e " ${CYAN}├──${RESET} High: ${RED}${high}${RESET}"
        echo -e " ${CYAN}├──${RESET} Medium: ${YELLOW}${medium}${RESET}"
        echo -e " ${CYAN}├──${RESET} Low: ${WHITE}${low}${RESET}"
        echo -e " ${CYAN}├──${RESET} Info: ${WHITE}${info}${RESET}"
        echo -e " ${CYAN}└──${RESET} Time Taken: ${CYAN}${time_display}${RESET}"
    else
        echo -e " ${CYAN}└──${RESET} ${GREEN}No vulnerabilities found${RESET} ${CYAN}[${time_display}]${RESET}"
    fi
    echo ""
}

# Port scanning with nmap
port_scan() {
    echo ""
    echo -e "${YELLOW}[${RESET} ${BOLD}${WHITE}Port Scanning${RESET} ${YELLOW}]${RESET}"
    echo ""
    
    # Check if resolved_ips.txt exists
    if [ ! -f "$OUTPUT_DIR/resolved_ips.txt" ] || [ ! -s "$OUTPUT_DIR/resolved_ips.txt" ]; then
        echo -e "${YELLOW}●${RESET} ${CYAN}nmap${RESET} ${YELLOW}skipped (no IPs found)${RESET}"
        echo ""
        return
    fi
    
    # Check if nmap is installed
    if ! command -v nmap &> /dev/null; then
        echo -e "${YELLOW}●${RESET} ${CYAN}nmap${RESET} ${YELLOW}skipped (tool not installed)${RESET}"
        echo ""
        return
    fi
    
    # Create ports directory
    mkdir -p "$OUTPUT_DIR/ports"
    
    local start_time=$(date +%s)
    local ip_count=$(wc -l < "$OUTPUT_DIR/resolved_ips.txt" 2>/dev/null || echo 0)
    
    echo -e "${YELLOW}●${RESET} ${CYAN}nmap${RESET} is scanning ${WHITE}${ip_count}${RESET} IPs with OS and service detection..."
    echo ""
    
    # Run nmap with comprehensive scanning
    nmap -iL "$OUTPUT_DIR/resolved_ips.txt" \
        -p- \
        -T4 \
        -A \
        -sV \
        -O \
        --osscan-guess \
        --version-intensity 5 \
        -oN "$OUTPUT_DIR/ports/nmap_scan.txt" \
        -oX "$OUTPUT_DIR/ports/nmap_scan.xml" \
        --open 2>&1 | tee -a "$OUTPUT_DIR/ports/nmap_output.log"
    
    local end_time=$(date +%s)
    local duration=$((end_time - start_time))
    
    # Format time
    local time_display
    if [ $duration -ge 60 ]; then
        local mins=$((duration / 60))
        local secs=$((duration % 60))
        time_display="${mins}m ${secs}s"
    else
        time_display="${duration}s"
    fi
    
    # Count open ports from nmap output
    local port_count=$(grep -c "^[0-9]*/.*open" "$OUTPUT_DIR/ports/nmap_scan.txt" 2>/dev/null || echo 0)
    
    # Count hosts with open ports
    local hosts_with_ports=$(grep -c "Nmap scan report for" "$OUTPUT_DIR/ports/nmap_scan.txt" 2>/dev/null || echo 0)
    
    echo ""
    echo -e "${YELLOW}[${RESET} ${BOLD}${WHITE}Nmap Scan Summary${RESET} ${YELLOW}]${RESET}"
    echo ""
    
    if [ $port_count -gt 0 ]; then
        echo -e " ${CYAN}├──${RESET} Hosts Scanned: ${WHITE}${ip_count}${RESET}"
        echo -e " ${CYAN}├──${RESET} Hosts with Open Ports: ${GREEN}${hosts_with_ports}${RESET}"
        echo -e " ${CYAN}├──${RESET} Total Open Ports: ${GREEN}${BOLD}${port_count}${RESET}"
        echo -e " ${CYAN}└──${RESET} Time Taken: ${CYAN}${time_display}${RESET}"
    else
        echo -e " ${CYAN}└──${RESET} ${YELLOW}No open ports found${RESET} ${CYAN}[${time_display}]${RESET}"
    fi
    echo ""
}

# Directory fuzzing with ffuf
directory_fuzz() {
    echo ""
    echo -e "${YELLOW}[${RESET} ${BOLD}${WHITE}Directory Fuzzing${RESET} ${YELLOW}]${RESET}"
    echo ""
    
    # Check if live_urls.txt exists
    if [ ! -f "$OUTPUT_DIR/live_urls.txt" ] || [ ! -s "$OUTPUT_DIR/live_urls.txt" ]; then
        echo -e "${YELLOW}●${RESET} ${CYAN}ffuf${RESET} ${YELLOW}skipped (no live URLs found)${RESET}"
        echo ""
        return
    fi
    
    # Check if ffuf is installed
    if ! command -v ffuf &> /dev/null; then
        echo -e "${YELLOW}●${RESET} ${CYAN}ffuf${RESET} ${YELLOW}skipped (tool not installed)${RESET}"
        echo ""
        return
    fi
    
    # Check if wordlist exists
    if [ ! -f "$FUZZ" ]; then
        echo -e "${YELLOW}●${RESET} ${CYAN}ffuf${RESET} ${YELLOW}skipped (wordlist not found: $FUZZ)${RESET}"
        echo ""
        return
    fi
    
    # Create ffuf directory
    mkdir -p "$OUTPUT_DIR/ffuf"
    
    local start_time=$(date +%s)
    local url_count=$(wc -l < "$OUTPUT_DIR/live_urls.txt" 2>/dev/null || echo 0)
    
    echo -e "${YELLOW}●${RESET} ${CYAN}ffuf${RESET} is fuzzing ${WHITE}${url_count}${RESET} URLs..."
    echo ""
    
    # Run ffuf on each URL
    local total_found=0
    while IFS= read -r url; do
        local domain=$(echo "$url" | awk -F/ '{print $3}')
        echo -e "${CYAN}Fuzzing:${RESET} ${WHITE}${domain}${RESET}"
        
        ffuf -u "$url/FUZZ" \
            -w "$FUZZ" \
            -mc 200,201,202,203,301,302,307,308,401,403,405 \
            -fc 404 \
            -t 100 \
            -rate 100 \
            -o "$OUTPUT_DIR/ffuf/${domain}_ffuf.json" 2>&1
        
        if [ -f "$OUTPUT_DIR/ffuf/${domain}_ffuf.json" ]; then
            local count=$(grep -c '"status":' "$OUTPUT_DIR/ffuf/${domain}_ffuf.json" 2>/dev/null || echo 0)
            total_found=$((total_found + count))
        fi
        echo ""
    done < "$OUTPUT_DIR/live_urls.txt"
    
    local end_time=$(date +%s)
    local duration=$((end_time - start_time))
    
    # Format time
    local time_display
    if [ $duration -ge 60 ]; then
        local mins=$((duration / 60))
        local secs=$((duration % 60))
        time_display="${mins}m ${secs}s"
    else
        time_display="${duration}s"
    fi
    
    echo ""
    if [ $total_found -gt 0 ]; then
        echo -e "${GREEN}●${RESET} ${CYAN}ffuf${RESET} ${WHITE}${BOLD}${total_found}${RESET} directories/files found ${CYAN}[${time_display}]${RESET}"
    else
        echo -e "${YELLOW}●${RESET} ${CYAN}ffuf${RESET} ${YELLOW}No hidden paths found${RESET} ${CYAN}[${time_display}]${RESET}"
    fi
    echo ""
}

# WAF detection with wafw00f
waf_detection() {
    echo ""
    echo -e "${YELLOW}[${RESET} ${BOLD}${WHITE}WAF Detection${RESET} ${YELLOW}]${RESET}"
    echo ""
    
    # Check if live_urls.txt exists
    if [ ! -f "$OUTPUT_DIR/live_urls.txt" ] || [ ! -s "$OUTPUT_DIR/live_urls.txt" ]; then
        echo -e "${YELLOW}●${RESET} ${CYAN}wafw00f${RESET} ${YELLOW}skipped (no live URLs found)${RESET}"
        echo ""
        return
    fi
    
    # Check if wafw00f is installed
    if ! command -v wafw00f &> /dev/null; then
        echo -e "${YELLOW}●${RESET} ${CYAN}wafw00f${RESET} ${YELLOW}skipped (tool not installed)${RESET}"
        echo ""
        return
    fi
    
    # Create waf directory
    mkdir -p "$OUTPUT_DIR/waf"
    
    local start_time=$(date +%s)
    local url_count=$(wc -l < "$OUTPUT_DIR/live_urls.txt" 2>/dev/null || echo 0)
    
    echo -e "${YELLOW}●${RESET} ${CYAN}wafw00f${RESET} is detecting WAF on ${WHITE}${url_count}${RESET} URLs..."
    echo ""
    
    # Run wafw00f
    wafw00f -i "$OUTPUT_DIR/live_urls.txt" \
        -o "$OUTPUT_DIR/waf/waf_results.txt" 2>&1
    
    local end_time=$(date +%s)
    local duration=$((end_time - start_time))
    
    # Format time
    local time_display
    if [ $duration -ge 60 ]; then
        local mins=$((duration / 60))
        local secs=$((duration % 60))
        time_display="${mins}m ${secs}s"
    else
        time_display="${duration}s"
    fi
    
    # Count WAFs detected
    local waf_count=$(grep -c "is behind" "$OUTPUT_DIR/waf/waf_results.txt" 2>/dev/null || echo 0)
    
    echo ""
    if [ $waf_count -gt 0 ]; then
        echo -e "${RED}●${RESET} ${CYAN}wafw00f${RESET} ${RED}${BOLD}${waf_count}${RESET} WAFs detected ${CYAN}[${time_display}]${RESET}"
    else
        echo -e "${GREEN}●${RESET} ${CYAN}wafw00f${RESET} ${GREEN}No WAF detected${RESET} ${CYAN}[${time_display}]${RESET}"
    fi
    echo ""
}

# Resolve IPs
resolve_ips() {
    echo ""
    echo -e "${YELLOW}[${RESET} ${BOLD}${WHITE}Resolving IP Addresses${RESET} ${YELLOW}]${RESET}"
    echo ""
    
    # Check if live_urls.txt exists
    if [ ! -f "$OUTPUT_DIR/live_urls.txt" ] || [ ! -s "$OUTPUT_DIR/live_urls.txt" ]; then
        echo -e "${YELLOW}●${RESET} ${CYAN}dnsx${RESET} ${YELLOW}skipped (no live URLs found)${RESET}"
        return
    fi
    
    local start_time=$(date +%s)
    
    # Show running status
    echo -e "${YELLOW}●${RESET} ${CYAN}dnsx${RESET} is resolving..."
    echo ""
    
    # Run dnsx and show output in terminal
    dnsx -l "$OUTPUT_DIR/live_urls.txt" -a -resp -silent | tee "$OUTPUT_DIR/dns_records.txt"
    
    # Extract only IPs from dns_records.txt
    grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' "$OUTPUT_DIR/dns_records.txt" | sort -u > "$OUTPUT_DIR/resolved_ips.txt"
    
    local end_time=$(date +%s)
    local duration=$((end_time - start_time))
    
    # Format time
    local time_display
    if [ $duration -ge 60 ]; then
        local mins=$((duration / 60))
        local secs=$((duration % 60))
        time_display="${mins}m ${secs}s"
    else
        time_display="${duration}s"
    fi
    
    # Count results
    local total_ips=$(wc -l < "$OUTPUT_DIR/resolved_ips.txt" 2>/dev/null || echo 0)
    local total_records=$(wc -l < "$OUTPUT_DIR/dns_records.txt" 2>/dev/null || echo 0)
    
    # Display summary
    echo ""
    echo -e "${YELLOW}[${RESET} ${BOLD}${WHITE}DNS Resolution Summary${RESET} ${YELLOW}]${RESET}"
    echo ""
    echo -e " ${CYAN}├──${RESET} Total DNS Records: ${WHITE}${total_records}${RESET}"
    echo -e " ${CYAN}├──${RESET} Unique IPs: ${GREEN}${total_ips}${RESET}"
    echo -e " ${CYAN}└──${RESET} Time Taken: ${CYAN}${time_display}${RESET}"
    echo ""
}

# Create output directory with incremental numbering if exists
create_output_dir() {
    local domain="$1"
    local desktop="$HOME/Desktop"
    local base_dir="$desktop/$domain"
    local output_dir="$base_dir"
    local counter=1
    
    # Check if base directory exists
    if [ -d "$output_dir" ]; then
        # Find next available number
        while [ -d "${base_dir}_${counter}" ]; do
            ((counter++))
        done
        output_dir="${base_dir}_${counter}"
    fi
    
    # Create the directory
    mkdir -p "$output_dir"
    echo "$output_dir"
}

# Main function
main() {
    if [ $# -eq 0 ]; then
        display_help
        exit 1
    fi
    
    while getopts "d:ch" opt; do
        case $opt in
            d)
                DOMAIN="$OPTARG"
                OUTPUT_DIR=$(create_output_dir "$DOMAIN")
                display_banner
                subdomain_enumeration
                ;;
            c)
                check_tools
                exit 0
                ;;
            h)
                display_help
                exit 0
                ;;
            *)
                display_help
                exit 1
                ;;
        esac
    done
}

# Run main
main "$@"