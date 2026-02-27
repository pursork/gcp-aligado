#!/bin/bash

################################################################################
# cdn_ip_ban.sh - Block CDN IP addresses using iptables
#
# Description:
#   This script downloads the latest IP lists from multiple CDN providers
#   and blocks both inbound and outbound traffic using ipset + iptables.
#
# Usage:
#   sudo ./cdn_ip_ban.sh [install|uninstall|update|status] [OPTIONS]
#   ./cdn_ip_ban.sh proxy-run --target=HOST -- command [args...]
#   sudo ./cdn_ip_ban.sh bypass-init
#   ./cdn_ip_ban.sh bypass-status
#
# Options:
#   --provider=PROVIDER   Specify CDN provider (akamai, fastly, all)
#                         Default: all
#   --ipv6                Include IPv6 addresses (default: IPv4 only)
#   --target=HOST         Used by proxy-run to decide whitelist matching
#   --socks5=URL          Override SOCKS5 URL for current proxy-run
#
# Requirements:
#   - Debian 12 or compatible Linux distribution
#   - Root privileges
#   - iptables/ipset, iptables-persistent, ipset-persistent packages
#   - jq (for JSON parsing)
################################################################################

set -euo pipefail

# Configuration
readonly SCRIPT_NAME="$(basename "$0")"
readonly LOG_FILE="/var/log/cdn_ip_ban.log"
readonly LOCK_FILE="/var/run/cdn_ip_ban.lock"
readonly IP_LIST_DIR="/etc/cdn_blocked_ips"
readonly BYPASS_LIST_FILE="/etc/cdn_bypass_white.list"
readonly BYPASS_PROXY_CONF="/etc/cdn_bypass_proxy.conf"
readonly DEFAULT_SOCKS5_PROXY="socks5h://127.0.0.1:1080"

# CDN Provider Configurations
declare -A CDN_PROVIDERS=(
    ["akamai_name"]="Akamai"
    ["akamai_url"]="https://raw.githubusercontent.com/platformbuilds/Akamai-ASN-and-IPs-List/master/akamai_ip_list.lst"
    ["akamai_format"]="text"
    ["akamai_chain"]="AKAMAI_BLOCK"
    ["akamai_file"]="$IP_LIST_DIR/akamai_ips.txt"

    ["fastly_name"]="Fastly"
    ["fastly_url"]="https://api.fastly.com/public-ip-list"
    ["fastly_format"]="json"
    ["fastly_chain"]="FASTLY_BLOCK"
    ["fastly_file"]="$IP_LIST_DIR/fastly_ips.txt"

    ["cloudflare_name"]="Cloudflare"
    ["cloudflare_url"]="https://www.cloudflare.com/ips-v4"
    ["cloudflare_url_ipv6"]="https://www.cloudflare.com/ips-v6"
    ["cloudflare_format"]="dual"
    ["cloudflare_chain"]="CLOUDFLARE_BLOCK"
    ["cloudflare_file"]="$IP_LIST_DIR/cloudflare_ips.txt"
)

# Optional source overrides (environment variables)
[[ -n "${AKAMAI_IP_LIST_URL:-}" ]] && CDN_PROVIDERS["akamai_url"]="$AKAMAI_IP_LIST_URL"
[[ -n "${FASTLY_IP_LIST_URL:-}" ]] && CDN_PROVIDERS["fastly_url"]="$FASTLY_IP_LIST_URL"
[[ -n "${CLOUDFLARE_IP_LIST_V4_URL:-}" ]] && CDN_PROVIDERS["cloudflare_url"]="$CLOUDFLARE_IP_LIST_V4_URL"
[[ -n "${CLOUDFLARE_IP_LIST_V6_URL:-}" ]] && CDN_PROVIDERS["cloudflare_url_ipv6"]="$CLOUDFLARE_IP_LIST_V6_URL"

# Default options
ENABLE_IPV6=false
SELECTED_PROVIDERS="all"
PROXY_TARGET=""
SOCKS5_PROXY_OVERRIDE=""
COMMAND=""
declare -a COMMAND_ARGS=()

# Colors for output
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly BLUE='\033[0;34m'
readonly NC='\033[0m' # No Color

################################################################################
# Utility Functions
################################################################################

log() {
    local level="$1"
    shift
    local message="$*"
    local timestamp
    timestamp=$(date '+%Y-%m-%d %H:%M:%S')

    # status/proxy-run can be non-root; logging must not break main flow.
    if [[ -w "$LOG_FILE" ]] || [[ ! -e "$LOG_FILE" && -w "$(dirname "$LOG_FILE")" ]]; then
        echo "[${timestamp}] [${level}] ${message}" | tee -a "$LOG_FILE" >/dev/null || true
    else
        echo "[${timestamp}] [${level}] ${message}" >&2
    fi
}

print_info() {
    echo -e "${BLUE}[INFO]${NC} $*"
    log "INFO" "$*"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $*"
    log "SUCCESS" "$*"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $*"
    log "WARNING" "$*"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $*" >&2
    log "ERROR" "$*"
}

check_root() {
    if [[ $EUID -ne 0 ]]; then
        print_error "This script must be run as root"
        exit 1
    fi
}

acquire_lock() {
    if ! command -v flock &> /dev/null; then
        # Fallback lock for minimal environments
        ( set -o noclobber; echo "$$" > "$LOCK_FILE" ) 2>/dev/null || {
            local pid
            pid=$(cat "$LOCK_FILE" 2>/dev/null || true)
            print_error "Another instance is already running (PID: ${pid:-unknown})"
            exit 1
        }
        trap 'rm -f "$LOCK_FILE"' EXIT INT TERM
        return 0
    fi

    exec 200>"$LOCK_FILE"
    if ! flock -n 200; then
        local pid
        pid=$(cat "$LOCK_FILE" 2>/dev/null || true)
        print_error "Another instance is already running (PID: ${pid:-unknown})"
        exit 1
    fi

    printf '%s\n' "$$" 1>&200
    trap 'rm -f "$LOCK_FILE"' EXIT INT TERM
}

check_dependencies() {
    local missing_deps=()

    if ! command -v iptables &> /dev/null; then
        missing_deps+=("iptables")
    fi

    if ! command -v curl &> /dev/null && ! command -v wget &> /dev/null; then
        missing_deps+=("curl")
    fi

    if ! command -v jq &> /dev/null; then
        missing_deps+=("jq")
    fi

    if ! command -v ipset &> /dev/null; then
        missing_deps+=("ipset")
    fi

    if ! command -v flock &> /dev/null; then
        missing_deps+=("flock")
    fi

    if [[ "$ENABLE_IPV6" = true ]] && ! command -v ip6tables &> /dev/null; then
        missing_deps+=("ip6tables")
    fi

    if [[ ${#missing_deps[@]} -gt 0 ]]; then
        print_error "Missing required dependencies: ${missing_deps[*]}"
        print_info "Installing dependencies..."
        apt-get update -qq
        apt-get install -y iptables ipset ipset-persistent curl jq iptables-persistent util-linux
    fi
}

get_provider_list() {
    if [[ "$SELECTED_PROVIDERS" == "all" ]]; then
        echo "akamai fastly cloudflare"
    else
        echo "$SELECTED_PROVIDERS" | tr ',' ' '
    fi
}

validate_provider() {
    local provider="$1"
    case "$provider" in
        akamai|fastly|cloudflare)
            return 0
            ;;
        *)
            return 1
            ;;
    esac
}

validate_selected_providers() {
    local providers
    providers=$(get_provider_list)

    local provider
    for provider in $providers; do
        if ! validate_provider "$provider"; then
            print_error "Unsupported provider: $provider"
            print_info "Supported providers: akamai, fastly, cloudflare, all"
            exit 1
        fi
    done
}

################################################################################
# Optional SOCKS5 Bypass
################################################################################

ensure_bypass_files() {
    local created_any=false

    if [[ ! -f "$BYPASS_LIST_FILE" ]]; then
        cat > "$BYPASS_LIST_FILE" << 'EOF'
# CDN bypass whitelist
# One entry per line. Blank lines and # comments are ignored.
#
# Domain suffix match:
# example.com
# api.example.com
#
# Exact IP match:
# 203.0.113.10
# 2001:db8::1
EOF
        chmod 644 "$BYPASS_LIST_FILE"
        created_any=true
        print_info "Created whitelist file: $BYPASS_LIST_FILE"
    fi

    if [[ ! -f "$BYPASS_PROXY_CONF" ]]; then
        cat > "$BYPASS_PROXY_CONF" << EOF
# SOCKS5 proxy used by proxy-run when a target matches $BYPASS_LIST_FILE
SOCKS5_PROXY="$DEFAULT_SOCKS5_PROXY"
EOF
        chmod 644 "$BYPASS_PROXY_CONF"
        created_any=true
        print_info "Created proxy config file: $BYPASS_PROXY_CONF"
    fi

    if [[ "$created_any" = true ]]; then
        print_success "Bypass files initialized"
    fi
}

is_ipv4_address() {
    local value="$1"
    [[ "$value" =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}$ ]]
}

is_ipv6_address() {
    local value="$1"
    [[ "$value" =~ ^([0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}$ ]]
}

normalize_host() {
    local input="$1"
    local host="$input"

    if [[ "$host" == *"://"* ]]; then
        host="${host#*://}"
    fi

    host="${host#*@}"
    host="${host%%/*}"
    host="${host%%\?*}"
    host="${host%%#*}"

    if [[ "$host" =~ ^\[(.*)\](:[0-9]+)?$ ]]; then
        host="${BASH_REMATCH[1]}"
    elif [[ "$host" == *:* ]] && [[ "$host" != *:*:* ]]; then
        host="${host%%:*}"
    fi

    echo "$host" | tr '[:upper:]' '[:lower:]'
}

load_socks5_proxy() {
    if [[ -n "$SOCKS5_PROXY_OVERRIDE" ]]; then
        echo "$SOCKS5_PROXY_OVERRIDE"
        return 0
    fi

    if [[ -f "$BYPASS_PROXY_CONF" ]]; then
        local value
        value=$(grep -E '^[[:space:]]*SOCKS5_PROXY=' "$BYPASS_PROXY_CONF" | tail -n 1 | cut -d '=' -f 2- || true)
        value=$(echo "$value" | sed -E "s/^[[:space:]]*[\"']?//; s/[\"']?[[:space:]]*$//")
        if [[ -n "$value" ]]; then
            echo "$value"
            return 0
        fi
    fi

    echo "$DEFAULT_SOCKS5_PROXY"
}

target_in_bypass_list() {
    local raw_target="$1"
    local target
    target=$(normalize_host "$raw_target")

    [[ -z "$target" ]] && return 1
    [[ ! -f "$BYPASS_LIST_FILE" ]] && return 1

    local line rule
    while IFS= read -r line || [[ -n "$line" ]]; do
        rule=$(echo "$line" | sed 's/#.*$//' | tr -d '[:space:]')
        [[ -z "$rule" ]] && continue
        rule=$(echo "$rule" | tr '[:upper:]' '[:lower:]')

        if [[ "$target" == "$rule" ]]; then
            return 0
        fi

        if is_ipv4_address "$rule" || is_ipv6_address "$rule"; then
            continue
        fi

        if [[ "$target" == *".${rule}" ]]; then
            return 0
        fi
    done < "$BYPASS_LIST_FILE"

    return 1
}

guess_target_from_args() {
    local arg
    for arg in "$@"; do
        if [[ "$arg" == *"://"* ]]; then
            normalize_host "$arg"
            return 0
        fi
    done

    for arg in "$@"; do
        local candidate
        candidate=$(normalize_host "$arg")
        if is_ipv4_address "$candidate" || is_ipv6_address "$candidate" || [[ "$candidate" =~ ^[a-z0-9.-]+\.[a-z]{2,}$ ]]; then
            echo "$candidate"
            return 0
        fi
    done

    return 1
}

proxy_run() {
    if [[ ${#COMMAND_ARGS[@]} -eq 0 ]]; then
        print_error "proxy-run requires a command to execute"
        print_info "Example: $SCRIPT_NAME proxy-run --target=example.com -- curl -I https://example.com"
        exit 1
    fi

    local target="$PROXY_TARGET"
    if [[ -z "$target" ]]; then
        target=$(guess_target_from_args "${COMMAND_ARGS[@]}" || true)
    fi

    if [[ -z "$target" ]]; then
        print_error "Cannot determine target host/IP for proxy decision"
        print_info "Use --target=HOST to specify a domain/IP explicitly"
        exit 1
    fi

    local normalized_target
    normalized_target=$(normalize_host "$target")

    if target_in_bypass_list "$normalized_target"; then
        local proxy_url
        proxy_url=$(load_socks5_proxy)
        print_info "Bypass hit: '$normalized_target' matched $BYPASS_LIST_FILE, using SOCKS5 proxy"
        ALL_PROXY="$proxy_url" all_proxy="$proxy_url" \
        HTTP_PROXY="$proxy_url" http_proxy="$proxy_url" \
        HTTPS_PROXY="$proxy_url" https_proxy="$proxy_url" \
        "${COMMAND_ARGS[@]}"
    else
        print_info "Bypass miss: '$normalized_target' not in whitelist, running command directly"
        "${COMMAND_ARGS[@]}"
    fi
}

bypass_init() {
    check_root
    ensure_bypass_files
}

bypass_status() {
    echo ""
    echo "=========================================="
    echo "  Optional SOCKS5 Bypass Status"
    echo "=========================================="
    echo ""

    if [[ -f "$BYPASS_LIST_FILE" ]]; then
        local count
        count=$(grep -Evc '^[[:space:]]*(#|$)' "$BYPASS_LIST_FILE" || true)
        count="${count:-0}"
        print_success "Whitelist file: $BYPASS_LIST_FILE ($count entries)"
    else
        print_warning "Whitelist file not found: $BYPASS_LIST_FILE"
    fi

    if [[ -f "$BYPASS_PROXY_CONF" ]]; then
        local proxy_url
        proxy_url=$(load_socks5_proxy)
        print_success "Proxy config file: $BYPASS_PROXY_CONF"
        echo -e "  ${BLUE}- Active SOCKS5 proxy:${NC} $proxy_url"
    else
        print_warning "Proxy config file not found: $BYPASS_PROXY_CONF"
    fi

    echo ""
    echo "=========================================="
}

################################################################################
# IP List Management
################################################################################

download_text_format() {
    local url="$1"
    local output_file="$2"

    local temp_file
    temp_file=$(mktemp)
    local download_success=false

    # Try curl first, then wget
    if command -v curl &> /dev/null; then
        if curl -fsSL --connect-timeout 30 --max-time 120 "$url" -o "$temp_file"; then
            download_success=true
        fi
    elif command -v wget &> /dev/null; then
        if wget -q --timeout=120 "$url" -O "$temp_file"; then
            download_success=true
        fi
    fi

    if [[ "$download_success" = false ]] || [[ ! -s "$temp_file" ]]; then
        rm -f "$temp_file"
        return 1
    fi

    # Validate and clean the IP list
    local valid_ips
    valid_ips=$(mktemp)
    while IFS= read -r line; do
        # Remove comments and whitespace
        line=$(echo "$line" | sed 's/#.*$//' | tr -d '[:space:]')

        # Skip empty lines
        [[ -z "$line" ]] && continue

        # Validate IP address or CIDR notation (IPv4)
        if [[ "$line" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}(/[0-9]{1,2})?$ ]]; then
            echo "$line" >> "$valid_ips"
        # Validate IPv6 if enabled
        elif [[ "$ENABLE_IPV6" = true ]] && [[ "$line" =~ ^([0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}(/[0-9]{1,3})?$ ]]; then
            echo "$line" >> "$valid_ips"
        fi
    done < "$temp_file"

    rm -f "$temp_file"

    if [[ ! -s "$valid_ips" ]]; then
        rm -f "$valid_ips"
        return 1
    fi

    mv "$valid_ips" "$output_file"
    chmod 644 "$output_file"
    return 0
}

download_json_format() {
    local url="$1"
    local output_file="$2"

    local temp_file
    temp_file=$(mktemp)
    local download_success=false

    # Download JSON
    if command -v curl &> /dev/null; then
        if curl -fsSL --connect-timeout 30 --max-time 120 "$url" -o "$temp_file"; then
            download_success=true
        fi
    elif command -v wget &> /dev/null; then
        if wget -q --timeout=120 "$url" -O "$temp_file"; then
            download_success=true
        fi
    fi

    if [[ "$download_success" = false ]] || [[ ! -s "$temp_file" ]]; then
        rm -f "$temp_file"
        return 1
    fi

    # Parse JSON and extract IPs
    local valid_ips
    valid_ips=$(mktemp)

    # Extract IPv4 addresses
    if jq -r '.addresses[]' "$temp_file" >> "$valid_ips" 2>/dev/null; then
        :
    else
        rm -f "$temp_file" "$valid_ips"
        return 1
    fi

    # Extract IPv6 addresses if enabled
    if [[ "$ENABLE_IPV6" = true ]]; then
        jq -r '.ipv6_addresses[]' "$temp_file" >> "$valid_ips" 2>/dev/null || true
    fi

    rm -f "$temp_file"

    if [[ ! -s "$valid_ips" ]]; then
        rm -f "$valid_ips"
        return 1
    fi

    mv "$valid_ips" "$output_file"
    chmod 644 "$output_file"
    return 0
}

download_dual_format() {
    local url_ipv4="$1"
    local url_ipv6="$2"
    local output_file="$3"

    local temp_ipv4
    local temp_ipv6
    local valid_ips
    temp_ipv4=$(mktemp)
    temp_ipv6=$(mktemp)
    valid_ips=$(mktemp)
    local download_success=false

    # Download IPv4 list
    if command -v curl &> /dev/null; then
        if curl -fsSL --connect-timeout 30 --max-time 120 "$url_ipv4" -o "$temp_ipv4"; then
            download_success=true
        fi
    elif command -v wget &> /dev/null; then
        if wget -q --timeout=120 "$url_ipv4" -O "$temp_ipv4"; then
            download_success=true
        fi
    fi

    if [[ "$download_success" = false ]] || [[ ! -s "$temp_ipv4" ]]; then
        rm -f "$temp_ipv4" "$temp_ipv6" "$valid_ips"
        return 1
    fi

    # Validate and add IPv4 addresses
    while IFS= read -r line; do
        # Remove comments and whitespace
        line=$(echo "$line" | sed 's/#.*$//' | tr -d '[:space:]')

        # Skip empty lines
        [[ -z "$line" ]] && continue

        # Validate IP address or CIDR notation (IPv4)
        if [[ "$line" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}(/[0-9]{1,2})?$ ]]; then
            echo "$line" >> "$valid_ips"
        fi
    done < "$temp_ipv4"

    # Download and process IPv6 list if enabled
    if [[ "$ENABLE_IPV6" = true ]]; then
        download_success=false

        if command -v curl &> /dev/null; then
            if curl -fsSL --connect-timeout 30 --max-time 120 "$url_ipv6" -o "$temp_ipv6"; then
                download_success=true
            fi
        elif command -v wget &> /dev/null; then
            if wget -q --timeout=120 "$url_ipv6" -O "$temp_ipv6"; then
                download_success=true
            fi
        fi

        if [[ "$download_success" = true ]] && [[ -s "$temp_ipv6" ]]; then
            while IFS= read -r line; do
                # Remove comments and whitespace
                line=$(echo "$line" | sed 's/#.*$//' | tr -d '[:space:]')

                # Skip empty lines
                [[ -z "$line" ]] && continue

                # Validate IPv6 address or CIDR notation
                if [[ "$line" =~ ^([0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}(/[0-9]{1,3})?$ ]]; then
                    echo "$line" >> "$valid_ips"
                fi
            done < "$temp_ipv6"
        fi
    fi

    rm -f "$temp_ipv4" "$temp_ipv6"

    if [[ ! -s "$valid_ips" ]]; then
        rm -f "$valid_ips"
        return 1
    fi

    mv "$valid_ips" "$output_file"
    chmod 644 "$output_file"
    return 0
}

download_provider_ips() {
    local provider="$1"
    local name="${CDN_PROVIDERS[${provider}_name]}"
    local url="${CDN_PROVIDERS[${provider}_url]}"
    local format="${CDN_PROVIDERS[${provider}_format]}"
    local file="${CDN_PROVIDERS[${provider}_file]}"

    print_info "Downloading $name IP list..."
    if [[ "$provider" == "akamai" ]] && [[ "$url" == *"raw.githubusercontent.com"* ]]; then
        print_warning "Akamai list source is a third-party GitHub repo. Consider overriding AKAMAI_IP_LIST_URL."
    fi

    # Create directory if it doesn't exist
    mkdir -p "$IP_LIST_DIR"

    if [[ "$format" == "text" ]]; then
        if download_text_format "$url" "$file"; then
            local count
            count=$(wc -l < "$file")
            print_success "Downloaded $count $name IP addresses"
            return 0
        fi
    elif [[ "$format" == "json" ]]; then
        if download_json_format "$url" "$file"; then
            local count
            count=$(wc -l < "$file")
            print_success "Downloaded $count $name IP addresses"
            return 0
        fi
    elif [[ "$format" == "dual" ]]; then
        local url_ipv6="${CDN_PROVIDERS[${provider}_url_ipv6]}"
        if download_dual_format "$url" "$url_ipv6" "$file"; then
            local count
            count=$(wc -l < "$file")
            print_success "Downloaded $count $name IP addresses"
            return 0
        fi
    fi

    print_error "Failed to download $name IP list from $url"
    return 1
}

################################################################################
# Iptables Management
################################################################################

create_chain() {
    local chain="$1"
    local table="${2:-filter}"

    if ! iptables -t "$table" -L "$chain" &> /dev/null; then
        iptables -t "$table" -N "$chain"
        print_info "Created iptables chain: $chain"
    fi
}

delete_chain() {
    local chain="$1"
    local table="${2:-filter}"

    if iptables -t "$table" -L "$chain" &> /dev/null; then
        # Flush the chain first
        iptables -t "$table" -F "$chain" 2>/dev/null || true

        # Remove references to this chain
        iptables -t "$table" -D INPUT -j "$chain" 2>/dev/null || true
        iptables -t "$table" -D OUTPUT -j "$chain" 2>/dev/null || true
        iptables -t "$table" -D FORWARD -j "$chain" 2>/dev/null || true

        # Delete the chain
        iptables -t "$table" -X "$chain" 2>/dev/null || true
        print_info "Deleted iptables chain: $chain"
    fi
}

ipset_exists() {
    local set_name="$1"
    if ! command -v ipset &> /dev/null; then
        return 1
    fi
    ipset list -n 2>/dev/null | grep -Fxq "$set_name"
}

ipset_entry_count() {
    local set_name="$1"
    if ! command -v ipset &> /dev/null; then
        echo "0"
        return 0
    fi
    local count
    count=$(ipset list "$set_name" 2>/dev/null | awk -F': ' '/Number of entries:/ {print $2}' | tail -n 1)
    echo "${count:-0}"
}

ensure_ipv4_drop_rule() {
    local set_name="$1"
    local direction="$2"
    local mark="$3"

    if [[ "$direction" == "src" ]]; then
        if ! iptables -C INPUT -m set --match-set "$set_name" src -m comment --comment "$mark" -j DROP 2>/dev/null; then
            iptables -I INPUT 1 -m set --match-set "$set_name" src -m comment --comment "$mark" -j DROP
        fi
    else
        if ! iptables -C OUTPUT -m set --match-set "$set_name" dst -m comment --comment "$mark" -j DROP 2>/dev/null; then
            iptables -I OUTPUT 1 -m set --match-set "$set_name" dst -m comment --comment "$mark" -j DROP
        fi
    fi
}

ensure_ipv6_drop_rule() {
    local set_name="$1"
    local direction="$2"
    local mark="$3"

    if ! command -v ip6tables &> /dev/null; then
        return 0
    fi

    if [[ "$direction" == "src" ]]; then
        if ! ip6tables -C INPUT -m set --match-set "$set_name" src -m comment --comment "$mark" -j DROP 2>/dev/null; then
            ip6tables -I INPUT 1 -m set --match-set "$set_name" src -m comment --comment "$mark" -j DROP
        fi
    else
        if ! ip6tables -C OUTPUT -m set --match-set "$set_name" dst -m comment --comment "$mark" -j DROP 2>/dev/null; then
            ip6tables -I OUTPUT 1 -m set --match-set "$set_name" dst -m comment --comment "$mark" -j DROP
        fi
    fi
}

remove_ipv4_drop_rules() {
    local set_name="$1"
    local rule_in_mark="$2"
    local rule_out_mark="$3"

    while iptables -D INPUT -m set --match-set "$set_name" src -m comment --comment "$rule_in_mark" -j DROP 2>/dev/null; do :; done
    while iptables -D OUTPUT -m set --match-set "$set_name" dst -m comment --comment "$rule_out_mark" -j DROP 2>/dev/null; do :; done
}

remove_ipv6_drop_rules() {
    local set_name="$1"
    local rule_in_mark="$2"
    local rule_out_mark="$3"

    if ! command -v ip6tables &> /dev/null; then
        return 0
    fi
    while ip6tables -D INPUT -m set --match-set "$set_name" src -m comment --comment "$rule_in_mark" -j DROP 2>/dev/null; do :; done
    while ip6tables -D OUTPUT -m set --match-set "$set_name" dst -m comment --comment "$rule_out_mark" -j DROP 2>/dev/null; do :; done
}

apply_provider_rules() {
    local provider="$1"
    local name="${CDN_PROVIDERS[${provider}_name]}"
    local chain="${CDN_PROVIDERS[${provider}_chain]}"
    local file="${CDN_PROVIDERS[${provider}_file]}"
    local set_v4="${chain}_V4"
    local set_v6="${chain}_V6"
    local set_v4_new="${set_v4}_N$$"
    local set_v6_new="${set_v6}_N$$"
    local rule_in_mark="${chain}_IN"
    local rule_out_mark="${chain}_OUT"

    print_info "Applying $name blocking rules (ipset backend)..."

    if [[ ! -f "$file" ]]; then
        print_error "$name IP list file not found: $file"
        return 1
    fi

    # Compatibility cleanup for old chain-based versions.
    delete_chain "$chain"

    local restore_file
    restore_file=$(mktemp)
    {
        echo "create $set_v4_new hash:net family inet -exist"
        if [[ "$ENABLE_IPV6" = true ]]; then
            echo "create $set_v6_new hash:net family inet6 -exist"
        fi
    } > "$restore_file"

    local ip
    local count=0
    while IFS= read -r ip; do
        [[ -z "$ip" ]] && continue
        if [[ "$ip" == *:* ]]; then
            [[ "$ENABLE_IPV6" = true ]] && echo "add $set_v6_new $ip -exist" >> "$restore_file"
        else
            echo "add $set_v4_new $ip -exist" >> "$restore_file"
        fi
        count=$((count + 1))
    done < "$file"

    if ! ipset restore < "$restore_file"; then
        rm -f "$restore_file"
        ipset destroy "$set_v4_new" 2>/dev/null || true
        ipset destroy "$set_v6_new" 2>/dev/null || true
        print_error "Failed to load ipset entries for $name"
        return 1
    fi
    rm -f "$restore_file"

    ipset create "$set_v4" hash:net family inet -exist
    ipset swap "$set_v4_new" "$set_v4"
    ipset destroy "$set_v4_new" 2>/dev/null || true

    if [[ "$ENABLE_IPV6" = true ]]; then
        if command -v ip6tables &> /dev/null; then
            ipset create "$set_v6" hash:net family inet6 -exist
            ipset swap "$set_v6_new" "$set_v6"
            ipset destroy "$set_v6_new" 2>/dev/null || true
        else
            print_warning "IPv6 requested but ip6tables is unavailable; IPv6 blocking is skipped"
            ipset destroy "$set_v6_new" 2>/dev/null || true
        fi
    else
        ipset destroy "$set_v6_new" 2>/dev/null || true
        ipset destroy "$set_v6" 2>/dev/null || true
    fi

    ensure_ipv4_drop_rule "$set_v4" "src" "$rule_in_mark"
    ensure_ipv4_drop_rule "$set_v4" "dst" "$rule_out_mark"

    if [[ "$ENABLE_IPV6" = true ]] && command -v ip6tables &> /dev/null; then
        ensure_ipv6_drop_rule "$set_v6" "src" "$rule_in_mark"
        ensure_ipv6_drop_rule "$set_v6" "dst" "$rule_out_mark"
    else
        remove_ipv6_drop_rules "$set_v6" "$rule_in_mark" "$rule_out_mark"
    fi

    print_success "Applied $name blocking rules for $count IP addresses/ranges"
    return 0
}

save_rules() {
    print_info "Saving iptables/ipset rules..."

    if command -v netfilter-persistent &> /dev/null; then
        netfilter-persistent save
    elif command -v iptables-save &> /dev/null; then
        iptables-save > /etc/iptables/rules.v4 2>/dev/null || \
        iptables-save > /etc/iptables.rules 2>/dev/null || \
        print_warning "Could not save iptables rules to standard location"
        if command -v ip6tables-save &> /dev/null; then
            ip6tables-save > /etc/iptables/rules.v6 2>/dev/null || true
        fi
        if command -v ipset &> /dev/null; then
            ipset save > /etc/iptables/ipset.rules 2>/dev/null || \
            print_warning "Could not save ipset rules to /etc/iptables/ipset.rules"
        fi
    fi

    print_success "Netfilter rules saved"
}

remove_provider_rules() {
    local provider="$1"
    local name="${CDN_PROVIDERS[${provider}_name]}"
    local chain="${CDN_PROVIDERS[${provider}_chain]}"
    local file="${CDN_PROVIDERS[${provider}_file]}"
    local set_v4="${chain}_V4"
    local set_v6="${chain}_V6"
    local rule_in_mark="${chain}_IN"
    local rule_out_mark="${chain}_OUT"

    print_info "Removing $name blocking rules..."

    remove_ipv4_drop_rules "$set_v4" "$rule_in_mark" "$rule_out_mark"
    remove_ipv6_drop_rules "$set_v6" "$rule_in_mark" "$rule_out_mark"
    delete_chain "$chain"

    ipset destroy "$set_v4" 2>/dev/null || true
    ipset destroy "$set_v6" 2>/dev/null || true

    # Remove IP list file
    if [[ -f "$file" ]]; then
        rm -f "$file"
        print_info "Removed $name IP list file"
    fi
}

show_provider_status() {
    local provider="$1"
    local name="${CDN_PROVIDERS[${provider}_name]}"
    local chain="${CDN_PROVIDERS[${provider}_chain]}"
    local file="${CDN_PROVIDERS[${provider}_file]}"
    local set_v4="${chain}_V4"
    local set_v6="${chain}_V6"
    local rule_in_mark="${chain}_IN"
    local rule_out_mark="${chain}_OUT"
    local can_probe=true

    if [[ $EUID -ne 0 ]]; then
        can_probe=false
    fi

    echo ""
    echo "=========================================="
    echo "  $name CDN IP Blocking Status"
    echo "=========================================="
    echo ""

    if [[ -f "$file" ]]; then
        local ip_count
        ip_count=$(wc -l < "$file")
        print_success "IP list file: $file ($ip_count entries)"
    else
        print_warning "IP list file not found: $file"
    fi

    echo ""

    if [[ "$can_probe" != true ]]; then
        print_warning "ipset '$set_v4': unknown (not root)"
    elif ipset_exists "$set_v4"; then
        local v4_count
        v4_count=$(ipset_entry_count "$set_v4")
        print_success "ipset '$set_v4' exists ($v4_count entries)"
    else
        print_warning "ipset '$set_v4' does not exist"
    fi

    if [[ "$can_probe" != true ]] || [[ "$ENABLE_IPV6" = true ]] || ipset_exists "$set_v6"; then
        if [[ "$can_probe" != true ]]; then
            print_warning "ipset '$set_v6': unknown (not root)"
        elif ipset_exists "$set_v6"; then
            local v6_count
            v6_count=$(ipset_entry_count "$set_v6")
            print_success "ipset '$set_v6' exists ($v6_count entries)"
        else
            print_warning "ipset '$set_v6' does not exist"
        fi
    fi

    if [[ "$can_probe" != true ]]; then
        echo -e "  ${BLUE}-${NC} IPv4 INPUT rule: ${YELLOW}unknown (not root)${NC}"
        echo -e "  ${BLUE}-${NC} IPv4 OUTPUT rule: ${YELLOW}unknown (not root)${NC}"
    else
        if iptables -C INPUT -m set --match-set "$set_v4" src -m comment --comment "$rule_in_mark" -j DROP 2>/dev/null; then
            echo -e "  ${BLUE}-${NC} IPv4 INPUT rule: ${GREEN}yes${NC}"
        else
            echo -e "  ${BLUE}-${NC} IPv4 INPUT rule: ${RED}no${NC}"
        fi

        if iptables -C OUTPUT -m set --match-set "$set_v4" dst -m comment --comment "$rule_out_mark" -j DROP 2>/dev/null; then
            echo -e "  ${BLUE}-${NC} IPv4 OUTPUT rule: ${GREEN}yes${NC}"
        else
            echo -e "  ${BLUE}-${NC} IPv4 OUTPUT rule: ${RED}no${NC}"
        fi
    fi

    if [[ "$can_probe" != true ]]; then
        echo -e "  ${BLUE}-${NC} IPv6 INPUT rule: ${YELLOW}unknown (not root)${NC}"
        echo -e "  ${BLUE}-${NC} IPv6 OUTPUT rule: ${YELLOW}unknown (not root)${NC}"
    elif command -v ip6tables &> /dev/null; then
        if ip6tables -C INPUT -m set --match-set "$set_v6" src -m comment --comment "$rule_in_mark" -j DROP 2>/dev/null; then
            echo -e "  ${BLUE}-${NC} IPv6 INPUT rule: ${GREEN}yes${NC}"
        else
            echo -e "  ${BLUE}-${NC} IPv6 INPUT rule: ${RED}no${NC}"
        fi

        if ip6tables -C OUTPUT -m set --match-set "$set_v6" dst -m comment --comment "$rule_out_mark" -j DROP 2>/dev/null; then
            echo -e "  ${BLUE}-${NC} IPv6 OUTPUT rule: ${GREEN}yes${NC}"
        else
            echo -e "  ${BLUE}-${NC} IPv6 OUTPUT rule: ${RED}no${NC}"
        fi
    else
        print_warning "ip6tables not available; IPv6 rule status unavailable"
    fi

    echo ""
    echo "=========================================="
}

show_status() {
    validate_selected_providers
    local providers
    providers=$(get_provider_list)

    for provider in $providers; do
        show_provider_status "$provider"
    done
}

################################################################################
# Main Functions
################################################################################

install_blocking() {
    print_info "Installing CDN IP blocking..."

    check_dependencies
    ensure_bypass_files
    validate_selected_providers

    local providers
    providers=$(get_provider_list)
    local failed=0
    local applied=0

    for provider in $providers; do
        local name="${CDN_PROVIDERS[${provider}_name]}"

        if ! download_provider_ips "$provider"; then
            print_error "Failed to download $name IP list"
            failed=$((failed + 1))
            continue
        fi

        if ! apply_provider_rules "$provider"; then
            print_error "Failed to apply $name rules"
            failed=$((failed + 1))
        else
            applied=$((applied + 1))
        fi
    done

    if [[ $applied -gt 0 ]]; then
        save_rules
    fi

    if [[ $failed -gt 0 ]]; then
        print_warning "Installation completed with $failed error(s)"
    else
        print_success "Installation complete!"
    fi

    print_info "Run '$SCRIPT_NAME status' to verify the configuration"
}

uninstall_blocking() {
    print_info "Uninstalling CDN IP blocking..."

    validate_selected_providers
    local providers
    providers=$(get_provider_list)

    for provider in $providers; do
        remove_provider_rules "$provider"
    done

    # Clean up directory if empty
    if [[ -d "$IP_LIST_DIR" ]] && [[ -z "$(ls -A "$IP_LIST_DIR")" ]]; then
        rmdir "$IP_LIST_DIR"
        print_info "Removed IP list directory"
    fi

    save_rules
    print_success "Uninstallation complete!"
}

update_blocking() {
    print_info "Updating CDN IP blocking rules..."

    check_dependencies
    validate_selected_providers
    local providers
    providers=$(get_provider_list)
    local failed=0
    local applied=0

    for provider in $providers; do
        local name="${CDN_PROVIDERS[${provider}_name]}"

        if ! download_provider_ips "$provider"; then
            print_error "Failed to download $name IP list"
            failed=$((failed + 1))
            continue
        fi

        if ! apply_provider_rules "$provider"; then
            print_error "Failed to apply $name rules"
            failed=$((failed + 1))
        else
            applied=$((applied + 1))
        fi
    done

    if [[ $applied -gt 0 ]]; then
        save_rules
    fi

    if [[ $failed -gt 0 ]]; then
        print_warning "Update completed with $failed error(s)"
    else
        print_success "Update complete!"
    fi
}

show_usage() {
    cat << EOF
Usage: $SCRIPT_NAME [COMMAND] [OPTIONS]
       $SCRIPT_NAME proxy-run [--target=HOST] [--socks5=URL] -- command [args...]

Commands:
    install     Download IP lists and install blocking rules
    uninstall   Remove all blocking rules and clean up
    update      Update IP lists and refresh blocking rules
    status      Show current blocking status
    bypass-init Initialize optional SOCKS5 bypass files
    bypass-status
                Show optional SOCKS5 bypass status
    proxy-run   Run one command; if target hits whitelist, use SOCKS5
    help        Display this help message

Options:
    --provider=PROVIDER   Specify CDN provider to manage
                          Values: akamai, fastly, cloudflare, all (default: all)
                          Multiple: --provider=akamai,fastly,cloudflare

    --ipv6                Include IPv6 addresses (default: IPv4 only)
    --target=HOST         Target host/IP/URL used by proxy-run decision
    --socks5=URL          Override SOCKS5 URL for current proxy-run

Examples:
    # Install blocking for all CDN providers
    sudo $SCRIPT_NAME install

    # Install blocking for Akamai only
    sudo $SCRIPT_NAME install --provider=akamai

    # Install blocking for Cloudflare with IPv6
    sudo $SCRIPT_NAME install --provider=cloudflare --ipv6

    # Install blocking for multiple providers
    sudo $SCRIPT_NAME install --provider=akamai,cloudflare --ipv6

    # Update all providers
    sudo $SCRIPT_NAME update

    # Check status
    $SCRIPT_NAME status

    # Uninstall Cloudflare only
    sudo $SCRIPT_NAME uninstall --provider=cloudflare

    # Initialize optional bypass files
    sudo $SCRIPT_NAME bypass-init

    # Run one command with optional SOCKS5 bypass
    $SCRIPT_NAME proxy-run --target=example.com -- curl -I https://example.com
    $SCRIPT_NAME proxy-run -- curl -I https://example.com

Supported CDN Providers (ipset names):
    - Akamai      (AKAMAI_BLOCK_V4 / AKAMAI_BLOCK_V6)
    - Fastly      (FASTLY_BLOCK_V4 / FASTLY_BLOCK_V6)
    - Cloudflare  (CLOUDFLARE_BLOCK_V4 / CLOUDFLARE_BLOCK_V6)

EOF
}

parse_arguments() {
    COMMAND=""
    COMMAND_ARGS=()
    PROXY_TARGET=""
    SOCKS5_PROXY_OVERRIDE=""

    while [[ $# -gt 0 ]]; do
        case "$1" in
            install|uninstall|update|status|help|proxy-run|bypass-init|bypass-status)
                if [[ -z "$COMMAND" ]]; then
                    COMMAND="$1"
                else
                    COMMAND_ARGS+=("$1")
                fi
                shift
                ;;
            --provider=*)
                SELECTED_PROVIDERS="${1#*=}"
                shift
                ;;
            --ipv6)
                ENABLE_IPV6=true
                shift
                ;;
            --target=*)
                PROXY_TARGET="${1#*=}"
                shift
                ;;
            --socks5=*)
                SOCKS5_PROXY_OVERRIDE="${1#*=}"
                shift
                ;;
            --)
                shift
                while [[ $# -gt 0 ]]; do
                    COMMAND_ARGS+=("$1")
                    shift
                done
                break
                ;;
            *)
                if [[ -z "$COMMAND" ]] && [[ ! "$1" =~ ^-- ]]; then
                    COMMAND="$1"
                else
                    COMMAND_ARGS+=("$1")
                fi
                shift
                ;;
        esac
    done
}

main() {
    parse_arguments "$@"

    case "$COMMAND" in
        install)
            check_root
            acquire_lock
            install_blocking
            ;;
        uninstall)
            check_root
            acquire_lock
            uninstall_blocking
            ;;
        update)
            check_root
            acquire_lock
            update_blocking
            ;;
        status)
            show_status
            bypass_status
            ;;
        bypass-init)
            bypass_init
            ;;
        bypass-status)
            bypass_status
            ;;
        proxy-run)
            proxy_run
            ;;
        help|--help|-h)
            show_usage
            ;;
        "")
            print_error "No command specified"
            echo ""
            show_usage
            exit 1
            ;;
        *)
            print_error "Unknown command: $COMMAND"
            echo ""
            show_usage
            exit 1
            ;;
    esac
}

main "$@"
