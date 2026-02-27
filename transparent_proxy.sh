#!/bin/bash

################################################################################
# transparent_proxy.sh - Auto-routing transparent SOCKS5 bypass
# Part of: https://github.com/pursork/gcp-aligado
#
# Architecture:
#   App → TCP to CDN IP
#       → iptables nat OUTPUT REDIRECT → redsocks:12345
#       → redsocks → SOCKS5 proxy (non-CDN IP, not blocked)
#       → SOCKS5 proxy → CDN IP  (done on remote, bypasses local DROP rules)
#
# The CDN DROP rules in the filter table are NOT modified.
# nat REDIRECT happens before filter DROP, so whitelisted traffic
# is transparently tunnelled without touching the block rules.
#
# Commands:
#   install      Install and start transparent proxy
#   uninstall    Remove all rules, ipset, redsocks config, cron
#   status       Show current status (no root required for display)
#   resolve-now  Resolve whitelist domains → update ipset (run by cron)
#   help         Show this help
#
# Config files (shared with cdn_ip_ban.sh):
#   /etc/cdn_bypass_proxy.conf   SOCKS5_PROXY URL
#   /etc/cdn_bypass_white.list   Whitelist domains / IPs
################################################################################

set -euo pipefail

readonly TP_SCRIPT_NAME="$(basename "$0")"
readonly BYPASS_LIST_FILE="/etc/cdn_bypass_white.list"
readonly BYPASS_PROXY_CONF="/etc/cdn_bypass_proxy.conf"
readonly REDSOCKS_CONF="/etc/redsocks.conf"
readonly REDSOCKS_LOG="/var/log/redsocks.log"
readonly TP_IPSET="cdn_bypass_tp"
readonly TP_CHAIN="CDN_BYPASS_TP"
readonly TP_PORT=12345
readonly TP_CRON_FILE="/etc/cron.d/cdn-ip-ban-tproxy"
readonly TP_INSTALLED_PATH="/usr/local/bin/cdn-ip-ban-tproxy"

readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly BLUE='\033[0;34m'
readonly NC='\033[0m'

SOCKS5_HOST=""
SOCKS5_PORT=""
SOCKS5_USER=""
SOCKS5_PASS=""

tp_info()    { echo -e "${BLUE}[INFO]${NC} $*"; }
tp_success() { echo -e "${GREEN}[SUCCESS]${NC} $*"; }
tp_warning() { echo -e "${YELLOW}[WARNING]${NC} $*"; }
tp_error()   { echo -e "${RED}[ERROR]${NC} $*" >&2; }

check_root() {
    if [[ $EUID -ne 0 ]]; then
        tp_error "This command requires root privileges"
        exit 1
    fi
}

################################################################################
# Config Parsing
################################################################################

parse_socks5_url() {
    local url="$1"
    url="${url#socks5h://}"
    url="${url#socks5://}"

    local auth="" hostport="$url"
    if [[ "$url" == *"@"* ]]; then
        auth="${url%@*}"
        hostport="${url##*@}"
    fi

    SOCKS5_HOST="${hostport%:*}"
    SOCKS5_PORT="${hostport##*:}"

    if [[ -n "$auth" && "$auth" == *":"* ]]; then
        SOCKS5_USER="${auth%%:*}"
        SOCKS5_PASS="${auth#*:}"
    fi
}

load_socks5_config() {
    if [[ ! -f "$BYPASS_PROXY_CONF" ]]; then
        tp_error "Proxy config not found: $BYPASS_PROXY_CONF"
        tp_info "Run: sudo cdn-ip-ban bypass-init"
        exit 1
    fi

    local raw
    raw=$(grep -E '^[[:space:]]*SOCKS5_PROXY=' "$BYPASS_PROXY_CONF" \
        | tail -n 1 | cut -d= -f2- || true)
    # Strip inline comment, then surrounding whitespace and quotes
    raw=$(echo "$raw" | sed -E "s/#.*$//; s/^[[:space:]]*[\"']?//; s/[\"']?[[:space:]]*$//")

    if [[ -z "$raw" ]]; then
        tp_error "SOCKS5_PROXY not configured in $BYPASS_PROXY_CONF"
        exit 1
    fi

    parse_socks5_url "$raw"

    if [[ -z "$SOCKS5_HOST" || -z "$SOCKS5_PORT" ]]; then
        tp_error "Cannot parse SOCKS5 URL: $raw"
        tp_info "Expected: socks5h://[user:pass@]host:port"
        exit 1
    fi
}

################################################################################
# Dependencies
################################################################################

tp_check_deps() {
    local missing=()
    command -v redsocks &>/dev/null || missing+=("redsocks")
    command -v ipset    &>/dev/null || missing+=("ipset")
    command -v iptables &>/dev/null || missing+=("iptables")

    if [[ ${#missing[@]} -gt 0 ]]; then
        tp_info "Installing: ${missing[*]}"
        apt-get update -qq
        apt-get install -y "${missing[@]}"
    fi
}

################################################################################
# redsocks
################################################################################

write_redsocks_conf() {
    local auth_block=""
    if [[ -n "$SOCKS5_USER" ]]; then
        auth_block="    login    = \"${SOCKS5_USER}\";
    password = \"${SOCKS5_PASS}\";"
    fi

    cat > "$REDSOCKS_CONF" << EOF
base {
    log_debug = off;
    log_info  = on;
    log       = "file:${REDSOCKS_LOG}";
    daemon    = on;
    redirector = iptables;
}

redsocks {
    local_ip   = 127.0.0.1;
    local_port = ${TP_PORT};
    ip         = ${SOCKS5_HOST};
    port       = ${SOCKS5_PORT};
    type       = socks5;
${auth_block}
}
EOF
    chmod 640 "$REDSOCKS_CONF"
    tp_info "Wrote redsocks config: $REDSOCKS_CONF"
}

start_redsocks() {
    if systemctl is-active redsocks &>/dev/null; then
        systemctl restart redsocks
        tp_info "Restarted redsocks"
    else
        systemctl enable redsocks 2>/dev/null || true
        systemctl start redsocks
        tp_info "Started redsocks"
    fi
}

stop_redsocks() {
    systemctl stop    redsocks 2>/dev/null || true
    systemctl disable redsocks 2>/dev/null || true
    tp_info "Stopped redsocks"
}

################################################################################
# ipset + Domain Resolution
################################################################################

tp_ensure_ipset() {
    if ! ipset list -n 2>/dev/null | grep -Fxq "$TP_IPSET"; then
        ipset create "$TP_IPSET" hash:ip family inet -exist
        tp_info "Created ipset: $TP_IPSET"
    fi
}

resolve_whitelist_ips() {
    [[ -f "$BYPASS_LIST_FILE" ]] || { tp_warning "Whitelist not found: $BYPASS_LIST_FILE"; return 0; }

    local added=0 line ip

    while IFS= read -r line || [[ -n "$line" ]]; do
        # Strip inline comments and whitespace
        line=$(echo "$line" | sed 's/#.*$//' | tr -d '[:space:]')
        [[ -z "$line" ]] && continue

        # Direct IPv4 address (with optional /prefix) → add directly
        if [[ "$line" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}(/[0-9]+)?$ ]]; then
            ipset add "$TP_IPSET" "$line" -exist 2>/dev/null && added=$((added + 1)) || true
            continue
        fi

        # Domain name → resolve all A records
        if [[ "$line" =~ ^[a-zA-Z0-9._-]+\.[a-zA-Z]{2,}$ ]]; then
            while IFS= read -r ip; do
                [[ -z "$ip" ]] && continue
                # IPv4 only
                [[ "$ip" =~ ^[0-9]{1,3}\.[0-9]{1,3} ]] || continue
                ipset add "$TP_IPSET" "$ip" -exist 2>/dev/null && added=$((added + 1)) || true
            done < <(getent ahosts "$line" 2>/dev/null | awk '{print $1}' | sort -u)
        fi
    done < "$BYPASS_LIST_FILE"

    tp_success "Resolved whitelist: $added IPs added to ipset $TP_IPSET"
}

################################################################################
# iptables nat rules
################################################################################

setup_nat_rules() {
    # Create (or flush) the dedicated chain
    if iptables -t nat -L "$TP_CHAIN" &>/dev/null 2>&1; then
        iptables -t nat -F "$TP_CHAIN"
    else
        iptables -t nat -N "$TP_CHAIN"
    fi

    # Skip loopback
    iptables -t nat -A "$TP_CHAIN" -d 127.0.0.0/8    -j RETURN
    # Skip RFC1918 private networks (avoid proxying LAN traffic)
    iptables -t nat -A "$TP_CHAIN" -d 10.0.0.0/8     -j RETURN
    iptables -t nat -A "$TP_CHAIN" -d 172.16.0.0/12  -j RETURN
    iptables -t nat -A "$TP_CHAIN" -d 192.168.0.0/16 -j RETURN
    # Skip redsocks' own traffic to prevent redirect loops
    if id -u redsocks &>/dev/null 2>&1; then
        iptables -t nat -A "$TP_CHAIN" -m owner --uid-owner redsocks -j RETURN
    fi
    # Skip the SOCKS5 proxy server itself (avoid routing proxy traffic back in)
    if [[ -n "$SOCKS5_HOST" ]]; then
        iptables -t nat -A "$TP_CHAIN" -d "$SOCKS5_HOST" -j RETURN
    fi
    # REDIRECT whitelisted destinations to redsocks
    iptables -t nat -A "$TP_CHAIN" -p tcp \
        -m set --match-set "$TP_IPSET" dst \
        -j REDIRECT --to-port "$TP_PORT"
    # Hook into OUTPUT (outbound traffic from this host)
    if ! iptables -t nat -C OUTPUT -j "$TP_CHAIN" 2>/dev/null; then
        iptables -t nat -I OUTPUT 1 -j "$TP_CHAIN"
    fi

    tp_success "nat chain $TP_CHAIN set up"
}

remove_nat_rules() {
    iptables -t nat -D OUTPUT -j "$TP_CHAIN" 2>/dev/null || true
    iptables -t nat -F "$TP_CHAIN"             2>/dev/null || true
    iptables -t nat -X "$TP_CHAIN"             2>/dev/null || true
    tp_info "Removed nat chain: $TP_CHAIN"
}

################################################################################
# Cron
################################################################################

setup_cron() {
    cat > "$TP_CRON_FILE" << EOF
# cdn-ip-ban transparent proxy: refresh whitelist IPs every 5 minutes
*/5 * * * * root ${TP_INSTALLED_PATH} resolve-now >> /var/log/cdn_ip_ban_tproxy.log 2>&1
EOF
    chmod 644 "$TP_CRON_FILE"
    tp_info "Cron installed: $TP_CRON_FILE (every 5 min)"
}

remove_cron() {
    rm -f "$TP_CRON_FILE"
    tp_info "Removed cron: $TP_CRON_FILE"
}

################################################################################
# Persist rules
################################################################################

save_rules() {
    if command -v netfilter-persistent &>/dev/null; then
        netfilter-persistent save 2>/dev/null || true
    elif command -v iptables-save &>/dev/null; then
        iptables-save > /etc/iptables/rules.v4 2>/dev/null || true
    fi
    if command -v ipset &>/dev/null; then
        ipset save > /etc/iptables/ipset.rules 2>/dev/null || true
    fi
}

################################################################################
# Main commands
################################################################################

tp_install() {
    check_root
    tp_info "Installing transparent SOCKS5 proxy..."
    tp_check_deps
    load_socks5_config
    tp_info "SOCKS5 proxy: ${SOCKS5_HOST}:${SOCKS5_PORT}"

    write_redsocks_conf
    tp_ensure_ipset
    resolve_whitelist_ips
    setup_nat_rules
    start_redsocks
    setup_cron
    save_rules

    tp_success "Transparent proxy installed."
    tp_info "Whitelist IPs refresh every 5 min via cron."
    tp_info "Run 'sudo ${TP_SCRIPT_NAME} resolve-now' to refresh immediately."
}

tp_uninstall() {
    check_root
    tp_info "Removing transparent SOCKS5 proxy..."
    remove_cron
    remove_nat_rules
    stop_redsocks
    ipset destroy "$TP_IPSET" 2>/dev/null || true
    tp_info "Destroyed ipset: $TP_IPSET"
    rm -f "$REDSOCKS_CONF"
    save_rules
    tp_success "Transparent proxy removed."
}

tp_resolve_now() {
    check_root
    tp_ensure_ipset
    resolve_whitelist_ips
}

tp_status() {
    local can_probe=true
    [[ $EUID -ne 0 ]] && can_probe=false

    echo ""
    echo "=========================================="
    echo "  Transparent Proxy Status"
    echo "=========================================="
    echo ""

    if [[ "$can_probe" != true ]]; then
        tp_warning "Some status fields require root (run with sudo for full info)"
        echo ""
    fi

    # redsocks service
    if systemctl is-active redsocks &>/dev/null 2>&1; then
        tp_success "redsocks: running  (local port ${TP_PORT})"
    else
        tp_warning "redsocks: not running"
    fi

    # ipset
    if [[ "$can_probe" = true ]]; then
        if ipset list -n 2>/dev/null | grep -Fxq "$TP_IPSET"; then
            local count
            count=$(ipset list "$TP_IPSET" 2>/dev/null \
                | awk -F': ' '/Number of entries:/ {print $2}')
            tp_success "ipset ${TP_IPSET}: ${count:-?} IPs"
        else
            tp_warning "ipset ${TP_IPSET}: not found (run: sudo ${TP_SCRIPT_NAME} install)"
        fi
    else
        tp_warning "ipset ${TP_IPSET}: unknown (not root)"
    fi

    # nat chain + OUTPUT hook
    if [[ "$can_probe" = true ]]; then
        if iptables -t nat -L "$TP_CHAIN" &>/dev/null 2>&1; then
            tp_success "nat chain ${TP_CHAIN}: exists"
        else
            tp_warning "nat chain ${TP_CHAIN}: not found"
        fi
        if iptables -t nat -C OUTPUT -j "$TP_CHAIN" 2>/dev/null; then
            tp_success "nat OUTPUT → ${TP_CHAIN}: hooked"
        else
            tp_warning "nat OUTPUT → ${TP_CHAIN}: not hooked"
        fi
    fi

    # Cron
    if [[ -f "$TP_CRON_FILE" ]]; then
        tp_success "Cron: $TP_CRON_FILE"
    else
        tp_warning "Cron: not installed"
    fi

    # SOCKS5 proxy address
    if [[ -f "$BYPASS_PROXY_CONF" ]]; then
        load_socks5_config 2>/dev/null || true
        if [[ -n "$SOCKS5_HOST" ]]; then
            echo -e "  ${BLUE}- SOCKS5 proxy:${NC} ${SOCKS5_HOST}:${SOCKS5_PORT}"
        fi
    fi

    echo ""
    echo "=========================================="
}

show_usage() {
    cat << EOF
Usage: ${TP_SCRIPT_NAME} <command>

Commands:
    install      Install redsocks + iptables nat rules + cron (requires root)
    uninstall    Remove all transparent proxy components (requires root)
    resolve-now  Resolve whitelist domains → refresh ipset (requires root, run by cron)
    status       Show current status
    help         Show this help

Config (shared with cdn-ip-ban):
    ${BYPASS_PROXY_CONF}   SOCKS5_PROXY=socks5h://[user:pass@]host:port
    ${BYPASS_LIST_FILE}   domain/IP whitelist

Called automatically by:
    cdn-ip-ban install    (when PROXY_AUTO=true)
    cdn-ip-ban uninstall  (when PROXY_AUTO=true)
EOF
}

################################################################################
# Entry point
################################################################################

case "${1:-help}" in
    install)     tp_install    ;;
    uninstall)   tp_uninstall  ;;
    resolve-now) tp_resolve_now ;;
    status)      tp_status     ;;
    help|--help|-h) show_usage ;;
    *)
        tp_error "Unknown command: $1"
        show_usage
        exit 1
        ;;
esac
