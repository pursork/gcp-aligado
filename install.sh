#!/usr/bin/env bash

set -euo pipefail

readonly INSTALL_PATH="/usr/local/sbin/cdn_ip_ban.sh"
readonly LINK_PATH="/usr/local/bin/cdn-ip-ban"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" && pwd)"
SOURCE_SCRIPT="$SCRIPT_DIR/cdn_ip_ban.sh"
RAW_BASE_URL=""
EXPECTED_SHA256=""
AUTO_APPLY=true
declare -a APPLY_ARGS=()

print_usage() {
    cat << EOF
Usage: sudo ./install.sh [OPTIONS]

Options:
  --raw-base=URL   Download cdn_ip_ban.sh from URL/cdn_ip_ban.sh when local file is missing
  --script-sha256=HEX
                   Verify downloaded cdn_ip_ban.sh sha256
  --no-apply       Only install command files, do not apply iptables rules immediately
  --help           Show this help message

Any extra options are passed to:
  cdn_ip_ban.sh install [EXTRA_OPTIONS]

Examples:
  sudo ./install.sh --provider=all --ipv6
  sudo ./install.sh --no-apply
  curl -fsSL <INSTALL_SH_URL> | sudo bash -s -- --raw-base=<RAW_BASE_URL>
EOF
}

download_script() {
    local url="$1"
    local dest="$2"
    local temp_file
    temp_file=$(mktemp)

    if command -v curl > /dev/null 2>&1; then
        curl -fsSL --connect-timeout 30 --max-time 120 "$url" -o "$temp_file"
    elif command -v wget > /dev/null 2>&1; then
        wget -q --timeout=120 "$url" -O "$temp_file"
    else
        echo "[ERROR] curl/wget not found; cannot download $url" >&2
        return 1
    fi

    mv -f "$temp_file" "$dest"
}

parse_args() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --raw-base=*)
                RAW_BASE_URL="${1#*=}"
                shift
                ;;
            --script-sha256=*)
                EXPECTED_SHA256="${1#*=}"
                shift
                ;;
            --no-apply)
                AUTO_APPLY=false
                shift
                ;;
            --help|-h)
                print_usage
                exit 0
                ;;
            *)
                APPLY_ARGS+=("$1")
                shift
                ;;
        esac
    done
}

main() {
    if [[ $EUID -ne 0 ]]; then
        echo "[ERROR] install.sh must be run as root" >&2
        exit 1
    fi

    parse_args "$@"

    local staged_path
    staged_path=$(mktemp)

    if [[ -f "$SOURCE_SCRIPT" ]]; then
        cp "$SOURCE_SCRIPT" "$staged_path"
    elif [[ -n "$RAW_BASE_URL" ]]; then
        download_script "${RAW_BASE_URL%/}/cdn_ip_ban.sh" "$staged_path"
        if [[ -z "$EXPECTED_SHA256" ]]; then
            echo "[WARNING] raw download used without --script-sha256 verification" >&2
        fi
    else
        rm -f "$staged_path"
        echo "[ERROR] cdn_ip_ban.sh not found next to install.sh" >&2
        echo "[INFO] use --raw-base=<raw_base_url> to download from GitHub raw" >&2
        exit 1
    fi

    if [[ -n "$EXPECTED_SHA256" ]]; then
        local actual_sha256
        actual_sha256=$(sha256sum "$staged_path" | awk '{print $1}')
        if [[ "$actual_sha256" != "$EXPECTED_SHA256" ]]; then
            rm -f "$staged_path"
            echo "[ERROR] sha256 mismatch for cdn_ip_ban.sh" >&2
            echo "[ERROR] expected: $EXPECTED_SHA256" >&2
            echo "[ERROR] actual:   $actual_sha256" >&2
            exit 1
        fi
    fi

    chmod 755 "$staged_path"

    if [[ -f "$INSTALL_PATH" ]]; then
        local backup_path
        backup_path="${INSTALL_PATH}.bak.$(date +%Y%m%d%H%M%S)"
        cp "$INSTALL_PATH" "$backup_path"
        echo "[INFO] Backup:    $backup_path"
    fi

    mv -f "$staged_path" "$INSTALL_PATH"
    ln -sf "$INSTALL_PATH" "$LINK_PATH"

    echo "[INFO] Installed: $INSTALL_PATH"
    echo "[INFO] Symlink:   $LINK_PATH"

    if [[ "$AUTO_APPLY" = true ]]; then
        "$INSTALL_PATH" install "${APPLY_ARGS[@]}"
        echo "[INFO] CDN blocking installed."
    else
        "$INSTALL_PATH" bypass-init
        echo "[INFO] Install-only mode complete. Run '$LINK_PATH install' when ready."
    fi
}

main "$@"
