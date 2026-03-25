#!/usr/bin/env bash
set -euo pipefail

# Nudgebee Forager Installer for macOS
# Usage: curl -fsSL <url>/install-macos.sh | sudo NB_ACCESS_KEY=xxx NB_ACCESS_SECRET=yyy bash

INSTALL_DIR="/usr/local/bin"
CONFIG_DIR="/usr/local/etc/nudgebee"
DATA_DIR="/usr/local/var/nudgebee"
LOG_DIR="/usr/local/var/log"
BINARY_NAME="nudgebee-forager"
PLIST_LABEL="com.nudgebee.forager"
PLIST_PATH="/Library/LaunchDaemons/${PLIST_LABEL}.plist"
DOWNLOAD_BASE="${NB_DOWNLOAD_URL:-https://registry.nudgebee.com/downloads/forager}"
VERSION="${NB_VERSION:-latest}"
RELAY_URL="${NB_RELAY_URL:-wss://relay.nudgebee.com/register}"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log()  { echo -e "${GREEN}[nudgebee]${NC} $*"; }
warn() { echo -e "${YELLOW}[nudgebee]${NC} $*"; }
err()  { echo -e "${RED}[nudgebee]${NC} $*" >&2; }

check_root() {
    if [ "$(id -u)" -ne 0 ]; then
        err "This script must be run as root (use sudo)"
        exit 1
    fi
}

check_required_vars() {
    if [ -z "${NB_ACCESS_KEY:-}" ]; then
        err "NB_ACCESS_KEY is required"
        err "Usage: curl -fsSL <url>/install-macos.sh | sudo NB_ACCESS_KEY=xxx NB_ACCESS_SECRET=yyy bash"
        exit 1
    fi
    if [ -z "${NB_ACCESS_SECRET:-}" ]; then
        err "NB_ACCESS_SECRET is required"
        exit 1
    fi
}

detect_platform() {
    OS=$(uname -s | tr '[:upper:]' '[:lower:]')
    ARCH=$(uname -m)

    if [ "$OS" != "darwin" ]; then
        err "This installer is for macOS only. Use install.sh for Linux."
        exit 1
    fi

    case "$ARCH" in
        x86_64|amd64) ARCH="amd64" ;;
        arm64) ARCH="arm64" ;;
        *)
            err "Unsupported architecture: $ARCH"
            exit 1
            ;;
    esac

    log "Detected platform: ${OS}/${ARCH}"
}

download_binary() {
    local url="${DOWNLOAD_BASE}/${VERSION}/${BINARY_NAME}-darwin-${ARCH}"
    log "Downloading forager from ${url}..."

    if command -v curl &>/dev/null; then
        curl -fsSL -o "/tmp/${BINARY_NAME}" "$url"
    elif command -v wget &>/dev/null; then
        wget -q -O "/tmp/${BINARY_NAME}" "$url"
    else
        err "Neither curl nor wget found. Install one and retry."
        exit 1
    fi

    chmod +x "/tmp/${BINARY_NAME}"
    mv "/tmp/${BINARY_NAME}" "${INSTALL_DIR}/${BINARY_NAME}"
    log "Installed binary to ${INSTALL_DIR}/${BINARY_NAME}"
}

create_config() {
    mkdir -p "$CONFIG_DIR"
    mkdir -p "$DATA_DIR"
    mkdir -p "$LOG_DIR"

    if [ ! -f "${CONFIG_DIR}/forager.yaml" ]; then
        log "Writing config to ${CONFIG_DIR}/forager.yaml..."
        cat > "${CONFIG_DIR}/forager.yaml" <<EOF
relay_url: ${RELAY_URL}
access_key: ${NB_ACCESS_KEY}
access_secret: ${NB_ACCESS_SECRET}
data_dir: ${DATA_DIR}
$([ -n "${NB_SIGNING_PUBLIC_KEY:-}" ] && echo "signing_public_key: \"${NB_SIGNING_PUBLIC_KEY}\"")
EOF
        chmod 600 "${CONFIG_DIR}/forager.yaml"
    else
        warn "Config file already exists at ${CONFIG_DIR}/forager.yaml, skipping (upgrade mode)"
    fi
}

install_launchd_service() {
    log "Installing launchd service..."

    # Unload existing service if present
    if launchctl list | grep -q "$PLIST_LABEL" 2>/dev/null; then
        launchctl unload "$PLIST_PATH" 2>/dev/null || true
    fi

    cat > "$PLIST_PATH" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>${PLIST_LABEL}</string>
    <key>ProgramArguments</key>
    <array>
        <string>${INSTALL_DIR}/${BINARY_NAME}</string>
        <string>--config</string>
        <string>${CONFIG_DIR}/forager.yaml</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>WorkingDirectory</key>
    <string>${DATA_DIR}</string>
    <key>StandardOutPath</key>
    <string>${LOG_DIR}/nudgebee-forager.log</string>
    <key>StandardErrorPath</key>
    <string>${LOG_DIR}/nudgebee-forager.log</string>
</dict>
</plist>
EOF

    launchctl load "$PLIST_PATH"
    log "Service ${PLIST_LABEL} loaded and started"
}

print_status() {
    echo ""
    log "Installation complete!"
    echo ""
    echo "  Binary:  ${INSTALL_DIR}/${BINARY_NAME}"
    echo "  Config:  ${CONFIG_DIR}/forager.yaml"
    echo "  Data:    ${DATA_DIR}/"
    echo "  Logs:    ${LOG_DIR}/nudgebee-forager.log"
    echo "  Service: ${PLIST_LABEL}"
    echo ""
    echo "  Check status:  sudo launchctl list | grep nudgebee"
    echo "  View logs:     tail -f ${LOG_DIR}/nudgebee-forager.log"
    echo "  Stop:          sudo launchctl unload ${PLIST_PATH}"
    echo "  Start:         sudo launchctl load ${PLIST_PATH}"
    echo ""
}

main() {
    log "Nudgebee Forager Installer (macOS)"
    echo ""

    check_root
    check_required_vars
    detect_platform
    download_binary
    create_config
    install_launchd_service
    print_status
}

main "$@"
