#!/usr/bin/env bash
set -euo pipefail

# Nudgebee Forager Installer
# Usage:
#   curl -fsSL https://github.com/nudgebee/forager/releases/latest/download/install.sh \
#     | sudo NB_ACCESS_KEY=xxx NB_ACCESS_SECRET=yyy bash

INSTALL_DIR="/usr/local/bin"
CONFIG_DIR="/etc/nudgebee"
DATA_DIR="/var/lib/nudgebee"
SERVICE_NAME="nudgebee-forager"
BINARY_NAME="nudgebee-forager"
# Default downloads come from GitHub Releases. Mirror users can point
# NB_DOWNLOAD_URL at any host that mirrors the same path layout
# (/download/<tag>/<file> and /latest/download/<file>).
DOWNLOAD_BASE="${NB_DOWNLOAD_URL:-https://github.com/nudgebee/forager/releases}"
VERSION="${NB_VERSION:-latest}"
RELAY_URL="${NB_RELAY_URL:-wss://relay.nudgebee.com/register}"

# Colors for output
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
        err "Usage: curl -fsSL https://github.com/nudgebee/forager/releases/latest/download/install.sh | sudo NB_ACCESS_KEY=xxx NB_ACCESS_SECRET=yyy bash"
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

    case "$OS" in
        linux) ;;
        *)
            err "Unsupported OS: $OS (only linux is supported)"
            exit 1
            ;;
    esac

    case "$ARCH" in
        x86_64|amd64) ARCH="amd64" ;;
        aarch64|arm64) ARCH="arm64" ;;
        *)
            err "Unsupported architecture: $ARCH"
            exit 1
            ;;
    esac

    log "Detected platform: ${OS}/${ARCH}"
}

download_binary() {
    local url
    if [ "$VERSION" = "latest" ]; then
        url="${DOWNLOAD_BASE}/latest/download/${BINARY_NAME}-${OS}-${ARCH}"
    else
        url="${DOWNLOAD_BASE}/download/${VERSION}/${BINARY_NAME}-${OS}-${ARCH}"
    fi
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

create_user() {
    if ! id -u nudgebee &>/dev/null; then
        log "Creating nudgebee user..."
        useradd --system --no-create-home --shell /usr/sbin/nologin nudgebee
    fi
}

create_config() {
    mkdir -p "$CONFIG_DIR"
    mkdir -p "$DATA_DIR"
    chown nudgebee:nudgebee "$DATA_DIR"

    # Only write config if it doesn't exist (don't overwrite on upgrade)
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
        chown nudgebee:nudgebee "${CONFIG_DIR}/forager.yaml"
    else
        warn "Config file already exists at ${CONFIG_DIR}/forager.yaml, skipping (upgrade mode)"
    fi
}

install_systemd_service() {
    log "Installing systemd service..."
    cat > "/etc/systemd/system/${SERVICE_NAME}.service" <<'EOF'
[Unit]
Description=Nudgebee Forager
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=nudgebee
Group=nudgebee
ExecStart=/usr/local/bin/nudgebee-forager --config /etc/nudgebee/forager.yaml
Restart=always
RestartSec=5
LimitNOFILE=65536
StandardOutput=journal
StandardError=journal
WorkingDirectory=/var/lib/nudgebee

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable "${SERVICE_NAME}"
    systemctl restart "${SERVICE_NAME}"
    log "Service ${SERVICE_NAME} enabled and started"
}

print_status() {
    echo ""
    log "Installation complete!"
    echo ""
    echo "  Binary:  ${INSTALL_DIR}/${BINARY_NAME}"
    echo "  Config:  ${CONFIG_DIR}/forager.yaml"
    echo "  Data:    ${DATA_DIR}/"
    echo "  Service: ${SERVICE_NAME}"
    echo ""
    echo "  Check status:  systemctl status ${SERVICE_NAME}"
    echo "  View logs:     journalctl -u ${SERVICE_NAME} -f"
    echo "  Restart:       systemctl restart ${SERVICE_NAME}"
    echo ""

    # Show current status
    if systemctl is-active --quiet "${SERVICE_NAME}"; then
        log "Agent is running"
    else
        warn "Agent is not running. Check logs: journalctl -u ${SERVICE_NAME} -e"
    fi
}

main() {
    log "Nudgebee Forager Installer"
    echo ""

    check_root
    check_required_vars
    detect_platform
    download_binary
    create_user
    create_config
    install_systemd_service
    print_status
}

main "$@"
