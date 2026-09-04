#!/usr/bin/env bash
set -euo pipefail

# Nudgebee Forager Installer
# Usage:
#   curl -fsSL https://github.com/nudgebee/forager/releases/latest/download/install.sh \
#     | sudo NB_ACCESS_KEY=xxx NB_ACCESS_SECRET=yyy bash
#
# Optional discovery setup (non-interactive):
#   NB_DATASOURCES=discovery NB_DISCOVERY_ALLOWED_CIDRS=10.0.0.0/24 \
#   NB_DISCOVERY_SSH_USERNAME=nudgebee-ro \
#   NB_DISCOVERY_SSH_PRIVATE_KEY_FILE=/root/.ssh/id_ed25519 \
#   NB_PACK_PUBLIC_KEY=<base64-ed25519-public-key> bash

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
DATASOURCES="${NB_DATASOURCES:-}"
REPLACE_CONFIG="${NB_REPLACE_CONFIG:-false}"
PACK_PUBLIC_KEY="${NB_PACK_PUBLIC_KEY:-}"
PACK_URL="${NB_PACK_URL:-}"
DISCOVERY_NAME="${NB_DISCOVERY_NAME:-linux-inventory}"
DISCOVERY_SSH_USERNAME="${NB_DISCOVERY_SSH_USERNAME:-nudgebee-ro}"
DISCOVERY_SSH_KEY_FILE="${NB_DISCOVERY_SSH_PRIVATE_KEY_FILE:-}"
DISCOVERY_ALLOWED_CIDRS="${NB_DISCOVERY_ALLOWED_CIDRS:-}"
SSH_NAME="${NB_SSH_NAME:-ssh}"
SSH_ALLOWED_HOSTS="${NB_SSH_ALLOWED_HOSTS:-}"
SSH_USERNAME="${NB_SSH_USERNAME:-}"
SSH_KEY_FILE="${NB_SSH_PRIVATE_KEY_FILE:-}"
PACK_DIR="${CONFIG_DIR}/packs"
TEMP_DIR=""
PACK_TMP_FILE=""

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log()  { echo -e "${GREEN}[nudgebee]${NC} $*"; }
warn() { echo -e "${YELLOW}[nudgebee]${NC} $*"; }
err()  { echo -e "${RED}[nudgebee]${NC} $*" >&2; }

cleanup_temp_files() {
    [ -z "$PACK_TMP_FILE" ] || rm -f "$PACK_TMP_FILE"
    [ -z "$TEMP_DIR" ] || rm -rf "$TEMP_DIR"
}

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

yaml_quote() {
    local value="$1"
    value="${value//\'/\'\'}"
    printf "'%s'" "$value"
}

validate_name() {
    [[ "$1" =~ ^[A-Za-z0-9][A-Za-z0-9_.-]*$ ]] || {
        err "Invalid datasource name '$1' (use letters, numbers, '.', '_' or '-')"
        return 1
    }
}

validate_list() {
    local value="$1" label="$2" item
    local -a items
    [ -n "$value" ] || { err "$label is required"; return 1; }
    IFS=',' read -r -a items <<< "$value"
    for item in "${items[@]}"; do
        item="${item#${item%%[![:space:]]*}}"
        item="${item%${item##*[![:space:]]}}"
        [ -n "$item" ] || { err "$label contains an empty entry"; return 1; }
        [[ "$item" =~ ^[A-Za-z0-9:./_-]+$ ]] || { err "Invalid $label entry '$item'"; return 1; }
    done
}

prompt_discovery() {
    local tty=/dev/tty value
    [ -r "$tty" ] || { err "Interactive setup requires a terminal"; exit 1; }
    read -r -p "Discovery datasource name [linux-inventory]: " value <"$tty"; DISCOVERY_NAME="${value:-linux-inventory}"
    read -r -p "Discovery CIDRs (comma-separated): " DISCOVERY_ALLOWED_CIDRS <"$tty"
    read -r -p "SSH username [nudgebee-ro]: " value <"$tty"; DISCOVERY_SSH_USERNAME="${value:-nudgebee-ro}"
    read -r -p "SSH private key file: " DISCOVERY_SSH_KEY_FILE <"$tty"
    read -r -p "Pack public key (base64): " PACK_PUBLIC_KEY <"$tty"
}

prepare_pack() {
    [ -n "$PACK_PUBLIC_KEY" ] || { err "NB_PACK_PUBLIC_KEY is required for discovery setup"; return 1; }
    mkdir -p "$PACK_DIR"
    local url tmp_pack
    if [ -n "$PACK_URL" ]; then
        url="$PACK_URL"
    elif [ "$VERSION" = "latest" ]; then
        url="${DOWNLOAD_BASE}/latest/download/linux-inventory-v2.yaml"
    else
        url="${DOWNLOAD_BASE}/download/${VERSION}/linux-inventory-v2.yaml"
    fi
    PACK_TMP_FILE="$(mktemp)"
    tmp_pack="$PACK_TMP_FILE"
    if command -v curl &>/dev/null; then curl -fsSL -o "$tmp_pack" "$url"; elif command -v wget &>/dev/null; then wget -q -O "$tmp_pack" "$url"; else err "Neither curl nor wget found"; return 1; fi
    [ -s "$tmp_pack" ] || { rm -f "$tmp_pack"; err "Downloaded inventory pack is empty"; return 1; }
    "$INSTALL_DIR/$BINARY_NAME" pack verify "$tmp_pack" --key "$PACK_PUBLIC_KEY" >/dev/null
    install -o nudgebee -g nudgebee -m 0644 "$tmp_pack" "${PACK_DIR}/linux-inventory-v2.yaml"
}

copy_ssh_key() {
    local source="$1" name="$2" destination="${DATA_DIR}/ssh/${name}_id_ed25519"
    [ -n "$source" ] || { err "SSH private key file is required for datasource '$name'"; return 1; }
    [ -r "$source" ] || { err "SSH private key file is not readable: $source"; return 1; }
    [ -s "$source" ] || { err "SSH private key file is empty: $source"; return 1; }
    install -d -o nudgebee -g nudgebee -m 0700 "${DATA_DIR}/ssh"
    install -o nudgebee -g nudgebee -m 0600 "$source" "$destination"
    printf '%s' "$destination"
}

configure_datasources() {
    [ -n "$DATASOURCES" ] || return 0
    if [ -f "${CONFIG_DIR}/forager.yaml" ] && [ "$REPLACE_CONFIG" != "true" ]; then
        err "${CONFIG_DIR}/forager.yaml already exists; set NB_REPLACE_CONFIG=true to regenerate it"
        exit 1
    fi
    if [ "$DATASOURCES" = "interactive" ]; then
        prompt_discovery
        DATASOURCES=discovery
    fi
    local key_path item
    local -a items
    DATASOURCE_YAML="datasources:\n"
    case ",$DATASOURCES," in
        *,discovery,*)
            validate_name "$DISCOVERY_NAME"
            validate_list "$DISCOVERY_ALLOWED_CIDRS" "NB_DISCOVERY_ALLOWED_CIDRS"
            key_path="$(copy_ssh_key "$DISCOVERY_SSH_KEY_FILE" "$DISCOVERY_NAME")"
            prepare_pack
            DATASOURCE_YAML+="  - type: discovery\n    name: $(yaml_quote "$DISCOVERY_NAME")\n    allowed_hosts:\n"
            IFS=',' read -r -a items <<< "$DISCOVERY_ALLOWED_CIDRS"
            for item in "${items[@]}"; do
                item="${item#${item%%[![:space:]]*}}"; item="${item%${item##*[![:space:]]}}"
                DATASOURCE_YAML+="      - $(yaml_quote "$item")\n"
            done
            DATASOURCE_YAML+="    discovery:\n      pack_public_key: $(yaml_quote "$PACK_PUBLIC_KEY")\n      pack_dir: $(yaml_quote "$PACK_DIR")\n    credential_source: local\n    credentials:\n      username: $(yaml_quote "$DISCOVERY_SSH_USERNAME")\n      private_key_file: $(yaml_quote "$key_path")\n"
            ;;
    esac
    case ",$DATASOURCES," in
        *,ssh,*)
            validate_name "$SSH_NAME"
            validate_list "$SSH_ALLOWED_HOSTS" "NB_SSH_ALLOWED_HOSTS"
            [ -n "$SSH_USERNAME" ] || { err "NB_SSH_USERNAME is required"; exit 1; }
            key_path="$(copy_ssh_key "$SSH_KEY_FILE" "$SSH_NAME")"
            DATASOURCE_YAML+="  - type: ssh\n    name: $(yaml_quote "$SSH_NAME")\n    allowed_hosts:\n"
            IFS=',' read -r -a items <<< "$SSH_ALLOWED_HOSTS"
            for item in "${items[@]}"; do
                item="${item#${item%%[![:space:]]*}}"; item="${item%${item##*[![:space:]]}}"
                DATASOURCE_YAML+="      - $(yaml_quote "$item")\n"
            done
            DATASOURCE_YAML+="    credential_source: local\n    credentials:\n      username: $(yaml_quote "$SSH_USERNAME")\n      private_key_file: $(yaml_quote "$key_path")"
            ;;
        *,discovery,*|*,ssh,*) ;;
        *) err "NB_DATASOURCES supports discovery and ssh"; exit 1 ;;
    esac
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

    # Download into a private directory rather than a fixed /tmp path.
    #
    # Writing to /tmp/<name> fails when a file of that name already exists
    # owned by another user: fs.protected_regular=1 (the default on modern
    # distros) stops even root opening it for writing inside a world-writable
    # sticky directory. curl surfaces that as a bare "error 23" with no
    # indication of the cause, and a leftover file from a previous manual
    # install is enough to trigger it.
    local tmpdir
    tmpdir="$(mktemp -d)" || { err "Could not create a temporary directory"; exit 1; }
    # Keep cleanup in one EXIT trap so both binary and pack downloads are
    # removed on success and on any failure path.
    TEMP_DIR="$tmpdir"
    trap cleanup_temp_files EXIT

    local tmpbin="${tmpdir}/${BINARY_NAME}"

    if command -v curl &>/dev/null; then
        curl -fsSL -o "$tmpbin" "$url"
    elif command -v wget &>/dev/null; then
        wget -q -O "$tmpbin" "$url"
    else
        err "Neither curl nor wget found. Install one and retry."
        exit 1
    fi

    # A truncated or error-page download would otherwise be installed and
    # only fail later, when the service refuses to start.
    if [ ! -s "$tmpbin" ]; then
        err "Downloaded file is empty — check ${url}"
        exit 1
    fi

    chmod +x "$tmpbin"
    mv "$tmpbin" "${INSTALL_DIR}/${BINARY_NAME}"
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
    if [ ! -f "${CONFIG_DIR}/forager.yaml" ] || { [ "$REPLACE_CONFIG" = "true" ] && [ -n "$DATASOURCES" ]; }; then
        log "Writing config to ${CONFIG_DIR}/forager.yaml..."
        cat > "${CONFIG_DIR}/forager.yaml" <<EOF
relay_url: ${RELAY_URL}
access_key: ${NB_ACCESS_KEY}
access_secret: ${NB_ACCESS_SECRET}
data_dir: ${DATA_DIR}
$([ -n "${NB_SIGNING_PUBLIC_KEY:-}" ] && echo "signing_public_key: \"${NB_SIGNING_PUBLIC_KEY}\"")
$(printf '%b\n' "${DATASOURCE_YAML:-}")
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
    configure_datasources
    create_config
    install_systemd_service
    print_status
}

main "$@"
