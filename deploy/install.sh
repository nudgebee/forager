#!/usr/bin/env bash
set -euo pipefail

# Nudgebee Forager Installer
# Usage:
#   curl -fsSL https://github.com/nudgebee/forager/releases/latest/download/install.sh \
#     | sudo NB_ACCESS_KEY=xxx NB_ACCESS_SECRET=yyy bash
#
# A new install also sets up VM discovery for the local network: it detects
# the primary interface's subnet, generates an SSH key for the agent, fetches
# the inventory content pack and writes a discovery datasource. An upgrade
# (config already present) leaves the config untouched.
#
# Discovery settings (all optional):
#   NB_DISCOVERY=false      skip discovery setup
#   NB_DISCOVERY_CIDR       subnet to discover, a /22 or narrower (default: the
#                           primary interface's subnet, narrowed to the
#                           host's /24 when wider than /22)
#   NB_SSH_USER             login user on the VMs (default: the sudo user,
#                           else ubuntu)
#   NB_DISCOVERY_NAME       datasource name (default: local-network)
#   NB_PACK_URL             content pack to download (default: the example
#                           pack in this repository)
#   NB_SIGNING_PUBLIC_KEY   also turns on ad-hoc SSH access to discovered hosts
#                           (ssh_access); without it only inventory runs
#
# Testing aids, not for production installs:
#   NB_PREFIX=/some/dir     prepend to every install path
#   NB_CONFIG_ONLY=true     only write the config: no root check, binary
#                           download, user or service

PREFIX="${NB_PREFIX:-}"
INSTALL_DIR="${PREFIX}/usr/local/bin"
CONFIG_DIR="${PREFIX}/etc/nudgebee"
DATA_DIR="${PREFIX}/var/lib/nudgebee"
CONFIG_ONLY="${NB_CONFIG_ONLY:-false}"
SERVICE_USER="nudgebee"
SERVICE_NAME="nudgebee-forager"
BINARY_NAME="nudgebee-forager"
# Default downloads come from GitHub Releases. Mirror users can point
# NB_DOWNLOAD_URL at any host that mirrors the same path layout
# (/download/<tag>/<file> and /latest/download/<file>).
DOWNLOAD_BASE="${NB_DOWNLOAD_URL:-https://github.com/nudgebee/forager/releases}"
VERSION="${NB_VERSION:-latest}"
RELAY_URL="${NB_RELAY_URL:-wss://relay.nudgebee.com/register}"

DISCOVERY_ENABLED="${NB_DISCOVERY:-true}"
DISCOVERY_NAME="${NB_DISCOVERY_NAME:-local-network}"
PACK_URL="${NB_PACK_URL:-https://raw.githubusercontent.com/nudgebee/forager/main/docs/content-packs/linux-inventory-example.yaml}"
# A sweep contacts every address in scope. Anything wider than this is more
# likely a misdetected or site-wide network than the local one.
MAX_DISCOVERY_PREFIX=22
DISCOVERY_CIDR=""
DISCOVERY_SSH_USER=""
DISCOVERY_PUBKEY=""

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
    # Double-quoted so ${tmpdir} expands now. Single quotes defer expansion
    # to when the trap fires, by which point this function has returned and
    # its local is out of scope — the trap would run `rm -rf ""` and leave
    # the directory behind on every successful install.
    trap "rm -rf \"${tmpdir}\"" EXIT

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
    if ! id -u "$SERVICE_USER" &>/dev/null; then
        log "Creating ${SERVICE_USER} user..."
        useradd --system --no-create-home --shell /usr/sbin/nologin "$SERVICE_USER"
    fi
}

# own hands paths to the service user. Skipped when not running as root (an
# NB_CONFIG_ONLY test run) or when the user does not exist.
own() {
    if [ "$(id -u)" -eq 0 ] && id -u "$SERVICE_USER" &>/dev/null; then
        chown "${SERVICE_USER}:${SERVICE_USER}" "$@"
    fi
}

is_new_install() {
    [ ! -f "${CONFIG_DIR}/forager.yaml" ]
}

# --- discovery: network detection (bash 3.2 safe) ---------------------------

# valid_ipv4 accepts dotted-quad IPv4 without leading zeros (bash arithmetic
# would read 08 as octal).
valid_ipv4() {
    local octet='(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])'
    [[ "$1" =~ ^${octet}\.${octet}\.${octet}\.${octet}$ ]]
}

ip_to_int() {
    local a b c d
    IFS=. read -r a b c d <<<"$1"
    echo $(( (a << 24) | (b << 16) | (c << 8) | d ))
}

int_to_ip() {
    local n="$1"
    echo "$(( (n >> 24) & 255 )).$(( (n >> 16) & 255 )).$(( (n >> 8) & 255 )).$(( n & 255 ))"
}

# network_cidr IP PREFIX prints the network containing IP, e.g. 10.0.1.0/24.
network_cidr() {
    local ip_int mask=0
    ip_int=$(ip_to_int "$1")
    if [ "$2" -gt 0 ]; then
        mask=$(( (0xFFFFFFFF << (32 - $2)) & 0xFFFFFFFF ))
    fi
    echo "$(int_to_ip $(( ip_int & mask )))/$2"
}

# validate_cidr checks a user-supplied CIDR and prints it normalized.
validate_cidr() {
    local cidr="$1" ip prefix
    if [[ ! "$cidr" =~ ^([0-9.]+)/([0-9]{1,2})$ ]]; then
        err "NB_DISCOVERY_CIDR=${cidr} is not an IPv4 CIDR (expected something like 10.0.1.0/24)"
        return 1
    fi
    ip="${BASH_REMATCH[1]}"
    prefix="${BASH_REMATCH[2]}"
    if ! valid_ipv4 "$ip" || [ "$prefix" -gt 32 ]; then
        err "NB_DISCOVERY_CIDR=${cidr} is not a valid IPv4 CIDR"
        return 1
    fi
    if [ "$prefix" -lt "$MAX_DISCOVERY_PREFIX" ]; then
        err "NB_DISCOVERY_CIDR=${cidr} is wider than /${MAX_DISCOVERY_PREFIX}. Discovery contacts every address in it; give a /${MAX_DISCOVERY_PREFIX} or narrower range."
        return 1
    fi
    network_cidr "$ip" "$prefix"
}

# detect_primary_ipv4 prints "IP PREFIX" for the interface that holds the
# default route.
detect_primary_ipv4() {
    command -v ip &>/dev/null || return 1
    local dev addr
    dev=$(ip -4 route show default 2>/dev/null | awk '{for (i = 1; i < NF; i++) if ($i == "dev") { print $(i + 1); exit }}')
    [ -n "$dev" ] || return 1
    addr=$(ip -4 -o addr show dev "$dev" scope global 2>/dev/null | awk '{for (i = 1; i < NF; i++) if ($i == "inet") { print $(i + 1); exit }}')
    [[ "$addr" =~ ^([0-9.]+)/([0-9]+)$ ]] || return 1
    echo "${BASH_REMATCH[1]} ${BASH_REMATCH[2]}"
}

resolve_discovery_cidr() {
    if [ -n "${NB_DISCOVERY_CIDR:-}" ]; then
        DISCOVERY_CIDR=$(validate_cidr "$NB_DISCOVERY_CIDR") || exit 1
        return 0
    fi

    local detected ip prefix
    detected=$(detect_primary_ipv4) || detected=""
    if [ -z "$detected" ]; then
        warn "Could not detect the local network; skipping discovery setup. Set NB_DISCOVERY_CIDR to enable it."
        DISCOVERY_ENABLED=false
        return 0
    fi
    read -r ip prefix <<<"$detected"
    if ! valid_ipv4 "$ip"; then
        warn "Detected address ${ip} is not IPv4; skipping discovery setup. Set NB_DISCOVERY_CIDR to enable it."
        DISCOVERY_ENABLED=false
        return 0
    fi
    if [ "$prefix" -gt 30 ]; then
        warn "Local network ${ip}/${prefix} has no other hosts (a VPN or point-to-point link?); skipping discovery setup. Set NB_DISCOVERY_CIDR to enable it."
        DISCOVERY_ENABLED=false
        return 0
    fi
    if [ "$prefix" -lt "$MAX_DISCOVERY_PREFIX" ]; then
        warn "Local network ${ip}/${prefix} is wider than /${MAX_DISCOVERY_PREFIX}; discovering only $(network_cidr "$ip" 24). Set NB_DISCOVERY_CIDR to choose another range."
        prefix=24
    fi
    DISCOVERY_CIDR=$(network_cidr "$ip" "$prefix")
}

# resolve_discovery_inputs validates the discovery settings before anything is
# installed, so a bad value fails the install up front.
resolve_discovery_inputs() {
    if [ "$DISCOVERY_ENABLED" = "false" ] || ! is_new_install; then
        DISCOVERY_ENABLED=false
        return 0
    fi

    local default_user="${SUDO_USER:-}"
    if [ -z "$default_user" ] || [ "$default_user" = "root" ]; then
        default_user="ubuntu"
    fi
    DISCOVERY_SSH_USER="${NB_SSH_USER:-$default_user}"
    if [[ ! "$DISCOVERY_SSH_USER" =~ ^[A-Za-z0-9._][A-Za-z0-9._-]*$ ]]; then
        err "NB_SSH_USER=${DISCOVERY_SSH_USER} is not a valid user name"
        exit 1
    fi
    if [[ ! "$DISCOVERY_NAME" =~ ^[A-Za-z0-9][A-Za-z0-9._-]*$ ]]; then
        err "NB_DISCOVERY_NAME=${DISCOVERY_NAME} may contain only letters, digits, '.', '_' and '-'"
        exit 1
    fi

    resolve_discovery_cidr
}

# --- discovery: files and config ---------------------------------------------

download_pack() {
    local dest="$1" tmp ok=true
    tmp="$(mktemp "${dest}.XXXXXX")" || return 1
    log "Downloading content pack from ${PACK_URL}..."
    if command -v curl &>/dev/null; then
        curl -fsSL -o "$tmp" "$PACK_URL" || ok=false
    elif command -v wget &>/dev/null; then
        wget -q -O "$tmp" "$PACK_URL" || ok=false
    else
        ok=false
    fi
    # The file name promises version 2. An empty file, an error page or a pack
    # declaring another version would only be refused by the agent later.
    if [ "$ok" = true ] && [ -s "$tmp" ] && grep -Eq '^version:[[:space:]]*2[[:space:]]*$' "$tmp"; then
        chmod 644 "$tmp"
        mv "$tmp" "$dest"
        log "Installed content pack to ${dest}"
        return 0
    fi
    rm -f "$tmp"
    warn "Could not get a version 2 content pack from ${PACK_URL}; inventory stays off until one is placed at ${dest}"
    return 1
}

# setup_discovery_files creates the agent's SSH key, the known_hosts file the
# agent learns host keys into, and the content pack. Sets DISCOVERY_PUBKEY
# when a key exists.
setup_discovery_files() {
    local ssh_dir="${CONFIG_DIR}/ssh"
    local key="${ssh_dir}/id_ed25519"
    local packs="${CONFIG_DIR}/packs"

    # The directory is traversable so whoever runs ssh-copy-id can read the
    # public key; the private key's own 0600 mode is what protects it.
    mkdir -p "$ssh_dir"
    chmod 755 "$ssh_dir"
    if [ ! -f "$key" ]; then
        if command -v ssh-keygen &>/dev/null; then
            log "Generating SSH key ${key}..."
            ssh-keygen -q -t ed25519 -N "" -C "nudgebee-forager@$(hostname -s 2>/dev/null || echo host)" -f "$key" \
                || warn "ssh-keygen failed; discovery will find hosts but not log in to them"
        else
            warn "ssh-keygen not found; discovery will find hosts but not log in to them"
        fi
    fi
    if [ -f "$key" ]; then
        chmod 600 "$key"
        chmod 644 "${key}.pub"
        own "$ssh_dir" "$key" "${key}.pub"
        DISCOVERY_PUBKEY="${key}.pub"
    fi

    # The agent appends host keys here on first contact (accept-new), so the
    # service user owns it.
    touch "${CONFIG_DIR}/known_hosts"
    chmod 600 "${CONFIG_DIR}/known_hosts"
    own "${CONFIG_DIR}/known_hosts"

    # Packs stay root-owned: the agent runs pack commands on every host it can
    # log in to, so the agent itself must not be able to change them.
    mkdir -p "$packs"
    chmod 755 "$packs"
    if [ ! -f "${packs}/linux-inventory-v2.yaml" ]; then
        download_pack "${packs}/linux-inventory-v2.yaml" || true
    fi
}

# write_discovery_config appends a discovery datasource to the config, in the
# schema of pkg/config (LocalDatasource / DiscoveryDatasource).
write_discovery_config() {
    local cfg="$1" ssh_access=false
    if [ -n "$DISCOVERY_PUBKEY" ] && [ -n "${NB_SIGNING_PUBLIC_KEY:-}" ]; then
        ssh_access=true
    fi

    {
        echo ""
        echo "datasources:"
        echo "  - type: discovery"
        echo "    name: \"${DISCOVERY_NAME}\""
        echo "    allowed_hosts:"
        echo "      - \"${DISCOVERY_CIDR}\""
        if [ -n "$DISCOVERY_PUBKEY" ]; then
            echo "    credential_source: local"
            echo "    credentials:"
            echo "      username: \"${DISCOVERY_SSH_USER}\""
            echo "      private_key_file: \"${DISCOVERY_PUBKEY%.pub}\""
        fi
        echo "    discovery:"
        echo "      pack_dir: \"${CONFIG_DIR}/packs\""
        echo "      known_hosts_file: \"${CONFIG_DIR}/known_hosts\""
        echo "      host_key_policy: accept-new"
        echo "      ssh_access: ${ssh_access}"
    } >> "$cfg"

    if [ -n "$DISCOVERY_PUBKEY" ] && [ "$ssh_access" = false ]; then
        warn "NB_SIGNING_PUBLIC_KEY is not set: discovered hosts will be inventoried, but ad-hoc SSH access (ssh_access) stays off"
    fi
}

create_config() {
    mkdir -p "$CONFIG_DIR"
    mkdir -p "$DATA_DIR"
    own "$DATA_DIR"

    # Only write config if it doesn't exist (don't overwrite on upgrade)
    if is_new_install; then
        local cfg="${CONFIG_DIR}/forager.yaml"
        log "Writing config to ${cfg}..."
        cat > "$cfg" <<EOF
relay_url: ${RELAY_URL}
access_key: ${NB_ACCESS_KEY}
access_secret: ${NB_ACCESS_SECRET}
data_dir: ${DATA_DIR}
EOF
        if [ -n "${NB_SIGNING_PUBLIC_KEY:-}" ]; then
            echo "signing_public_key: \"${NB_SIGNING_PUBLIC_KEY}\"" >> "$cfg"
        fi
        chmod 600 "$cfg"
        own "$cfg"

        if [ "$DISCOVERY_ENABLED" != "false" ] && [ -n "$DISCOVERY_CIDR" ]; then
            setup_discovery_files
            write_discovery_config "$cfg"
            log "Discovery configured for ${DISCOVERY_CIDR}"
        fi
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

print_discovery_next_steps() {
    [ "$DISCOVERY_ENABLED" != "false" ] && [ -n "$DISCOVERY_CIDR" ] || return 0
    echo ""
    log "VM discovery"
    echo "  Network scanned: ${DISCOVERY_CIDR}"
    if [ -z "$DISCOVERY_PUBKEY" ]; then
        echo "  No SSH key was created, so hosts are found but not inventoried."
        return 0
    fi
    echo "  Agent public key: ${DISCOVERY_PUBKEY}"
    echo ""
    echo "  On each VM to inventory, authorize the key for ${DISCOVERY_SSH_USER}:"
    echo "    ssh-copy-id -f -i ${DISCOVERY_PUBKEY} ${DISCOVERY_SSH_USER}@<vm-ip>"
    echo "  or append this line to ~${DISCOVERY_SSH_USER}/.ssh/authorized_keys on the VM:"
    echo "    $(cat "$DISCOVERY_PUBKEY")"
    echo ""
    echo "  The server sweeps ${DISCOVERY_CIDR} automatically shortly after the agent connects."
    echo "  Host keys are learned on first contact and kept in ${CONFIG_DIR}/known_hosts."
}

main() {
    log "Nudgebee Forager Installer"
    echo ""

    if [ "$CONFIG_ONLY" = "true" ]; then
        check_required_vars
        resolve_discovery_inputs
        create_config
        print_discovery_next_steps
        return 0
    fi

    check_root
    check_required_vars
    detect_platform
    resolve_discovery_inputs
    download_binary
    create_user
    create_config
    install_systemd_service
    print_status
    print_discovery_next_steps
}

main "$@"
