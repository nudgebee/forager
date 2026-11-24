#!/usr/bin/env bash
set -euo pipefail

# Nudgebee Forager Installer for macOS
# Usage:
#   curl -fsSL https://github.com/nudgebee/forager/releases/latest/download/install-macos.sh \
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
#   NB_DISCOVERY_NAME       datasource name (default: <hostname>-<first 6 characters
#                           of NB_ACCESS_KEY>, unique per agent)
#   NB_PACK_URL             content pack to download (default: the release asset linux-inventory-v2.yaml)
#   NB_SIGNING_PUBLIC_KEY   also turns on ad-hoc SSH access to discovered hosts
#                           (ssh_access); without it only inventory runs
#
# Testing aids, not for production installs:
#   NB_PREFIX=/some/dir     prepend to every install path
#   NB_CONFIG_ONLY=true     only write the config: no root check, binary
#                           download or service

PREFIX="${NB_PREFIX:-}"
INSTALL_DIR="${PREFIX}/usr/local/bin"
CONFIG_DIR="${PREFIX}/usr/local/etc/nudgebee"
DATA_DIR="${PREFIX}/usr/local/var/nudgebee"
LOG_DIR="${PREFIX}/usr/local/var/log"
CONFIG_ONLY="${NB_CONFIG_ONLY:-false}"
BINARY_NAME="nudgebee-forager"
PLIST_LABEL="com.nudgebee.forager"
PLIST_PATH="${PREFIX}/Library/LaunchDaemons/${PLIST_LABEL}.plist"
# Default downloads come from GitHub Releases. Mirror users can point
# NB_DOWNLOAD_URL at any host that mirrors the same path layout
# (/download/<tag>/<file> and /latest/download/<file>).
DOWNLOAD_BASE="${NB_DOWNLOAD_URL:-https://github.com/nudgebee/forager/releases}"
VERSION="${NB_VERSION:-latest}"
RELAY_URL="${NB_RELAY_URL:-wss://relay.nudgebee.com/register}"

DISCOVERY_ENABLED="${NB_DISCOVERY:-true}"
# Nudgebee identifies an agent-reported datasource by its type and name within
# the tenant, so two agents using the same name would share one record. The
# default is therefore unique per agent: the host name plus the start of the
# access key (stable across reinstalls with the same key).
default_discovery_name() {
    local host key
    host=$( (scutil --get LocalHostName 2>/dev/null || hostname -s) | tr '[:upper:]' '[:lower:]' | tr -c 'a-z0-9-' '-' | sed -e 's/--*/-/g' -e 's/^-//' -e 's/-$//' | cut -c1-40)
    key=$(printf '%s' "${NB_ACCESS_KEY:-}" | tr '[:upper:]' '[:lower:]' | tr -cd 'a-z0-9' | cut -c1-6)
    printf '%s-%s' "${host:-lan}" "${key:-local}"
}
DISCOVERY_NAME="${NB_DISCOVERY_NAME:-$(default_discovery_name)}"
# The pack ships as a release asset next to the binary, so it comes from the
# same release (and mirror) as the agent rather than a moving branch.
if [ "$VERSION" = "latest" ]; then
    PACK_URL="${NB_PACK_URL:-${DOWNLOAD_BASE}/latest/download/linux-inventory-v2.yaml}"
else
    PACK_URL="${NB_PACK_URL:-${DOWNLOAD_BASE}/download/${VERSION}/linux-inventory-v2.yaml}"
fi
# A sweep contacts every address in scope. Anything wider than this is more
# likely a misdetected or site-wide network than the local one.
MAX_DISCOVERY_PREFIX=22
DISCOVERY_CIDR=""
DISCOVERY_SSH_USER=""
DISCOVERY_PUBKEY=""

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
        err "Usage: curl -fsSL https://github.com/nudgebee/forager/releases/latest/download/install-macos.sh | sudo NB_ACCESS_KEY=xxx NB_ACCESS_SECRET=yyy bash"
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
    local url
    if [ "$VERSION" = "latest" ]; then
        url="${DOWNLOAD_BASE}/latest/download/${BINARY_NAME}-darwin-${ARCH}"
    else
        url="${DOWNLOAD_BASE}/download/${VERSION}/${BINARY_NAME}-darwin-${ARCH}"
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

# mask_to_prefix turns a netmask (255.255.255.0 or 0xffffff00) into a prefix
# length, failing on a non-contiguous mask.
mask_to_prefix() {
    local m="$1" n bits=0
    if [[ "$m" =~ ^0x[0-9a-fA-F]{8}$ ]]; then
        n=$(( m ))
    elif valid_ipv4 "$m"; then
        n=$(ip_to_int "$m")
    else
        return 1
    fi
    while [ $(( n & 0x80000000 )) -ne 0 ]; do
        bits=$(( bits + 1 ))
        n=$(( (n << 1) & 0xFFFFFFFF ))
    done
    [ "$n" -eq 0 ] || return 1
    echo "$bits"
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
    local dev ip mask prefix
    dev=$(route -n get default 2>/dev/null | awk '/interface:/ { print $2; exit }')
    [ -n "$dev" ] || return 1
    ip=$(ipconfig getifaddr "$dev" 2>/dev/null || true)
    mask=$(ipconfig getoption "$dev" subnet_mask 2>/dev/null || true)
    if [ -z "$ip" ] || [ -z "$mask" ]; then
        # Not every interface is managed by ipconfig (VPNs, manual setups).
        read -r ip mask <<<"$(ifconfig "$dev" 2>/dev/null | awk '$1 == "inet" { for (i = 3; i < NF; i++) if ($i == "netmask") { print $2, $(i + 1); exit } }')"
    fi
    [ -n "$ip" ] && [ -n "$mask" ] || return 1
    prefix=$(mask_to_prefix "$mask") || return 1
    echo "$ip $prefix"
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
# when a key exists. The daemon runs as root, so everything stays root-owned;
# only the public key is world-readable.
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
        DISCOVERY_PUBKEY="${key}.pub"
    fi

    # The agent appends host keys here on first contact (accept-new).
    touch "${CONFIG_DIR}/known_hosts"
    chmod 600 "${CONFIG_DIR}/known_hosts"

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
    mkdir -p "$LOG_DIR"

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

        if [ "$DISCOVERY_ENABLED" != "false" ] && [ -n "$DISCOVERY_CIDR" ]; then
            setup_discovery_files
            write_discovery_config "$cfg"
            log "Discovery configured for ${DISCOVERY_CIDR}"
        fi
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
    log "Nudgebee Forager Installer (macOS)"
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
    create_config
    install_launchd_service
    print_status
    print_discovery_next_steps
}

main "$@"
