#!/bin/bash
# DroneAware Feeder Node Installer
# Version: 1.0.13
# Usage:  sudo bash install.sh
#
# Requires: Raspberry Pi OS Bookworm 64-bit, internet connection,
#           USB BT dongle (UD100 or equivalent), USB WiFi adapter (Alfa AWUS036N or equivalent)

set -e

INSTALLER_VERSION="v1.0.13"
BINARY_VERSION="v1.0.12"  # last release containing updated binaries
SERVICE_VERSION="v1.0.6"  # last release containing service files and bt-select script
GITHUB_REPO="fduflyer/DroneAware-Node-Releases"
INSTALL_DIR="/opt/droneaware"
BIN_DIR="/usr/local/bin"
SERVER_URL="https://api.droneaware.io/api"

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BOLD='\033[1m'; NC='\033[0m'
info()    { echo -e "  ${GREEN}✓${NC}  $*"; }
warn()    { echo -e "  ${YELLOW}!${NC}  $*"; }
fatal()   { echo -e "\n  ${RED}✗  ERROR: $*${NC}\n"; exit 1; }
heading() { echo -e "\n${BOLD}$*${NC}"; }

require_root() {
    [[ $EUID -eq 0 ]] || fatal "This installer must be run as root: sudo bash install.sh"
}

# ---------------------------------------------------------------------------
# 1. Terms and Conditions
# ---------------------------------------------------------------------------
show_terms() {
    clear
    echo -e "${BOLD}"
    echo "╔══════════════════════════════════════════════════════════════════════╗"
    echo "║            DroneAware Feeder Node — Installer v1.0.13              ║"
    echo "╚══════════════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"

    echo -e "${BOLD}ACCEPTANCE UPON NODE REGISTRATION${NC}"
    echo ""
    echo "  BINDING ACCEPTANCE"
    echo "  You are entering into and agreeing to be legally bound by the"
    echo "  DroneAware Feeder Node Contributor Agreement at the time you claim"
    echo "  or activate a Node."
    echo ""
    echo "  CONDITION OF PARTICIPATION"
    echo "  Acceptance of this Agreement is a mandatory condition of registering"
    echo "  or operating any Node on the DroneAware network. You may not transmit"
    echo "  data to DroneAware systems without accepting this Agreement."
    echo ""
    echo "  DATA OWNERSHIP ASSIGNMENT"
    echo "  As a condition of Node registration and operation, you agree that all"
    echo "  data transmitted from your Node is subject to the Data Ownership"
    echo "  Assignment provisions of this Agreement, including the irrevocable"
    echo "  assignment of all rights, title, and interest to DroneAware, LLC."
    echo ""
    echo "  AFFIRMATIVE ACTION REQUIRED"
    echo "  Acceptance requires an affirmative action during Node registration."
    echo ""
    echo "  RECORD OF ACCEPTANCE"
    echo "  DroneAware may record and retain evidence of your acceptance,"
    echo "  including: timestamp, IP address, account identity, and agreement"
    echo "  version. Such records shall constitute proof of your agreement."
    echo ""
    echo "  NO OPERATION WITHOUT ACCEPTANCE"
    echo "  If you do not accept this Agreement, you are not authorized to"
    echo "  register a Node, connect a Node to the network, or transmit any"
    echo "  data to DroneAware."
    echo ""
    echo "──────────────────────────────────────────────────────────────────────"
    echo ""
}

accept_terms() {
    show_terms
    while true; do
        read -rp "  Do you accept these terms and conditions? [yes/no]: " answer </dev/tty
        case "${answer,,}" in
            yes)
                info "Terms accepted."
                echo ""
                break
                ;;
            no)
                echo ""
                echo "  Installation cancelled. You must accept the terms to use DroneAware."
                echo ""
                exit 0
                ;;
            *)
                warn "Please type 'yes' to accept or 'no' to decline."
                ;;
        esac
    done
}

# ---------------------------------------------------------------------------
# 2. Collect node nickname
# ---------------------------------------------------------------------------
prompt_node_id() {
    heading "Node Setup"
    echo ""
    echo "  Choose a short nickname for this node (letters, numbers, hyphens)."
    echo "  This will identify your node on the DroneAware network."
    echo "  Examples: my-garage, rooftop-east, backyard-01"
    echo ""
    while true; do
        read -rp "  Node nickname: " NODE_ID </dev/tty
        NODE_ID="${NODE_ID// /-}"
        NODE_ID="${NODE_ID,,}"
        if [[ -z "$NODE_ID" ]]; then
            warn "Nickname cannot be empty."
        elif [[ ! "$NODE_ID" =~ ^[a-z0-9][a-z0-9-]{1,30}[a-z0-9]$ ]]; then
            warn "Use 3–32 lowercase letters, numbers, or hyphens. Cannot start/end with a hyphen."
        else
            info "Node ID: $NODE_ID"
            break
        fi
    done
}

# ---------------------------------------------------------------------------
# 3. Node location — mobile vs. static
# ---------------------------------------------------------------------------
prompt_location() {
    heading "Node Location"
    echo ""
    echo "  Is this node fixed in one place, or will it move around"
    echo "  (e.g. mounted in a vehicle or carried on a drone)"
    echo ""

    while true; do
        read -rp "  Node type — [S]tatic or [M]obile: " loc_type </dev/tty
        case "${loc_type,,}" in
            s|static)
                NODE_MOBILE=false
                _prompt_coordinates
                break
                ;;
            m|mobile)
                NODE_MOBILE=true
                _detect_gps
                break
                ;;
            *)
                warn "Please enter S for Static or M for Mobile."
                ;;
        esac
    done
}

_prompt_coordinates() {
    echo ""
    echo "  Enter the GPS coordinates of this node's fixed location."
    echo ""
    echo "  How to find your coordinates:"
    echo "    1. Open https://maps.google.com in your browser"
    echo "    2. Navigate to the exact spot where this node is installed"
    echo "    3. Right-click on that spot"
    echo "    4. The coordinates appear at the top of the menu — click them to copy"
    echo ""
    echo "    Example: 40.457568, -74.339130"
    echo ""
    echo -e "  ${BOLD}Note:${NC} Your precise location is never publicly visible. DroneAware"
    echo "  displays only a 2-mile detection ring around your node — your exact"
    echo "  coordinates are kept private."
    echo ""

    while true; do
        read -rp "  Latitude  (e.g. 40.457568): " NODE_LAT </dev/tty
        NODE_LAT="${NODE_LAT// /}"
        if [[ "$NODE_LAT" =~ ^-?[0-9]+(\.[0-9]+)?$ ]] && \
           awk -v v="$NODE_LAT" 'BEGIN{exit !(v>=-90&&v<=90)}'; then
            break
        fi
        warn "Invalid latitude. Must be a number between -90 and 90."
    done

    while true; do
        read -rp "  Longitude (e.g. -74.339130): " NODE_LON </dev/tty
        NODE_LON="${NODE_LON// /}"
        if [[ "$NODE_LON" =~ ^-?[0-9]+(\.[0-9]+)?$ ]] && \
           awk -v v="$NODE_LON" 'BEGIN{exit !(v>=-180&&v<=180)}'; then
            break
        fi
        warn "Invalid longitude. Must be a number between -180 and 180."
    done

    info "Location set: $NODE_LAT, $NODE_LON"
    GPS_DEVICE=""
}

_detect_gps() {
    heading "Detecting USB GPS"
    GPS_DEVICE=""
    NODE_LAT=""
    NODE_LON=""

    for dev in /dev/ttyUSB* /dev/ttyACM*; do
        [[ -e "$dev" ]] || continue
        GPS_DEVICE="$dev"
        info "USB GPS device detected: $GPS_DEVICE"
        break
    done

    if [[ -z "$GPS_DEVICE" ]]; then
        warn "No USB GPS device detected."
        warn "Connect a USB GPS module (e.g. u-blox 7/8) before starting the feeder."
        warn "The node will operate without GPS — detections will have no location data."
    fi
}

# ---------------------------------------------------------------------------
# 4. Detect external USB WiFi adapter
# ---------------------------------------------------------------------------
detect_wifi_adapter() {
    heading "Detecting WiFi Adapter"
    WIFI_ADAPTER=""

    for iface_path in /sys/class/net/wlan*/; do
        [[ -d "$iface_path" ]] || continue
        iface=$(basename "$iface_path")
        subsystem=$(readlink -f "${iface_path}device/subsystem" 2>/dev/null || true)
        if [[ "$subsystem" == */usb* ]]; then
            WIFI_ADAPTER="$iface"
            info "Found USB WiFi adapter: $WIFI_ADAPTER"
            break
        fi
    done

    if [[ -z "$WIFI_ADAPTER" ]]; then
        warn "No USB WiFi adapter detected."
        warn "Connect your Alfa AWUS036N (or compatible adapter) and re-run this installer."
        fatal "USB WiFi adapter required."
    fi
}

# ---------------------------------------------------------------------------
# 4. Persist any netplan-backed WiFi profiles to disk before touching NM
# ---------------------------------------------------------------------------
persist_wifi_profiles() {
    heading "Securing WiFi Profiles"
    local count=0

    while IFS= read -r name; do
        [[ -z "$name" ]] && continue
        # Check if this profile is backed by a real system-connections file
        local fname
        fname=$(nmcli -f FILENAME con show "$name" 2>/dev/null | awk 'NR==2{print $1}')
        if [[ "$fname" != /etc/NetworkManager/system-connections/* ]]; then
            # Force NM to write the profile to disk by doing a no-op modify
            nmcli con modify "$name" connection.autoconnect yes 2>/dev/null || true
            count=$((count + 1))
            info "Persisted: $name"
        fi
    done < <(nmcli -t -f NAME,TYPE con show 2>/dev/null | grep "802-11-wireless" | cut -d: -f1)

    if [[ $count -gt 0 ]]; then
        info "$count WiFi profile(s) secured to /etc/NetworkManager/system-connections/"
    else
        info "All WiFi profiles already backed by persistent files."
    fi
}

# ---------------------------------------------------------------------------
# 5. Pin WiFi monitor adapter as unmanaged in NetworkManager
# ---------------------------------------------------------------------------
pin_wifi_unmanaged() {
    heading "Configuring NetworkManager"
    mkdir -p /etc/NetworkManager/conf.d
    cat > /etc/NetworkManager/conf.d/droneaware.conf <<EOF
# DroneAware — prevent NetworkManager from managing the monitor adapter.
# If NM manages the monitor interface it fights the feeder's monitor mode
# setup, causing zero packet capture and intermittent SSH instability.
[keyfile]
unmanaged-devices=interface-name:${WIFI_ADAPTER}
EOF
    # Apply immediately without restarting NM (restart drops SSH)
    nmcli device set "${WIFI_ADAPTER}" managed no > /dev/null 2>&1 || true
    info "${WIFI_ADAPTER} set as unmanaged (monitor-only) in NetworkManager."
}

# ---------------------------------------------------------------------------
# 6. System packages
# ---------------------------------------------------------------------------
install_packages() {
    heading "Installing System Packages"
    apt-get update -qq
    apt-get install -y --no-install-recommends \
        bluez bluetooth iw rfkill curl \
        > /dev/null 2>&1
    systemctl enable bluetooth > /dev/null 2>&1
    systemctl start bluetooth  > /dev/null 2>&1

    # Disable boot-delay services — reduces boot-to-SSH from ~15s to <5s
    systemctl disable cloud-init cloud-init-local cloud-init-main cloud-init-network > /dev/null 2>&1 || true
    systemctl disable NetworkManager-wait-online.service > /dev/null 2>&1 || true
    info "Boot optimisations applied."

    info "System packages ready."
}

# ---------------------------------------------------------------------------
# 7. Download binaries from GitHub Release
# ---------------------------------------------------------------------------
download_binaries() {
    heading "Downloading DroneAware Binaries ($BINARY_VERSION)"
    local base_url="https://github.com/${GITHUB_REPO}/releases/download/${BINARY_VERSION}"
    mkdir -p "$BIN_DIR"

    for binary in ble_feeder wifi_feeder; do
        echo "    Downloading $binary..."
        curl -fsSL --retry 3 \
            "${base_url}/${binary}" \
            -o "${BIN_DIR}/${binary}"
        chmod +x "${BIN_DIR}/${binary}"
        info "$binary → ${BIN_DIR}/${binary}"
    done
}

# ---------------------------------------------------------------------------
# 8. Install bt-select script and service files
# ---------------------------------------------------------------------------
install_services() {
    heading "Installing Services"
    local base_url="https://github.com/${GITHUB_REPO}/releases/download/${SERVICE_VERSION}"

    # bt-select helper
    curl -fsSL --retry 3 \
        "${base_url}/droneaware-bt-select" \
        -o "${BIN_DIR}/droneaware-bt-select"
    chmod +x "${BIN_DIR}/droneaware-bt-select"
    info "droneaware-bt-select installed."

    # Systemd service files
    for svc in droneaware-bt-select.service droneaware-ble.service droneaware-wifi.service; do
        curl -fsSL --retry 3 \
            "${base_url}/${svc}" \
            -o "/etc/systemd/system/${svc}"
        info "$svc installed."
    done

    systemctl daemon-reload
    systemctl enable droneaware-bt-select droneaware-ble droneaware-wifi > /dev/null 2>&1
    info "Services enabled for autostart."
}

# ---------------------------------------------------------------------------
# 9. Write config.env
# ---------------------------------------------------------------------------
write_config() {
    heading "Writing Configuration"
    mkdir -p "$INSTALL_DIR"
    mkdir -p /etc/droneaware

    # Detect BT adapter MAC — bt-select will refine on first boot
    BLE_ADAPTER="hci0"
    BLE_ADAPTER_MAC=$(hciconfig hci0 2>/dev/null | awk '/BD Address/{print $3}' || true)
    [[ -z "$BLE_ADAPTER_MAC" ]] && BLE_ADAPTER_MAC="00:00:00:00:00:00"

    cat > "${INSTALL_DIR}/config.env" <<EOF
NODE_ID=${NODE_ID}
SERVER_URL=${SERVER_URL}
BLE_ADAPTER=${BLE_ADAPTER}
BLE_ADAPTER_MAC=${BLE_ADAPTER_MAC}
WIFI_ADAPTER=${WIFI_ADAPTER}
NODE_MOBILE=${NODE_MOBILE}
NODE_LAT=${NODE_LAT:-}
NODE_LON=${NODE_LON:-}
GPS_DEVICE=${GPS_DEVICE:-}
BATCH_SIZE=200
FLUSH_INTERVAL=5.0
EOF
    chmod 600 "${INSTALL_DIR}/config.env"
    info "Configuration written to ${INSTALL_DIR}/config.env"
}

# ---------------------------------------------------------------------------
# 10. Enroll node — requires a logged-in DroneAware account
# ---------------------------------------------------------------------------
enroll_node() {
    heading "Node Enrollment"
    echo ""
    echo "  To enroll this node you need a DroneAware account."
    echo ""
    echo -e "  1. Open ${BOLD}https://flight.droneaware.io/nodes${NC} in your browser"
    echo "  2. Log in (or create a free account)"
    echo -e "  3. Click ${BOLD}Add Node${NC}"
    echo "  4. Accept the Contributor Agreement if prompted"
    echo "  5. Copy the enrollment token shown (valid for 15 minutes)"
    echo ""

    local enrollment_token
    while true; do
        read -rp "  Paste enrollment token: " enrollment_token </dev/tty
        enrollment_token="${enrollment_token// /}"
        [[ -n "$enrollment_token" ]] && break
        warn "Enrollment token cannot be empty."
    done

    # Build JSON-safe values for optional numeric/boolean fields
    local lat_json lon_json has_gps_json
    if [[ -n "${NODE_LAT:-}" ]]; then
        lat_json="${NODE_LAT}"
        lon_json="${NODE_LON}"
    else
        lat_json="null"
        lon_json="null"
    fi
    [[ -n "${GPS_DEVICE:-}" ]] && has_gps_json="true" || has_gps_json="false"

    while true; do
        echo ""
        echo "  Contacting DroneAware network..."

        local http_status response
        http_status=$(curl -s --max-time 15 \
            -o /tmp/droneaware_enroll.json \
            -w "%{http_code}" \
            -H "Content-Type: application/json" \
            -d "{\"node_id\":\"${NODE_ID}\",\"enrollment_token\":\"${enrollment_token}\",\"mobile\":${NODE_MOBILE},\"has_gps\":${has_gps_json},\"lat\":${lat_json},\"lon\":${lon_json}}" \
            "${SERVER_URL}/node/enroll" 2>/dev/null) || true
        response=$(cat /tmp/droneaware_enroll.json 2>/dev/null || true)

        if [[ -z "$http_status" || "$http_status" == "000" ]]; then
            rm -f /tmp/droneaware_enroll.json
            fatal "Enrollment request failed. Check your internet connection and try again."
        fi

        if [[ "$http_status" == "409" ]]; then
            warn "That node name is already taken by another account. Please choose a different name."
            echo ""
            while true; do
                read -rp "  New node nickname: " NODE_ID </dev/tty
                NODE_ID="${NODE_ID// /-}"
                NODE_ID="${NODE_ID,,}"
                if [[ -z "$NODE_ID" ]]; then
                    warn "Nickname cannot be empty."
                elif [[ ! "$NODE_ID" =~ ^[a-z0-9][a-z0-9-]{1,30}[a-z0-9]$ ]]; then
                    warn "Use 3–32 lowercase letters, numbers, or hyphens. Cannot start/end with a hyphen."
                else
                    info "Node ID: $NODE_ID"
                    sed -i "s/^NODE_ID=.*/NODE_ID=${NODE_ID}/" "${INSTALL_DIR}/config.env"
                    break
                fi
            done
            continue
        elif [[ "$http_status" == "200" || "$http_status" == "201" ]]; then
            local node_credential
            node_credential=$(echo "$response" | grep -oP '"node_credential"\s*:\s*"\K[^"]+' || true)
            if [[ -z "$node_credential" ]]; then
                rm -f /tmp/droneaware_enroll.json
                fatal "Enrollment failed: server returned success but no credential was found in the response."
            fi
            echo "$node_credential" > /etc/droneaware/token
            chmod 600 /etc/droneaware/token
            rm -f /tmp/droneaware_enroll.json
            info "Node enrolled and credential saved."
            break
        else
            local error_msg
            error_msg=$(echo "$response" | grep -oP '"detail"\s*:\s*"\K[^"]+' || true)
            rm -f /tmp/droneaware_enroll.json
            if [[ -n "$error_msg" ]]; then
                fatal "Enrollment failed: ${error_msg}"
            fi
            fatal "Enrollment failed (HTTP ${http_status}). The token may have expired — generate a new one and try again."
        fi
    done
}

# ---------------------------------------------------------------------------
# 11. Print summary
# ---------------------------------------------------------------------------
print_summary() {
    echo ""
    echo -e "${BOLD}"
    echo "╔══════════════════════════════════════════════════════════════════════╗"
    echo "║                    Installation Complete!                           ║"
    echo "╠══════════════════════════════════════════════════════════════════════╣"
    printf  "║  Node ID : %-57s║\n" "$NODE_ID"
    echo  "╠══════════════════════════════════════════════════════════════════════╣"
    echo  "║  Your node is enrolled and active on the DroneAware network.       ║"
    echo  "║  View it at: https://flight.droneaware.io/nodes                    ║"
    echo  "╠══════════════════════════════════════════════════════════════════════╣"
    echo  "║  Feeders start automatically on next reboot.                       ║"
    echo  "║  To start now:  sudo systemctl start droneaware-ble droneaware-wifi║"
    echo  "║  To view logs:  journalctl -u droneaware-ble -f                    ║"
    echo  "╠══════════════════════════════════════════════════════════════════════╣"
    echo  "║  NOTE: On first boot your Pi may reboot once automatically to      ║"
    echo  "║  configure the Bluetooth adapter. This is normal — wait 30         ║"
    echo  "║  seconds and reconnect if your SSH drops after rebooting.          ║"
    echo  "╚══════════════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
require_root
accept_terms
prompt_node_id
prompt_location
detect_wifi_adapter
persist_wifi_profiles
pin_wifi_unmanaged
install_packages
download_binaries
install_services
write_config
enroll_node
print_summary
