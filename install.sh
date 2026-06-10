#!/bin/bash
# DroneAware Feeder Node Installer
# Version: 1.1.3
# Usage:  sudo bash install.sh
#
# Requires: Raspberry Pi OS Bookworm 64-bit, internet connection,
#           USB BT dongle (UD100 or equivalent), USB WiFi adapter (Alfa AWUS036N or equivalent)

set -e

# LOCAL_INSTALL=1 skips GitHub downloads and copies from local dist/ instead.
# Usage: sudo LOCAL_INSTALL=1 bash install.sh
LOCAL_INSTALL="${LOCAL_INSTALL:-0}"
LOCAL_DIST="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/dist"

NM_TOUCHED=0
_rollback_nm() {
    if [[ "${NM_TOUCHED}" == "1" ]]; then
        echo -e "\n  Installer failed — rolling back NetworkManager changes..."
        rm -f /etc/NetworkManager/conf.d/droneaware.conf
        nmcli device set "${WIFI_ADAPTER:-}" managed yes > /dev/null 2>&1 || true
        systemctl reload NetworkManager > /dev/null 2>&1 || true
        echo "  NetworkManager restored. Your WiFi connection should recover."
    fi
}
trap '_rollback_nm' ERR

INSTALLER_VERSION="v1.1.3"
BINARY_VERSION="v1.1.3"  # CI stamps this with the actual release version
GITHUB_REPO="fduflyer/DroneAware-Node-Releases"  # CI stamps this with the building repo
INSTALL_DIR="/opt/droneaware"
CLI_DIR="/usr/local/bin"
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
    echo "║         DroneAware Feeder Node — Installer ${INSTALLER_VERSION}                 ║"
    echo "╚══════════════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"

    cat <<'EOF'
DroneAware Feeder Node Contributor Agreement
Last Updated: May 2026

This Feeder Node Contributor Agreement ("Agreement") governs participation
in the DroneAware Network.

By installing or operating a DroneAware feeder node you agree to these
terms.

1. PARTICIPATION IN THE NETWORK
   Participants may operate hardware devices ("Feeder Nodes") that
   collect and transmit radio signals and telemetry data to DroneAware
   servers. Participation is voluntary. DroneAware may approve or reject
   nodes at its discretion.

2. HARDWARE RESPONSIBILITY
   Participants are responsible for: acquiring hardware, maintaining
   equipment, complying with local laws, and ensuring safe installation.
   DroneAware is not responsible for hardware damage or operating costs.

3. DATA CONTRIBUTION
   Feeder nodes transmit captured ASTM F3411 Remote Identification
   broadcasts to DroneAware servers. This data may include:
   - Remote ID Basic ID, Location/Vector, System, Operator ID, Self ID,
     and Authentication messages
   - Signal strength (RSSI) and capture timestamps
   - Detecting node identifier and radio band (BLE 4 Legacy, BLE 5 Long
     Range, Wi-Fi NAN, Wi-Fi Beacon)

3.1 SCOPE OF DATA COLLECTION
    DroneAware feeder software runs Wi-Fi adapters in monitor mode,
    which is technically capable of capturing many kinds of radio
    traffic. By design, the feeder collects and forwards only ASTM
    F3411 Remote ID broadcasts. Specifically, the feeder will not:
    - Capture, store, or transmit non-Remote-ID Bluetooth advertisements
      (including Apple Continuity, AirDrop, AirTag, fitness trackers, or
      other proximity beacon transmissions)
    - Capture, store, or transmit non-Remote-ID Wi-Fi traffic (including
      probe requests, encrypted client frames, hidden-SSID enumeration,
      or device-fingerprinting metadata)
    - Correlate observed MAC addresses or hardware identifiers with
      personal identities outside of what the Remote ID specification
      itself discloses
    - Build movement profiles, location histories, or behavioral
      analytics from non-Remote-ID radio observations
    These commitments are enforced in the feeder software itself. The
    node release binaries are published in DroneAware's public GitHub
    repository so that operators may independently verify the scope of
    collection.

4. LICENSE TO SUBMITTED DATA
   By operating a feeder node, the participant grants DroneAware, LLC a
   worldwide, royalty-free, perpetual, irrevocable, sublicensable
   license to use, reproduce, modify, distribute, and create derivative
   works from the data transmitted through the feeder node ("Submitted
   Data"), for any purpose consistent with this Agreement and the
   Privacy Policy. The participant retains whatever underlying ownership
   rights they may have in such data; this license does not transfer
   ownership.

   The scope of Submitted Data is limited as described in Section 3.1.

5. DATA USAGE
   DroneAware may use Submitted Data to:
   - Display real-time and historical drone activity on droneaware.io
   - Generate aggregate airspace statistics and analytics
   - Power detection-alert features for node operators and subscribers
   - Improve detection algorithms and platform reliability
   - Provide controlled API access to approved third-party users under
     separate written agreement, subject to this Agreement and the
     Privacy Policy

   Participants acknowledge that DroneAware may generate revenue from
   the Service. Participants are not entitled to compensation unless
   otherwise agreed in writing.

   DroneAware will not sell Node Owner Personal Information for
   advertising, identity resolution, law-enforcement targeting, or
   unrelated third-party profiling purposes. DroneAware is a public
   airspace-awareness and data platform and is not provided as a
   certified, safety-critical, law-enforcement, counter-UAS, or
   operational security system; it should not be used as the sole
   basis for enforcement, interdiction, navigation, or safety-of-life
   decisions.

6. NODE MONITORING
   DroneAware may monitor feeder nodes for uptime, data integrity,
   software version, and network health. DroneAware may collect system
   metrics from nodes.

7. SOFTWARE UPDATES
   Feeder software updates are not pushed automatically. Updates are
   pulled by the operator running 'sudo droneaware update' on the node.
   DroneAware does not have unattended administrative access to
   participant hardware.

   A future version of the installer may offer an opt-in daily
   auto-update mechanism for operators who prefer it. If introduced,
   auto-update will be off by default and require explicit consent at
   install time or via Settings.

8. NODE REVOCATION
   DroneAware may suspend or disable feeder nodes if data appears
   manipulated, the node violates network policies, the node threatens
   network integrity, or legal issues arise. DroneAware may revoke
   participation at any time.

9. NETWORK INTEGRITY
   Participants agree not to: inject false data, modify detection
   outputs, reverse engineer proprietary software, or interfere with
   network operation. Violations may result in permanent removal from
   the network.

10. NO WARRANTY
    Participation is provided "as-is." DroneAware does not guarantee
    network uptime, data access, or availability of dashboards or APIs.

11. LIMITATION OF LIABILITY
    DroneAware shall not be liable for equipment damage, electricity
    costs, network usage charges, or indirect damages arising from
    participation in the feeder network.

12. GOVERNING LAW
    This Agreement is governed by the laws of the State of New Jersey,
    without regard to conflict-of-law principles.

13. CHANGES TO THIS AGREEMENT
    DroneAware is committed to changing this Agreement only through a
    deliberate, transparent process. Material changes to the scope of
    data collection (Section 3 and 3.1), the license grant (Section 4),
    or the data usage (Section 5) will:
    - Be announced publicly at least 30 days before taking effect,
      posted on droneaware.io and sent by email to affected participants
    - Require explicit re-consent from existing participants before
      applying retroactively
    - Be tied to a versioned revision with a public changelog
    - Not apply retroactively to Submitted Data collected under prior
      versions without re-consent

    Tightening commitments (additional restrictions on collection,
    additional protections for participants) may be applied immediately
    without re-consent.

──────────────────────────────────────────────────────────────────────
Full agreement and revision history: https://droneaware.io/legal.html
──────────────────────────────────────────────────────────────────────
EOF
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
    echo "    Example: 40.712800, -74.006000"
    echo ""
    echo -e "  ${BOLD}Note:${NC} Your precise location is never publicly visible. DroneAware"
    echo "  displays only a 2-mile detection ring around your node — your exact"
    echo "  coordinates are kept private."
    echo ""

    while true; do
        read -rp "  Latitude  (e.g. 40.712800): " NODE_LAT </dev/tty
        NODE_LAT="${NODE_LAT// /}"
        if [[ "$NODE_LAT" =~ ^-?[0-9]+(\.[0-9]+)?$ ]] && \
           awk -v v="$NODE_LAT" 'BEGIN{exit !(v>=-90&&v<=90)}'; then
            break
        fi
        warn "Invalid latitude. Must be a number between -90 and 90."
    done

    while true; do
        read -rp "  Longitude (e.g. -74.006000): " NODE_LON </dev/tty
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
    WIFI_ADAPTER_MAC=""

    local active_iface
    active_iface=$(ip route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<=NF;i++) if ($i=="dev") print $(i+1); exit}' || true)

    # Use iw dev to enumerate all wireless interfaces — handles wlx* names
    # as well as wlan* and skips the active backhaul interface.
    while IFS= read -r iface; do
        [[ -z "$iface" ]] && continue
        [[ "$iface" == "$active_iface" ]] && continue
        local subsystem
        subsystem=$(readlink -f "/sys/class/net/${iface}/device/subsystem" 2>/dev/null || true)
        if [[ "$subsystem" == */usb* ]]; then
            WIFI_ADAPTER="$iface"
            WIFI_ADAPTER_MAC=$(cat "/sys/class/net/${iface}/address" 2>/dev/null || true)
            info "Found USB WiFi adapter: $WIFI_ADAPTER ($WIFI_ADAPTER_MAC)"
            break
        fi
    done < <(iw dev 2>/dev/null | awk '$1=="Interface"{print $2}')

    if [[ -z "$WIFI_ADAPTER" ]]; then
        echo ""
        warn "No USB WiFi adapter detected."
        warn "Continuing in BLE-only mode — WiFi detection will be disabled."
        warn "The wifi feeder will start, report FAULT status, and produce no detections."
        warn "To enable WiFi later: connect a USB monitor-mode adapter (e.g. Alfa AWUS036N)"
        warn "and re-run this installer."
        echo ""
        read -rp "  Continue without a WiFi adapter? [y/N]: " WIFI_SKIP </dev/tty
        if [[ ! "${WIFI_SKIP,,}" =~ ^y(es)?$ ]]; then
            fatal "Installation cancelled. Connect a WiFi adapter and re-run."
        fi
        WIFI_ADAPTER=""
        WIFI_ADAPTER_MAC=""
    fi
}

# ---------------------------------------------------------------------------
# 4. Persist any netplan-backed WiFi profiles to disk before touching NM
# ---------------------------------------------------------------------------
persist_wifi_profiles() {
    if [[ -z "$WIFI_ADAPTER" ]]; then
        info "Skipping WiFi profile persistence — no WiFi adapter present."
        return
    fi
    heading "Securing WiFi Profiles"
    local count=0

    # Identify the onboard (non-USB) wlan adapter so we can rebind mis-bound profiles.
    # If a profile is active on the ALFA/monitor adapter when we flush it to disk,
    # it snapshots connection.interface-name=wlan1 — then pin_wifi_unmanaged marks
    # wlan1 unmanaged and the profile is permanently locked to an interface NM won't touch.
    local onboard_wlan=""
    for iface_path in /sys/class/net/wlan*/; do
        [[ -d "$iface_path" ]] || continue
        local iface; iface=$(basename "$iface_path")
        [[ "$iface" == "$WIFI_ADAPTER" ]] && continue
        local sub; sub=$(readlink -f "${iface_path}device/subsystem" 2>/dev/null || true)
        if [[ "$sub" != */usb* ]]; then
            onboard_wlan="$iface"
            break
        fi
    done

    while IFS= read -r name; do
        [[ -z "$name" ]] && continue

        # If this profile is bound to the monitor adapter, rebind to onboard wlan first.
        local cur_iface
        cur_iface=$(nmcli -g connection.interface-name con show "$name" 2>/dev/null | tr -d ' ')
        if [[ -n "$cur_iface" && "$cur_iface" == "$WIFI_ADAPTER" && -n "$onboard_wlan" ]]; then
            nmcli con modify "$name" connection.interface-name "$onboard_wlan" 2>/dev/null || true
            info "Rebound $name → $onboard_wlan (was mis-bound to $WIFI_ADAPTER)"
        fi

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
    if [[ -z "$WIFI_ADAPTER" ]]; then
        info "Skipping NetworkManager configuration — no WiFi adapter to manage."
        return
    fi
    heading "Configuring NetworkManager"

    # Safety check: if the USB adapter is currently the active network interface,
    # try to migrate the connection to the onboard wlan first before marking it
    # unmanaged. Only fail hard if there is no onboard interface to fall back to.
    local active_iface onboard_wlan
    active_iface=$(ip route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<=NF;i++) if ($i=="dev") print $(i+1); exit}' || true)
    if [[ -n "$active_iface" && "$active_iface" == "$WIFI_ADAPTER" ]]; then
        warn "${WIFI_ADAPTER} is currently your active network interface — migrating connection to onboard WiFi first..."
        onboard_wlan=""
        for iface_path in /sys/class/net/wlan*/; do
            [[ -d "$iface_path" ]] || continue
            local iface; iface=$(basename "$iface_path")
            [[ "$iface" == "$WIFI_ADAPTER" ]] && continue
            local sub; sub=$(readlink -f "${iface_path}device/subsystem" 2>/dev/null || true)
            if [[ "$sub" != */usb* ]]; then
                onboard_wlan="$iface"
                break
            fi
        done
        if [[ -z "$onboard_wlan" ]]; then
            fatal "No onboard WiFi found to migrate to. Connect via Ethernet or use a dedicated USB adapter for DroneAware monitoring."
        fi
        nmcli device set "$onboard_wlan" managed yes > /dev/null 2>&1 || true
        timeout 15 nmcli device connect "$onboard_wlan" > /dev/null 2>&1 || true
        sleep 5
        local new_active
        new_active=$(ip route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<=NF;i++) if ($i=="dev") print $(i+1); exit}' || true)
        if [[ "$new_active" == "$WIFI_ADAPTER" ]]; then
            fatal "Could not migrate network connection from ${WIFI_ADAPTER} to ${onboard_wlan}. Connect via Ethernet and re-run the installer."
        fi
        info "Network migrated to ${onboard_wlan}."
    fi

    echo ""
    echo -e "  ${YELLOW}⚠  SSH NOTICE${NC}"
    echo "  The next step marks your WiFi adapter as monitor-only in"
    echo "  NetworkManager. In some configurations this may briefly"
    echo "  interrupt your SSH session."
    echo ""
    echo "  If you get disconnected:"
    echo "    1. Wait 15 seconds"
    echo "    2. Reconnect via SSH"
    echo "    3. Re-run the installer — this step will already be done"
    echo "       and you will only need to enter your node name and location."
    echo ""
    read -rp "  Press Enter to continue..." </dev/tty
    echo ""

    mkdir -p /etc/NetworkManager/conf.d
    # Pin by MAC address — more robust than interface name since USB enumeration
    # order can change across reboots, which would bind the wrong interface.
    local unmanaged_entry="interface-name:${WIFI_ADAPTER}"
    if [[ -n "$WIFI_ADAPTER_MAC" ]]; then
        unmanaged_entry="mac:${WIFI_ADAPTER_MAC}"
    fi
    cat > /etc/NetworkManager/conf.d/droneaware.conf <<EOF
# DroneAware — prevent NetworkManager from managing the monitor adapter.
# If NM manages the monitor interface it fights the feeder's monitor mode
# setup, causing zero packet capture and intermittent SSH instability.
[keyfile]
unmanaged-devices=${unmanaged_entry}
EOF
    NM_TOUCHED=1
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

    # Allow feeder to read GPS serial device without root
    usermod -aG dialout "$SUDO_USER" 2>/dev/null || true
    info "System packages ready."
}

# ---------------------------------------------------------------------------
# 7. Download binaries from GitHub Release
# ---------------------------------------------------------------------------
download_binaries() {
    heading "Downloading DroneAware Binaries ($BINARY_VERSION)"
    # Stop any running feeders so binaries aren't locked during download
    systemctl stop droneaware-ble droneaware-wifi 2>/dev/null || true
    mkdir -p "$INSTALL_DIR" "$CLI_DIR"

    if [[ "$LOCAL_INSTALL" == "1" ]]; then
        info "LOCAL_INSTALL mode — copying from ${LOCAL_DIST}"
        for binary in ble_feeder wifi_feeder; do
            cp "${LOCAL_DIST}/${binary}" "${INSTALL_DIR}/${binary}"
            chmod +x "${INSTALL_DIR}/${binary}"
            info "$binary → ${INSTALL_DIR}/${binary}"
        done
        cp "${LOCAL_DIST}/../droneaware" "${CLI_DIR}/droneaware"
        chmod +x "${CLI_DIR}/droneaware"
        info "droneaware → ${CLI_DIR}/droneaware"
    else
        local base_url="https://github.com/${GITHUB_REPO}/releases/download/${BINARY_VERSION}"
        for binary in ble_feeder wifi_feeder; do
            echo "    Downloading $binary..."
            curl -fsSL --retry 3 \
                "${base_url}/${binary}" \
                -o "${INSTALL_DIR}/${binary}"
            chmod +x "${INSTALL_DIR}/${binary}"
            info "$binary → ${INSTALL_DIR}/${binary}"
        done
        echo "    Downloading droneaware CLI..."
        curl -fsSL --retry 3 \
            "${base_url}/droneaware" \
            -o "${CLI_DIR}/droneaware"
        chmod +x "${CLI_DIR}/droneaware"
        info "droneaware → ${CLI_DIR}/droneaware"
    fi

    # Version file — used by droneaware update to track installed version
    echo "${BINARY_VERSION}" > "${INSTALL_DIR}/version"
}

# ---------------------------------------------------------------------------
# 8. Install bt-select script and service files
# ---------------------------------------------------------------------------
install_services() {
    heading "Installing Services"
    # As of v1.2.0, service files ship with the same release as the binaries.
    local base_url="https://github.com/${GITHUB_REPO}/releases/download/${BINARY_VERSION}"
    local local_root
    local_root="$(dirname "${LOCAL_DIST}")"

    # bt-select helper
    if [[ "$LOCAL_INSTALL" == "1" ]]; then
        cp "${local_root}/droneaware-bt-select" "${CLI_DIR}/droneaware-bt-select"
    else
        curl -fsSL --retry 3 \
            "${base_url}/droneaware-bt-select" \
            -o "${CLI_DIR}/droneaware-bt-select"
    fi
    chmod +x "${CLI_DIR}/droneaware-bt-select"
    info "droneaware-bt-select installed."

    # Systemd service files
    for svc in droneaware-bt-select.service droneaware-ble.service droneaware-wifi.service; do
        if [[ "$LOCAL_INSTALL" == "1" ]]; then
            cp "${local_root}/${svc}" "/etc/systemd/system/${svc}"
        else
            curl -fsSL --retry 3 \
                "${base_url}/${svc}" \
                -o "/etc/systemd/system/${svc}"
        fi
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
# ─── Hardware adapters ────────────────────────────────────────────────────
BLE_ADAPTER=${BLE_ADAPTER}
BLE_ADAPTER_MAC=${BLE_ADAPTER_MAC}
WIFI_ADAPTER=${WIFI_ADAPTER}

# ─── Location & GPS ───────────────────────────────────────────────────────
NODE_MOBILE=${NODE_MOBILE}
NODE_LAT=${NODE_LAT:-}
NODE_LON=${NODE_LON:-}
GPS_DEVICE=${GPS_DEVICE:-}
GPS_BAUD=

# ─── Channel hopper ───────────────────────────────────────────────────────
# "true" = adaptive (channel-6 biased, sweep+sticky — recommended).
# "false" = legacy flat hop across channels 1-11.
ADAPTIVE_DWELL=true
# Optional adaptive-hopper tuning (uncomment to override defaults):
# FIXED_CHANNEL=6           # Lock 100% to this channel — overrides adaptive logic
#                           # (useful for DFR monitoring of a known-channel drone)
# ACTIVE_WINDOW_SEC=3       # Sticky-mode reset threshold in seconds (default 3.0)
# DWELL_CH6_MS=800          # Primary channel dwell in sweep mode (default 800ms)
# DWELL_PEEK_MS=50          # Peek dwell on channels 1 and 11 (default 50ms)

# ─── Advanced — do not edit unless directed by DroneAware support ─────────
# NODE_ID and SERVER_URL are set automatically at install and bind this node
# to your DroneAware account. Changing them will break the server connection —
# the node will appear offline and detections will stop flowing. Contact
# support@droneaware.io if you need to migrate or rename a node.
NODE_ID=${NODE_ID}
SERVER_URL=${SERVER_URL}

# BATCH_SIZE and FLUSH_INTERVAL control how often detections are forwarded to
# the server. Increasing them holds events on the node longer, which can delay
# real-time map updates and email alerts — and a crash before the next flush
# will lose buffered detections. Leave at defaults unless directed by support.
BATCH_SIZE=200
FLUSH_INTERVAL=5.0

# Forwarder buffer cap. Bytes-based RAM cap for unsent observations during
# upstream outages. FIFO drop-oldest on overflow preserves recent forensic
# context during sustained spoof floods near offline nodes. 50 MB is safe
# on every supported Pi tier (including Pi Zero 2 W). Log warning fires
# at DRONEAWARE_BUFFER_WARN_PCT (default 75%) and one info-line when the
# buffer drains back below 10% after a reconnect.
DRONEAWARE_BUFFER_MAX_BYTES=50000000
DRONEAWARE_BUFFER_WARN_PCT=75
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
    echo -e "  1. Open ${BOLD}https://droneaware.io/nodes${NC} in your browser"
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
    echo  "║  View it at: https://droneaware.io/nodes                    ║"
    echo  "╠══════════════════════════════════════════════════════════════════════╣"
    echo  "║  Reboot now to start your feeders:  sudo reboot now               ║"
    echo  "║  After reboot, services start automatically on every boot.         ║"
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
detect_wifi_adapter
persist_wifi_profiles
pin_wifi_unmanaged
prompt_node_id
prompt_location
install_packages
download_binaries
install_services
write_config
enroll_node
print_summary
