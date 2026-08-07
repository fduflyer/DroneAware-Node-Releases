#!/bin/bash
# v1.5.0.6 hardware validation harness.
#
# Dev tooling, not shipped as a release asset. Run each stage on the test
# node and paste the output back.
#
#   sudo bash validate-1506.sh a1     # fresh dual install, BEFORE reboot
#   sudo bash validate-1506.sh a2     # after reboot
#   sudo bash validate-1506.sh b      # after unplugging ONE adapter + refresh
#   sudo bash validate-1506.sh c      # after replugging + refresh
#   sudo bash validate-1506.sh d      # ETXTBSY / stop-list check (restarts feeders)
#
# Every check prints PASS or FAIL with what was expected, so a failure
# says which defect regressed rather than just "something is wrong".

set -uo pipefail

CFG=/opt/droneaware/config.env
SYSD=/etc/systemd/system
PASS=0; FAIL=0

ok()   { echo "  PASS  $1"; PASS=$((PASS+1)); }
bad()  { echo "  FAIL  $1"; echo "        expected: $2"; echo "        actual:   $3"; FAIL=$((FAIL+1)); }
note() { echo "  ....  $1"; }

cfg()  { grep -E "^$1=" "$CFG" 2>/dev/null | tail -1 | cut -d= -f2- | tr -d '"'"'"' '; }
act()  { systemctl is-active "$1" 2>/dev/null; }
ena()  { systemctl is-enabled "$1" 2>/dev/null; }

want() { # want <label> <actual> <expected>
    [[ "$2" == "$3" ]] && ok "$1" || bad "$1" "$3" "${2:-<empty>}"
}
want_empty() {
    [[ -z "$2" ]] && ok "$1" || bad "$1" "<empty>" "$2"
}
want_nonempty() {
    [[ -n "$2" ]] && ok "$1" || bad "$1" "<non-empty>" "<empty>"
}

banner() { echo ""; echo "=== $* ==="; }

show_context() {
    banner "context"
    note "version   : $(cat /opt/droneaware/version 2>/dev/null || echo '<none>')"
    note "throttled : $(vcgencmd get_throttled 2>/dev/null || echo '<n/a>')"
    note "adapters  : $(iw dev 2>/dev/null | awk '$1=="Interface"{printf "%s ", $2}')"
    note "2G key    : '$(cfg WIFI_ADAPTER_2G_MAC)'"
    note "5G key    : '$(cfg WIFI_ADAPTER_5G_MAC)'"
    note "single key: '$(cfg WIFI_ADAPTER_MAC)'"
    for u in droneaware-wifi droneaware-wifi-2g droneaware-wifi-5g droneaware-ble; do
        note "$u: active=$(act $u) enabled=$(ena $u)"
    done
}

unit_files_present() {
    banner "unit files on disk"
    for f in droneaware-ble.service droneaware-bt-select.service \
             droneaware-wifi.service droneaware-wifi-2g.service \
             droneaware-wifi-5g.service; do
        [[ -f "$SYSD/$f" ]] && ok "$f present" || bad "$f present" "file exists" "missing"
    done
}

stage_a1() {
    banner "STAGE A1 — fresh dual-adapter install, BEFORE reboot"
    echo "Validates: item 4 (no pre-token service start), item 3 (install completed)"
    unit_files_present

    banner "enrollment ran"
    [[ -s /etc/droneaware/token ]] && ok "token written" || bad "token written" "non-empty /etc/droneaware/token" "missing/empty"

    banner "dual-adapter config"
    want_nonempty "WIFI_ADAPTER_2G_MAC set" "$(cfg WIFI_ADAPTER_2G_MAC)"
    want_nonempty "WIFI_ADAPTER_5G_MAC set" "$(cfg WIFI_ADAPTER_5G_MAC)"

    banner "unit topology: dual enabled, single disabled"
    want "droneaware-wifi-2g enabled" "$(ena droneaware-wifi-2g)" "enabled"
    want "droneaware-wifi-5g enabled" "$(ena droneaware-wifi-5g)" "enabled"
    [[ "$(ena droneaware-wifi)" == "enabled" ]] \
        && bad "droneaware-wifi disabled" "disabled" "enabled" \
        || ok "droneaware-wifi not enabled ($(ena droneaware-wifi))"

    banner "ITEM 4 — feeders must NOT be running yet"
    echo "  (they start on reboot; starting here means a credential-less feeder)"
    want "droneaware-wifi-2g inactive" "$(act droneaware-wifi-2g)" "inactive"
    want "droneaware-wifi-5g inactive" "$(act droneaware-wifi-5g)" "inactive"
}

stage_a2() {
    banner "STAGE A2 — after reboot"
    echo "Validates: both split feeders come up with a token present"
    want "droneaware-wifi-2g active" "$(act droneaware-wifi-2g)" "active"
    want "droneaware-wifi-5g active" "$(act droneaware-wifi-5g)" "active"
    want "droneaware-wifi inactive"  "$(act droneaware-wifi)"    "inactive"
    banner "droneaware status"
    droneaware status 2>&1 | sed 's/^/  /'
}

stage_b() {
    banner "STAGE B — dual -> single (one adapter unplugged + refresh)"
    echo "Validates: item 1. THIS IS THE CASE THAT TOOK A NODE DARK."
    echo "Pre-fix behaviour: band keys stayed set, the split units were"
    echo "started over the single unit, and nothing ended up running."

    banner "band keys must be CLEARED"
    want_empty "WIFI_ADAPTER_2G_MAC cleared" "$(cfg WIFI_ADAPTER_2G_MAC)"
    want_empty "WIFI_ADAPTER_5G_MAC cleared" "$(cfg WIFI_ADAPTER_5G_MAC)"
    want_nonempty "WIFI_ADAPTER_MAC set"     "$(cfg WIFI_ADAPTER_MAC)"

    banner "single-adapter feeder must be RUNNING (not dark)"
    want "droneaware-wifi active"      "$(act droneaware-wifi)"    "active"
    want "droneaware-wifi-2g inactive" "$(act droneaware-wifi-2g)" "inactive"
    want "droneaware-wifi-5g inactive" "$(act droneaware-wifi-5g)" "inactive"

    banner "status shows ONE wifi row"
    droneaware status 2>&1 | sed 's/^/  /'
    local rows
    rows=$(droneaware status 2>/dev/null | grep -c "droneaware-wifi")
    want "one wifi row in status" "$rows" "1"
}

stage_c() {
    banner "STAGE C — single -> dual (adapter replugged + refresh)"
    echo "Validates: the transition is reversible, keys repopulate"
    want_nonempty "WIFI_ADAPTER_2G_MAC repopulated" "$(cfg WIFI_ADAPTER_2G_MAC)"
    want_nonempty "WIFI_ADAPTER_5G_MAC repopulated" "$(cfg WIFI_ADAPTER_5G_MAC)"
    want "droneaware-wifi-2g active" "$(act droneaware-wifi-2g)" "active"
    want "droneaware-wifi-5g active" "$(act droneaware-wifi-5g)" "active"
    want "droneaware-wifi inactive"  "$(act droneaware-wifi)"    "inactive"
}

stage_d() {
    banner "STAGE D — ETXTBSY / stop-list (item 2)"
    echo "Validates: the v1.5.0.6 stop list releases the binary so an"
    echo "update can overwrite it. This STOPS and RESTARTS your feeders."
    echo ""
    systemctl stop droneaware-ble droneaware-wifi \
        droneaware-wifi-2g droneaware-wifi-5g 2>/dev/null || true
    sleep 2
    local holders
    holders=$(fuser /opt/droneaware/wifi_feeder 2>/dev/null | tr -s ' ')
    want_empty "no process holds wifi_feeder" "$holders"

    if cp /opt/droneaware/wifi_feeder /tmp/_wf_check 2>/dev/null \
       && cp /tmp/_wf_check /opt/droneaware/wifi_feeder 2>/dev/null; then
        ok "binary overwrite succeeds (no ETXTBSY)"
    else
        bad "binary overwrite succeeds" "cp succeeds" "cp failed (ETXTBSY?)"
    fi
    rm -f /tmp/_wf_check

    banner "refresh must bring the stopped feeders back"
    echo "  A correctly-configured but stopped feeder is the most common"
    echo "  reason an operator runs refresh. Before v1.5.0.6 nothing in the"
    echo "  restart decision looked at whether the units were RUNNING, so"
    echo "  refresh reported success and left them down."
    droneaware refresh 2>&1 | sed 's/^/  /'
    systemctl start droneaware-ble 2>/dev/null || true
    sleep 5

    local m2 m5
    m2=$(cfg WIFI_ADAPTER_2G_MAC); m5=$(cfg WIFI_ADAPTER_5G_MAC)
    if [[ -n "$m2" && -n "$m5" ]]; then
        want "droneaware-wifi-2g back up" "$(act droneaware-wifi-2g)" "active"
        want "droneaware-wifi-5g back up" "$(act droneaware-wifi-5g)" "active"
    else
        want "droneaware-wifi back up" "$(act droneaware-wifi)" "active"
    fi
    want "droneaware-ble back up" "$(act droneaware-ble)" "active"

    banner "final state"
    droneaware status 2>&1 | sed 's/^/  /'
}

case "${1:-}" in
    a1) show_context; stage_a1 ;;
    a2) show_context; stage_a2 ;;
    b)  show_context; stage_b  ;;
    c)  show_context; stage_c  ;;
    d)  show_context; stage_d  ;;
    *)  echo "usage: sudo bash $0 {a1|a2|b|c|d}"; exit 2 ;;
esac

echo ""
echo "======================================"
echo "  STAGE ${1} RESULT:  PASS=$PASS  FAIL=$FAIL"
echo "======================================"
[[ $FAIL -eq 0 ]]
