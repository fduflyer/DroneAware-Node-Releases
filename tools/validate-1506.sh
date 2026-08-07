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

# Generic state check for adapter-permutation testing.
#
# Derives the EXPECTED mode from the hardware independently of the CLI's
# own classifier — reimplementing the documented rules against `iw` — so
# that a classifier bug cannot hide from its own test. Run after any
# plug/unplug followed by `sudo droneaware refresh`.
stage_check() {
    banner "STATE CHECK — expectation derived independently from iw"
    python3 - <<'PY'
import glob, os, re, subprocess, sys

IW = "/usr/sbin/iw" if os.path.exists("/usr/sbin/iw") else "iw"
CFG = "/opt/droneaware/config.env"

def read(p):
    try: return open(p).read().strip()
    except OSError: return None

def link(p):
    try: return os.path.basename(os.readlink(p))
    except OSError: return None

def cfg(key):
    try:
        for line in open(CFG):
            if line.startswith(key + "="):
                return line.split("=", 1)[1].strip().strip('"').strip("'")
    except OSError:
        pass
    return ""

def sysd(verb, unit):
    r = subprocess.run(["systemctl", verb, unit], capture_output=True, text=True)
    return r.stdout.strip()

adapters = []
for path in sorted(glob.glob("/sys/class/net/wlan*")):
    a = {"iface": os.path.basename(path),
         "mac": (read(f"{path}/address") or "?").lower(),
         "driver": link(f"{path}/device/driver") or "?",
         "bus": link(f"{path}/device/subsystem") or "?",
         "bands": [], "monitor": False}
    phy = read(f"{path}/phy80211/name")
    if phy:
        try:
            out = subprocess.run([IW, "phy", phy, "info"], capture_output=True,
                                 text=True, timeout=8).stdout
            b = set()
            for line in out.splitlines():
                m = re.search(r"\*\s+(\d{4})\.\d+\s+MHz\s+\[\d+\]", line)
                if m:
                    f = int(m.group(1))
                    if 2400 <= f <= 2500: b.add("2.4")
                    elif 5000 <= f <= 6000: b.add("5")
            a["bands"] = sorted(b)
            a["monitor"] = bool(re.search(r"^\s*\*\s+monitor$", out, re.M))
        except Exception:
            pass
    a["onboard"] = a["driver"] == "brcmfmac" or a["bus"] in ("sdio", "mmc")
    adapters.append(a)

print("  Adapters seen:")
for a in adapters:
    kind = "ONBOARD (never monitor)" if a["onboard"] else (
        "usb-monitor" if a["bus"] == "usb" and a["monitor"] else "usb (no monitor)")
    print(f"    {a['iface']:<7} {a['mac']}  bands={','.join(a['bands']) or '?':<8} {kind}")

monitor = sorted([a for a in adapters if not a["onboard"]
                  and a["bus"] == "usb" and a["monitor"]], key=lambda a: a["mac"])

r24 = r5 = None
if len(monitor) == 1:
    only = monitor[0]
    if "2.4" in only["bands"]: r24 = only
    if "5" in only["bands"]:   r5 = only
elif len(monitor) >= 2:
    fiveg = [a for a in monitor if "5" in a["bands"]]
    twofour_only = [a for a in monitor if "2.4" in a["bands"] and "5" not in a["bands"]]
    if fiveg and twofour_only:
        r5, r24 = fiveg[0], twofour_only[0]
    elif fiveg:
        r5 = fiveg[0]
        r24 = next((a for a in monitor if a is not r5 and "2.4" in a["bands"]), None)
    else:
        r24 = next((a for a in monitor if "2.4" in a["bands"]), None)

dual = len(monitor) >= 2 and r24 and r5
mode = "dual" if dual else ("single" if monitor else "none")
print(f"\n  Monitor-capable USB adapters: {len(monitor)}   -> EXPECTED MODE: {mode}")
if dual:
    print(f"    expect 2G role = {r24['mac']} ({r24['iface']}, bands={','.join(r24['bands'])})")
    print(f"    expect 5G role = {r5['mac']} ({r5['iface']}, bands={','.join(r5['bands'])})")
elif monitor:
    single = r24 or r5
    print(f"    expect single  = {single['mac']} ({single['iface']}, bands={','.join(single['bands'])})")
    if single["bands"] == ["2.4"]:
        print("    expect dashboard: 2.4 GHz lock / 5 GHz ABSENT")
    elif "2.4" in single["bands"] and "5" in single["bands"]:
        print("    expect dashboard: 2.4 GHz dwell / 5 GHz dwell")
if dual:
    print("    expect dashboard: 2.4 GHz lock / 5 GHz lock")

if len(monitor) >= 2 and not dual:
    print("\n  NOTE: 2+ monitor adapters but roles did not both resolve"
          " (e.g. no 5 GHz-capable card) -> falls back to SINGLE, second"
          " adapter idle. Known gap, not a v1.5.0.6 regression.")

P = F = 0
def ck(label, got, want):
    global P, F
    if got == want:
        print(f"  PASS  {label}"); P += 1
    else:
        print(f"  FAIL  {label}\n        expected: {want!r}\n        actual:   {got!r}"); F += 1

print()
if mode == "none":
    print("  (no monitor-capable adapters — orchestration leaves state unchanged)")
elif dual:
    ck("WIFI_ADAPTER_2G_MAC matches 2G role", cfg("WIFI_ADAPTER_2G_MAC"), r24["mac"])
    ck("WIFI_ADAPTER_5G_MAC matches 5G role", cfg("WIFI_ADAPTER_5G_MAC"), r5["mac"])
    ck("droneaware-wifi-2g enabled", sysd("is-enabled", "droneaware-wifi-2g"), "enabled")
    ck("droneaware-wifi-5g enabled", sysd("is-enabled", "droneaware-wifi-5g"), "enabled")
    ck("droneaware-wifi disabled",   sysd("is-enabled", "droneaware-wifi"),    "disabled")
    ck("droneaware-wifi-2g active",  sysd("is-active",  "droneaware-wifi-2g"), "active")
    ck("droneaware-wifi-5g active",  sysd("is-active",  "droneaware-wifi-5g"), "active")
    ck("droneaware-wifi inactive",   sysd("is-active",  "droneaware-wifi"),    "inactive")
else:
    single = r24 or r5
    ck("WIFI_ADAPTER_2G_MAC cleared", cfg("WIFI_ADAPTER_2G_MAC"), "")
    ck("WIFI_ADAPTER_5G_MAC cleared", cfg("WIFI_ADAPTER_5G_MAC"), "")
    ck("WIFI_ADAPTER_MAC matches adapter", cfg("WIFI_ADAPTER_MAC"), single["mac"])
    ck("droneaware-wifi enabled",     sysd("is-enabled", "droneaware-wifi"),    "enabled")
    ck("droneaware-wifi-2g disabled", sysd("is-enabled", "droneaware-wifi-2g"), "disabled")
    ck("droneaware-wifi-5g disabled", sysd("is-enabled", "droneaware-wifi-5g"), "disabled")
    ck("droneaware-wifi active",      sysd("is-active",  "droneaware-wifi"),    "active")
    ck("droneaware-wifi-2g inactive", sysd("is-active",  "droneaware-wifi-2g"), "inactive")
    ck("droneaware-wifi-5g inactive", sysd("is-active",  "droneaware-wifi-5g"), "inactive")

# --- Bluetooth / UD100 -------------------------------------------------
print("\n  Bluetooth:")
hci = subprocess.run(["hciconfig"], capture_output=True, text=True).stdout
for line in hci.splitlines():
    if line.startswith("hci") or "BD Address" in line:
        print("    " + line.strip())
print(f"    config BLE_ADAPTER     = {cfg('BLE_ADAPTER')!r}")
print(f"    config BLE_ADAPTER_MAC = {cfg('BLE_ADAPTER_MAC')!r}")
ck("droneaware-ble active", sysd("is-active", "droneaware-ble"), "active")
print("\n  NOTE: `refresh` does NOT re-run droneaware-bt-select, so plugging"
      "\n  or removing a BT dongle needs a reboot (or: systemctl restart"
      "\n  droneaware-bt-select && systemctl restart droneaware-ble).")

print(f"\n  checks: PASS={P} FAIL={F}")
sys.exit(1 if F else 0)
PY
    local rc=$?
    if [[ $rc -eq 0 ]]; then ok "state matches hardware"; else bad "state matches hardware" "all checks pass" "see FAILs above"; fi
}

case "${1:-}" in
    check) show_context; stage_check ;;
    a1) show_context; stage_a1 ;;
    a2) show_context; stage_a2 ;;
    b)  show_context; stage_b  ;;
    c)  show_context; stage_c  ;;
    d)  show_context; stage_d  ;;
    *)  echo "usage: sudo bash $0 {check|a1|a2|b|c|d}"
        echo "  check   verify state against hardware (use after any plug/unplug + refresh)"
        echo "  a1..d   install-flow stages"
        exit 2 ;;
esac

echo ""
echo "======================================"
echo "  STAGE ${1} RESULT:  PASS=$PASS  FAIL=$FAIL"
echo "======================================"
[[ $FAIL -eq 0 ]]
