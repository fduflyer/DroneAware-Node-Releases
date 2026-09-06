#!/usr/bin/env bash
# Verify a PMTiles host before node code depends on it.
#
# Every check here corresponds to a failure that is SILENT in the browser:
# a missing CORS header, a 200-instead-of-206, or a mangled content-type all
# produce a blank map with nothing in the UI to say why.
#
#   ./check-tile-host.sh https://tiles.droneaware.io/20260905.pmtiles
usage() { echo "usage: $0 <pmtiles-url> [browser-origin]"; exit 1; }
URL="${1:-}"; [ -n "$URL" ] || usage
ORIGIN="${2:-http://192.168.68.187:5000}"

pass=0; fail=0
ok()   { printf '  \033[32mPASS\033[0m  %s\n' "$1"; pass=$((pass+1)); }
bad()  { printf '  \033[31mFAIL\033[0m  %s\n' "$1"; fail=$((fail+1)); }
note() { printf '        %s\n' "$1"; }

echo "Checking $URL"
echo

H=$(curl -s -D- -o /dev/null --max-time 20 \
      -H "Origin: $ORIGIN" -H "Range: bytes=0-16383" "$URL" 2>/dev/null)
CODE=$(printf '%s' "$H" | awk 'NR==1{print $2}')

# 1. Range support. PMTiles is byte-range addressed; a 200 means the reader
#    receives the whole archive and cannot seek, so nothing renders.
if [ "$CODE" = "206" ]; then
  ok "206 Partial Content on a range request"
elif [ "$CODE" = "404" ]; then
  bad "404 — object not present at this key"
  echo; echo "  $fail failed, $pass passed"; exit 1
else
  bad "expected 206, got ${CODE:-no response}"
fi

printf '%s' "$H" | grep -qi '^accept-ranges: *bytes' \
  && ok "accept-ranges: bytes" || bad "no accept-ranges: bytes"

printf '%s' "$H" | grep -qi '^content-range:' \
  && ok "content-range present ($(printf '%s' "$H" | grep -i '^content-range:' | tr -d '\r' | cut -d' ' -f2-))" \
  || bad "no content-range"

# 2. CORS. Only matters if a browser reads the archive directly, but it is
#    the single easiest thing to forget on an R2 custom domain — the bucket
#    needs an explicit CORS policy, the domain does not add one.
if printf '%s' "$H" | grep -qi '^access-control-allow-origin'; then
  ok "CORS: $(printf '%s' "$H" | grep -i '^access-control-allow-origin' | tr -d '\r')"
else
  bad "no access-control-allow-origin — a browser cannot read this cross-origin"
  note "node-side Python is unaffected; only the in-browser path breaks"
fi

CT=$(printf '%s' "$H" | grep -i '^content-type:' | tr -d '\r' | cut -d' ' -f2-)
case "$CT" in
  *octet-stream*|*pmtiles*) ok "content-type: $CT" ;;
  *) bad "content-type: ${CT:-none} — expected octet-stream or vnd.pmtiles" ;;
esac

# 3. Is it actually a PMTiles archive? Byte 0-6 spell PMTiles, byte 7 is the
#    spec version. Catches an HTML error page served with a 206.
MAGIC=$(curl -s --max-time 20 -H "Range: bytes=0-7" "$URL" 2>/dev/null | head -c 7)
if [ "$MAGIC" = "PMTiles" ]; then
  VER=$(curl -s --max-time 20 -H "Range: bytes=7-7" "$URL" 2>/dev/null | od -An -tu1 | tr -d ' \n')
  ok "valid PMTiles archive, spec version ${VER:-?}"
else
  bad "not a PMTiles archive (first 7 bytes: '${MAGIC}')"
fi

echo
echo "  $pass passed, $fail failed"
[ "$fail" -eq 0 ]
