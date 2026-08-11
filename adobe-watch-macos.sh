#!/bin/bash
# =============================================================================
#  adobe-watch-macos.sh
#
#  macOS counterpart of the Windows monitoring pass: shows exactly which Adobe
#  processes are running and every outbound endpoint they hold open, with the
#  remote host resolved.
#
#  Read-only. It changes nothing - no firewall rules, no hosts file, no plists.
#
#  WHY THERE IS NO MAC EQUIVALENT OF adobe-isolate.bat
#  --------------------------------------------------
#  macOS's built-in Application Firewall (socketfilterfw) filters INBOUND
#  connections only. `pf` can block by address, port, protocol or user - but
#  not "this executable". So the per-program outbound rule that the Windows
#  script relies on has no built-in counterpart here. Per-app outbound blocking
#  on macOS needs a network-extension tool: LuLu (free, open source,
#  objective-see.org/products/lulu.html) or Little Snitch.
#
#  Use this to identify the talkers, then create rules for exactly those in
#  whichever of those tools you install.
#
#  Usage:
#    ./adobe-watch-macos.sh              watch for 75 seconds
#    ./adobe-watch-macos.sh 180          watch for 180 seconds
#    ./adobe-watch-macos.sh 60 noresolve skip reverse DNS (faster)
# =============================================================================

set -uo pipefail

DURATION="${1:-75}"
RESOLVE="${2:-resolve}"
INTERVAL=2

# Adobe process names seen on macOS. Matched case-insensitively as substrings,
# so version suffixes (e.g. "Adobe Illustrator 2024") are covered.
PATTERN='Illustrator|Photoshop|InDesign|Premiere|Adobe Desktop Service|AdobeIPCBroker|CCXProcess|CCLibrary|Core Sync|CoreSync|AdobeCRDaemon|Creative Cloud|AdobeGCClient|AdobeUpdate|Adobe Installer|AdobeNotification'

TMP="$(mktemp -t adobewatch)" || { echo "cannot create temp file"; exit 1; }
PROCS="$(mktemp -t adobeprocs)" || { echo "cannot create temp file"; exit 1; }
trap 'rm -f "$TMP" "$PROCS"' EXIT

echo
echo "================================================================"
echo "  Adobe network watch - macOS"
echo "================================================================"
echo "  sampling for ${DURATION}s (every ${INTERVAL}s), read-only"
echo

END=$(( $(date +%s) + DURATION ))
while [ "$(date +%s)" -lt "$END" ]; do
  # Running Adobe processes.
  ps -axo pid=,comm= 2>/dev/null \
    | grep -Ei "$PATTERN" \
    | awk '{pid=$1; $1=""; sub(/^ /,""); n=split($0,p,"/"); print pid"\t"p[n]}' \
    >> "$PROCS"

  # Established outbound TCP for those pids.
  # -nP keeps numbers (fast); -i TCP limits to network sockets.
  while IFS= read -r pid; do
    [ -z "$pid" ] && continue
    lsof -nP -a -p "$pid" -i TCP -sTCP:ESTABLISHED 2>/dev/null \
      | awk 'NR>1 {print $1"\t"$9}'
  done < <(ps -axo pid=,comm= 2>/dev/null | grep -Ei "$PATTERN" | awk '{print $1}') \
    >> "$TMP"

  sleep "$INTERVAL"
done

echo "Adobe processes seen"
echo "--------------------"
if [ -s "$PROCS" ]; then
  sort -u -k2 "$PROCS" | awk -F'\t' '{print "   " $2 "   (pid " $1 ")"}' | sort -u
else
  echo "   none running"
fi
echo

echo "Distinct outbound endpoints"
echo "---------------------------"
if [ ! -s "$TMP" ]; then
  echo "   NONE - no established outbound TCP from any Adobe process"
  echo
  exit 0
fi

# $9 from lsof looks like  192.168.1.10:54321->52.48.126.58:443
sort -u "$TMP" | while IFS=$'\t' read -r proc conn; do
  remote="${conn##*->}"
  [ "$remote" = "$conn" ] && continue          # no arrow: not an outbound pair
  rip="${remote%:*}"
  rport="${remote##*:}"
  case "$rip" in
    127.*|localhost|\[::1\]|"") continue ;;    # loopback is not interesting
  esac
  # lsof escapes spaces in the COMMAND column as \x20 - put them back.
  proc="$(printf '%s' "$proc" | sed 's/\\x20/ /g')"
  if [ "$RESOLVE" = "resolve" ]; then
    # dig is not guaranteed present on every macOS release; fall back to host.
    if command -v dig >/dev/null 2>&1; then
      host="$( { dig +short -x "$rip" +time=1 +tries=1 2>/dev/null || true; } | head -1 )"
    elif command -v host >/dev/null 2>&1; then
      host="$( { host -W 1 "$rip" 2>/dev/null || true; } | awk '/pointer/ {print $NF; exit}' )"
    else
      host=""
    fi
    [ -z "$host" ] && host="(no reverse DNS)"
  else
    host=""
  fi
  printf '   %-26s %-18s %-6s %s\n' "$proc" "$rip" "$rport" "$host"
done | sort -u

echo
echo "Next step: to actually BLOCK these per-application, install LuLu"
echo "(free, open source - objective-see.org/products/lulu.html) or Little"
echo "Snitch, and create a deny rule for each process listed above."
echo "macOS has no built-in per-app outbound firewall."
echo
