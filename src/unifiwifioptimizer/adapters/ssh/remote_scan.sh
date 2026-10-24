# shellcheck shell=sh
# Neighbour scan on a UniFi access point, read by the tool over `ssh … sh -s`.
#
# Dialect: busybox ash (the access points ship no bash). The caller prepends three assignments on stdin:
#   SCAN_ATTEMPTS=<1..5>   consecutive `iw scan` runs per band, merged by the reader (strongest wins)
#   IFACE_TOGGLE=<0|1>     whether a down scan interface may be brought up for the scan (restored after)
#   SCAN_TIMEOUT_S=<5..25> bound on one `iw scan`, derived by the caller from its own call budget
# Output protocol (one line each, parsed by iw_parser.py):
#   ===2GHZ===  STATUS=<ok|no_radio|interface_down|empty|failed> [IFACE=<name>] <filtered iw lines>
#   ===5GHZ===  same
#   ===META===  MODEL_NAME=… DFS_CAC_5G=<active|ready|unknown> WATCHDOG=<timeout|watcher>
#   ===POWER5G=== STATUS=<ok|unknown> [PHY_INDEX=N CURRENT_FREQ_MHZ=N <bounded iw frequency lines>]
# No file is written anywhere on the access point; everything lives in shell variables.

SCAN_ATTEMPTS="${SCAN_ATTEMPTS:-1}"
IFACE_TOGGLE="${IFACE_TOGGLE:-0}"
# Seconds one `iw scan` may take on the access point; shorter than the tool's own call budget.
SCAN_TIMEOUT_S="${SCAN_TIMEOUT_S:-25}"
case "$SCAN_TIMEOUT_S" in '' | *[!0-9]* | 0) SCAN_TIMEOUT_S=25 ;; esac
case "$SCAN_ATTEMPTS" in '' | *[!0-9]* | 0) SCAN_ATTEMPTS=1 ;; esac
[ "$SCAN_ATTEMPTS" -gt 5 ] && SCAN_ATTEMPTS=5

# Interfaces this run brought up. Every band restores them explicitly; the signal traps cover the ways
# the script can die early: a signal, and — on hardware that delivers it — SIGPIPE when the ssh client
# has gone (the tool kills it at its call budget) and the next line written has no reader.
TOGGLED=""

restore_toggled() {
  for _iface in $TOGGLED; do
    ifconfig "$_iface" down 2>/dev/null
  done
  TOGGLED=""
}

on_signal() {
  restore_toggled
  exit $((128 + $1))
}

trap 'on_signal 1' HUP
trap 'on_signal 2' INT
trap 'on_signal 13' PIPE
trap 'on_signal 15' TERM

# Only a `timeout` that takes `SECS PROG` counts: busybox before 1.30 wanted `-t SECS`, and with that
# syntax `timeout 25 iw …` would run `25` as the program and every attempt would fail.
if timeout 1 true >/dev/null 2>&1; then
  WATCHDOG=timeout
else
  WATCHDOG=watcher
fi

IW_DEV=$(iw dev 2>/dev/null)

list_ifaces() {
  printf '%s\n' "$IW_DEV" | awk '/Interface/ { print $2 }'
}

iface_info() {
  iw dev "$1" info 2>/dev/null
}

iface_type() {
  iface_info "$1" | awk '/type/ { print $2; exit }'
}

iface_wiphy() {
  iface_info "$1" | awk '/wiphy/ { print $2; exit }'
}

iface_freq() {
  iface_info "$1" | awk '/channel/ { gsub(/[()]/, "", $3); f = $3 + 0; if (f > 0) print f; exit }'
}

iface_exists() {
  [ -n "$(iface_info "$1")" ]
}

iface_is_up() {
  ifconfig "$1" 2>/dev/null | grep -q "UP"
}

phy_info() {
  iw phy "phy$1" info 2>/dev/null
}

phy_has_set_scan_dwell() {
  _wiphy=$(iface_wiphy "$1")
  [ -n "$_wiphy" ] || return 1
  phy_info "$_wiphy" | grep -q "SET_SCAN_DWELL"
}

phy_supports_5g() {
  phy_info "$1" | awk '/\* [0-9]+ MHz/ { f = $2 + 0; if (f >= 5000 && f < 5900) found = 1 } END { print found + 0 }'
}

# managed: a dedicated scan interface (apcli0/apclii0); AP: only when the PHY scans off-channel without
# blocking (SET_SCAN_DWELL, Qualcomm); anything else (monitor, vendor-internal) is left alone.
iface_can_scan() {
  case "$(iface_type "$1")" in
  managed) return 0 ;;
  AP) phy_has_set_scan_dwell "$1" ;;
  *) return 1 ;;
  esac
}

band_bounds() {
  case "$1" in
  2g)
    FREQ_MIN=2400
    FREQ_MAX=2500
    ;;
  5g)
    FREQ_MIN=5000
    FREQ_MAX=5900
    ;;
  esac
}

# Static names first (U6: apcli0/apclii0), then every scan-capable interface on the band's frequencies.
scan_candidates() {
  band_bounds "$1"
  case "$1" in
  2g) _static="apcli0 apcli2" ;;
  5g) _static="apclii0 apcli1 apcli3" ;;
  esac
  _found=""
  for _iface in $(list_ifaces); do
    _freq=$(iface_freq "$_iface")
    [ -n "$_freq" ] || continue
    if [ "$_freq" -ge "$FREQ_MIN" ] && [ "$_freq" -lt "$FREQ_MAX" ]; then
      case " $_static " in
      *" $_iface "*) ;;
      *) iface_can_scan "$_iface" && _found="$_found $_iface" ;;
      esac
    fi
  done
  echo "$_static$_found"
}

# The band serves clients: an UP AP-mode interface on its frequencies. Older MediaTek firmware reports no
# channel over nl80211; there the PHY's band support decides. No cfg80211 interface at all → unknown → scan.
band_is_active() {
  band_bounds "$1"
  _any=0
  for _iface in $(list_ifaces); do
    _any=1
    [ "$(iface_type "$_iface")" = "AP" ] || continue
    iface_is_up "$_iface" || continue
    _freq=$(iface_freq "$_iface")
    if [ -n "$_freq" ]; then
      [ "$_freq" -ge "$FREQ_MIN" ] && [ "$_freq" -lt "$FREQ_MAX" ] && return 0
    else
      _wiphy=$(iface_wiphy "$_iface")
      [ -n "$_wiphy" ] || continue
      case "$1:$(phy_supports_5g "$_wiphy")" in
      2g:0 | 5g:1) return 0 ;;
      esac
    fi
  done
  [ "$_any" = "0" ]
}

# One `iw scan`, bounded on the access point itself: a local kill of the ssh client carries no signal
# across dropbear, so the remote side must end the scan on its own.
run_iw_scan() {
  if [ "$WATCHDOG" = "timeout" ]; then
    timeout "$SCAN_TIMEOUT_S" iw dev "$1" scan 2>/dev/null
    return $?
  fi
  iw dev "$1" scan 2>/dev/null &
  _scan_pid=$!
  # The watcher's own sleep must die with it, or every scan would leave a sleeping orphan behind.
  (
    trap 'kill $! 2>/dev/null; exit 0' TERM
    sleep "$SCAN_TIMEOUT_S" &
    wait $!
    kill "$_scan_pid" 2>/dev/null
  ) >/dev/null 2>&1 &
  _watcher_pid=$!
  wait "$_scan_pid"
  _status=$?
  kill "$_watcher_pid" 2>/dev/null
  wait "$_watcher_pid" 2>/dev/null
  return $_status
}

# Scan one band: prints the STATUS line, optionally IFACE, then the filtered readings.
scan_band() {
  _band="$1"
  if ! band_is_active "$_band"; then
    echo "STATUS=no_radio"
    return 0
  fi
  _usable=""
  _down_seen=0
  for _iface in $(scan_candidates "$_band"); do
    iface_exists "$_iface" || continue
    iface_can_scan "$_iface" || continue
    if iface_is_up "$_iface"; then
      _usable="$_iface"
      break
    fi
    _down_seen=1
    if [ "$IFACE_TOGGLE" = "1" ] && [ "$(iface_type "$_iface")" = "managed" ]; then
      if ifconfig "$_iface" up 2>/dev/null; then
        TOGGLED="$TOGGLED $_iface"
        sleep 1
        _usable="$_iface"
        break
      fi
    fi
  done
  if [ -z "$_usable" ]; then
    if [ "$_down_seen" = "1" ]; then
      echo "STATUS=interface_down"
    else
      echo "STATUS=no_radio"
    fi
    return 0
  fi
  _output=""
  _completed=0
  _attempt=1
  while [ "$_attempt" -le "$SCAN_ATTEMPTS" ]; do
    # The scan's exit status is kept apart from its output: a scan that ran and saw nothing is `empty`,
    # one that failed or hit the watchdog on every attempt is `failed` — the analysis must never read a
    # failure as "no neighbours".
    _raw=$(run_iw_scan "$_usable")
    _rc=$?
    # A failed or killed scan may already have printed part of its list; a partial list must never pass
    # as a complete one, so only attempts that ran to completion contribute readings. The exit status is
    # the only completion signal: anything in the output itself could be spoofed by a neighbour's SSID.
    if [ "$_rc" = "0" ]; then
      _completed=1
      _scan=$(printf '%s\n' "$_raw" | grep -E '^BSS |^[[:space:]]+(freq|signal|SSID):')
      if [ -n "$_scan" ]; then
        _output="$_output
$_scan"
      fi
    fi
    [ "$_attempt" -lt "$SCAN_ATTEMPTS" ] && sleep 1
    _attempt=$((_attempt + 1))
  done
  if [ "$_completed" != "1" ]; then
    echo "STATUS=failed"
  elif [ -n "$_output" ]; then
    echo "STATUS=ok"
  else
    echo "STATUS=empty"
  fi
  echo "IFACE=$_usable"
  [ -n "$_output" ] && printf '%s\n' "$_output"
  return 0
}

# U6 radios log DFS/CAC progress to the kernel log; other platforms do not, so "unknown" there.
dfs_cac_state_5g() {
  if ! iface_exists rai0 && ! iface_exists apclii0; then
    echo "unknown"
    return 0
  fi
  _last=$(
    { logread 2>/dev/null || dmesg 2>/dev/null; } |
      grep -E '\[DfsCacEndUpdate\]\[RDM\] CAC end\. Enable MAC TX\.|\[DfsCacNormalStart\]\[RDM\] CAC [0-9]+ seconds start \. Disable MAC TX|\[DfsCacNormalStart\]\[RDM\] Normal start\. Enable MAC TX' |
      tail -n 1
  )
  if [ -z "$_last" ]; then
    echo "unknown"
  elif printf '%s\n' "$_last" | grep -q 'Disable MAC TX'; then
    echo "active"
  else
    echo "ready"
  fi
}

model_name() {
  _model=$(awk -F '=' '/^board\.name=/ { print substr($0, index($0, "=") + 1); exit }' /etc/board.info 2>/dev/null)
  if [ -z "$_model" ]; then
    _model=$(awk -F '=' '/^name=/ { print substr($0, index($0, "=") + 1); exit }' /proc/ubnthal/system.info 2>/dev/null)
  fi
  printf '%s\n' "$_model" | tr '\t\r\n' '   ' | sed 's/[[:space:]][[:space:]]*/ /g; s/^ //; s/ $//'
}

# Read only the PHY that actually serves an UP 5 GHz AP interface. Some devices expose another PHY with
# a different regulatory table; a conflicting AP interface or an unreported current frequency is unknown.
serving_power_5g() {
  _serving_phy=""
  _serving_freq=""
  for _iface in $(list_ifaces); do
    [ "$(iface_type "$_iface")" = "AP" ] || continue
    iface_is_up "$_iface" || continue
    _freq=$(iface_freq "$_iface")
    if [ -z "$_freq" ]; then
      echo "STATUS=unknown"
      return 0
    fi
    [ "$_freq" -gt 5000 ] && [ "$_freq" -lt 5900 ] || continue
    _wiphy=$(iface_wiphy "$_iface")
    case "$_wiphy" in '' | *[!0-9]*)
      echo "STATUS=unknown"
      return 0
      ;;
    esac
    if [ -n "$_serving_phy" ] && { [ "$_wiphy" != "$_serving_phy" ] || [ "$_freq" != "$_serving_freq" ]; }; then
      echo "STATUS=unknown"
      return 0
    fi
    _serving_phy="$_wiphy"
    _serving_freq="$_freq"
  done
  if [ -z "$_serving_phy" ]; then
    echo "STATUS=unknown"
    return 0
  fi
  if ! _limits=$(phy_info "$_serving_phy" | awk '$1 == "*" && $2 + 0 > 5000 && $2 + 0 < 5900 && /dBm/ { print; n++; if (n > 64) exit 1 }'); then
    echo "STATUS=unknown"
    return 0
  fi
  if [ -z "$_limits" ]; then
    echo "STATUS=unknown"
    return 0
  fi
  echo "STATUS=ok"
  printf 'PHY_INDEX=%s\nCURRENT_FREQ_MHZ=%s\n' "$_serving_phy" "$_serving_freq"
  printf '%s\n' "$_limits"
}

echo "===2GHZ==="
scan_band 2g
restore_toggled
echo "===5GHZ==="
scan_band 5g
restore_toggled
echo "===META==="
printf 'MODEL_NAME=%s\n' "$(model_name)"
printf 'DFS_CAC_5G=%s\n' "$(dfs_cac_state_5g)"
printf 'WATCHDOG=%s\n' "$WATCHDOG"
echo "===POWER5G==="
serving_power_5g
