#!/usr/bin/env bash
set -euo pipefail

# ==============================================================================
# breachtrail.sh (v1.4.8 patched) — Project Breach Trail (Kali)
#
# Fixes applied in v1.4.8:
#  - FIX (critical): Truly remove duplicate carving helper function definitions
#       (write_min_scalpel_conf / locate_bulk_extractor_pcap / count_files / run_carving)
#  - FIX: parse_args() no longer hard-crashes on missing option arguments under `set -e`
#       (now prints an error + usage and exits cleanly)
#  - FIX: zip_case_dir() zip name no longer double-prefixes (now OUT_BASE/<case_basename>.zip)
#  - HARDEN: Add safe_path() + end-of-options guards where appropriate to prevent paths
#       beginning with '-' from being treated as options by common utilities
#  - HARDEN (minor): If the script exits before case dir creation, bootstrap commands
#       are written best-effort to /tmp for debugging (since commands.log can't exist yet).
#
# Constraints (per brief):
#  - Kali Linux; internet available
#  - Tool limits: Bulk Extractor, Binwalk, Foremost, Strings, Volatility, Scalpel, dd
#    (plus standard shell utilities)
#  - Must attempt cmdline + cmdscan + consoles (or closest Vol3 equivalents)
#  - Must attempt Windows credential hashes: Vol2 hashdump / Vol3 hashdump where possible
#  - Must locate bulk_extractor packets.pcap and print path + size; record in report
#  - Must log EVERY executed command to 00_logs/commands.log (one line, as executed)
#  - Check current user; exit if not root
# ==============================================================================

SCRIPT_NAME="breachtrail.sh"
TZ_DEFAULT="Asia/Singapore"

# Optional mitigation for large disk strings output (0/unset = full disk)
BT_STRINGS_DISK_MAX_BYTES="${BT_STRINGS_DISK_MAX_BYTES:-0}"

# -----------------------------
# Globals populated at runtime
# -----------------------------
MEM_PATH=""
DISK_PATH=""
OUT_BASE=""
CASE_DIR=""
VOL_MODE="auto"     # auto|vol2|vol3|both|none
VOL2_PROFILE=""     # chosen profile (Vol2 only)
VOL2_PROFILE_ARG="" # optional provided
PATTERNS_SRC=""     # optional user-supplied patterns file path
PATTERNS_MODE=""    # default|edit|custom

START_EPOCH=0
END_EPOCH=0

# Logging
LOG_DIR=""
CMDLOG=""
VERSIONS_LOG=""
INSTALL_LOG=""
STDERR_DIR=""

# Report paths
REPORT_DIR=""
REPORT_MD=""

# Outputs
MEM_DIR=""
VOL2_DIR=""
VOL3_DIR=""
CARVE_DIR=""
BE_DIR=""
FOREMOST_DIR=""
SCALPEL_DIR=""
BINWALK_DIR=""
STR_DIR=""

# State for report
declare -a FAILURES
declare -a SKIPS
PCAP_PATH=""
PCAP_SIZE_BYTES=""
VOL3_HASHDUMP_PLUGIN=""

# Tool commands (detected)
declare -a VOL2_CMD_ARR=()   # e.g., (volatility)
declare -a VOL3_CMD_ARR=()   # e.g., (vol) or (python3 -c '...cli.main()') or (python3 /opt/volatility3/vol.py)

# -----------------------------
# Bootstrap-safe command logging
# -----------------------------
LOG_READY=0
declare -a BOOTSTRAP_CMDS=()
BOOTSTRAP_FALLBACK_LOG="/tmp/breachtrail_bootstrap_${$}.commands.log"

on_exit() {
  local rc=$?
  if [[ $LOG_READY -eq 0 && ${#BOOTSTRAP_CMDS[@]} -gt 0 ]]; then
    {
      printf '%s\n' "${BOOTSTRAP_CMDS[@]}" >"$BOOTSTRAP_FALLBACK_LOG"
      printf '[%s] NOTE: case directory was not created; bootstrap commands were saved to: %s\n' "$(ts 2>/dev/null || true)" "$BOOTSTRAP_FALLBACK_LOG" >&2
    } 2>/dev/null || true
  fi
  return "$rc"
}
trap on_exit EXIT

# -----------------------------
# Small helpers
# -----------------------------
is_interactive() { [[ -t 0 && -t 1 ]]; }

trim() {
  local s="$1"
  s="${s#"${s%%[![:space:]]*}"}"
  s="${s%"${s##*[![:space:]]}"}"
  printf '%s' "$s"
}

bn() { local p="${1:-}"; printf '%s' "${p##*/}"; }

dir_of() {
  local p="${1:-}"
  if [[ "$p" == */* ]]; then printf '%s' "${p%/*}"; else printf '%s' "."; fi
}

append_failure() { FAILURES+=("$1"); }
append_skip() { SKIPS+=("$1"); }

# If a (relative) path starts with '-', prefix './' to avoid it being parsed as an option.
safe_path() {
  local p="${1:-}"
  if [[ -z "$p" ]]; then
    printf '%s' "$p"
  elif [[ "$p" == "-" ]]; then
    printf '%s' "./-"
  elif [[ "$p" == -* ]]; then
    printf './%s' "$p"
  else
    printf '%s' "$p"
  fi
}

# Build a shell-escaped command line string from args
cmdline_str() {
  local s="" arg
  for arg in "$@"; do
    s+="$(printf '%q ' "$arg")"
  done
  printf '%s' "${s% }"
}

# Log a raw string line (already shell-escaped by caller, if desired)
log_raw() {
  local line="$1"
  if [[ $LOG_READY -eq 1 && -n "${CMDLOG:-}" ]]; then
    printf '%s\n' "$line" >>"$CMDLOG"
  else
    BOOTSTRAP_CMDS+=("$line")
  fi
}

# Log the exact command line (shell-escaped)
log_cmdline() { log_raw "$(cmdline_str "$@")"; }

flush_bootstrap_cmds() {
  [[ -n "${CMDLOG:-}" ]] || return 0
  if [[ ${#BOOTSTRAP_CMDS[@]} -gt 0 ]]; then
    local line
    for line in "${BOOTSTRAP_CMDS[@]}"; do
      printf '%s\n' "$line" >>"$CMDLOG"
    done
    BOOTSTRAP_CMDS=()
  fi
}

# Use bash printf time formatting when available; fall back to GNU date if needed.
ts() {
  local out=""
  if out="$(printf '%(%Y-%m-%d %H:%M:%S %Z)T' -1 2>/dev/null)"; then
    printf '%s' "$out"
  else
    log_cmdline date '+%Y-%m-%d %H:%M:%S %Z'
    date '+%Y-%m-%d %H:%M:%S %Z'
  fi
}

# Prefer EPOCHSECONDS (bash 5+). Fallback to external date (logged) if missing.
date_epoch() {
  if [[ -n "${EPOCHSECONDS-}" ]]; then
    printf '%s' "$EPOCHSECONDS"
  else
    log_cmdline date +%s
    date +%s
  fi
}

date_stamp() {
  local out=""
  if out="$(printf '%(%Y%m%d_%H%M%S)T' -1 2>/dev/null)"; then
    printf '%s' "$out"
  else
    log_cmdline date '+%Y%m%d_%H%M%S'
    date '+%Y%m%d_%H%M%S'
  fi
}

fmt_epoch() {
  local e="$1" fmt="$2" out=""
  if out="$(printf "%(${fmt})T" "$e" 2>/dev/null)"; then
    printf '%s' "$out"
    return 0
  fi
  if [[ "$e" =~ ^-?[0-9]+$ ]] && command -v date >/dev/null 2>&1; then
    log_raw "date -d $(printf '%q' "@$e") $(printf '%q' "+$fmt") 2>/dev/null || true"
    out="$(date -d "@$e" "+$fmt" 2>/dev/null || true)"
    if [[ -n "$out" ]]; then
      printf '%s' "$out"
      return 0
    fi
  fi
  printf 'UNKNOWN(%s)' "$e"
}

log() { printf '[%s] %s\n' "$(ts)" "$*"; }

die() {
  printf '[%s] ERROR: %s\n' "$(ts)" "$*" >&2
  exit 1
}

human_size() {
  local bytes="${1:-0}"
  if command -v numfmt >/dev/null 2>&1; then
    log_raw "numfmt --to=iec --suffix=B $(printf '%q' "$bytes") 2>/dev/null || echo $(printf '%q' "${bytes}B")"
    numfmt --to=iec --suffix=B "$bytes" 2>/dev/null || echo "${bytes}B"
  else
    echo "${bytes}B"
  fi
}

file_size_bytes() {
  local p="$1"
  [[ -e "$p" ]] || { echo ""; return 0; }
  local sp; sp="$(safe_path "$p")"
  log_raw "stat -c '%s' -- $(printf '%q' "$sp") 2>/dev/null || true"
  local out
  out="$(stat -c '%s' -- "$sp" 2>/dev/null || true)"
  printf '%s' "$out"
}

sha256_file() {
  local p="$1"
  command -v sha256sum >/dev/null 2>&1 || { echo ""; return 0; }
  [[ -e "$p" ]] || { echo ""; return 0; }

  local sp; sp="$(safe_path "$p")"
  log_raw "sha256sum -- $(printf '%q' "$sp") 2>/dev/null || true"

  local sum=""
  if read -r sum _ < <(sha256sum -- "$sp" 2>/dev/null || true); then
    printf '%s' "$sum"
  else
    echo ""
  fi
}

ensure_dir() {
  local d="$1"
  local sd; sd="$(safe_path "$d")"
  log_cmdline mkdir -p -- "$sd"
  mkdir -p -- "$sd"
}

truncate_file() {
  local f="$1"
  log_raw ": > $(printf '%q' "$f")"
  : > "$f"
}

# Remove dir best-effort (logged as executed)
rm_rf_best_effort() {
  local p="$1"
  [[ -e "$p" ]] || return 0
  local sp; sp="$(safe_path "$p")"
  log_raw "rm -rf -- $(printf '%q' "$sp") 2>/dev/null || true"
  rm -rf -- "$sp" 2>/dev/null || true
}

# Append one line to a file (logged as executed).
append_line_file() {
  local file="$1" line="$2"
  local pbin="/usr/bin/printf"
  if [[ -x "$pbin" ]]; then
    log_raw "$(cmdline_str "$pbin" '%s\n' "$line") >> $(printf '%q' "$file")"
    "$pbin" '%s\n' "$line" >>"$file"
  else
    log_raw "printf '%s\n' $(printf '%q' "$line") >> $(printf '%q' "$file")"
    printf '%s\n' "$line" >>"$file"
  fi
}

# -----------------------------
# Command runners (logging + error handling)
# -----------------------------
run_cmd() {
  local desc="$1"; shift
  local outfile="$1"; shift
  local errfile="$1"; shift

  ensure_dir "$(dir_of "$outfile")"
  ensure_dir "$(dir_of "$errfile")"

  local cmd; cmd="$(cmdline_str "$@")"
  log_raw "${cmd} > $(printf '%q' "$outfile") 2> $(printf '%q' "$errfile")"

  set +e
  "$@" >"$outfile" 2>"$errfile"
  local rc=$?
  set -e

  if [[ $rc -ne 0 ]]; then
    append_failure "$desc (rc=$rc) — see $errfile"
    log "FAILED: $desc (rc=$rc). Continuing."
  else
    log "OK: $desc"
  fi
}

run_cmd_allow() {
  local desc="$1"; shift
  local outfile="$1"; shift
  local errfile="$1"; shift
  local allowed="$1"; shift

  ensure_dir "$(dir_of "$outfile")"
  ensure_dir "$(dir_of "$errfile")"

  local cmd; cmd="$(cmdline_str "$@")"
  log_raw "${cmd} > $(printf '%q' "$outfile") 2> $(printf '%q' "$errfile")"

  set +e
  "$@" >"$outfile" 2>"$errfile"
  local rc=$?
  set -e

  if [[ " ${allowed} " == *" ${rc} "* ]]; then
    log "OK: $desc (rc=$rc allowed)"
    return 0
  fi

  append_failure "$desc (rc=$rc) — see $errfile"
  log "FAILED: $desc (rc=$rc). Continuing."
  return 0
}

run_cmd_probe() {
  local desc="$1"; shift
  local outfile="$1"; shift
  local errfile="$1"; shift

  ensure_dir "$(dir_of "$outfile")"
  ensure_dir "$(dir_of "$errfile")"

  local cmd; cmd="$(cmdline_str "$@")"
  log_raw "${cmd} > $(printf '%q' "$outfile") 2> $(printf '%q' "$errfile")"

  set +e
  "$@" >"$outfile" 2>"$errfile"
  local rc=$?
  set -e

  if [[ $rc -eq 0 ]]; then log "OK (probe): $desc"; else log "Probe failed: $desc (rc=$rc)"; fi
  return "$rc"
}

run_cmd_sink() {
  local desc="$1"; shift
  local errfile="$1"; shift

  ensure_dir "$(dir_of "$errfile")"

  local cmd; cmd="$(cmdline_str "$@")"
  log_raw "${cmd} >/dev/null 2> $(printf '%q' "$errfile")"

  set +e
  "$@" >/dev/null 2>"$errfile"
  local rc=$?
  set -e

  if [[ $rc -ne 0 ]]; then
    append_failure "$desc (rc=$rc) — see $errfile"
    log "FAILED: $desc (rc=$rc). Continuing."
  else
    log "OK: $desc"
  fi
}

show_snippet() {
  local title="$1" path="$2" lines="${3:-25}"
  echo
  log "$title: $path"
  if [[ -s "$path" ]]; then
    local sp; sp="$(safe_path "$path")"
    log_raw "head -n $(printf '%q' "$lines") -- $(printf '%q' "$sp") || true"
    head -n "$lines" -- "$sp" || true
  else
    echo "(no output)"
  fi
}

usage() {
  cat <<'EOF'
Usage:
  sudo ./breachtrail.sh [options]

Options:
  -m, --mem <path>         Path to memory dump (any extension)
  -d, --disk <path>        Path to disk image (.dd/.img/.raw etc.)
  -o, --out <dir>          Output base directory (case folder created inside)
  -p, --patterns <file>    Use a custom patterns list file (one per line)
      --vol2               Force Volatility 2
      --vol3               Force Volatility 3
      --vol-auto           Auto-detect and prompt (default)
      --vol-both           Run both Vol2 and Vol3 (where possible)
      --vol2-profile <p>   Pre-set Vol2 profile (skips prompt if provided)
  -h, --help               Show help

Notes:
  - Exits if not root (brief 2.1).
  - Every executed command is logged to: 00_logs/commands.log
  - Optional: set BT_STRINGS_DISK_MAX_BYTES to cap disk strings input size (0 = full disk).
  - Non-interactive runs must supply -o and at least one of -m/-d.
EOF
}

parse_args() {
  while [[ $# -gt 0 ]]; do
    case "$1" in
      -m|--mem)
        [[ $# -ge 2 ]] || { printf 'Missing argument for %s\n' "$1" >&2; usage; exit 1; }
        MEM_PATH="$2"; shift 2 ;;
      -d|--disk)
        [[ $# -ge 2 ]] || { printf 'Missing argument for %s\n' "$1" >&2; usage; exit 1; }
        DISK_PATH="$2"; shift 2 ;;
      -o|--out)
        [[ $# -ge 2 ]] || { printf 'Missing argument for %s\n' "$1" >&2; usage; exit 1; }
        OUT_BASE="$2"; shift 2 ;;
      -p|--patterns)
        [[ $# -ge 2 ]] || { printf 'Missing argument for %s\n' "$1" >&2; usage; exit 1; }
        PATTERNS_SRC="$2"; shift 2 ;;
      --vol2) VOL_MODE="vol2"; shift ;;
      --vol3) VOL_MODE="vol3"; shift ;;
      --vol-auto) VOL_MODE="auto"; shift ;;
      --vol-both|--both) VOL_MODE="both"; shift ;;
      --vol2-profile)
        [[ $# -ge 2 ]] || { printf 'Missing argument for %s\n' "$1" >&2; usage; exit 1; }
        VOL2_PROFILE_ARG="$2"; shift 2 ;;
      --) shift; break ;;
      -h|--help) usage; exit 0 ;;
      *) printf 'Unknown option: %s\n' "$1" >&2; usage; exit 1 ;;
    esac
  done

  if [[ $# -gt 0 ]]; then
    printf 'Unexpected positional arguments: %s\n' "$(cmdline_str "$@")" >&2
    usage
    exit 1
  fi
}

interactive_menu_if_needed() {
  if [[ -z "${MEM_PATH}" && -z "${DISK_PATH}" ]]; then
    if is_interactive; then
      echo
      log "No evidence paths provided via flags. Interactive mode:"
      read -r -p "Path to memory dump (blank to skip): " MEM_PATH || true
      read -r -p "Path to disk image (.dd/.img) (blank to skip): " DISK_PATH || true
    else
      die "Non-interactive run requires -m and/or -d."
    fi
  fi

  if [[ -z "${OUT_BASE}" ]]; then
    if is_interactive; then
      read -r -p "Output base directory (blank for current directory): " OUT_BASE || true
      OUT_BASE="${OUT_BASE:-$PWD}"
    else
      die "Non-interactive run requires -o/--out <dir>."
    fi
  fi
}

validate_inputs() {
  if [[ -n "${MEM_PATH}" ]]; then [[ -f "${MEM_PATH}" ]] || die "Memory file not found: ${MEM_PATH}"; fi
  if [[ -n "${DISK_PATH}" ]]; then [[ -f "${DISK_PATH}" ]] || die "Disk image not found: ${DISK_PATH}"; fi
  [[ -d "${OUT_BASE}" ]] || die "Output base directory not found: ${OUT_BASE}"
}

init_case_dirs() {
  local stamp; stamp="$(date_stamp)"
  CASE_DIR="${OUT_BASE%/}/breachtrail_${stamp}"

  LOG_DIR="${CASE_DIR}/00_logs"
  CMDLOG="${LOG_DIR}/commands.log"
  VERSIONS_LOG="${LOG_DIR}/tool_versions.txt"
  INSTALL_LOG="${LOG_DIR}/installs.log"
  STDERR_DIR="${LOG_DIR}/stderr"

  MEM_DIR="${CASE_DIR}/01_memory"
  VOL2_DIR="${MEM_DIR}/vol2"
  VOL3_DIR="${MEM_DIR}/vol3"

  CARVE_DIR="${CASE_DIR}/02_carving"
  BE_DIR="${CARVE_DIR}/bulk_extractor"
  FOREMOST_DIR="${CARVE_DIR}/foremost"
  SCALPEL_DIR="${CARVE_DIR}/scalpel"
  BINWALK_DIR="${CARVE_DIR}/binwalk"

  STR_DIR="${CASE_DIR}/03_strings_grep"

  REPORT_DIR="${CASE_DIR}/report"
  REPORT_MD="${REPORT_DIR}/report.md"

  ensure_dir "$LOG_DIR"
  ensure_dir "$STDERR_DIR"
  ensure_dir "$VOL2_DIR"
  ensure_dir "$VOL3_DIR"
  ensure_dir "$CARVE_DIR"
  ensure_dir "$STR_DIR"
  ensure_dir "$REPORT_DIR"

  truncate_file "$CMDLOG"
  truncate_file "$VERSIONS_LOG"
  truncate_file "$INSTALL_LOG"

  LOG_READY=1
  flush_bootstrap_cmds
}

# -----------------------------
# Tool installation / detection
# -----------------------------
apt_install() {
  local pkgs=("$@")
  if [[ $EUID -ne 0 ]]; then
    append_failure "Cannot apt-get install (not root). Missing packages: ${pkgs[*]}"
    log "Not root; cannot apt-get install: ${pkgs[*]}"
    return 1
  fi

  log "Installing missing packages (apt-get): ${pkgs[*]}"

  log_raw "apt-get update >> $(printf '%q' "$INSTALL_LOG") 2>&1"
  { set +e; apt-get update >>"$INSTALL_LOG" 2>&1; set -e; }

  local install_cmd; install_cmd="$(cmdline_str apt-get install -y "${pkgs[@]}")"
  log_raw "${install_cmd} >> $(printf '%q' "$INSTALL_LOG") 2>&1"
  {
    set +e
    apt-get install -y "${pkgs[@]}" >>"$INSTALL_LOG" 2>&1
    local rc=$?
    set -e
    if [[ $rc -ne 0 ]]; then
      append_failure "apt-get install failed for: ${pkgs[*]} (rc=$rc) — see $INSTALL_LOG"
      return 1
    fi
  }
  return 0
}

ensure_tools() {
  declare -A pkgmap=(
    [bulk_extractor]="bulk-extractor"
    [foremost]="foremost"
    [scalpel]="scalpel"
    [binwalk]="binwalk"
    [strings]="binutils"
    [zip]="zip"
    [nano]="nano"
    [python3]="python3"
    [pip3]="python3-pip"
    [git]="git"
    [volatility]="volatility"
    [volatility3]="volatility3"
  )

  local needed_pkgs=() cmd

  for cmd in bulk_extractor foremost scalpel binwalk strings zip nano python3; do
    command -v "$cmd" >/dev/null 2>&1 || needed_pkgs+=("${pkgmap[$cmd]}")
  done

  command -v volatility >/dev/null 2>&1 || needed_pkgs+=("${pkgmap[volatility]}")
  if ! command -v volatility3 >/dev/null 2>&1 && ! command -v vol >/dev/null 2>&1; then
    needed_pkgs+=("${pkgmap[volatility3]}")
    command -v git >/dev/null 2>&1 || needed_pkgs+=("${pkgmap[git]}")
  fi

  if [[ ${#needed_pkgs[@]} -gt 0 ]]; then
    declare -A seen=()
    local uniq=() p
    for p in "${needed_pkgs[@]}"; do
      [[ -z "$p" ]] && continue
      if [[ -z "${seen[$p]+x}" ]]; then
        seen["$p"]=1
        uniq+=("$p")
      fi
    done
    apt_install "${uniq[@]}" || true
  fi

  # pip3 fallback (primarily for Vol3)
  if ! command -v vol >/dev/null 2>&1 && ! command -v volatility3 >/dev/null 2>&1; then
    if command -v pip3 >/dev/null 2>&1; then
      log "Volatility 3 not found via apt; trying pip3 install volatility3 (best-effort)"
      log_raw "pip3 install --upgrade volatility3 >> $(printf '%q' "$INSTALL_LOG") 2>&1"
      {
        set +e
        pip3 install --upgrade volatility3 >>"$INSTALL_LOG" 2>&1
        local rc=$?
        set -e
        [[ $rc -ne 0 ]] && append_failure "pip3 install volatility3 failed (rc=$rc) — see $INSTALL_LOG"
      }
    else
      apt_install python3-pip || true
    fi
  fi

  # git fallback (Vol3) — last resort
  if ! command -v vol >/dev/null 2>&1 && ! command -v volatility3 >/dev/null 2>&1; then
    local v3dir="/opt/volatility3"
    if command -v git >/dev/null 2>&1; then
      if [[ $EUID -eq 0 && ! -d "$v3dir" ]]; then
        log "Volatility 3 still not found; trying git clone into $v3dir (best-effort)"
        log_raw "git clone https://github.com/volatilityfoundation/volatility3.git $(printf '%q' "$v3dir") >> $(printf '%q' "$INSTALL_LOG") 2>&1"
        {
          set +e
          git clone https://github.com/volatilityfoundation/volatility3.git "$v3dir" >>"$INSTALL_LOG" 2>&1
          local rc=$?
          set -e
          [[ $rc -ne 0 ]] && append_failure "git clone volatility3 failed (rc=$rc) — see $INSTALL_LOG"
        }
      fi
    else
      append_failure "Volatility 3 missing and git not available for fallback"
    fi
  fi
}

detect_volatility_cmds() {
  VOL2_CMD_ARR=()
  VOL3_CMD_ARR=()

  if command -v volatility >/dev/null 2>&1; then
    VOL2_CMD_ARR=(volatility)
  else
    append_failure "Volatility 2 command not found (volatility). Vol2 analysis will be skipped."
  fi

  if command -v vol >/dev/null 2>&1; then
    VOL3_CMD_ARR=(vol)
  elif command -v volatility3 >/dev/null 2>&1; then
    VOL3_CMD_ARR=(volatility3)
  else
    log_raw "python3 -c $(printf '%q' "import volatility3.cli") >/dev/null 2>&1"
    if python3 -c "import volatility3.cli" >/dev/null 2>&1; then
      local v3code
      v3code='import sys; import volatility3.cli as cli; sys.argv[0]="vol"; cli.main()'
      VOL3_CMD_ARR=(python3 -c "$v3code")
    elif [[ -f "/opt/volatility3/vol.py" ]]; then
      VOL3_CMD_ARR=(python3 /opt/volatility3/vol.py)
    else
      append_failure "Volatility 3 command not found (vol/volatility3/python3 -c cli.main()/vol.py). Vol3 analysis will be skipped."
    fi
  fi
}

append_cmd_first_lines() {
  local title="$1" lines="$2"; shift 2
  local tmp="${LOG_DIR}/tmp_${title//[^A-Za-z0-9]/_}.txt"
  local err="${STDERR_DIR}/versions_${title//[^A-Za-z0-9]/_}.err"

  append_line_file "$VERSIONS_LOG" "## ${title}"
  run_cmd_allow "${title} (version/help)" "$tmp" "$err" "0 1" "$@"

  if [[ -s "$tmp" ]]; then
    log_raw "head -n $(printf '%q' "$lines") -- $(printf '%q' "$tmp") >> $(printf '%q' "$VERSIONS_LOG") || true"
    head -n "$lines" -- "$tmp" >>"$VERSIONS_LOG" || true
  else
    append_line_file "$VERSIONS_LOG" "(no output)"
  fi
  append_line_file "$VERSIONS_LOG" ""
}

gather_tool_versions() {
  truncate_file "$VERSIONS_LOG"
  append_line_file "$VERSIONS_LOG" "# Tool versions collected: $(ts)"
  append_line_file "$VERSIONS_LOG" ""

  command -v bulk_extractor >/dev/null 2>&1 && append_cmd_first_lines "bulk_extractor" 3 bulk_extractor -h
  command -v foremost >/dev/null 2>&1 && append_cmd_first_lines "foremost" 3 foremost -V
  command -v scalpel >/dev/null 2>&1 && append_cmd_first_lines "scalpel" 3 scalpel -V
  command -v binwalk >/dev/null 2>&1 && append_cmd_first_lines "binwalk" 3 binwalk --version
  command -v strings >/dev/null 2>&1 && append_cmd_first_lines "strings" 2 strings --version

  if [[ ${#VOL2_CMD_ARR[@]} -gt 0 ]]; then
    append_cmd_first_lines "Volatility2" 5 "${VOL2_CMD_ARR[@]}" --info
  fi
  if [[ ${#VOL3_CMD_ARR[@]} -gt 0 ]]; then
    append_cmd_first_lines "Volatility3" 5 "${VOL3_CMD_ARR[@]}" -h
  fi
}

# -----------------------------
# Volatility helpers (unchanged)
# -----------------------------
ensure_vol2_imageinfo() {
  [[ ${#VOL2_CMD_ARR[@]} -gt 0 ]] || return 1
  local out="${VOL2_DIR}/00_imageinfo.txt"
  local err="${STDERR_DIR}/vol2_imageinfo.err"
  [[ -s "$out" ]] && return 0
  run_cmd_probe "Vol2 imageinfo (probe/cache)" "$out" "$err" "${VOL2_CMD_ARR[@]}" -f "$MEM_PATH" imageinfo || return 1
  [[ -s "$out" ]] || return 1
  return 0
}

ensure_vol3_windows_info() {
  [[ ${#VOL3_CMD_ARR[@]} -gt 0 ]] || return 1
  local out="${VOL3_DIR}/00_windows_info.txt"
  local err="${STDERR_DIR}/vol3_windows_info.err"
  [[ -s "$out" ]] && return 0
  run_cmd_probe "Vol3 windows.info (probe/cache)" "$out" "$err" "${VOL3_CMD_ARR[@]}" -f "$MEM_PATH" windows.info || return 1
  [[ -s "$out" ]] || return 1
  return 0
}

vol2_can_parse() {
  [[ ${#VOL2_CMD_ARR[@]} -gt 0 ]] || return 1
  ensure_vol2_imageinfo || return 1
  local out="${VOL2_DIR}/00_imageinfo.txt"
  log_raw "grep -qiE $(printf '%q' "Suggested Profile|KDBG|DTB") -- $(printf '%q' "$out") 2>/dev/null"
  grep -qiE "Suggested Profile|KDBG|DTB" -- "$out" 2>/dev/null
}

vol3_can_parse() {
  [[ ${#VOL3_CMD_ARR[@]} -gt 0 ]] || return 1
  ensure_vol3_windows_info || return 1
  local out="${VOL3_DIR}/00_windows_info.txt"
  log_raw "grep -qiE $(printf '%q' "Windows|Kernel|NT|Is64Bit|Kernel Base|Major|Minor") -- $(printf '%q' "$out") 2>/dev/null"
  grep -qiE "Windows|Kernel|NT|Is64Bit|Kernel Base|Major|Minor" -- "$out" 2>/dev/null
}

choose_vol_mode_auto() {
  [[ "$VOL_MODE" == "auto" ]] || return 0

  local v2ok=1 v3ok=1
  if vol2_can_parse; then v2ok=0; fi
  if vol3_can_parse; then v3ok=0; fi

  if [[ $v2ok -ne 0 && $v3ok -ne 0 ]]; then
    log "Volatility auto-detect could not confirm parsing. Will still attempt analysis (default BOTH)."
    if is_interactive; then
      echo
      echo "  1) Volatility 2"
      echo "  2) Volatility 3"
      echo "  3) Both"
      read -r -p "Choose [1-3] (default 3): " pick || true
      case "${pick:-3}" in
        1) VOL_MODE="vol2" ;;
        2) VOL_MODE="vol3" ;;
        *) VOL_MODE="both" ;;
      esac
    else
      VOL_MODE="both"
    fi
    return 0
  fi

  if [[ $v2ok -eq 0 && $v3ok -ne 0 ]]; then VOL_MODE="vol2"; return 0; fi
  if [[ $v2ok -ne 0 && $v3ok -eq 0 ]]; then VOL_MODE="vol3"; return 0; fi

  log "Memory dump appears parseable by BOTH Vol2 and Vol3."
  if is_interactive; then
    echo
    echo "  1) Volatility 2"
    echo "  2) Volatility 3"
    echo "  3) Both"
    read -r -p "Choose [1-3] (default 3): " pick || true
    case "${pick:-3}" in
      1) VOL_MODE="vol2" ;;
      2) VOL_MODE="vol3" ;;
      *) VOL_MODE="both" ;;
    esac
  else
    VOL_MODE="both"
  fi
}

select_vol2_profile() {
  [[ ${#VOL2_CMD_ARR[@]} -gt 0 ]] || return 0

  if [[ -n "$VOL2_PROFILE_ARG" ]]; then
    VOL2_PROFILE="$VOL2_PROFILE_ARG"
    log "Using Vol2 profile from flag: $VOL2_PROFILE"
    return 0
  fi

  ensure_vol2_imageinfo || true
  local imginfo="${VOL2_DIR}/00_imageinfo.txt"

  local suggested_line=""
  log_raw "grep -iE $(printf '%q' "Suggested Profile") -- $(printf '%q' "$imginfo") 2>/dev/null || true"
  while IFS= read -r line; do
    suggested_line="$line"
    break
  done < <(grep -iE "Suggested Profile" -- "$imginfo" 2>/dev/null || true)

  local suggested="" default_profile=""
  if [[ -n "$suggested_line" && "$suggested_line" == *:* ]]; then
    suggested="$(trim "${suggested_line#*:}")"
  fi
  if [[ -n "$suggested" ]]; then
    default_profile="$(trim "${suggested%%,*}")"
  fi

  if is_interactive; then
    local summary="${VOL2_DIR}/00_imageinfo_summary.txt"
    local sumerr="${STDERR_DIR}/vol2_imageinfo_summary.err"
    echo
    log "Vol2 imageinfo summary (Suggested Profiles / Candidates):"
    run_cmd_allow "Vol2 imageinfo summary grep" "$summary" "$sumerr" "0 1" \
      grep -iE "Suggested Profile|Profile|AS Layer1|KDBG|DTB" -- "$imginfo"
    [[ -s "$summary" ]] && show_snippet "Vol2 imageinfo summary" "$summary" 40

    read -r -p "Enter Vol2 profile (blank for default: ${default_profile:-NONE}): " VOL2_PROFILE || true
    VOL2_PROFILE="${VOL2_PROFILE:-$default_profile}"
  else
    if [[ -n "$default_profile" ]]; then
      VOL2_PROFILE="$default_profile"
      append_skip "Vol2 profile prompt skipped (non-interactive); using default profile: $VOL2_PROFILE"
      log "Non-interactive: using default Vol2 profile: $VOL2_PROFILE"
    else
      append_skip "Vol2 profile prompt skipped (non-interactive); no Suggested Profile found"
      VOL2_PROFILE=""
    fi
  fi

  if [[ -z "$VOL2_PROFILE" ]]; then
    append_failure "Vol2 profile not selected (imageinfo did not provide suggestions). Vol2 analysis may fail."
  else
    log "Selected Vol2 profile: $VOL2_PROFILE"
  fi
}

# (Vol2/Vol3 plugin runners and run_memory_analysis are unchanged from v1.4.6)
# -----------------------------
# NOTE: For brevity, these sections are identical to v1.4.6 except for added `--`
# in a few grep calls above. Keep your existing v1.4.6 bodies here unchanged.
# -----------------------------

# -----------------------------
# Carving helpers (SINGLE canonical copy)
# -----------------------------
write_min_scalpel_conf() {
  local dst="${SCALPEL_DIR}/scalpel.conf"
  log_raw "cat > $(printf '%q' "$dst") <<'EOF'"
  cat >"$dst" <<'EOF'
# Minimal scalpel.conf generated by breachtrail.sh
# Format: ext case_sensitive max_size header [footer] [keywords]
# Footer optional; header required.
gif y 5000000 \x47\x49\x46\x38\x37\x61 \x00\x3b
gif y 5000000 \x47\x49\x46\x38\x39\x61 \x00\x00\x3b
jpg y 200000000 \xff\xd8\xff\xe0\x00\x10 \xff\xd9
jpg y 200000000 \xff\xd8\xff\xe1 \xff\xd9
png y 20000000 \x89\x50\x4e\x47\x0d\x0a\x1a\x0a \x00\x00\x00\x00\x49\x45\x4e\x44\xae\x42\x60\x82
pdf y 50000000 %PDF %EOF\x0d REVERSE
pdf y 50000000 %PDF %EOF\x0a REVERSE
zip y 100000000 PK\x03\x04 \x3c\xac
rar y 100000000 Rar!
doc y 10000000 \xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1\x00\x00 \xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1\x00\x00 NEXT
exe y 200000000 MZ
EOF
  echo "$dst"
}

locate_bulk_extractor_pcap() {
  PCAP_PATH=""
  PCAP_SIZE_BYTES=""

  if [[ -d "$BE_DIR" ]]; then
    local found=""
    local sdir; sdir="$(safe_path "$BE_DIR")"
    log_raw "find $(printf '%q' "$sdir") -maxdepth 3 \\( -iname 'packets.pcap' -o -iname 'packets.pcap.gz' \\) -type f -print -quit 2>/dev/null || true"
    found="$(find "$sdir" -maxdepth 3 \( -iname "packets.pcap" -o -iname "packets.pcap.gz" \) -type f -print -quit 2>/dev/null || true)"
    if [[ -n "$found" && -f "$found" ]]; then
      PCAP_PATH="$found"
      PCAP_SIZE_BYTES="$(file_size_bytes "$found")"
    fi
  fi
}

count_files() {
  local dir="$1"
  [[ -d "$dir" ]] || { echo "0"; return 0; }

  local sdir; sdir="$(safe_path "$dir")"
  log_raw "find $(printf '%q' "$sdir") -type f -print 2>/dev/null | wc -l 2>/dev/null || echo 0"
  local c
  c="$(find "$sdir" -type f -print 2>/dev/null | wc -l 2>/dev/null || echo 0)"
  c="${c//[[:space:]]/}"
  echo "${c:-0}"
}

run_carving() {
  [[ -n "${DISK_PATH}" ]] || { append_skip "Carving skipped (no disk image)"; return 0; }

  # Ensure tools that expect to create their output dirs start from "dir does not exist"
  rm_rf_best_effort "$BE_DIR"
  rm_rf_best_effort "$FOREMOST_DIR"

  run_cmd "bulk_extractor" "${CARVE_DIR}/bulk_extractor_stdout.txt" "${STDERR_DIR}/bulk_extractor.err" \
    bulk_extractor -o "$BE_DIR" "$DISK_PATH"

  run_cmd "foremost" "${CARVE_DIR}/foremost_stdout.txt" "${STDERR_DIR}/foremost.err" \
    foremost -i "$DISK_PATH" -o "$FOREMOST_DIR"

  # Scalpel: start from clean, empty dir
  rm_rf_best_effort "$SCALPEL_DIR"
  ensure_dir "$SCALPEL_DIR"

  local sc_conf; sc_conf="$(write_min_scalpel_conf || true)"
  if [[ -n "$sc_conf" && -f "$sc_conf" ]]; then
    run_cmd "scalpel" "${CARVE_DIR}/scalpel_stdout.txt" "${STDERR_DIR}/scalpel.err" \
      scalpel -c "$sc_conf" -o "$SCALPEL_DIR" "$DISK_PATH"
  else
    append_failure "Scalpel config generation failed; scalpel run skipped."
  fi

  # Binwalk: start from clean dir
  rm_rf_best_effort "$BINWALK_DIR"
  ensure_dir "$BINWALK_DIR"
  run_cmd "binwalk extract" "${CARVE_DIR}/binwalk_stdout.txt" "${STDERR_DIR}/binwalk.err" \
    binwalk -e --directory "$BINWALK_DIR" "$DISK_PATH"

  locate_bulk_extractor_pcap
  if [[ -n "$PCAP_PATH" ]]; then
    local pcap_h=""; pcap_h="$(human_size "${PCAP_SIZE_BYTES:-0}")"
    log "Found network traffic artifact: $PCAP_PATH ($pcap_h)"
  else
    log "No packets.pcap found under bulk_extractor output."
  fi

  local be_files fm_files sc_files bw_files
  be_files="$(count_files "$BE_DIR")"
  fm_files="$(count_files "$FOREMOST_DIR")"
  sc_files="$(count_files "$SCALPEL_DIR")"
  bw_files="$(count_files "$BINWALK_DIR")"
  log "Carving summary (found X artifacts): bulk_extractor=$be_files, foremost=$fm_files, scalpel=$sc_files, binwalk=$bw_files"
}

# -----------------------------
# strings -> grep (human-readable search)
# -----------------------------
write_default_patterns() {
  local f="$1"
  log_raw "cat > $(printf '%q' "$f") <<'EOF'"
  cat >"$f" <<'EOF'
# breachtrail default patterns (one per line). Treated as ERE (grep -E), case-insensitive (grep -i).
# Keep patterns simple and portable (avoid PCRE-only syntax).

password
passwd
pwd
user(name)?
login
credential
token
api[_-]?key
secret

# URLs / web
https?://

# Email (basic)
[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}

# IPv4 (basic)
([0-9]{1,3}\.){3}[0-9]{1,3}

# Tor / dark web indicators
\.onion
darkweb
tor

# Executables / scripts
\.exe
\.dll
powershell
cmd\.exe
wscript
cscript

# Common attacker tooling keywords (best-effort)
mimikatz
psexec
wmic
schtasks
netsh
reg\.exe

# RDP indicator
3389

# Crypto keywords (best-effort)
bitcoin
btc
monero
xmr
EOF
}

choose_patterns_mode() {
  ensure_dir "$STR_DIR"
  local patterns_dst="${STR_DIR}/patterns.txt"

  if [[ -n "$PATTERNS_SRC" ]]; then
    [[ -f "$PATTERNS_SRC" ]] || die "Patterns file not found: $PATTERNS_SRC"
    run_cmd_sink "Copy custom patterns file" "${STDERR_DIR}/patterns_cp.err" cp -- "$(safe_path "$PATTERNS_SRC")" "$(safe_path "$patterns_dst")"
    PATTERNS_MODE="custom"
    log "Using custom patterns file: $PATTERNS_SRC"
    return 0
  fi

  write_default_patterns "$patterns_dst"

  if ! is_interactive; then
    PATTERNS_MODE="default"
    log "Non-interactive: using default patterns."
    return 0
  fi

  echo
  log "Patterns configuration (human-readable search):"
  echo "  1) Use default patterns (created at $patterns_dst)"
  echo "  2) Edit patterns via nano"
  echo "  3) Supply custom list file path"
  read -r -p "Choose [1-3] (default 1): " pm || true

  case "${pm:-1}" in
    2)
      PATTERNS_MODE="edit"
      log "Opening nano for patterns: $patterns_dst"
      log_cmdline nano -- "$patterns_dst"
      nano -- "$patterns_dst" || true
      ;;
    3)
      PATTERNS_MODE="custom"
      read -r -p "Enter path to your custom patterns file: " customp || true
      [[ -f "${customp:-}" ]] || die "Custom patterns file not found: ${customp:-}"
      run_cmd_sink "Copy custom patterns file" "${STDERR_DIR}/patterns_cp.err" cp -- "$(safe_path "$customp")" "$(safe_path "$patterns_dst")"
      log "Copied custom patterns file into case folder."
      ;;
    *)
      PATTERNS_MODE="default"
      log "Using default patterns."
      ;;
  esac
}

run_strings_grep() {
  if [[ -z "${MEM_PATH}" && -z "${DISK_PATH}" ]]; then
    append_skip "strings/grep skipped (no evidence paths)."
    return 0
  fi

  choose_patterns_mode

  local patterns="${STR_DIR}/patterns.txt"
  local active="${STR_DIR}/patterns.active.txt"
  run_cmd_allow "Build active patterns (strip comments/blanks)" "$active" "${STDERR_DIR}/patterns_active.err" "0 1" \
    grep -vE '^[[:space:]]*#|^[[:space:]]*$' "$patterns"

  local strings_out="${STR_DIR}/strings.txt"
  local grep_out="${STR_DIR}/grep_hits.txt"
  truncate_file "$strings_out"
  truncate_file "$grep_out"

  if [[ -n "${MEM_PATH}" ]]; then
    run_cmd "strings (memory)" "${STR_DIR}/strings_mem.txt" "${STDERR_DIR}/strings_mem.err" \
      strings -a -n 4 -t d "$MEM_PATH"

    local header_mem="===== STRINGS: MEMORY ($(bn "$MEM_PATH")) ====="
    log_raw "printf '%s\n' $(printf '%q' "$header_mem") >> $(printf '%q' "$strings_out")"
    printf '%s\n' "$header_mem" >>"$strings_out"

    log_raw "cat $(printf '%q' "${STR_DIR}/strings_mem.txt") >> $(printf '%q' "$strings_out") 2>/dev/null || true"
    cat "${STR_DIR}/strings_mem.txt" >>"$strings_out" 2>/dev/null || true

    log_raw "printf '\n' >> $(printf '%q' "$strings_out")"
    printf '\n' >>"$strings_out"
  fi

  if [[ -n "${DISK_PATH}" ]]; then
    if [[ "$BT_STRINGS_DISK_MAX_BYTES" =~ ^[0-9]+$ ]] && [[ "$BT_STRINGS_DISK_MAX_BYTES" -gt 0 ]]; then
      local sample="${STR_DIR}/disk_sample_first_${BT_STRINGS_DISK_MAX_BYTES}.bin"
      run_cmd_sink "dd disk sample (BT_STRINGS_DISK_MAX_BYTES=$BT_STRINGS_DISK_MAX_BYTES)" "${STDERR_DIR}/dd_disk_sample.err" \
        dd if="$DISK_PATH" of="$sample" bs=1 count="$BT_STRINGS_DISK_MAX_BYTES" status=none
      run_cmd "strings (disk sample)" "${STR_DIR}/strings_disk.txt" "${STDERR_DIR}/strings_disk.err" \
        strings -a -n 4 -t d "$sample"
    else
      run_cmd "strings (disk)" "${STR_DIR}/strings_disk.txt" "${STDERR_DIR}/strings_disk.err" \
        strings -a -n 4 -t d "$DISK_PATH"
    fi

    local header_disk="===== STRINGS: DISK ($(bn "$DISK_PATH")) ====="
    log_raw "printf '%s\n' $(printf '%q' "$header_disk") >> $(printf '%q' "$strings_out")"
    printf '%s\n' "$header_disk" >>"$strings_out"

    log_raw "cat $(printf '%q' "${STR_DIR}/strings_disk.txt") >> $(printf '%q' "$strings_out") 2>/dev/null || true"
    cat "${STR_DIR}/strings_disk.txt" >>"$strings_out" 2>/dev/null || true

    log_raw "printf '\n' >> $(printf '%q' "$strings_out")"
    printf '\n' >>"$strings_out"
  fi

  run_cmd_allow "grep hits (strings -> grep)" "$grep_out" "${STDERR_DIR}/grep_hits.err" "0 1" \
    grep -i -n -E -f "$active" "$strings_out"

  log_raw "wc -l < $(printf '%q' "$grep_out")"
  local hit_count; hit_count="$(wc -l <"$grep_out" 2>/dev/null || echo 0)"; hit_count="${hit_count//[[:space:]]/}"

  log_raw "wc -l < $(printf '%q' "$strings_out")"
  local line_count; line_count="$(wc -l <"$strings_out" 2>/dev/null || echo 0)"; line_count="${line_count//[[:space:]]/}"

  log "Human-readable search complete: strings lines=$line_count, grep hits=$hit_count"
  show_snippet "Top grep hits" "$grep_out" 25
}

# -----------------------------
# Report + Zip
# -----------------------------
generate_report() {
  END_EPOCH="$(date_epoch)"
  local duration=$((END_EPOCH - START_EPOCH))

  local mem_size="" disk_size="" mem_sha="" disk_sha=""
  local mem_size_h="" disk_size_h=""
  if [[ -n "$MEM_PATH" ]]; then
    mem_size="$(file_size_bytes "$MEM_PATH")"
    mem_sha="$(sha256_file "$MEM_PATH")"
    [[ -n "$mem_size" ]] && mem_size_h="$(human_size "$mem_size")"
  fi
  if [[ -n "$DISK_PATH" ]]; then
    disk_size="$(file_size_bytes "$DISK_PATH")"
    disk_sha="$(sha256_file "$DISK_PATH")"
    [[ -n "$disk_size" ]] && disk_size_h="$(human_size "$disk_size")"
  fi

  locate_bulk_extractor_pcap
  local pcap_size_h=""
  if [[ -n "${PCAP_SIZE_BYTES:-}" ]]; then
    pcap_size_h="$(human_size "$PCAP_SIZE_BYTES")"
  fi

  local vol2_files vol3_files carve_files str_files
  vol2_files="$(count_files "$VOL2_DIR")"
  vol3_files="$(count_files "$VOL3_DIR")"
  carve_files="$(count_files "$CARVE_DIR")"
  str_files="$(count_files "$STR_DIR")"

  local grep_hits="0"
  if [[ -f "${STR_DIR}/grep_hits.txt" ]]; then
    log_raw "wc -l < $(printf '%q' "${STR_DIR}/grep_hits.txt")"
    grep_hits="$(wc -l <"${STR_DIR}/grep_hits.txt" 2>/dev/null || echo 0)"
    grep_hits="${grep_hits//[[:space:]]/}"
  fi

  local host uname
  host="${HOSTNAME:-}"
  if [[ -z "$host" ]]; then
    log_cmdline hostname
    host="$(hostname 2>/dev/null || true)"
  fi
  uname="${SUDO_USER:-}"
  if [[ -z "$uname" ]]; then
    log_cmdline id -un
    uname="$(id -un 2>/dev/null || true)"
  fi
  if [[ -z "$uname" ]]; then
    log_cmdline whoami
    uname="$(whoami 2>/dev/null || true)"
  fi

  local start_str end_str
  start_str="$(fmt_epoch "$START_EPOCH" "%Y-%m-%d %H:%M:%S %Z")"
  end_str="$(fmt_epoch "$END_EPOCH" "%Y-%m-%d %H:%M:%S %Z")"

  local failures_md skips_md f s
  failures_md=""
  if [[ ${#FAILURES[@]} -gt 0 ]]; then
    for f in "${FAILURES[@]}"; do failures_md+="- $f"$'\n'; done
  else
    failures_md="- (none recorded)"$'\n'
  fi
  skips_md=""
  if [[ ${#SKIPS[@]} -gt 0 ]]; then
    for s in "${SKIPS[@]}"; do skips_md+="- $s"$'\n'; done
  else
    skips_md="- (none recorded)"$'\n'
  fi

  log_raw "cat > $(printf '%q' "$REPORT_MD") <<BREACHTRAIL_REPORT"
  cat >"$REPORT_MD" <<BREACHTRAIL_REPORT
# BreachTrail Report

## Case metadata
- Case directory: \`$CASE_DIR\`
- Start time: $start_str
- End time: $end_str
- Duration (seconds): \`$duration\`
- Host: \`$host\`
- User: \`$uname\` (EUID=$EUID)

## Evidence
$(if [[ -n "$MEM_PATH" ]]; then
  printf -- "- Memory: \`%s\`\n" "$MEM_PATH"
  [[ -n "$mem_size" ]] && printf "  - Size: %s (%s bytes)\n" "$mem_size_h" "$mem_size"
  [[ -n "$mem_sha" ]] && printf "  - SHA256: \`%s\`\n" "$mem_sha"
else
  printf -- "- Memory: (not provided)\n"
fi)
$(if [[ -n "$DISK_PATH" ]]; then
  printf -- "- Disk: \`%s\`\n" "$DISK_PATH"
  [[ -n "$disk_size" ]] && printf "  - Size: %s (%s bytes)\n" "$disk_size_h" "$disk_size"
  [[ -n "$disk_sha" ]] && printf "  - SHA256: \`%s\`\n" "$disk_sha"
else
  printf -- "- Disk: (not provided)\n"
fi)

## Tool versions
- Versions log: \`$VERSIONS_LOG\`
- Installs log: \`$INSTALL_LOG\`

## Memory analysis outputs
- Vol2 output folder: \`$VOL2_DIR\` (files: $vol2_files)$(if [[ -n "$VOL2_PROFILE" ]]; then printf "\n  - Vol2 selected profile: \`%s\`" "$VOL2_PROFILE"; fi)
- Vol3 output folder: \`$VOL3_DIR\` (files: $vol3_files)$(if [[ -n "$VOL3_HASHDUMP_PLUGIN" ]]; then printf "\n  - Vol3 hashdump plugin used: \`%s\`" "$VOL3_HASHDUMP_PLUGIN"; fi)

## Carving outputs
- Carving folder: \`$CARVE_DIR\` (files: $carve_files)

### Network traffic artifact (bulk_extractor)
$(if [[ -n "$PCAP_PATH" ]]; then
  printf -- "- packets.pcap path: \`%s\`\n" "$PCAP_PATH"
  if [[ -n "${PCAP_SIZE_BYTES:-}" ]]; then
    printf -- "- packets.pcap size: %s (%s bytes)\n" "$pcap_size_h" "$PCAP_SIZE_BYTES"
  fi
else
  printf -- "- packets.pcap: (not found)\n"
fi)

## Human-readable search (strings -> grep)
- Folder: \`$STR_DIR\` (files: $str_files)
- Patterns: \`${STR_DIR}/patterns.txt\` (mode: ${PATTERNS_MODE:-unknown})
- Strings output: \`${STR_DIR}/strings.txt\`
- Grep hits: \`${STR_DIR}/grep_hits.txt\` (count: $grep_hits)$(if [[ "$BT_STRINGS_DISK_MAX_BYTES" =~ ^[0-9]+$ ]] && [[ "$BT_STRINGS_DISK_MAX_BYTES" -gt 0 ]]; then printf "\n- Disk strings cap: \`BT_STRINGS_DISK_MAX_BYTES=%s\` (dd sample used)" "$BT_STRINGS_DISK_MAX_BYTES"; fi)

## General statistics
- Total artifacts (found X artifacts):
  - Vol2 files: $vol2_files
  - Vol3 files: $vol3_files
  - Carving files: $carve_files
  - Strings/grep files: $str_files

## Failures / Skipped
### Failures
$failures_md
### Skipped
$skips_md
BREACHTRAIL_REPORT

  log_raw "printf '%s\n' '## Commands executed (exact)' \"Commands log file: \`$CMDLOG\`\" '' '\`\`\`' >> $(printf '%q' "$REPORT_MD")"
  {
    printf "\n## Commands executed (exact)\n"
    printf "Commands log file: \`%s\`\n\n" "$CMDLOG"
    printf '```\n'
  } >>"$REPORT_MD"

  log_raw "cat $(printf '%q' "$CMDLOG") >> $(printf '%q' "$REPORT_MD") 2>/dev/null || true"
  cat "$CMDLOG" >>"$REPORT_MD" 2>/dev/null || true

  log_raw "printf '%s\n' '\`\`\`' >> $(printf '%q' "$REPORT_MD")"
  printf '```\n' >>"$REPORT_MD"

  log "Report written: $REPORT_MD"
}

zip_case_dir() {
  local parent base zip_path

  parent="$(safe_path "${CASE_DIR%/*}")" || { append_failure "zip: invalid parent dir: ${CASE_DIR%/*}"; return 0; }
  base="$(bn "$CASE_DIR")"
  zip_path="${OUT_BASE%/}/${base}.zip"

  # Best-effort zip: guard pushd/popd under set -e
  log_raw "pushd $(printf '%q' "$parent") >/dev/null"
  set +e
  pushd "$parent" >/dev/null
  local push_rc=$?
  set -e
  if [[ $push_rc -ne 0 ]]; then
    append_failure "zip: pushd failed (rc=$push_rc) for: $parent"
    log "FAILED: zip (pushd rc=$push_rc). Continuing."
    return 0
  fi

  log_raw "zip -r $(printf '%q' "$zip_path") $(printf '%q' "$base") >/dev/null 2>>$(printf '%q' "${STDERR_DIR}/zip.err")"
  set +e
  zip -r "$zip_path" "$base" >/dev/null 2>>"${STDERR_DIR}/zip.err"
  local rc=$?
  set -e

  log_raw "popd >/dev/null"
  set +e
  popd >/dev/null
  local pop_rc=$?
  set -e
  [[ $pop_rc -ne 0 ]] && append_failure "zip: popd failed (rc=$pop_rc)"

  if [[ $rc -ne 0 ]]; then
    append_failure "zip failed (rc=$rc) — see ${STDERR_DIR}/zip.err"
    log "FAILED: zip (rc=$rc). Continuing."
    return 0
  fi

  local zbytes; zbytes="$(file_size_bytes "$zip_path")"
  local zbytes_h=""; zbytes_h="$(human_size "${zbytes:-0}")"
  log "Zip created: $zip_path ($zbytes_h)"
  return 0
}

# -----------------------------
# Main
# -----------------------------
main() {
  export TZ="$TZ_DEFAULT"

  # Allow -h/--help without root (parse only; no prompting/work yet)
  parse_args "$@"

  # Brief 2.1: exit if not root (do this BEFORE any prompting/validation)
  if [[ $EUID -ne 0 ]]; then
    die "This script must be run as root. Re-run with sudo."
  fi

  START_EPOCH="$(date_epoch)"

  interactive_menu_if_needed
  validate_inputs

  init_case_dirs

  log "Case folder created: $CASE_DIR"
  log "Logging commands to: $CMDLOG"

  ensure_tools
  detect_volatility_cmds
  gather_tool_versions

  run_memory_analysis
  run_carving
  run_strings_grep

  generate_report
  zip_case_dir || true

  echo
  log "DONE. Outputs:"
  log "  - Case directory: $CASE_DIR"
  log "  - Report: $REPORT_MD"
  log "  - Commands log: $CMDLOG"
  if [[ -n "$PCAP_PATH" ]]; then
    local pcap_h=""; pcap_h="$(human_size "${PCAP_SIZE_BYTES:-0}")"
    log "  - packets.pcap: $PCAP_PATH ($pcap_h)"
  fi
}


main "$@"