#!/usr/bin/env bash
set -euo pipefail

echo "=== Forensic Analysis Automation Script ==="

START_TIME=$(date +%s)
VOL2_AVAILABLE=0
VOL3_AVAILABLE=0
VOL2_ANALYZABLE=0
VOL3_ANALYZABLE=0
VOL2_DEPS_OK=1
VOL2_SYSTEM_HIVE=""
VOL2_SAM_HIVE=""
VOL2_CMD=()
VOL3_CMD=()
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
TOOLS_DIR="${SCRIPT_DIR}/tools"
VOL2_HOME="${TOOLS_DIR}/volatility2"
VOL3_VENV="${TOOLS_DIR}/volatility3-venv"
PYENV_ROOT="${PYENV_ROOT:-$HOME/.pyenv}"
LOCAL_PY2="${PYENV_ROOT}/versions/2.7.18/bin/python"
LATEST_VOL3_VERSION="2.27.0"
ARTIFACT_INDEX_FILE=""
RESULTS_MANIFEST_FILE=""
ISSUES_FILE=""
PCAP_FILE=""
PCAP_SIZE=""
ZIP_FILE=""

# Print a message to screen and append it to the report.
log_message() {
    local message="$1"
    echo "$message"
    echo "$message" >> "$REPORT_FILE"

    case "$message" in
        Warning:*|Error:*|Skipping*|*inconclusive*|[-]*)
            if [ -n "${ISSUES_FILE:-}" ]; then
                echo "$message" >> "$ISSUES_FILE"
            fi
            ;;
    esac
}

# Return a best-effort size in bytes for a file.
get_file_size_bytes() {
    local path="$1"

    if [ -f "$path" ]; then
        stat --format='%s' "$path" 2>/dev/null || echo 0
    else
        echo 0
    fi
}

# Record a file or directory result so the final report can summarize outputs cleanly.
record_artifact() {
    local label="$1"
    local path="$2"
    local artifact_type="$3"
    local status="$4"
    local note="${5:-}"
    local metric="0"

    if [ -z "${ARTIFACT_INDEX_FILE:-}" ]; then
        return 0
    fi

    if [ "$artifact_type" = "file" ]; then
        metric="$(get_file_size_bytes "$path")"
    elif [ "$artifact_type" = "directory" ] && [ -d "$path" ]; then
        metric="$(find "$path" -type f | wc -l | awk '{print $1}')"
    fi

    printf '%s\t%s\t%s\t%s\t%s\t%s\n' "$label" "$artifact_type" "$status" "$metric" "$path" "$note" >> "$ARTIFACT_INDEX_FILE"
}

# Write a manifest of result files saved under the case directory.
generate_results_manifest() {
    : > "$RESULTS_MANIFEST_FILE"

    while IFS= read -r -d '' result_file; do
        local relative_path size_bytes modified_time
        relative_path="${result_file#"$OUTPUT_DIR"/}"
        size_bytes="$(stat --format='%s' "$result_file" 2>/dev/null || echo 0)"
        modified_time="$(stat --format='%y' "$result_file" 2>/dev/null | cut -d'.' -f1)"
        printf '%s | %s bytes | %s\n' "$relative_path" "$size_bytes" "$modified_time" >> "$RESULTS_MANIFEST_FILE"
    done < <(find "$OUTPUT_DIR" -type f \
        ! -path "$RESULTS_MANIFEST_FILE" \
        ! -path "$ARTIFACT_INDEX_FILE" \
        ! -path "$ISSUES_FILE" \
        -print0)
}

# Append a structured result summary so the report includes names and extracted files.
write_report_summary() {
    local end_time="$1"
    local analysis_time="$2"
    local found_files="$3"
    local input_size="0"
    local foremost_files="0"
    local bulk_files="0"
    local registry_files="0"
    local strings_hits="0"
    local selected_volatility="Not run"

    input_size="$(get_file_size_bytes "$INPUT_FILE")"

    if [ -d "$OUTPUT_DIR/foremost" ]; then
        foremost_files="$(find "$OUTPUT_DIR/foremost" -type f | wc -l | awk '{print $1}')"
    fi

    if [ -d "$OUTPUT_DIR/bulk_extractor" ]; then
        bulk_files="$(find "$OUTPUT_DIR/bulk_extractor" -type f | wc -l | awk '{print $1}')"
    fi

    if [ -d "$OUTPUT_DIR/registry_hives" ]; then
        registry_files="$(find "$OUTPUT_DIR/registry_hives" -type f | wc -l | awk '{print $1}')"
    fi

    if [ -f "$OUTPUT_DIR/strings/strings_of_interest.txt" ]; then
        strings_hits="$(wc -l < "$OUTPUT_DIR/strings/strings_of_interest.txt" | awk '{print $1}')"
    fi

    if [ -n "${VOL_MODE:-}" ]; then
        selected_volatility="Volatility $VOL_MODE"
    fi

    generate_results_manifest
    record_artifact "results_inventory.txt" "$RESULTS_MANIFEST_FILE" "file" "created" "Case result inventory manifest"

    {
        echo
        echo "==================== Structured Report Summary ===================="
        echo "Case name: $(basename "$OUTPUT_DIR")"
        echo "Input file name: $(basename "$INPUT_FILE")"
        echo "Input file path: $INPUT_FILE"
        echo "Input file size (bytes): $input_size"
        echo "Analysis started: $(date -d "@$START_TIME" '+%Y-%m-%d %H:%M:%S')"
        echo "Analysis ended: $(date -d "@$end_time" '+%Y-%m-%d %H:%M:%S')"
        echo "Analysis duration (seconds): $analysis_time"
        echo "Selected memory analysis path: $selected_volatility"
        echo "Case output directory: $OUTPUT_DIR"
        echo
        echo "General statistics:"
        echo "- Total files found/created in case directory: $found_files"
        echo "- Foremost regular files: $foremost_files"
        echo "- Bulk Extractor regular files: $bulk_files"
        echo "- Registry hive files dumped: $registry_files"
        echo "- Strings-of-interest hits: $strings_hits"
        echo
        echo "Network traffic artifact:"
        if [ -n "${PCAP_FILE:-}" ] && [ -f "$PCAP_FILE" ]; then
            echo "- packets.pcap path: $PCAP_FILE"
            echo "- packets.pcap size: ${PCAP_SIZE:-unknown}"
        else
            echo "- packets.pcap: not found"
        fi
        echo
        echo "Key result files:"
        echo "- Report file: $REPORT_FILE"
        echo "- Results inventory manifest: $RESULTS_MANIFEST_FILE"
        echo "- Issues / skipped items log: $ISSUES_FILE"
        echo "- Planned zip file: $ZIP_FILE"
        echo
        echo "Artifact inventory:"
        if [ -s "$ARTIFACT_INDEX_FILE" ]; then
            while IFS=$'\t' read -r label artifact_type status metric path note; do
                if [ "$artifact_type" = "directory" ]; then
                    printf -- '- %s | %s | %s regular files | %s' "$label" "$status" "$metric" "$path"
                else
                    printf -- '- %s | %s | %s bytes | %s' "$label" "$status" "$metric" "$path"
                fi

                if [ -n "$note" ]; then
                    printf ' | %s' "$note"
                fi

                printf '\n'
            done < "$ARTIFACT_INDEX_FILE"
        else
            echo "- No artifacts were registered."
        fi
        echo
        echo "Failures / skipped items:"
        if [ -s "$ISSUES_FILE" ]; then
            sed 's/^/- /' "$ISSUES_FILE"
        else
            echo "- None recorded."
        fi
        echo
        echo "Extracted/result file inventory saved to: $RESULTS_MANIFEST_FILE"
    } >> "$REPORT_FILE"
}

# Stop early if the current user is not root.
check_root() {
    if [ "$(whoami)" != "root" ]; then
        echo "Error: This script must be run as root."
        exit 1
    fi
}

# Ask the user for an evidence file and keep prompting until it exists.
get_file() {
    read -r -p "Enter the file you want to analyze: " INPUT_FILE

    while [ ! -f "$INPUT_FILE" ]; do
        echo "Error: File '$INPUT_FILE' does not exist. Please try again."
        read -r -p "Enter the file you want to analyze: " INPUT_FILE
    done
    echo "File '$INPUT_FILE' exists. Proceeding with analysis..."
}

# Create a case output folder and the main report file.
make_output_dir() {
    BASENAME=$(basename "$INPUT_FILE")
    BASENAME="${BASENAME%.*}"
    OUTPUT_DIR="${BASENAME}_analysis_$(date +%Y%m%d_%H%M%S)"
    mkdir -p "$OUTPUT_DIR"
    echo "Results will be saved to: $OUTPUT_DIR"

    REPORT_FILE="$OUTPUT_DIR/report.txt"
    ARTIFACT_INDEX_FILE="$OUTPUT_DIR/artifact_inventory.tsv"
    RESULTS_MANIFEST_FILE="$OUTPUT_DIR/results_inventory.txt"
    ISSUES_FILE="$OUTPUT_DIR/failures_skipped.txt"

    : > "$REPORT_FILE"
    : > "$ARTIFACT_INDEX_FILE"
    : > "$RESULTS_MANIFEST_FILE"
    : > "$ISSUES_FILE"

    echo "Analysis started: $(date)" >> "$REPORT_FILE"
    echo "Input file: $INPUT_FILE" >> "$REPORT_FILE"
}

# Check whether a candidate Volatility launcher actually runs.
vol_cmd_works() {
    "$@" -h >/dev/null 2>&1 || "$@" --help >/dev/null 2>&1
}

version_lt() {
    [ "$(printf '%s\n%s\n' "$1" "$2" | sort -V | head -n1)" != "$2" ]
}

vol3_cli_version() {
    local version_text=""
    version_text=$("${VOL3_CMD[@]}" frameworkinfo 2>&1 || true)
    echo "$version_text" | grep -Eo 'Volatility 3 Framework [0-9]+\.[0-9]+\.[0-9]+' | awk '{print $4}' | head -n1
}

vol3_needs_upgrade() {
    local detected_version=""

    if [ "${#VOL3_CMD[@]}" -eq 0 ]; then
        return 1
    fi

    # If we are already using the managed local venv copy, do not force reinstall.
    if [[ "${VOL3_CMD[0]}" == "$VOL3_VENV/bin/"* ]]; then
        return 1
    fi

    detected_version="$(vol3_cli_version)"
    if [ -n "$detected_version" ] && version_lt "$detected_version" "$LATEST_VOL3_VERSION"; then
        return 0
    fi

    return 1
}

# Ensure a managed Python 2.7 runtime exists for Volatility 2.
# Do not treat the system python2 as sufficient for dependency repair.
ensure_pyenv_python2() {
    if [ -x "$LOCAL_PY2" ]; then
        return 0
    fi

    mkdir -p "$TOOLS_DIR"

    apt-get update > /dev/null 2>&1 || true
    apt-get install -y git curl build-essential libssl-dev zlib1g-dev \
        libbz2-dev libreadline-dev libsqlite3-dev libffi-dev xz-utils \
        tk-dev > /dev/null 2>&1 || true

    if [ ! -d "$PYENV_ROOT" ]; then
        log_message "Python 2 is not present. Installing pyenv for a local Python 2.7 runtime..."
        if ! curl -fsSL https://pyenv.run | bash > "$OUTPUT_DIR/pyenv_install_log.txt" 2>&1; then
            log_message "Warning: Failed to install pyenv automatically. Review $OUTPUT_DIR/pyenv_install_log.txt"
            return 1
        fi
    fi

    export PYENV_ROOT
    export PATH="$PYENV_ROOT/bin:$PATH"

    if [ ! -x "$LOCAL_PY2" ]; then
        log_message "Installing Python 2.7.18 locally for Volatility 2..."
        if ! CFLAGS="-std=c11" "$PYENV_ROOT/bin/pyenv" install -s 2.7.18 > "$OUTPUT_DIR/python2_install_log.txt" 2>&1; then
            log_message "Warning: Failed to install Python 2.7.18 automatically. Review $OUTPUT_DIR/python2_install_log.txt"
            return 1
        fi
    fi

    [ -x "$LOCAL_PY2" ]
}

install_vol2_dependencies() {
    local get_pip_file="$TOOLS_DIR/get-pip.py"

    if ! ensure_pyenv_python2; then
        log_message "Warning: Managed Python 2.7 is not available for Volatility 2 dependency repair."
        return 1
    fi

    if ! "$LOCAL_PY2" -m pip --version > /dev/null 2>&1; then
        log_message "Bootstrapping pip inside the managed Python 2.7 environment..."
        if ! curl -fsSL https://bootstrap.pypa.io/pip/2.7/get-pip.py -o "$get_pip_file" >> "$OUTPUT_DIR/volatility2_deps_log.txt" 2>&1; then
            log_message "Warning: Failed to download get-pip.py for managed Python 2.7. Review $OUTPUT_DIR/volatility2_deps_log.txt"
            return 1
        fi
        if ! "$LOCAL_PY2" "$get_pip_file" >> "$OUTPUT_DIR/volatility2_deps_log.txt" 2>&1; then
            log_message "Warning: Failed to bootstrap pip inside managed Python 2.7. Review $OUTPUT_DIR/volatility2_deps_log.txt"
            return 1
        fi
    fi

    if ! "$LOCAL_PY2" -m pip install --upgrade pip setuptools >> "$OUTPUT_DIR/volatility2_deps_log.txt" 2>&1; then
        log_message "Warning: Failed to bootstrap pip/setuptools for Volatility 2. Review $OUTPUT_DIR/volatility2_deps_log.txt"
        return 1
    fi

    if ! "$LOCAL_PY2" -m pip install pycrypto distorm3 >> "$OUTPUT_DIR/volatility2_deps_log.txt" 2>&1; then
        log_message "Warning: Failed to install Volatility 2 Python dependencies. Review $OUTPUT_DIR/volatility2_deps_log.txt"
        return 1
    fi

    return 0
}

vol2_needs_dependency_fix() {
    local check_file="$OUTPUT_DIR/vol2_dependency_check.txt"

    if [ "${#VOL2_CMD[@]}" -eq 0 ]; then
        return 1
    fi

    "${VOL2_CMD[@]}" --info > "$check_file" 2>&1 || true
    grep -Eq 'Crypto\.Hash|distorm3' "$check_file"
}

extract_vol2_hive_offsets() {
    VOL2_SYSTEM_HIVE=""
    VOL2_SAM_HIVE=""

    if [ ! -f "$OUTPUT_DIR/vol2_hivelist.txt" ]; then
        return 1
    fi

    VOL2_SYSTEM_HIVE="$(awk '
        {
            line=tolower($0)
            if ((line ~ /\\registry\\machine\\system$/) ||
                (line ~ /\\system32\\config\\system$/)) {
                print $1
                exit
            }
        }
    ' "$OUTPUT_DIR/vol2_hivelist.txt")"

    VOL2_SAM_HIVE="$(awk '
        {
            line=tolower($0)
            if ((line ~ /\\registry\\machine\\sam$/) ||
                (line ~ /\\system32\\config\\sam$/)) {
                print $1
                exit
            }
        }
    ' "$OUTPUT_DIR/vol2_hivelist.txt")"

    [ -n "$VOL2_SYSTEM_HIVE" ] && [ -n "$VOL2_SAM_HIVE" ]
}

vol2_hashdump_has_hashes() {
    local hash_file="$OUTPUT_DIR/vol2_hashdump.txt"

    [ -f "$hash_file" ] || return 1
    grep -Eq '^[^:]+:[0-9]+:[0-9A-Fa-f]{32}:[0-9A-Fa-f]{32}:::' "$hash_file"
}

# Install or update Volatility 2 from the official source into a local tools dir.
install_vol2() {
    mkdir -p "$TOOLS_DIR"

    log_message "Volatility 2 is not packaged in current Kali. Attempting a local source install..."

    apt-get update > /dev/null 2>&1 || true
    apt-get install -y git > /dev/null 2>&1 || true

    if [ -d "$VOL2_HOME/.git" ]; then
        if ! git -C "$VOL2_HOME" pull --ff-only > "$OUTPUT_DIR/volatility2_install_log.txt" 2>&1; then
            log_message "Warning: Failed to update Volatility 2. Review $OUTPUT_DIR/volatility2_install_log.txt"
            return 1
        fi
    else
        if ! git clone https://github.com/volatilityfoundation/volatility.git "$VOL2_HOME" > "$OUTPUT_DIR/volatility2_install_log.txt" 2>&1; then
            log_message "Warning: Failed to clone Volatility 2. Review $OUTPUT_DIR/volatility2_install_log.txt"
            return 1
        fi
    fi

    if ! ensure_pyenv_python2; then
        log_message "Warning: Volatility 2 source was prepared, but a working Python 2 runtime is not available."
        return 1
    fi

    if ! install_vol2_dependencies; then
        log_message "Warning: Volatility 2 launcher may work, but some plugins can still fail without required dependencies."
    fi

    resolve_volatility_tools
    if [ "$VOL2_AVAILABLE" -eq 1 ]; then
        log_message "Volatility 2 is now available from the local tools directory."
        return 0
    fi

    log_message "Warning: Volatility 2 installation completed, but no working launcher was detected."
    return 1
}

# Install Volatility 3 into a local virtual environment so the script can use
# a predictable and current launcher without depending on the system package set.
install_vol3() {
    mkdir -p "$TOOLS_DIR"

    if ! command -v python3 >/dev/null 2>&1; then
        log_message "Warning: python3 is not available, so Volatility 3 cannot be installed automatically."
        return 1
    fi

    apt-get update > /dev/null 2>&1 || true
    apt-get install -y python3-venv > /dev/null 2>&1 || true

    log_message "Attempting a local Volatility 3 install in $VOL3_VENV ..."

    if ! python3 -m venv "$VOL3_VENV" > "$OUTPUT_DIR/volatility3_install_log.txt" 2>&1; then
        log_message "Warning: Failed to create the Volatility 3 virtual environment. Review $OUTPUT_DIR/volatility3_install_log.txt"
        return 1
    fi

    if ! "$VOL3_VENV/bin/pip" install --upgrade pip volatility3 >> "$OUTPUT_DIR/volatility3_install_log.txt" 2>&1; then
        log_message "Warning: Failed to install Volatility 3. Review $OUTPUT_DIR/volatility3_install_log.txt"
        return 1
    fi

    resolve_volatility_tools
    if [ "$VOL3_AVAILABLE" -eq 1 ]; then
        log_message "Volatility 3 is now available from the local virtual environment."
        return 0
    fi

    log_message "Warning: Volatility 3 installation completed, but no working launcher was detected."
    return 1
}

# Cache the Volatility 3 plugin list and test whether a plugin is available.
vol3_has_plugin() {
    local plugin="$1"
    local plugin_list_file="$OUTPUT_DIR/vol3_plugins.txt"

    if [ ! -f "$plugin_list_file" ]; then
        "${VOL3_CMD[@]}" -h > "$plugin_list_file" 2>&1 || true
    fi

    grep -Fq "$plugin" "$plugin_list_file"
}

detect_vol3_hashdump_plugin() {
    local candidate

    for candidate in windows.registry.hashdump windows.hashdump; do
        if "${VOL3_CMD[@]}" "$candidate" -h > /dev/null 2>&1; then
            printf '%s
' "$candidate"
            return 0
        fi
    done

    return 1
}

# Detect supported Volatility launch methods present on the system.
resolve_volatility_tools() {
    VOL2_AVAILABLE=0
    VOL3_AVAILABLE=0
    VOL2_CMD=()
    VOL3_CMD=()

    if [ -x "$LOCAL_PY2" ] && [ -f "$VOL2_HOME/vol.py" ] && vol_cmd_works "$LOCAL_PY2" "$VOL2_HOME/vol.py"; then
        VOL2_CMD=("$LOCAL_PY2" "$VOL2_HOME/vol.py")
        VOL2_AVAILABLE=1
    elif [ -f "$VOL2_HOME/vol.py" ] && command -v python2 >/dev/null 2>&1 && vol_cmd_works python2 "$VOL2_HOME/vol.py"; then
        VOL2_CMD=("python2" "$VOL2_HOME/vol.py")
        VOL2_AVAILABLE=1
    elif [ -f "$VOL2_HOME/vol.py" ] && command -v python2.7 >/dev/null 2>&1 && vol_cmd_works python2.7 "$VOL2_HOME/vol.py"; then
        VOL2_CMD=("python2.7" "$VOL2_HOME/vol.py")
        VOL2_AVAILABLE=1
    elif [ -f "$VOL2_HOME/vol.py" ] && command -v python >/dev/null 2>&1 && vol_cmd_works python "$VOL2_HOME/vol.py"; then
        VOL2_CMD=("python" "$VOL2_HOME/vol.py")
        VOL2_AVAILABLE=1
    elif [ -x "./vol" ] && vol_cmd_works ./vol; then
        VOL2_CMD=("./vol")
        VOL2_AVAILABLE=1
    elif [ -f "./vol.py" ] && command -v python2 >/dev/null 2>&1 && vol_cmd_works python2 ./vol.py; then
        VOL2_CMD=("python2" "./vol.py")
        VOL2_AVAILABLE=1
    elif [ -f "./vol.py" ] && command -v python >/dev/null 2>&1 && vol_cmd_works python ./vol.py; then
        VOL2_CMD=("python" "./vol.py")
        VOL2_AVAILABLE=1
    elif command -v vol.py >/dev/null 2>&1 && command -v python2 >/dev/null 2>&1 && vol_cmd_works python2 "$(command -v vol.py)"; then
        VOL2_CMD=("python2" "$(command -v vol.py)")
        VOL2_AVAILABLE=1
    elif command -v vol.py >/dev/null 2>&1 && command -v python >/dev/null 2>&1 && vol_cmd_works python "$(command -v vol.py)"; then
        VOL2_CMD=("python" "$(command -v vol.py)")
        VOL2_AVAILABLE=1
    elif command -v volatility >/dev/null 2>&1 && vol_cmd_works volatility; then
        VOL2_CMD=("volatility")
        VOL2_AVAILABLE=1
    fi

    if [ -x "$VOL3_VENV/bin/vol" ] && vol_cmd_works "$VOL3_VENV/bin/vol"; then
        VOL3_CMD=("$VOL3_VENV/bin/vol")
        VOL3_AVAILABLE=1
    elif [ -x "$VOL3_VENV/bin/volatility3" ] && vol_cmd_works "$VOL3_VENV/bin/volatility3"; then
        VOL3_CMD=("$VOL3_VENV/bin/volatility3")
        VOL3_AVAILABLE=1
    elif command -v volatility3 >/dev/null 2>&1 && vol_cmd_works volatility3; then
        VOL3_CMD=("volatility3")
        VOL3_AVAILABLE=1
    elif command -v vol >/dev/null 2>&1 && vol_cmd_works vol; then
        VOL3_CMD=("vol")
        VOL3_AVAILABLE=1
    elif [ -f "./vol.py" ] && command -v python3 >/dev/null 2>&1 && vol_cmd_works python3 ./vol.py; then
        VOL3_CMD=("python3" "./vol.py")
        VOL3_AVAILABLE=1
    fi
}

# Check/install the main carving/string tools and detect Volatility availability.
install_tools() {
    echo "Checking if tools are installed..."
    echo "Checking if tools are installed..." >> "$REPORT_FILE"

    TOOLS="foremost bulk_extractor strings"

    for tool in $TOOLS; do
        if command -v "$tool" >/dev/null 2>&1; then
            echo "$tool is already installed"
            echo "$tool is already installed" >> "$REPORT_FILE"
        else
            echo "$tool is not installed, installing..."
            echo "$tool is not installed, installing..." >> "$REPORT_FILE"

            PACKAGE_NAME=""
            case $tool in
                "strings")
                    PACKAGE_NAME="binutils"
                    ;;
                "bulk_extractor")
                    PACKAGE_NAME="bulk-extractor"
                    ;;
                *)
                    PACKAGE_NAME="$tool"
                    ;;
            esac

            apt-get update > /dev/null 2>&1
            apt-get install -y "$PACKAGE_NAME" > /dev/null 2>&1

            echo "$tool installed successfully"
            echo "$tool installed successfully" >> "$REPORT_FILE"
        fi
    done

    resolve_volatility_tools

    if [ "$VOL2_AVAILABLE" -eq 1 ]; then
        echo "Volatility 2 detected."
        echo "Volatility 2 detected." >> "$REPORT_FILE"
        VOL2_DEPS_OK=1

        if vol2_needs_dependency_fix; then
            echo "Volatility 2 dependency issues detected. Attempting repair..."
            echo "Volatility 2 dependency issues detected. Attempting repair..." >> "$REPORT_FILE"

            if ensure_pyenv_python2 && install_vol2_dependencies; then
                resolve_volatility_tools
                if vol2_needs_dependency_fix; then
                    VOL2_DEPS_OK=0
                    echo "Warning: Volatility 2 still reports missing dependency imports. Review $OUTPUT_DIR/vol2_dependency_check.txt and $OUTPUT_DIR/volatility2_deps_log.txt"
                    echo "Warning: Volatility 2 still reports missing dependency imports. Review $OUTPUT_DIR/vol2_dependency_check.txt and $OUTPUT_DIR/volatility2_deps_log.txt" >> "$REPORT_FILE"
                else
                    VOL2_DEPS_OK=1
                    echo "Volatility 2 dependency repair completed."
                    echo "Volatility 2 dependency repair completed." >> "$REPORT_FILE"
                fi
            else
                VOL2_DEPS_OK=0
                echo "Warning: Volatility 2 dependency repair failed. Review $OUTPUT_DIR/volatility2_deps_log.txt"
                echo "Warning: Volatility 2 dependency repair failed. Review $OUTPUT_DIR/volatility2_deps_log.txt" >> "$REPORT_FILE"
            fi
        fi
    else
        echo "Volatility 2 not detected. Attempting local source install..."
        echo "Volatility 2 not detected. Attempting local source install..." >> "$REPORT_FILE"

        if ! install_vol2; then
            echo "Warning: Volatility 2 could not be installed automatically."
            echo "Warning: Volatility 2 could not be installed automatically." >> "$REPORT_FILE"
        fi

        resolve_volatility_tools

        if [ "$VOL2_AVAILABLE" -eq 1 ]; then
            echo "Volatility 2 detected after local install."
            echo "Volatility 2 detected after local install." >> "$REPORT_FILE"
            if vol2_needs_dependency_fix; then
                VOL2_DEPS_OK=0
                echo "Warning: Volatility 2 is installed, but dependency-sensitive plugins are still unhealthy."
                echo "Warning: Volatility 2 is installed, but dependency-sensitive plugins are still unhealthy." >> "$REPORT_FILE"
            else
                VOL2_DEPS_OK=1
            fi
        else
            echo "Volatility 2 is still not available."
            echo "Volatility 2 is still not available." >> "$REPORT_FILE"
        fi
    fi

    if [ "$VOL3_AVAILABLE" -eq 1 ]; then
        echo "Volatility 3 detected."
        echo "Volatility 3 detected." >> "$REPORT_FILE"

        if vol3_needs_upgrade; then
            echo "Detected an older system Volatility 3 install. Attempting managed local upgrade..."
            echo "Detected an older system Volatility 3 install. Attempting managed local upgrade..." >> "$REPORT_FILE"

            if ! install_vol3; then
                echo "Warning: Could not upgrade Volatility 3 automatically."
                echo "Warning: Could not upgrade Volatility 3 automatically." >> "$REPORT_FILE"
            fi

            resolve_volatility_tools
        fi
    else
        echo "Volatility 3 not detected. Attempting a local install..."
        echo "Volatility 3 not detected. Attempting a local install..." >> "$REPORT_FILE"

        if ! install_vol3; then
            echo "Warning: Could not install Volatility 3 automatically."
            echo "Warning: Could not install Volatility 3 automatically." >> "$REPORT_FILE"
        fi

        resolve_volatility_tools

        if [ "$VOL3_AVAILABLE" -eq 1 ]; then
            echo "Volatility 3 detected after local install."
            echo "Volatility 3 detected after local install." >> "$REPORT_FILE"
        else
            echo "Volatility 3 is still not available."
            echo "Volatility 3 is still not available." >> "$REPORT_FILE"
        fi
    fi
}

# Save command output to a file, but do not abort the whole script if a plugin fails.
run_and_save() {
    local output_file="$1"
    shift

    if "$@" > "$output_file" 2>&1; then
        log_message "Results saved to: $output_file"
        if [ -s "$output_file" ]; then
            record_artifact "$(basename "$output_file")" "$output_file" "file" "created" "Command output"
        else
            record_artifact "$(basename "$output_file")" "$output_file" "file" "empty" "Command output completed with an empty file"
        fi
        return 0
    else
        log_message "Warning: command failed. Review $output_file"
        record_artifact "$(basename "$output_file")" "$output_file" "file" "failed" "Command failed; review output for details"
        return 1
    fi
}

# Show a short preview of a required artifact on screen.
display_preview() {
    local title="$1"
    local output_file="$2"

    if [ -f "$output_file" ]; then
        echo "=== $title ==="
        head -n 20 "$output_file"
        echo
    else
        echo "No output file available for: $title"
        echo
    fi
}

# Check whether the input appears analyzable by Volatility and select mode.
select_volatility_mode() {
    VOL2_ANALYZABLE=0
    VOL3_ANALYZABLE=0

    if [ "$VOL2_AVAILABLE" -eq 1 ]; then
        IMAGE_INFO_OUTPUT=$("${VOL2_CMD[@]}" -f "$INPUT_FILE" imageinfo 2>&1 || true)
        echo "$IMAGE_INFO_OUTPUT" > "$OUTPUT_DIR/vol2_imageinfo.txt"

        if echo "$IMAGE_INFO_OUTPUT" | grep -Eq 'Suggested Profile\(s\)|AS Layer|KDBG|Image date and time'; then
            VOL2_ANALYZABLE=1
            log_message "Volatility 2 pre-check suggests the image is analyzable."
        else
            log_message "Volatility 2 pre-check was inconclusive. Review $OUTPUT_DIR/vol2_imageinfo.txt"
        fi
    fi

    if [ "$VOL3_AVAILABLE" -eq 1 ]; then
        if "${VOL3_CMD[@]}" -f "$INPUT_FILE" windows.info > "$OUTPUT_DIR/vol3_windows_info.txt" 2>&1; then
            VOL3_ANALYZABLE=1
            log_message "Volatility 3 pre-check suggests the image is analyzable."
        else
            log_message "Volatility 3 pre-check was inconclusive. Review $OUTPUT_DIR/vol3_windows_info.txt"
        fi
    fi

    if [ "$VOL2_ANALYZABLE" -eq 0 ] && [ "$VOL3_ANALYZABLE" -eq 0 ]; then
        if [ "$VOL2_AVAILABLE" -eq 0 ] && [ "$VOL3_AVAILABLE" -eq 0 ]; then
            log_message "Warning: No working Volatility launcher was detected. Skipping memory analysis."
            return 1
        fi

        log_message "Warning: Volatility pre-checks were inconclusive. Allowing manual mode selection from detected launchers."

        if [ "$VOL2_AVAILABLE" -eq 1 ] && [ "$VOL3_AVAILABLE" -eq 1 ]; then
            while true; do
                read -r -p "Choose Volatility mode (2 for Volatility 2, 3 for Volatility 3): " VOL_MODE
                case "$VOL_MODE" in
                    2|3)
                        break
                        ;;
                    *)
                        echo "Invalid choice. Please enter 2 or 3."
                        ;;
                esac
            done
        elif [ "$VOL2_AVAILABLE" -eq 1 ]; then
            VOL_MODE=2
            log_message "Only a working Volatility 2 launcher was detected. Using Volatility 2."
        else
            VOL_MODE=3
            log_message "Only a working Volatility 3 launcher was detected. Using Volatility 3."
        fi

        return 0
    fi

    if [ "$VOL2_ANALYZABLE" -eq 1 ] && [ "$VOL3_ANALYZABLE" -eq 1 ]; then
        while true; do
            read -r -p "Choose Volatility mode (2 for Volatility 2, 3 for Volatility 3): " VOL_MODE
            case "$VOL_MODE" in
                2|3)
                    break
                    ;;
                *)
                    echo "Invalid choice. Please enter 2 or 3."
                    ;;
            esac
        done
    elif [ "$VOL2_ANALYZABLE" -eq 1 ]; then
        VOL_MODE=2
        log_message "Only Volatility 2 appears analyzable. Using Volatility 2."
    else
        VOL_MODE=3
        log_message "Only Volatility 3 appears analyzable. Using Volatility 3."
    fi

    return 0
}

# Run the required Volatility 2 artifacts.
run_vol2() {
    log_message "=== Volatility 2 Analysis ==="
    log_message "Identifying memory profile..."

    IMAGE_INFO_OUTPUT=$("${VOL2_CMD[@]}" -f "$INPUT_FILE" imageinfo 2>&1 || true)
    echo "$IMAGE_INFO_OUTPUT" > "$OUTPUT_DIR/vol2_imageinfo.txt"
    record_artifact "vol2_imageinfo.txt" "$OUTPUT_DIR/vol2_imageinfo.txt" "file" "created" "Volatility 2 profile detection output"

    MEM_PROFILE=$(echo "$IMAGE_INFO_OUTPUT" | grep 'Suggested Profile(s)' | awk -F ':' '{print $2}' | awk '{print $1}' | sed 's/,//g' || true)

    if [ -z "$MEM_PROFILE" ]; then
        log_message "Error: Could not determine memory profile. Check $OUTPUT_DIR/vol2_imageinfo.txt for details."
        return
    else
        log_message "[*] Profile identified: $MEM_PROFILE"
    fi

    run_and_save "$OUTPUT_DIR/vol2_pslist.txt" "${VOL2_CMD[@]}" -f "$INPUT_FILE" --profile="$MEM_PROFILE" pslist

    : > "$OUTPUT_DIR/vol2_netscan.txt"
    : > "$OUTPUT_DIR/vol2_connscan.txt"

    if echo "$MEM_PROFILE" | grep -Eq '^(Vista|Win7|Win2008)'; then
        run_and_save "$OUTPUT_DIR/vol2_netscan.txt" "${VOL2_CMD[@]}" -f "$INPUT_FILE" --profile="$MEM_PROFILE" netscan
        log_message "Skipping connscan for profile $MEM_PROFILE because connscan is not supported on Vista/2008/7 profiles."
    elif echo "$MEM_PROFILE" | grep -Eq '^(WinXP|Win2003)'; then
        run_and_save "$OUTPUT_DIR/vol2_connscan.txt" "${VOL2_CMD[@]}" -f "$INPUT_FILE" --profile="$MEM_PROFILE" connscan
        log_message "Skipping netscan for profile $MEM_PROFILE because connscan is the profile-appropriate fallback for XP/2003."
    else
        run_and_save "$OUTPUT_DIR/vol2_netscan.txt" "${VOL2_CMD[@]}" -f "$INPUT_FILE" --profile="$MEM_PROFILE" netscan || true
        if [ ! -s "$OUTPUT_DIR/vol2_netscan.txt" ]; then
            run_and_save "$OUTPUT_DIR/vol2_connscan.txt" "${VOL2_CMD[@]}" -f "$INPUT_FILE" --profile="$MEM_PROFILE" connscan || true
        fi
    fi

    run_and_save "$OUTPUT_DIR/vol2_cmdline.txt" "${VOL2_CMD[@]}" -f "$INPUT_FILE" --profile="$MEM_PROFILE" cmdline
    run_and_save "$OUTPUT_DIR/vol2_cmdscan.txt" "${VOL2_CMD[@]}" -f "$INPUT_FILE" --profile="$MEM_PROFILE" cmdscan
    run_and_save "$OUTPUT_DIR/vol2_consoles.txt" "${VOL2_CMD[@]}" -f "$INPUT_FILE" --profile="$MEM_PROFILE" consoles
    run_and_save "$OUTPUT_DIR/vol2_dlllist.txt" "${VOL2_CMD[@]}" -f "$INPUT_FILE" --profile="$MEM_PROFILE" dlllist
    run_and_save "$OUTPUT_DIR/vol2_hivelist.txt" "${VOL2_CMD[@]}" -f "$INPUT_FILE" --profile="$MEM_PROFILE" hivelist

    if [ "$VOL2_DEPS_OK" -eq 1 ]; then
        if extract_vol2_hive_offsets; then
            run_and_save "$OUTPUT_DIR/vol2_hashdump.txt" "${VOL2_CMD[@]}" -f "$INPUT_FILE" --profile="$MEM_PROFILE" hashdump -y "$VOL2_SYSTEM_HIVE" -s "$VOL2_SAM_HIVE"

            if grep -Fq "Unable to read hashes from registry" "$OUTPUT_DIR/vol2_hashdump.txt"; then
                log_message "Warning: SYSTEM and SAM hives were found, but required registry keys may not be available in memory for hashdump."
            elif ! vol2_hashdump_has_hashes; then
                log_message "Warning: SYSTEM and SAM hive offsets were found, but hashdump did not return any account hashes."
            fi
        else
            : > "$OUTPUT_DIR/vol2_hashdump.txt"
            record_artifact "vol2_hashdump.txt" "$OUTPUT_DIR/vol2_hashdump.txt" "file" "skipped" "SYSTEM and/or SAM hive offsets were not found"
            log_message "Warning: Could not locate SYSTEM and/or SAM hive virtual offsets in $OUTPUT_DIR/vol2_hivelist.txt; skipping hashdump."
        fi

        run_and_save "$OUTPUT_DIR/vol2_getsids.txt" "${VOL2_CMD[@]}" -f "$INPUT_FILE" --profile="$MEM_PROFILE" getsids

        log_message "Attempting to dump registry hives..."
        mkdir -p "$OUTPUT_DIR/registry_hives"
        if "${VOL2_CMD[@]}" -f "$INPUT_FILE" --profile="$MEM_PROFILE" dumpregistry -D "$OUTPUT_DIR/registry_hives" > "$OUTPUT_DIR/vol2_dumpregistry_log.txt" 2>&1; then
            log_message "Registry hives saved to: $OUTPUT_DIR/registry_hives"
            record_artifact "registry_hives" "$OUTPUT_DIR/registry_hives" "directory" "created" "Dumped registry hives"
            record_artifact "vol2_dumpregistry_log.txt" "$OUTPUT_DIR/vol2_dumpregistry_log.txt" "file" "created" "Volatility 2 dumpregistry log"
        else
            record_artifact "vol2_dumpregistry_log.txt" "$OUTPUT_DIR/vol2_dumpregistry_log.txt" "file" "failed" "Volatility 2 dumpregistry log"
            log_message "Warning: Failed to dump registry hives. Review $OUTPUT_DIR/vol2_dumpregistry_log.txt"
        fi
    else
        : > "$OUTPUT_DIR/vol2_hashdump.txt"
        : > "$OUTPUT_DIR/vol2_getsids.txt"
        : > "$OUTPUT_DIR/vol2_dumpregistry_log.txt"
        record_artifact "vol2_hashdump.txt" "$OUTPUT_DIR/vol2_hashdump.txt" "file" "skipped" "Dependency repair did not succeed"
        record_artifact "vol2_getsids.txt" "$OUTPUT_DIR/vol2_getsids.txt" "file" "skipped" "Dependency repair did not succeed"
        record_artifact "vol2_dumpregistry_log.txt" "$OUTPUT_DIR/vol2_dumpregistry_log.txt" "file" "skipped" "Dependency repair did not succeed"
        log_message "Skipping hashdump, getsids, and dumpregistry because Volatility 2 dependency repair did not succeed."
    fi

    display_preview "Running Processes (Volatility 2)" "$OUTPUT_DIR/vol2_pslist.txt"

    if [ -s "$OUTPUT_DIR/vol2_netscan.txt" ]; then
        display_preview "Network Connections (Volatility 2)" "$OUTPUT_DIR/vol2_netscan.txt"
    else
        display_preview "Network Connections (Volatility 2)" "$OUTPUT_DIR/vol2_connscan.txt"
    fi

    if [ -s "$OUTPUT_DIR/vol2_cmdscan.txt" ]; then
        display_preview "Commands Executed (Volatility 2)" "$OUTPUT_DIR/vol2_cmdscan.txt"
    elif [ -s "$OUTPUT_DIR/vol2_cmdline.txt" ]; then
        display_preview "Commands Executed (Volatility 2)" "$OUTPUT_DIR/vol2_cmdline.txt"
    else
        display_preview "Commands Executed (Volatility 2)" "$OUTPUT_DIR/vol2_consoles.txt"
    fi

    display_preview "Hashes (Volatility 2)" "$OUTPUT_DIR/vol2_hashdump.txt"
}

# Run the-required Volatility 3 artifacts.
run_vol3() {
    log_message "=== Volatility 3 Analysis ==="
    local vol3_hashdump_plugin=""

    run_and_save "$OUTPUT_DIR/vol3_windows_info.txt" "${VOL3_CMD[@]}" -f "$INPUT_FILE" windows.info
    run_and_save "$OUTPUT_DIR/vol3_pslist.txt" "${VOL3_CMD[@]}" -f "$INPUT_FILE" windows.pslist
    run_and_save "$OUTPUT_DIR/vol3_netscan.txt" "${VOL3_CMD[@]}" -f "$INPUT_FILE" windows.netscan
    run_and_save "$OUTPUT_DIR/vol3_cmdline.txt" "${VOL3_CMD[@]}" -f "$INPUT_FILE" windows.cmdline

    if vol3_has_plugin "windows.cmdscan"; then
        run_and_save "$OUTPUT_DIR/vol3_cmdscan.txt" "${VOL3_CMD[@]}" -f "$INPUT_FILE" windows.cmdscan
    else
        : > "$OUTPUT_DIR/vol3_cmdscan.txt"
        log_message "Skipping windows.cmdscan: plugin not available in the installed Volatility 3 build."
    fi

    if vol3_has_plugin "windows.consoles"; then
        run_and_save "$OUTPUT_DIR/vol3_consoles.txt" "${VOL3_CMD[@]}" -f "$INPUT_FILE" windows.consoles
    else
        : > "$OUTPUT_DIR/vol3_consoles.txt"
        log_message "Skipping windows.consoles: plugin not available in the installed Volatility 3 build."
    fi

    run_and_save "$OUTPUT_DIR/vol3_dlllist.txt" "${VOL3_CMD[@]}" -f "$INPUT_FILE" windows.dlllist

    vol3_hashdump_plugin="$(detect_vol3_hashdump_plugin || true)"
    if [ -n "$vol3_hashdump_plugin" ]; then
        run_and_save "$OUTPUT_DIR/vol3_hashdump.txt" "${VOL3_CMD[@]}" -f "$INPUT_FILE" "$vol3_hashdump_plugin"
    else
        : > "$OUTPUT_DIR/vol3_hashdump.txt"
        log_message "Skipping Volatility 3 hashdump: no exposed hashdump plugin namespace was detected in the installed build."
    fi

    run_and_save "$OUTPUT_DIR/vol3_hivelist.txt" "${VOL3_CMD[@]}" -f "$INPUT_FILE" windows.registry.hivelist
    run_and_save "$OUTPUT_DIR/vol3_getsids.txt" "${VOL3_CMD[@]}" -f "$INPUT_FILE" windows.getsids

    display_preview "Running Processes (Volatility 3)" "$OUTPUT_DIR/vol3_pslist.txt"
    display_preview "Network Connections (Volatility 3)" "$OUTPUT_DIR/vol3_netscan.txt"

    if [ -s "$OUTPUT_DIR/vol3_cmdscan.txt" ]; then
        display_preview "Commands Executed (Volatility 3)" "$OUTPUT_DIR/vol3_cmdscan.txt"
    elif [ -s "$OUTPUT_DIR/vol3_cmdline.txt" ]; then
        display_preview "Commands Executed (Volatility 3)" "$OUTPUT_DIR/vol3_cmdline.txt"
    else
        display_preview "Commands Executed (Volatility 3)" "$OUTPUT_DIR/vol3_consoles.txt"
    fi

    display_preview "Hashes (Volatility 3)" "$OUTPUT_DIR/vol3_hashdump.txt"
}

# Run the selected Volatility path, or skip if the image is not analyzable.
run_vol() {
    log_message "=== Volatility Analysis ==="

    if ! select_volatility_mode; then
        return
    fi

    if [ "$VOL_MODE" = "2" ]; then
        run_vol2
    else
        run_vol3
    fi
}

# Run carving tools, check for PCAP output, and search strings for readable artifacts.
run_carvers() {
    log_message "=== Data Carving & Extraction ==="

    log_message "Running Foremost..."
    mkdir -p "$OUTPUT_DIR/foremost"
    foremost -i "$INPUT_FILE" -o "$OUTPUT_DIR/foremost" > "$OUTPUT_DIR/foremost_log.txt" 2>&1
    chmod -R 777 "$OUTPUT_DIR/foremost"
    record_artifact "foremost" "$OUTPUT_DIR/foremost" "directory" "created" "Foremost output directory"
    record_artifact "foremost_log.txt" "$OUTPUT_DIR/foremost_log.txt" "file" "created" "Foremost execution log"
    log_message "Foremost results saved to: $OUTPUT_DIR/foremost"

    log_message "Running Bulk Extractor..."
    mkdir -p "$OUTPUT_DIR/bulk_extractor"
    bulk_extractor -o "$OUTPUT_DIR/bulk_extractor" "$INPUT_FILE" > "$OUTPUT_DIR/bulk_extractor_log.txt" 2>&1
    record_artifact "bulk_extractor" "$OUTPUT_DIR/bulk_extractor" "directory" "created" "Bulk Extractor output directory"
    record_artifact "bulk_extractor_log.txt" "$OUTPUT_DIR/bulk_extractor_log.txt" "file" "created" "Bulk Extractor execution log"
    log_message "Bulk Extractor results saved to: $OUTPUT_DIR/bulk_extractor"

    log_message "Checking for extracted network traffic..."
    PCAP_FILE="$OUTPUT_DIR/bulk_extractor/packets.pcap"
    if [ -f "$PCAP_FILE" ]; then
        PCAP_SIZE=$(du -h "$PCAP_FILE" | awk '{print $1}')
        record_artifact "packets.pcap" "$PCAP_FILE" "file" "created" "Bulk Extractor network traffic output"
        MESSAGE="[*] Found pcap file: $PCAP_FILE (Size: $PCAP_SIZE)"
        log_message "$MESSAGE"
    else
        PCAP_FILE=""
        PCAP_SIZE=""
        MESSAGE="[-] No pcap file found by Bulk Extractor."
        log_message "$MESSAGE"
    fi

    log_message "Running Strings..."
    mkdir -p "$OUTPUT_DIR/strings"
    ALL_STRINGS_FILE="$OUTPUT_DIR/strings/all_strings.txt"
    strings "$INPUT_FILE" > "$ALL_STRINGS_FILE"
    record_artifact "all_strings.txt" "$ALL_STRINGS_FILE" "file" "created" "Full strings output"

    log_message "Searching for strings of interest..."
    STRINGS_OF_INTEREST_FILE="$OUTPUT_DIR/strings/strings_of_interest.txt"
    if grep -iE '(password|pass|passwd|pwd|username|user|login|secret|apikey|api_key|token|admin|\.exe|\.dll|\.bat|\.ps1|([0-9]{1,3}\.){3}[0-9]{1,3}|[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}|\.onion|tor|darkweb)' "$ALL_STRINGS_FILE" > "$STRINGS_OF_INTEREST_FILE"; then
        record_artifact "strings_of_interest.txt" "$STRINGS_OF_INTEREST_FILE" "file" "created" "Filtered strings hits"
        log_message "Strings of interest saved to: $STRINGS_OF_INTEREST_FILE"
    else
        : > "$STRINGS_OF_INTEREST_FILE"
        record_artifact "strings_of_interest.txt" "$STRINGS_OF_INTEREST_FILE" "file" "empty" "No strings matched the current pattern list"
        log_message "No strings of interest matched the current pattern list."
    fi
}

# Summarize the run and package all outputs into a zip file.
zip_results() {
    END_TIME=$(date +%s)
    ANALYSIS_TIME=$((END_TIME - START_TIME))
    ZIP_FILE="${OUTPUT_DIR}.zip"

    FOUND_FILES=$(find "$OUTPUT_DIR" -type f | wc -l | awk '{print $1}')
    write_report_summary "$END_TIME" "$ANALYSIS_TIME" "$FOUND_FILES"

    log_message "Total analysis time: $ANALYSIS_TIME seconds."
    log_message "Total files found/created: $FOUND_FILES"
    log_message "Report written to: $REPORT_FILE"

    echo "Zipping results..."

    if (cd "$OUTPUT_DIR" && zip -r "../$ZIP_FILE" ./*) > /dev/null 2>&1; then
        ZIP_SIZE=$(du -h "$ZIP_FILE" | awk '{print $1}')
        log_message "[*] Results zipped to: $ZIP_FILE"
        log_message "[*] Zip size: $ZIP_SIZE"
    else
        log_message "Error: Failed to create zip file."
    fi

    log_message "=== Analysis Complete ==="
}

# Credits:
# - Volatility 2 plugin naming and imageinfo usage were aligned with the official
#   command reference: https://github.com/volatilityfoundation/volatility/wiki/command-reference
# - Volatility 3 plugin naming was aligned with the official documentation:
#   https://volatility3.readthedocs.io/en/latest/

check_root
get_file
make_output_dir
install_tools
run_vol
run_carvers
zip_results
