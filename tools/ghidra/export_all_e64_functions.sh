#!/usr/bin/env bash
# Run the exhaustive function inventory/decompiler pass for every supplied
# E64 ELF. Raw C output is intentionally kept under /private/tmp by default.

set -euo pipefail

workspace_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
ghidra_home="${GHIDRA_HOME:-$workspace_root/.tools/ghidra_12.1.3_PUBLIC}"
firmware_root="${E64_FIRMWARE_ROOT:-$workspace_root/.tools/firmware-1.16-24}"
project_dir_root="${E64_FULL_GHIDRA_PROJECT_DIR:-/private/tmp/mahlkoenig-ghidra-full-project}"
project_name="${E64_FULL_GHIDRA_PROJECT_NAME:-E64FullInventory}"
output_root="${E64_FULL_DECOMP_ROOT:-/private/tmp/mahlkoenig-e64-full-decomp}"
ghidra_user_home="${E64_GHIDRA_USER_HOME:-/private/tmp/mahlkoenig-ghidra-user}"

headless="$ghidra_home/support/analyzeHeadless"
script_dir="$workspace_root/tools/ghidra"
mkdir -p "$output_root" "$project_dir_root"
mkdir -p "$ghidra_user_home"
export GHIDRA_JAVA_OPTIONS="${GHIDRA_JAVA_OPTIONS:-} -Duser.home=$ghidra_user_home"
export JAVA_TOOL_OPTIONS="${JAVA_TOOL_OPTIONS:-} -Duser.home=$ghidra_user_home"

targets=(
  "$firmware_root/app-tree/bin/libNgxUi.so"
  "$firmware_root/app-tree/bin/EspWifiConfig"
  "$firmware_root/app-tree/bin/NgxUiApp"
  "$firmware_root/app-tree/bin/NgxWsClient"
)

for target in "${targets[@]}"; do
  if [[ ! -f "$target" ]]; then
    echo "missing target: $target" >&2
    exit 1
  fi
done

for target in "${targets[@]}"; do
  name="$(basename "$target")"
  safe_name="${name//[^A-Za-z0-9_.-]/_}"
  inventory="$output_root/$safe_name.csv"
  decomp="$output_root/$safe_name"
  # Keep each input in its own project.  Ghidra's -process mode only sees
  # programs already imported into that project; using one project per binary
  # makes the pass independently resumable and avoids silently skipping the
  # later firmware executables after the first import.
  project_dir="$project_dir_root/$safe_name-project"
  mkdir -p "$project_dir"
  marker="$project_dir/$project_name.gpr"
  if [[ ! -e "$inventory" || ! -e "$marker" && ! -e "$project_dir/$project_name.rep" ]]; then
    "$headless" "$project_dir" "$project_name" \
      -import "$target" \
      -overwrite \
      -scriptPath "$script_dir" \
      -postScript ExportE64FunctionInventory.java "output=$inventory" "decomp=$decomp"
  else
    echo "already exported: $name"
  fi
done

echo "full inventory/decompilation output: $output_root"
