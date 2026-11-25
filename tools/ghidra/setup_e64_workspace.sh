#!/usr/bin/env bash
# Reproducible, non-destructive Ghidra workspace setup for the supplied E64 WS
# image. The project database stays outside Git; the annotation Java script is
# the portable source of truth.

set -euo pipefail

workspace_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
ghidra_home="${GHIDRA_HOME:-$workspace_root/.tools/ghidra_12.1.3_PUBLIC}"
project_dir="${E64_GHIDRA_PROJECT_DIR:-/private/tmp/mahlkoenig-ghidra-project}"
project_name="${E64_GHIDRA_PROJECT_NAME:-E64Protocol}"
main_elf="${E64_MAIN_ELF:-$workspace_root/.tools/firmware-1.16-24/app-tree/bin/libNgxUi.so}"
elf_offset="${E64_GHIDRA_ELF_OFFSET:-0x10000}"
reuse_project=0

usage() {
    cat <<'EOF'
Usage: tools/ghidra/setup_e64_workspace.sh [options]

Options:
  --ghidra DIR       Ghidra installation (default: .tools/ghidra_12.1.3_PUBLIC)
  --project DIR      project directory (default: /private/tmp/mahlkoenig-ghidra-project)
  --name NAME        project name (default: E64Protocol)
  --main ELF         main libNgxUi.so (default: ignored firmware extraction)
  --elf-offset N     Ghidra image-base offset (default: 0x10000)
  --reuse            re-open an existing project/program and reapply annotations
  --help             show this help

The script never deletes an existing project. Use --reuse for iterative work.
Other ELFs can be imported into the same project from the Ghidra GUI or with
the follow-up commands in docs/GHIDRA_WORKSPACE.md.
EOF
}

while (($# > 0)); do
    case "$1" in
        --ghidra) ghidra_home="$2"; shift 2 ;;
        --project) project_dir="$2"; shift 2 ;;
        --name) project_name="$2"; shift 2 ;;
        --main) main_elf="$2"; shift 2 ;;
        --elf-offset) elf_offset="$2"; shift 2 ;;
        --reuse) reuse_project=1; shift ;;
        --help) usage; exit 0 ;;
        *) usage >&2; exit 2 ;;
    esac
done

headless="$ghidra_home/support/analyzeHeadless"
if [[ ! -x "$headless" ]]; then
    echo "Ghidra headless launcher not found or not executable: $headless" >&2
    exit 1
fi
if [[ ! -f "$main_elf" ]]; then
    echo "Main ELF not found: $main_elf" >&2
    echo "Place the ignored firmware extraction at .tools/firmware-1.16-24 or pass --main." >&2
    exit 1
fi

project_marker="$project_dir/$project_name.gpr"
project_rep="$project_dir/$project_name.rep"
if [[ $reuse_project -eq 0 && ( -e "$project_marker" || -e "$project_rep" ) ]]; then
    echo "Project already exists; use --reuse to annotate it: $project_dir/$project_name" >&2
    exit 1
fi

mkdir -p "$project_dir"

if [[ $reuse_project -eq 1 ]]; then
    "$headless" "$project_dir" "$project_name" \
        -process "$(basename "$main_elf")" \
        -scriptPath "$workspace_root/tools/ghidra" \
        -postScript ApplyE64RecoveredAnnotations.java "elf-offset=$elf_offset"
else
    "$headless" "$project_dir" "$project_name" \
        -import "$main_elf" \
        -scriptPath "$workspace_root/tools/ghidra" \
        -postScript ApplyE64RecoveredAnnotations.java "elf-offset=$elf_offset"
fi

cat <<EOF

Ghidra project ready:
  directory: $project_dir
  project:   $project_name
  program:   $(basename "$main_elf")
  offset:    $elf_offset

Open it with:
  "$ghidra_home/ghidraRun" "$project_dir/$project_name.gpr"

The annotation pass is repeatable. Keep the project database out of Git and
record substantive discoveries in docs/ and src/recovered/.
EOF
