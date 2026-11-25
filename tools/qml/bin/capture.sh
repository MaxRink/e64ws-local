#!/bin/bash
# Capture a set of vendor screens with the stub backend.
set -u
cd /tmp/qml-recon
for entry in "$@"; do
  name=${entry%%|*}
  rest=${entry#*|}
  printf '%s\n' "$rest" > payload/scene.txt
  echo "### $name"
  ./bin/run_vm.sh payload "out_$name" 2>&1 | grep -E "saved|scene|CRT|WRN.*MainItem" | head -4
  if [ -f "out_$name/shot_2.png" ]; then cp "out_$name/shot_2.png" "shots/$name.png"; fi
done
rm -f payload/scene.txt
ls -la shots
