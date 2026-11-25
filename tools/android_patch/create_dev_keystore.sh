#!/bin/sh
set -eu

if [ "$#" -ne 1 ]; then
  echo "usage: $0 OUTPUT_KEYSTORE" >&2
  exit 2
fi

if [ -e "$1" ]; then
  echo "refusing to overwrite existing keystore: $1" >&2
  exit 2
fi

keytool -genkeypair -noprompt \
  -keystore "$1" \
  -storepass android \
  -keypass android \
  -alias androiddebugkey \
  -dname "CN=Android Local Patch Development,O=Local Development,C=DE" \
  -keyalg RSA \
  -keysize 2048 \
  -validity 3650

echo "development keystore created at $1"
