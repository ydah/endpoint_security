#!/bin/sh
set -eu

source_ruby=${1:?ruby executable is required}
identity=${2:--}
project_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
destination="$project_root/build/es-ruby"

mkdir -p "$project_root/build"
cp "$source_ruby" "$destination"
codesign --force --options runtime --entitlements "$project_root/support/entitlements.plist" --sign "$identity" "$destination"
codesign --verify --strict --verbose=2 "$destination"
codesign -d --entitlements - "$destination"
