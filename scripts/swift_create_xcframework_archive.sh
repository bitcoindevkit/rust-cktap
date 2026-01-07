#!/bin/bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
XCFRAMEWORK_PATH="${ROOT_DIR}/cktap-swift/cktapFFI.xcframework"
ZIP_PATH="${ROOT_DIR}/cktap-swift/cktapFFI.xcframework.zip"

if [ ! -d "${XCFRAMEWORK_PATH}" ]; then
    echo "Missing xcframework at ${XCFRAMEWORK_PATH}" >&2
    exit 1
fi

ditto -c -k --sequesterRsrc --keepParent "${XCFRAMEWORK_PATH}" "${ZIP_PATH}"
CHECKSUM="$(swift package compute-checksum "${ZIP_PATH}")"
echo "New checksum: ${CHECKSUM}"

python3 "${ROOT_DIR}/scripts/swift_update_package_checksum.py" --checksum "${CHECKSUM}"
