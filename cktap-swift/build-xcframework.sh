#!/bin/bash

#
# Copyright (c) 2025 rust-cktap contributors
# SPDX-License-Identifier: MIT OR Apache-2.0
#

# This script builds local cktap Swift language bindings and corresponding cktapFFI.xcframework.

TARGETDIR="../target"
OUTDIR="."
RELDIR="release-smaller"

FFI_LIB_NAME="cktap_ffi"
FFI_PKG_NAME="cktap-ffi"

DYLIB_FILENAME="lib${FFI_LIB_NAME}.dylib"
HEADER_BASENAME="${FFI_LIB_NAME}FFI"
HEADER_FILENAME="${HEADER_BASENAME}.h"
MODULEMAP_FILENAME="module.modulemap"
GENERATED_MODULEMAP="${FFI_LIB_NAME}FFI.modulemap"

NAME="cktapFFI"
STATIC_LIB_FILENAME="lib${FFI_LIB_NAME}.a"
NEW_HEADER_DIR="${TARGETDIR}/include"

# set required rust version and install component and targets
rustup default 1.85.0
rustup component add rust-src
rustup target add aarch64-apple-ios # iOS arm64
rustup target add x86_64-apple-ios # iOS x86_64
rustup target add aarch64-apple-ios-sim # simulator mac M1
rustup target add aarch64-apple-darwin # mac M1
rustup target add x86_64-apple-darwin # mac x86_64

# Create all required directories first
mkdir -p Sources/CKTap
mkdir -p ${TARGETDIR}/include
mkdir -p ${TARGETDIR}/lipo-macos/${RELDIR}
mkdir -p ${TARGETDIR}/lipo-ios-sim/${RELDIR}

#cd ../ || exit

# Target architectures
# macOS Intel
cargo build --package ${FFI_PKG_NAME} --profile ${RELDIR} --target x86_64-apple-darwin
# macOS Apple Silicon
cargo build --package ${FFI_PKG_NAME} --profile ${RELDIR} --target aarch64-apple-darwin
# Simulator on Intel Macs
cargo build --package ${FFI_PKG_NAME} --profile ${RELDIR} --target x86_64-apple-ios
# Simulator on Apple Silicon Mac
cargo build --package ${FFI_PKG_NAME} --profile ${RELDIR} --target aarch64-apple-ios-sim
# iPhone devices
cargo build --package ${FFI_PKG_NAME} --profile ${RELDIR} --target aarch64-apple-ios

# Then run uniffi-bindgen
cargo run --package ${FFI_PKG_NAME} --bin cktap-uniffi-bindgen generate \
    --library ${TARGETDIR}/aarch64-apple-ios/${RELDIR}/${DYLIB_FILENAME} \
    --language swift \
    --out-dir ./Sources/CKTap \
    --no-format

# Create universal library for simulator targets
lipo ${TARGETDIR}/aarch64-apple-ios-sim/${RELDIR}/${STATIC_LIB_FILENAME} \
     ${TARGETDIR}/x86_64-apple-ios/${RELDIR}/${STATIC_LIB_FILENAME} \
     -create -output ${TARGETDIR}/lipo-ios-sim/${RELDIR}/${STATIC_LIB_FILENAME}

# Create universal library for mac targets
lipo ${TARGETDIR}/aarch64-apple-darwin/${RELDIR}/${STATIC_LIB_FILENAME} \
     ${TARGETDIR}/x86_64-apple-darwin/${RELDIR}/${STATIC_LIB_FILENAME} \
     -create -output ${TARGETDIR}/lipo-macos/${RELDIR}/${STATIC_LIB_FILENAME}

#cd cktap-swift || exit

# Unique subdir to prevent collisions
UNIQUE_HEADER_SUBDIR="${NEW_HEADER_DIR}/${HEADER_BASENAME}"

# Remove any previously generated headers to avoid duplicate module.modulemap files
rm -rf "${NEW_HEADER_DIR:?}"/*

mkdir -p "${UNIQUE_HEADER_SUBDIR}"

# Move the header file into the unique subdirectory
if [ -f "Sources/CKTap/${HEADER_FILENAME}" ]; then
    mv "Sources/CKTap/${HEADER_FILENAME}" "${UNIQUE_HEADER_SUBDIR}/"
else
    echo "Warning: Could not find header file Sources/CKTap/${HEADER_FILENAME}"
fi

# Handle modulemap using the correct filename pattern, placed inside unique subdirectory
if [ -f "Sources/CKTap/${GENERATED_MODULEMAP}" ]; then
    mv "Sources/CKTap/${GENERATED_MODULEMAP}" "${UNIQUE_HEADER_SUBDIR}/${MODULEMAP_FILENAME}"
else
    echo "Creating a standard module map."
    echo "framework module ${NAME} { umbrella header \"${HEADER_FILENAME}\" export * }" > "${UNIQUE_HEADER_SUBDIR}/${MODULEMAP_FILENAME}"
fi


# remove old xcframework directory
rm -rf "${OUTDIR}/${NAME}.xcframework"

# create new xcframework directory from cktap-ffi static libs and headers
xcodebuild -create-xcframework \
    -library "${TARGETDIR}/lipo-macos/${RELDIR}/${STATIC_LIB_FILENAME}" \
    -headers "${NEW_HEADER_DIR}" \
    -library "${TARGETDIR}/aarch64-apple-ios/${RELDIR}/${STATIC_LIB_FILENAME}" \
    -headers "${NEW_HEADER_DIR}" \
    -library "${TARGETDIR}/lipo-ios-sim/${RELDIR}/${STATIC_LIB_FILENAME}" \
    -headers "${NEW_HEADER_DIR}" \
    -output "${OUTDIR}/${NAME}.xcframework"

echo "Building Swift package completed."

