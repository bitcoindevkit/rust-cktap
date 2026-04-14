#!/bin/bash

if [ -z "$ANDROID_NDK_ROOT" ]; then
    echo "Error: ANDROID_NDK_ROOT is not defined in your environment"
    exit 1
fi

PATH="$ANDROID_NDK_ROOT/toolchains/llvm/prebuilt/darwin-x86_64/bin:$PATH"
CFLAGS="-D__ANDROID_MIN_SDK_VERSION__=24"
AR="llvm-ar"
LIB_NAME="libcktap_ffi.so"
FFI_PKG_NAME="cktap-ffi"
COMPILATION_TARGET_ARM64_V8A="aarch64-linux-android"
RESOURCE_DIR_ARM64_V8A="arm64-v8a"

# Move to the Rust library directory
cd ../cktap-ffi/ || exit
rustup target add $COMPILATION_TARGET_ARM64_V8A

# Build the binary (debug mode, single arch)
CC="aarch64-linux-android24-clang" CARGO_TARGET_AARCH64_LINUX_ANDROID_LINKER="aarch64-linux-android24-clang" \
    cargo build --package ${FFI_PKG_NAME} --target $COMPILATION_TARGET_ARM64_V8A

# Copy the binary to the resource directory
mkdir -p ../cktap-android/lib/src/main/jniLibs/$RESOURCE_DIR_ARM64_V8A/
cp ../target/$COMPILATION_TARGET_ARM64_V8A/debug/$LIB_NAME ../cktap-android/lib/src/main/jniLibs/$RESOURCE_DIR_ARM64_V8A/

# Generate Kotlin bindings using cktap-uniffi-bindgen with android-specific config
cargo run --package ${FFI_PKG_NAME} --bin cktap-uniffi-bindgen generate \
    --library ../target/$COMPILATION_TARGET_ARM64_V8A/debug/$LIB_NAME \
    --language kotlin \
    --out-dir ../cktap-android/lib/src/main/kotlin/ \
    --config uniffi-android.toml \
    --no-format
