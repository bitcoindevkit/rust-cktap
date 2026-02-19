// swift-tools-version:6.0
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

// Update tag and checksum when publishing a new Swift binary release.
let tag = "v0.2.0"
let checksum = "26e1419b0408a12c11c99fb3cec10b336f97b34eaf7fa8b708ae814cec9842d3"
let url = "https://github.com/bitcoindevkit/rust-cktap/releases/download/\(tag)/cktapFFI.xcframework.zip"

let package = Package(
    name: "rust-cktap",
    platforms: [
        .macOS(.v12),
        .iOS(.v18),
    ],
    products: [
        .library(
            name: "CKTap",
            targets: ["cktapFFI", "CKTap"]
        ),
    ],
    targets: [
        .target(
            name: "CKTap",
            dependencies: ["cktapFFI"],
            path: "./cktap-swift/Sources"
        ),
        .binaryTarget(
            name: "cktapFFI",
            url: url,
            checksum: checksum
        ),
    ]
)
