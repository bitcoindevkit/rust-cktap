# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.4.0](https://github.com/bitcoindevkit/rust-cktap/compare/rust-cktap-v0.3.0...rust-cktap-v0.4.0) - 2026-09-21

### Other

- Preserve typed errors across the FFI
- Preserve typed APDU errors
- Harden CVC authentication flows

## [0.3.0](https://github.com/bitcoindevkit/rust-cktap/compare/rust-cktap-v0.2.2...rust-cktap-v0.3.0) - 2026-09-11

### Fixed

- preserve card nonce after invalid signature
- counterfeit TAPSIGNER detection
- [**breaking**] increase ChangeError len values to u32
- [**breaking**] replace usize with u32 or smaller
- [**breaking**] change auth_delay to return u8

### Other

- replace notmandatory with bitcoindevkit
