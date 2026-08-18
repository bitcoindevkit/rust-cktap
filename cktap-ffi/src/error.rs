// Copyright (c) 2025 rust-cktap contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::fmt::Debug;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, uniffi::Error)]
pub enum KeyError {
    #[error("Secp256k1 error: {msg}")]
    Secp256k1 { msg: String },
    #[error("Key from slice error: {msg}")]
    KeyFromSlice { msg: String },
}

impl From<rust_cktap::SecpError> for KeyError {
    fn from(value: rust_cktap::SecpError) -> Self {
        KeyError::Secp256k1 {
            msg: value.to_string(),
        }
    }
}

impl From<rust_cktap::FromSliceError> for KeyError {
    fn from(value: rust_cktap::FromSliceError) -> Self {
        KeyError::KeyFromSlice {
            msg: value.to_string(),
        }
    }
}

/// Errors returned when a CVC does not satisfy its local constraints
#[derive(Debug, Copy, Clone, PartialEq, Eq, thiserror::Error, uniffi::Error)]
pub enum CvcError {
    /// The CVC contains fewer than six bytes
    #[error("CVC is too short: {length} bytes; minimum is 6")]
    TooShort { length: u32 },
    /// The CVC contains more than 32 bytes
    #[error("CVC is too long: {length} bytes; maximum is 32")]
    TooLong { length: u32 },
    /// The CVC contains a byte that is not an ASCII digit
    #[error("CVC contains a byte that is not an ASCII digit at byte index {index}")]
    NonAsciiDigit { index: u32 },
}

impl From<rust_cktap::CvcError> for CvcError {
    fn from(value: rust_cktap::CvcError) -> Self {
        match value {
            rust_cktap::CvcError::TooShort { length } => Self::TooShort {
                length: u32::try_from(length).unwrap_or(u32::MAX),
            },
            rust_cktap::CvcError::TooLong { length } => Self::TooLong {
                length: u32::try_from(length).unwrap_or(u32::MAX),
            },
            rust_cktap::CvcError::NonAsciiDigit { index } => Self::NonAsciiDigit {
                index: u32::try_from(index).unwrap_or(u32::MAX),
            },
        }
    }
}

/// Errors returned by the CkTap card.
#[derive(Debug, Copy, Clone, PartialEq, Eq, thiserror::Error, uniffi::Error)]
pub enum CardError {
    #[error("Rare or unlucky value used/occurred. Start again")]
    UnluckyNumber,
    #[error("Invalid/incorrect/incomplete arguments provided to command")]
    BadArguments,
    #[error("Authentication details (CVC/epubkey) are wrong")]
    BadAuth,
    #[error("Command requires auth, and none was provided")]
    NeedsAuth,
    #[error("The 'cmd' field is an unsupported command")]
    UnknownCommand,
    #[error("Command is not valid at this time, no point retrying")]
    InvalidCommand,
    #[error("You can't do that right now when card is in this state")]
    InvalidState,
    #[error("Nonce is not unique-looking enough")]
    WeakNonce,
    #[error("Unable to decode CBOR data stream")]
    BadCBOR,
    #[error("Can't change CVC without doing a backup first")]
    BackupFirst,
    #[error("Due to auth failures, delay required")]
    RateLimited,
}

impl From<rust_cktap::CardError> for CardError {
    fn from(value: rust_cktap::CardError) -> Self {
        match value {
            rust_cktap::CardError::UnluckyNumber => CardError::UnluckyNumber,
            rust_cktap::CardError::BadArguments => CardError::BadArguments,
            rust_cktap::CardError::BadAuth => CardError::BadAuth,
            rust_cktap::CardError::NeedsAuth => CardError::NeedsAuth,
            rust_cktap::CardError::UnknownCommand => CardError::UnknownCommand,
            rust_cktap::CardError::InvalidCommand => CardError::InvalidCommand,
            rust_cktap::CardError::InvalidState => CardError::InvalidState,
            rust_cktap::CardError::WeakNonce => CardError::WeakNonce,
            rust_cktap::CardError::BadCBOR => CardError::BadCBOR,
            rust_cktap::CardError::BackupFirst => CardError::BackupFirst,
            rust_cktap::CardError::RateLimited => CardError::RateLimited,
        }
    }
}

impl From<CardError> for rust_cktap::CardError {
    fn from(value: CardError) -> Self {
        match value {
            CardError::UnluckyNumber => Self::UnluckyNumber,
            CardError::BadArguments => Self::BadArguments,
            CardError::BadAuth => Self::BadAuth,
            CardError::NeedsAuth => Self::NeedsAuth,
            CardError::UnknownCommand => Self::UnknownCommand,
            CardError::InvalidCommand => Self::InvalidCommand,
            CardError::InvalidState => Self::InvalidState,
            CardError::WeakNonce => Self::WeakNonce,
            CardError::BadCBOR => Self::BadCBOR,
            CardError::BackupFirst => Self::BackupFirst,
            CardError::RateLimited => Self::RateLimited,
        }
    }
}

/// Errors returned by the card, CBOR deserialization or value encoding, or the APDU transport.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, uniffi::Error)]
pub enum CkTapError {
    #[error(transparent)]
    Card { err: CardError },
    #[error("CBOR deserialization error: {msg}")]
    CborDe { msg: String },
    #[error("CBOR value error: {msg}")]
    CborValue { msg: String },
    #[error("APDU transport error: {msg}")]
    Transport { msg: String },
    #[error("Unknown card error code ({code}): {message}")]
    UnknownErrorCode { code: u16, message: String },
    #[error("Unknown card type")]
    UnknownCardType,
}

impl From<rust_cktap::CkTapError> for CkTapError {
    fn from(value: rust_cktap::CkTapError) -> Self {
        match value {
            rust_cktap::CkTapError::Card(err) => CkTapError::Card { err: err.into() },
            rust_cktap::CkTapError::CborDe(msg) => CkTapError::CborDe { msg },
            rust_cktap::CkTapError::CborValue(msg) => CkTapError::CborValue { msg },
            rust_cktap::CkTapError::Transport(msg) => CkTapError::Transport { msg },
            rust_cktap::CkTapError::UnknownErrorCode { code, message } => {
                CkTapError::UnknownErrorCode { code, message }
            }
            rust_cktap::CkTapError::UnknownCardType => CkTapError::UnknownCardType,
        }
    }
}

impl From<CkTapError> for rust_cktap::CkTapError {
    fn from(value: CkTapError) -> Self {
        match value {
            CkTapError::Card { err } => Self::Card(err.into()),
            CkTapError::CborDe { msg } => Self::CborDe(msg),
            CkTapError::CborValue { msg } => Self::CborValue(msg),
            CkTapError::Transport { msg } => Self::Transport(msg),
            CkTapError::UnknownErrorCode { code, message } => {
                Self::UnknownErrorCode { code, message }
            }
            CkTapError::UnknownCardType => Self::UnknownCardType,
        }
    }
}

/// Errors returned by the `status` command.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, uniffi::Error)]
pub enum StatusError {
    #[error(transparent)]
    CkTap {
        #[from]
        err: CkTapError,
    },
    #[error(transparent)]
    Key {
        #[from]
        err: KeyError,
    },
}

/// Errors returned by the `init` command
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, uniffi::Error)]
pub enum InitError {
    /// The card or transport rejected the command
    #[error(transparent)]
    CkTap {
        #[from]
        err: CkTapError,
    },
    /// The CVC failed local validation
    #[error(transparent)]
    Cvc {
        #[from]
        err: CvcError,
    },
}

impl From<rust_cktap::StatusError> for StatusError {
    fn from(value: rust_cktap::StatusError) -> Self {
        match value {
            rust_cktap::StatusError::CkTap(err) => StatusError::CkTap { err: err.into() },
            rust_cktap::StatusError::KeyFromSlice(err) => StatusError::Key { err: err.into() },
        }
    }
}

/// Errors returned by the `read` command.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, uniffi::Error)]
pub enum ReadError {
    #[error(transparent)]
    CkTap {
        #[from]
        err: CkTapError,
    },
    #[error(transparent)]
    Key {
        #[from]
        err: KeyError,
    },
    /// The CVC failed local validation
    #[error(transparent)]
    Cvc {
        #[from]
        err: CvcError,
    },
}

impl From<rust_cktap::ReadError> for ReadError {
    fn from(value: rust_cktap::ReadError) -> Self {
        match value {
            rust_cktap::ReadError::CkTap(err) => ReadError::CkTap { err: err.into() },
            rust_cktap::ReadError::Secp256k1(err) => ReadError::Key { err: err.into() },
            rust_cktap::ReadError::KeyFromSlice(err) => ReadError::Key { err: err.into() },
        }
    }
}

/// Errors returned by the `certs` command.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, uniffi::Error)]
pub enum CertsError {
    #[error(transparent)]
    CkTap {
        #[from]
        err: CkTapError,
    },
    #[error(transparent)]
    Key {
        #[from]
        err: KeyError,
    },
    #[error("Root cert is not from Coinkite. Card is counterfeit: {msg}")]
    InvalidRootCert { msg: String },
}

impl From<rust_cktap::CertsError> for CertsError {
    fn from(value: rust_cktap::CertsError) -> Self {
        match value {
            rust_cktap::CertsError::CkTap(err) => CertsError::CkTap { err: err.into() },
            rust_cktap::CertsError::Secp256k1(err) => CertsError::Key { err: err.into() },
            rust_cktap::CertsError::KeyFromSlice(err) => CertsError::Key { err: err.into() },
            rust_cktap::CertsError::InvalidRootCert(msg) => CertsError::InvalidRootCert { msg },
        }
    }
}

/// Errors returned by the `derive` command.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, uniffi::Error)]
pub enum DeriveError {
    #[error(transparent)]
    CkTap {
        #[from]
        err: CkTapError,
    },
    #[error(transparent)]
    Key {
        #[from]
        err: KeyError,
    },
    #[error("Invalid chain code: {msg}")]
    InvalidChainCode { msg: String },
    /// The CVC failed local validation
    #[error(transparent)]
    Cvc {
        #[from]
        err: CvcError,
    },
}

impl From<rust_cktap::DeriveError> for DeriveError {
    fn from(value: rust_cktap::DeriveError) -> Self {
        match value {
            rust_cktap::DeriveError::CkTap(err) => DeriveError::CkTap { err: err.into() },
            rust_cktap::DeriveError::Secp256k1(err) => DeriveError::Key { err: err.into() },
            rust_cktap::DeriveError::KeyFromSlice(err) => DeriveError::Key { err: err.into() },
            rust_cktap::DeriveError::InvalidChainCode(msg) => DeriveError::InvalidChainCode { msg },
        }
    }
}

/// Errors returned by the `unseal` command.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, uniffi::Error)]
pub enum UnsealError {
    #[error(transparent)]
    CkTap {
        #[from]
        err: CkTapError,
    },
    #[error(transparent)]
    Key {
        #[from]
        err: KeyError,
    },
    /// The CVC failed local validation
    #[error(transparent)]
    Cvc {
        #[from]
        err: CvcError,
    },
}

impl From<rust_cktap::UnsealError> for UnsealError {
    fn from(value: rust_cktap::UnsealError) -> Self {
        match value {
            rust_cktap::UnsealError::CkTap(err) => UnsealError::CkTap { err: err.into() },
            rust_cktap::UnsealError::Secp256k1(err) => UnsealError::Key { err: err.into() },
            rust_cktap::UnsealError::KeyFromSlice(err) => UnsealError::Key { err: err.into() },
        }
    }
}

/// Errors returned by the `dump` command.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, uniffi::Error)]
pub enum DumpError {
    #[error(transparent)]
    CkTap {
        #[from]
        err: CkTapError,
    },
    #[error(transparent)]
    Key {
        #[from]
        err: KeyError,
    },
    #[error("Slot is sealed: {slot}")]
    SlotSealed { slot: u8 },
    #[error("Slot is unused: {slot}")]
    SlotUnused { slot: u8 },
    /// If the slot was unsealed due to confusion or uncertainty about its status.
    /// In other words, if the card unsealed itself rather than via a
    /// successful `unseal` command.
    #[error("Slot was unsealed improperly: {slot}")]
    SlotTampered { slot: u8 },
    /// The CVC failed local validation
    #[error(transparent)]
    Cvc {
        #[from]
        err: CvcError,
    },
}

impl From<rust_cktap::DumpError> for DumpError {
    fn from(value: rust_cktap::DumpError) -> Self {
        match value {
            rust_cktap::DumpError::CkTap(err) => DumpError::CkTap { err: err.into() },
            rust_cktap::DumpError::Secp256k1(err) => DumpError::Key { err: err.into() },
            rust_cktap::DumpError::KeyFromSlice(err) => DumpError::Key { err: err.into() },
            rust_cktap::DumpError::SlotSealed(slot) => DumpError::SlotSealed { slot },
            rust_cktap::DumpError::SlotUnused(slot) => DumpError::SlotUnused { slot },
            rust_cktap::DumpError::SlotTampered(slot) => DumpError::SlotTampered { slot },
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error, uniffi::Error)]
pub enum SignPsbtError {
    #[error("Invalid path at index: {index}")]
    InvalidPath { index: u32 },
    #[error("Invalid script at index: {index}")]
    InvalidScript { index: u32 },
    #[error("Missing pubkey at index: {index}")]
    MissingPubkey { index: u32 },
    #[error("Missing UTXO at index: {index}")]
    MissingUtxo { index: u32 },
    #[error("Pubkey mismatch at index: {index}")]
    PubkeyMismatch { index: u32 },
    #[error("Sighash error: {msg}")]
    SighashError { msg: String },
    #[error("Signature error: {msg}")]
    SignatureError { msg: String },
    #[error("Signing slot is not unsealed: {slot}")]
    SlotNotUnsealed { slot: u8 },
    #[error(transparent)]
    CkTap {
        #[from]
        err: CkTapError,
    },
    #[error("Witness program error: {msg}")]
    WitnessProgram { msg: String },
    #[error("Error in internal PSBT data structure: {msg}")]
    PsbtEncoding { msg: String },
    #[error("Error in PSBT Base64 encoding: {msg}")]
    Base64Encoding { msg: String },
    /// The CVC failed local validation
    #[error(transparent)]
    Cvc {
        #[from]
        err: CvcError,
    },
}

impl From<rust_cktap::SignPsbtError> for SignPsbtError {
    fn from(value: rust_cktap::SignPsbtError) -> SignPsbtError {
        match value {
            rust_cktap::SignPsbtError::InvalidPath(index) => SignPsbtError::InvalidPath { index },
            rust_cktap::SignPsbtError::InvalidScript(index) => {
                SignPsbtError::InvalidScript { index }
            }
            rust_cktap::SignPsbtError::MissingPubkey(index) => {
                SignPsbtError::MissingPubkey { index }
            }
            rust_cktap::SignPsbtError::MissingUtxo(index) => SignPsbtError::MissingUtxo { index },
            rust_cktap::SignPsbtError::PubkeyMismatch(index) => {
                SignPsbtError::PubkeyMismatch { index }
            }
            rust_cktap::SignPsbtError::SighashError(msg) => SignPsbtError::SighashError { msg },
            rust_cktap::SignPsbtError::SignatureError(msg) => SignPsbtError::SignatureError { msg },
            rust_cktap::SignPsbtError::SlotNotUnsealed(slot) => {
                SignPsbtError::SlotNotUnsealed { slot }
            }
            rust_cktap::SignPsbtError::CkTap(err) => SignPsbtError::CkTap { err: err.into() },
            rust_cktap::SignPsbtError::WitnessProgram(msg) => SignPsbtError::WitnessProgram { msg },
        }
    }
}

impl From<rust_cktap::PsbtParseError> for SignPsbtError {
    fn from(value: rust_cktap::PsbtParseError) -> SignPsbtError {
        match value {
            rust_cktap::PsbtParseError::PsbtEncoding(err) => SignPsbtError::PsbtEncoding {
                msg: err.to_string(),
            },
            rust_cktap::PsbtParseError::Base64Encoding(err) => SignPsbtError::Base64Encoding {
                msg: err.to_string(),
            },
            _ => panic!("Unexpected error: {value:?}"),
        }
    }
}

/// Errors returned by the `change` command.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error, uniffi::Error)]
pub enum ChangeError {
    #[error(transparent)]
    CkTap {
        #[from]
        err: CkTapError,
    },
    #[error("new cvc is the same as the old one")]
    SameAsOld,
    /// The current CVC failed local validation
    #[error("invalid current CVC: {err}")]
    CurrentCvc { err: CvcError },
    /// The new CVC failed local validation
    #[error("invalid new CVC: {err}")]
    NewCvc { err: CvcError },
}

impl From<rust_cktap::ChangeError> for ChangeError {
    fn from(value: rust_cktap::ChangeError) -> Self {
        match value {
            rust_cktap::ChangeError::CkTap(err) => ChangeError::CkTap { err: err.into() },
            rust_cktap::ChangeError::SameAsOld => ChangeError::SameAsOld,
        }
    }
}

/// Errors returned by the `xpub` command.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error, uniffi::Error)]
pub enum XpubError {
    #[error(transparent)]
    CkTap {
        #[from]
        err: CkTapError,
    },
    #[error("BIP32 error: {msg}")]
    Bip32 { msg: String },
    /// The CVC failed local validation
    #[error(transparent)]
    Cvc {
        #[from]
        err: CvcError,
    },
}

impl From<rust_cktap::XpubError> for XpubError {
    fn from(value: rust_cktap::XpubError) -> Self {
        match value {
            rust_cktap::XpubError::CkTap(err) => XpubError::CkTap { err: err.into() },
            rust_cktap::XpubError::Bip32(err) => XpubError::Bip32 {
                msg: err.to_string(),
            },
        }
    }
}
