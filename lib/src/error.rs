// Copyright (c) 2025 rust-cktap contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

use serde::Deserialize;
use std::fmt::Debug;

/// Errors returned by the card, CBOR deserialization or value encoding, or the APDU transport.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CkTapError {
    #[error(transparent)]
    Card(#[from] CardError),
    #[error("CBOR deserialization error: {0}")]
    CborDe(String),
    #[error("CBOR value error: {0}")]
    CborValue(String),
    #[error("APDU transport error: {0}")]
    Transport(String),
    #[error("Unknown card error code ({code}): {message}")]
    UnknownErrorCode { code: u16, message: String },
    #[error("Unknown card type")]
    UnknownCardType,
}

impl CkTapError {
    pub(crate) fn from_error_response(code: u16, message: impl Into<String>) -> Self {
        match CardError::error_from_code(code) {
            Some(error) => Self::Card(error),
            None => Self::UnknownErrorCode {
                code,
                message: message.into(),
            },
        }
    }
}

/// Errors returned by the CkTap card.
#[derive(Debug, Copy, Clone, PartialEq, Eq, thiserror::Error)]
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

impl CardError {
    pub fn error_from_code(code: u16) -> Option<CardError> {
        match code {
            205 => Some(CardError::UnluckyNumber),
            400 => Some(CardError::BadArguments),
            401 => Some(CardError::BadAuth),
            403 => Some(CardError::NeedsAuth),
            404 => Some(CardError::UnknownCommand),
            405 => Some(CardError::InvalidCommand),
            406 => Some(CardError::InvalidState),
            417 => Some(CardError::WeakNonce),
            422 => Some(CardError::BadCBOR),
            425 => Some(CardError::BackupFirst),
            429 => Some(CardError::RateLimited),
            _ => None,
        }
    }

    pub fn error_code(&self) -> u16 {
        match self {
            CardError::UnluckyNumber => 205,
            CardError::BadArguments => 400,
            CardError::BadAuth => 401,
            CardError::NeedsAuth => 403,
            CardError::UnknownCommand => 404,
            CardError::InvalidCommand => 405,
            CardError::InvalidState => 406,
            CardError::WeakNonce => 417,
            CardError::BadCBOR => 422,
            CardError::BackupFirst => 425,
            CardError::RateLimited => 429,
        }
    }
}

impl<T> From<ciborium::de::Error<T>> for CkTapError
where
    T: Debug,
{
    fn from(e: ciborium::de::Error<T>) -> Self {
        CkTapError::CborDe(e.to_string())
    }
}

impl From<ciborium::value::Error> for CkTapError {
    fn from(e: ciborium::value::Error) -> Self {
        CkTapError::CborValue(e.to_string())
    }
}

#[cfg(feature = "pcsc")]
impl From<pcsc::Error> for CkTapError {
    fn from(e: pcsc::Error) -> Self {
        CkTapError::Transport(e.to_string())
    }
}

#[derive(Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct ErrorResponse {
    pub error: String,
    pub code: u16,
}

/// Errors returned by the `status` command.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum StatusError {
    #[error(transparent)]
    CkTap(#[from] CkTapError),
    #[error(transparent)]
    KeyFromSlice(#[from] bitcoin::key::FromSliceError),
}

#[cfg(feature = "pcsc")]
impl From<pcsc::Error> for StatusError {
    fn from(e: pcsc::Error) -> Self {
        StatusError::CkTap(CkTapError::Transport(e.to_string()))
    }
}

/// Errors returned by the `change` command.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum ChangeError {
    #[error(transparent)]
    CkTap(#[from] CkTapError),
    #[error("new cvc is the same as the old one")]
    SameAsOld,
}

/// Errors returned by the `read` command.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ReadError {
    #[error(transparent)]
    CkTap(#[from] CkTapError),
    #[error(transparent)]
    Secp256k1(#[from] bitcoin::secp256k1::Error),
    #[error(transparent)]
    KeyFromSlice(#[from] bitcoin::key::FromSliceError),
}

impl From<ReadError> for CertsError {
    fn from(e: ReadError) -> Self {
        match e {
            ReadError::CkTap(e) => CertsError::CkTap(e),
            ReadError::Secp256k1(e) => CertsError::Secp256k1(e),
            ReadError::KeyFromSlice(e) => CertsError::KeyFromSlice(e),
        }
    }
}

/// Errors returned by the `certs` command.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CertsError {
    #[error(transparent)]
    CkTap(#[from] CkTapError),
    #[error(transparent)]
    Secp256k1(#[from] bitcoin::secp256k1::Error),
    #[error(transparent)]
    KeyFromSlice(#[from] bitcoin::key::FromSliceError),
    #[error("Root cert is not from Coinkite. Card is counterfeit: {0}")]
    InvalidRootCert(String),
}

/// Errors returned by the `derive` command.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum DeriveError {
    #[error(transparent)]
    CkTap(#[from] CkTapError),
    #[error(transparent)]
    Secp256k1(#[from] bitcoin::secp256k1::Error),
    #[error(transparent)]
    KeyFromSlice(#[from] bitcoin::key::FromSliceError),
    #[error("Invalid chain code: {0}")]
    InvalidChainCode(String),
}

/// Errors returned by the `xpub` command.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum XpubError {
    #[error(transparent)]
    CkTap(#[from] CkTapError),
    #[error(transparent)]
    Bip32(#[from] bitcoin::bip32::Error),
}

/// Errors returned by the `unseal` command.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum UnsealError {
    #[error(transparent)]
    CkTap(#[from] CkTapError),
    #[error(transparent)]
    Secp256k1(#[from] bitcoin::secp256k1::Error),
    #[error(transparent)]
    KeyFromSlice(#[from] bitcoin::key::FromSliceError),
}

/// Errors returned by the `dump` command.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum DumpError {
    #[error(transparent)]
    CkTap(#[from] CkTapError),
    #[error(transparent)]
    Secp256k1(#[from] bitcoin::secp256k1::Error),
    #[error(transparent)]
    KeyFromSlice(#[from] bitcoin::key::FromSliceError),
    #[error("Slot is sealed: {0}")]
    SlotSealed(u8),
    #[error("Slot is unused: {0}")]
    SlotUnused(u8),
    /// If the slot was unsealed due to confusion or uncertainty about its status.
    /// In other words, if the card unsealed itself rather than via a
    /// successful `unseal` command.
    #[error("Slot was unsealed improperly: {0}")]
    SlotTampered(u8),
}

#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum SignPsbtError {
    #[error("Invalid path at index: {0}")]
    InvalidPath(u32),
    #[error("Invalid script at index: {0}")]
    InvalidScript(u32),
    #[error("Missing pubkey at index: {0}")]
    MissingPubkey(u32),
    #[error("Missing UTXO at index: {0}")]
    MissingUtxo(u32),
    #[error("Pubkey mismatch at index: {0}")]
    PubkeyMismatch(u32),
    #[error("Sighash error: {0}")]
    SighashError(String),
    #[error("Signature error: {0}")]
    SignatureError(String),
    #[error("Signing slot is not unsealed: {0}")]
    SlotNotUnsealed(u8),
    #[error(transparent)]
    CkTap(#[from] CkTapError),
    #[error("Witness program error: {0}")]
    WitnessProgram(String),
}
