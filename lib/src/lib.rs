// Copyright (c) 2025 rust-cktap contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

extern crate core;

pub use bitcoin::Network;
pub use bitcoin::bip32::ChainCode;
pub use bitcoin::key::FromSliceError;
pub use bitcoin::psbt::{Psbt, PsbtParseError};
pub use bitcoin::secp256k1::{Error as SecpError, rand};
pub use bitcoin_hashes::sha256::Hash;
pub use miniscript::descriptor;

pub use cvc::{Cvc, CvcError, MAX_CVC_LENGTH, MIN_CVC_LENGTH};
pub use error::{
    CardError, CertsError, ChangeError, CkTapError, DeriveError, DumpError, ReadError,
    SignPsbtError, StatusError, UnsealError, XpubError,
};
pub use shared::{CkTransport, card_pubkey_to_ident};

use bitcoin::key::rand::Rng as _;

pub(crate) mod apdu;
pub mod cvc;
pub mod error;
pub mod sats_card;
pub mod sats_chip;
pub mod shared;
pub mod tap_signer;

#[cfg(feature = "emulator")]
pub mod emulator;

#[cfg(feature = "pcsc")]
pub mod pcsc;

pub type SatsCard = sats_card::SatsCard;
pub type TapSigner = tap_signer::TapSigner;
pub type SatsChip = sats_chip::SatsChip;

// BIP 32 hardened derivation bitmask, 1 << 31
const BIP32_HARDENED_MASK: u32 = 1 << 31;

pub enum CkTapCard {
    SatsCard(SatsCard),
    TapSigner(TapSigner),
    SatsChip(SatsChip),
}

impl core::fmt::Debug for CkTapCard {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match &self {
            CkTapCard::TapSigner(ts) => {
                write!(f, "CkTap::TapSigner({ts:?})")
            }
            CkTapCard::SatsChip(sc) => {
                write!(f, "CkTap::SatsChip({sc:?})")
            }
            CkTapCard::SatsCard(sc) => {
                write!(f, "CkTap::SatsCard({sc:?})")
            }
        }
    }
}

// utility functions

pub fn rand_chaincode() -> ChainCode {
    let rng = &mut rand::thread_rng();
    let mut chain_code = [0u8; 32];
    rng.fill(&mut chain_code);
    ChainCode::from(chain_code)
}

pub fn rand_nonce() -> [u8; 16] {
    let rng = &mut rand::thread_rng();
    let mut nonce = [0u8; 16];
    rng.fill(&mut nonce);
    nonce
}
