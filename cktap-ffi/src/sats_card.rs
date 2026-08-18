// Copyright (c) 2025 rust-cktap contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

use crate::check_cert;
use crate::error::{
    CertsError, CkTapError, DeriveError, DumpError, ReadError, SignPsbtError, UnsealError,
};
use futures::lock::Mutex;
use rust_cktap::descriptor::Wpkh;
use rust_cktap::shared::{Authentication, Nfc, Read, Wait};
use rust_cktap::{Cvc, Psbt, rand_chaincode};
use std::str::FromStr;

#[derive(uniffi::Object)]
pub struct SatsCard(pub Mutex<rust_cktap::SatsCard>);

#[derive(uniffi::Record, Debug, Clone)]
pub struct SatsCardStatus {
    pub proto: u32,
    pub ver: String,
    pub birth: u32,
    pub active_slot: u8,
    pub num_slots: u8,
    pub addr: Option<String>,
    pub pubkey: String,
    pub card_ident: String,
    pub auth_delay: Option<u8>,
}

#[derive(uniffi::Record, Clone)]
pub struct SlotDetails {
    privkey: Option<String>,
    pubkey: String,
    pubkey_descriptor: String,
}

#[uniffi::export]
impl SatsCard {
    pub async fn status(&self) -> SatsCardStatus {
        let card = self.0.lock().await;
        let pubkey = card.pubkey().to_string();
        SatsCardStatus {
            proto: card.proto,
            ver: card.ver().to_string(),
            birth: card.birth,
            active_slot: card.slots.0,
            num_slots: card.slots.1,
            addr: card.addr.clone(),
            pubkey,
            card_ident: card.card_ident(),
            auth_delay: card.auth_delay(),
        }
    }

    /// Get the current active slot's receive address
    pub async fn address(&self) -> Result<String, ReadError> {
        let mut card = self.0.lock().await;
        let address = card.address().await?;
        Ok(address.to_string())
    }

    /// Get the current active slot's wpkh public key descriptor
    pub async fn read(&self) -> Result<String, ReadError> {
        let mut card = self.0.lock().await;
        let pubkey = card.read(None).await?;
        let pubkey_desc = format!("{}", Wpkh::new(pubkey).unwrap());
        Ok(pubkey_desc)
    }

    /// Wait one second of auth delay and return the remaining delay, if any.
    pub async fn wait(&self) -> Result<Option<u8>, CkTapError> {
        let mut card = self.0.lock().await;
        card.wait(None).await.map_err(CkTapError::from)
    }

    /// Verify the card has authentic Coinkite root certificate
    pub async fn check_cert(&self) -> Result<(), CertsError> {
        let mut card = self.0.lock().await;
        check_cert(&mut *card).await
    }

    /// Open a new slot, it will be the current active but must be unused (no address)
    pub async fn new_slot(&self, cvc: String) -> Result<u8, DeriveError> {
        let cvc = Cvc::try_from(cvc).map_err(CkTapError::from)?;
        let mut card = self.0.lock().await;
        let (active_slot, _) = card.slots;
        let new_slot_chain_code = rand_chaincode();
        let new_slot = card
            .new_slot(active_slot, Some(new_slot_chain_code), &cvc)
            .await
            .map_err(CkTapError::from)?;
        let derive_chain_code = card.derive().await?;
        if derive_chain_code != new_slot_chain_code {
            return Err(DeriveError::InvalidChainCode {
                msg: "Chain code used by derive doesn't match new slot chain code".to_string(),
            });
        }
        Ok(new_slot)
    }

    /// Unseal currently active slot
    pub async fn unseal(&self, cvc: String) -> Result<SlotDetails, UnsealError> {
        let cvc = Cvc::try_from(cvc).map_err(CkTapError::from)?;
        let mut card = self.0.lock().await;
        let active_slot = card.slots.0;
        let (privkey, pubkey) = card.unseal(active_slot, &cvc).await?;
        Ok(SlotDetails {
            privkey: Some(privkey.to_string()),
            pubkey: pubkey.to_string(),
            pubkey_descriptor: format!("{}", Wpkh::new(pubkey).unwrap()),
        })
    }

    /// This is only needed for debugging, use `sign_psbt` for signing
    /// If no CVC given only pubkey and pubkey descriptor returned.
    pub async fn dump(&self, slot: u8, cvc: Option<String>) -> Result<SlotDetails, DumpError> {
        let cvc = cvc
            .map(Cvc::try_from)
            .transpose()
            .map_err(CkTapError::from)?;
        let mut card = self.0.lock().await;
        let (privkey, pubkey) = card.dump(slot, cvc).await?;
        Ok(SlotDetails {
            privkey: privkey.map(|sk| sk.to_string()),
            pubkey: pubkey.to_string(),
            pubkey_descriptor: format!("{}", Wpkh::new(pubkey).unwrap()),
        })
    }

    /// Sign PSBT, base64 encoded
    pub async fn sign_psbt(
        &self,
        slot: u8,
        psbt: String,
        cvc: String,
    ) -> Result<String, SignPsbtError> {
        let cvc = Cvc::try_from(cvc).map_err(CkTapError::from)?;
        let mut card = self.0.lock().await;
        let psbt = Psbt::from_str(&psbt)?;
        let signed_psbt = card.sign_psbt(slot, psbt, &cvc).await?;
        Ok(signed_psbt.to_string())
    }

    /// Return the same URL as given with a NFC tap.
    pub async fn nfc(&self) -> Result<String, CkTapError> {
        let mut card = self.0.lock().await;
        let url = card.nfc().await?;
        Ok(url)
    }
}
