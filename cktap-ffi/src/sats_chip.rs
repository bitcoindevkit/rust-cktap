// Copyright (c) 2025 rust-cktap contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

use crate::error::{
    CertsError, ChangeError, CkTapError, CvcError, DeriveError, InitError, ReadError,
    SignPsbtError, XpubError,
};
use crate::tap_signer::{change, derive, init, sign_psbt};
use crate::{check_cert, read};
use futures::lock::Mutex;
use rust_cktap::Cvc;
use rust_cktap::shared::{Authentication, Nfc, Wait};
use rust_cktap::tap_signer::TapSignerShared;

#[derive(uniffi::Object)]
pub struct SatsChip(pub Mutex<rust_cktap::SatsChip>);

#[derive(uniffi::Record, Debug, Clone)]
pub struct SatsChipStatus {
    pub proto: u32,
    pub ver: String,
    pub birth: u32,
    pub path: Option<Vec<u32>>,
    pub pubkey: String,
    pub card_ident: String,
    pub auth_delay: Option<u8>,
}

#[uniffi::export]
impl SatsChip {
    pub async fn status(&self) -> SatsChipStatus {
        let card = self.0.lock().await;
        SatsChipStatus {
            proto: card.proto,
            ver: card.ver().to_string(),
            birth: card.birth,
            path: card.path.clone(),
            pubkey: card.pubkey().to_string(),
            card_ident: card.card_ident(),
            auth_delay: card.auth_delay(),
        }
    }

    pub async fn read(&self) -> Result<String, ReadError> {
        let mut card = self.0.lock().await;
        read(&mut *card, None).await
    }

    pub async fn wait(&self) -> Result<Option<u8>, CkTapError> {
        let mut card = self.0.lock().await;
        card.wait(None).await.map_err(CkTapError::from)
    }

    pub async fn check_cert(&self) -> Result<(), CertsError> {
        let mut card = self.0.lock().await;
        check_cert(&mut *card).await
    }

    pub async fn init(&self, cvc: String) -> Result<(), InitError> {
        let cvc = Cvc::try_from(cvc).map_err(CvcError::from)?;
        let mut card = self.0.lock().await;
        init(&mut *card, cvc).await?;
        Ok(())
    }

    pub async fn sign_psbt(&self, psbt: String, cvc: String) -> Result<String, SignPsbtError> {
        let cvc = Cvc::try_from(cvc).map_err(CvcError::from)?;
        let mut card = self.0.lock().await;
        let psbt = sign_psbt(&mut *card, psbt, cvc).await?;
        Ok(psbt)
    }

    pub async fn derive(&self, path: Vec<u32>, cvc: String) -> Result<String, DeriveError> {
        let cvc = Cvc::try_from(cvc).map_err(CvcError::from)?;
        let mut card = self.0.lock().await;
        let pubkey = derive(&mut *card, path, cvc).await?;
        Ok(pubkey)
    }

    pub async fn change(&self, new_cvc: String, cvc: String) -> Result<(), ChangeError> {
        let new_cvc = Cvc::try_from(new_cvc).map_err(|err| ChangeError::NewCvc {
            err: CvcError::from(err),
        })?;
        let cvc = Cvc::try_from(cvc).map_err(|err| ChangeError::CurrentCvc {
            err: CvcError::from(err),
        })?;
        let mut card = self.0.lock().await;
        change(&mut *card, new_cvc, cvc).await?;
        Ok(())
    }

    pub async fn nfc(&self) -> Result<String, CkTapError> {
        let mut card = self.0.lock().await;
        let url = card.nfc().await?;
        Ok(url)
    }

    pub async fn xpub(&self, master: bool, cvc: String) -> Result<String, XpubError> {
        let cvc = Cvc::try_from(cvc).map_err(CvcError::from)?;
        let mut card = self.0.lock().await;
        let xpub = card.xpub(master, &cvc).await?;
        Ok(xpub.to_string())
    }
}
