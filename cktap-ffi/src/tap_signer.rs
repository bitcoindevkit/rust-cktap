// Copyright (c) 2025 rust-cktap contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

use crate::error::{
    CertsError, ChangeError, CkTapError, DeriveError, ReadError, SignDigestError, SignPsbtError,
    XpubError,
};
use crate::{check_cert, read};
use futures::lock::Mutex;
use rust_cktap::bitcoin::secp256k1::{
    Message, Secp256k1,
    ecdsa::{RecoverableSignature, RecoveryId},
};
use rust_cktap::shared::{Authentication, Nfc, Wait};
use rust_cktap::tap_signer::TapSignerShared;
use rust_cktap::{Psbt, rand_chaincode};
use std::str::FromStr;

#[derive(uniffi::Object)]
pub struct TapSigner(pub Mutex<rust_cktap::TapSigner>);

/// Result of signing an arbitrary 32-byte digest with a TAPSIGNER.
///
/// `signature` is the 64-byte compact ECDSA signature, `pubkey` is the 33-byte compressed
/// public key the card used to sign, and `rec_id` is the recovery id (0..=3) that lets a
/// verifier recover `pubkey` from `signature` and the digest. Together these are sufficient
/// to construct a BIP-137 "Bitcoin Signed Message" header byte or to verify the signature
/// locally without an extra round-trip to the card.
#[derive(uniffi::Record, Debug, Clone)]
pub struct SignedDigest {
    pub signature: Vec<u8>,
    pub pubkey: Vec<u8>,
    pub rec_id: u8,
}

#[derive(uniffi::Record, Debug, Clone)]
pub struct TapSignerStatus {
    pub proto: u32,
    pub ver: String,
    pub birth: u32,
    pub path: Option<Vec<u32>>,
    pub num_backups: u32,
    pub pubkey: String,
    pub card_ident: String,
    pub auth_delay: Option<u8>,
}

#[uniffi::export]
impl TapSigner {
    pub async fn status(&self) -> TapSignerStatus {
        let card = self.0.lock().await;
        TapSignerStatus {
            proto: card.proto,
            ver: card.ver().to_string(),
            birth: card.birth,
            path: card.path.clone(),
            num_backups: card.num_backups.unwrap_or_default(),
            pubkey: card.pubkey().to_string(),
            card_ident: card.card_ident(),
            auth_delay: card.auth_delay(),
        }
    }

    pub async fn read(&self, cvc: String) -> Result<String, ReadError> {
        let mut card = self.0.lock().await;
        read(&mut *card, Some(cvc)).await
    }

    pub async fn wait(&self) -> Result<Option<u8>, CkTapError> {
        let mut card = self.0.lock().await;
        card.wait(None).await.map_err(CkTapError::from)
    }

    pub async fn check_cert(&self) -> Result<(), CertsError> {
        let mut card = self.0.lock().await;
        check_cert(&mut *card).await
    }

    pub async fn init(&self, cvc: String) -> Result<(), CkTapError> {
        let mut card = self.0.lock().await;
        init(&mut *card, cvc).await
    }

    pub async fn sign_psbt(&self, psbt: String, cvc: String) -> Result<String, SignPsbtError> {
        let mut card = self.0.lock().await;
        let psbt = sign_psbt(&mut *card, psbt, cvc).await?;
        Ok(psbt)
    }

    /// Sign an arbitrary 32-byte `digest` with the key derived at `sub_path`.
    ///
    /// Use this for BIP-137 "Bitcoin Signed Message", proof-of-key challenges, or any
    /// other flow where the digest is computed off-card. Errors with
    /// [`SignDigestError::InvalidDigestLength`] if `digest.len() != 32`.
    pub async fn sign_digest(
        &self,
        digest: Vec<u8>,
        sub_path: Vec<u32>,
        cvc: String,
    ) -> Result<SignedDigest, SignDigestError> {
        let mut card = self.0.lock().await;
        sign_digest(&mut *card, digest, sub_path, cvc).await
    }

    pub async fn derive(&self, path: Vec<u32>, cvc: String) -> Result<String, DeriveError> {
        let mut card = self.0.lock().await;
        let pubkey = derive(&mut *card, path, cvc).await?;
        Ok(pubkey)
    }

    pub async fn change(&self, new_cvc: String, cvc: String) -> Result<(), ChangeError> {
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
        let mut card = self.0.lock().await;
        let xpub = card.xpub(master, &cvc).await?;
        Ok(xpub.to_string())
    }
}

/// Initialize a new TAPSIGNER card.
pub async fn init(
    card: &mut (impl TapSignerShared + Send + Sync),
    cvc: String,
) -> Result<(), CkTapError> {
    let chain_code = rand_chaincode();
    card.init(chain_code, &cvc).await.map_err(CkTapError::from)
}

/// Sign (but not finalize) the psbt
///
/// PSBT argument and return are encoded as base64 strings.
pub async fn sign_psbt(
    card: &mut (impl TapSignerShared + Send + Sync),
    psbt: String,
    cvc: String,
) -> Result<String, SignPsbtError> {
    let unsigned_psbt = Psbt::from_str(&psbt)?;
    let psbt = card.sign_psbt(unsigned_psbt, &cvc).await?;
    Ok(psbt.to_string())
}

/// Sign a 32-byte digest and return the signature alongside the pubkey and recovery id.
pub async fn sign_digest(
    card: &mut (impl TapSignerShared + Send + Sync),
    digest: Vec<u8>,
    sub_path: Vec<u32>,
    cvc: String,
) -> Result<SignedDigest, SignDigestError> {
    let digest: [u8; 32] = digest
        .as_slice()
        .try_into()
        .map_err(|_| SignDigestError::InvalidDigestLength {
            len: digest.len() as u32,
        })?;

    let sign_response = card.sign(digest, sub_path, &cvc).await?;

    let rec_id = derive_recovery_id(&digest, &sign_response.sig, &sign_response.pubkey)?;

    Ok(SignedDigest {
        signature: sign_response.sig.to_vec(),
        pubkey: sign_response.pubkey.to_vec(),
        rec_id,
    })
}

/// Try each of the four recovery ids until the one that recovers `expected_pubkey` is found.
fn derive_recovery_id(
    digest: &[u8; 32],
    signature: &[u8; 64],
    expected_pubkey: &[u8; 33],
) -> Result<u8, SignDigestError> {
    let secp = Secp256k1::verification_only();
    let message = Message::from_digest(*digest);
    for i in 0..4i32 {
        let rec_id = RecoveryId::from_i32(i).map_err(|e| SignDigestError::RecoveryId {
            msg: e.to_string(),
        })?;
        let rec_sig = match RecoverableSignature::from_compact(signature, rec_id) {
            Ok(s) => s,
            Err(_) => continue,
        };
        if let Ok(recovered) = secp.recover_ecdsa(&message, &rec_sig) {
            if recovered.serialize() == *expected_pubkey {
                return Ok(i as u8);
            }
        }
    }
    Err(SignDigestError::RecoveryId {
        msg: "no recovery id recovered the expected pubkey".to_string(),
    })
}

/// Derive the pubkey at the given derivation path, return as hex serialized string
pub async fn derive(
    card: &mut (impl TapSignerShared + Send + Sync),
    path: Vec<u32>,
    cvc: String,
) -> Result<String, DeriveError> {
    let pubkey = card.derive(path, &cvc).await.map(|pk| pk.to_string())?;
    Ok(pubkey)
}

pub async fn change(
    card: &mut (impl TapSignerShared + Send + Sync),
    new_cvc: String,
    cvc: String,
) -> Result<(), ChangeError> {
    card.change(&new_cvc, &cvc).await?;
    Ok(())
}
