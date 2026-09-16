// Copyright (c) 2025 rust-cktap contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

use crate::apdu::tap_signer::{XpubCommand, XpubResponse};
use crate::apdu::{
    CommandApdu as _, DeriveCommand, DeriveResponse, NewCommand, NewResponse, SignCommand,
    SignResponse, StatusCommand, StatusResponse,
    tap_signer::{BackupCommand, BackupResponse, ChangeCommand, ChangeResponse},
};
use crate::error::{ChangeError, DeriveError, ReadError, SignPsbtError, StatusError, XpubError};
use crate::shared::{
    Authentication, Certificate, CkTransport, Nfc, Read, Wait, card_pubkey_to_ident, transmit,
};
use crate::{BIP32_HARDENED_MASK, CkTapError};
use async_trait::async_trait;
use bitcoin::PublicKey;
use bitcoin::bip32::{ChainCode, Xpub};
use bitcoin::hex::DisplayHex;
use bitcoin::secp256k1::{self, All, Message, Secp256k1, ecdsa::Signature};
use bitcoin_hashes::sha256;
use std::sync::Arc;

const BIP84_PATH_LEN: u32 = 5;

// BIP84 derivation path structure, m / 84' / 0' / account' / change / address_index

// Derivation sub-path indexes that must be hardened
const BIP84_HARDENED_SUBPATH: [u32; 3] = [0, 1, 2];

pub struct TapSigner {
    pub transport: Arc<dyn CkTransport>,
    pub secp: Secp256k1<All>,
    pub proto: u32,
    pub ver: String,
    pub birth: u32,
    pub path: Option<Vec<u32>>,
    // [(1<<31)+84, (1<<31), (1<<31)], user-defined, will be omitted if not yet setup
    pub num_backups: Option<u32>,
    pub pubkey: PublicKey,
    pub card_nonce: [u8; 16],
    pub auth_delay: Option<u8>,
}

impl Authentication for TapSigner {
    fn secp(&self) -> &Secp256k1<All> {
        &self.secp
    }

    fn ver(&self) -> &str {
        &self.ver
    }

    fn pubkey(&self) -> &PublicKey {
        &self.pubkey
    }

    fn card_nonce(&self) -> &[u8; 16] {
        &self.card_nonce
    }

    fn set_card_nonce(&mut self, new_nonce: [u8; 16]) {
        self.card_nonce = new_nonce;
    }

    fn auth_delay(&self) -> Option<u8> {
        self.auth_delay
    }

    fn set_auth_delay(&mut self, auth_delay: Option<u8>) {
        self.auth_delay = auth_delay;
    }

    fn transport(&self) -> Arc<dyn CkTransport> {
        self.transport.clone()
    }
}

/// Function shared between TapSigner and SatsChip
#[async_trait]
pub trait TapSignerShared: Authentication {
    /// Initialize the tap signer or sats chip, can only be done once
    async fn init(&mut self, chain_code: ChainCode, cvc: &str) -> Result<(), CkTapError> {
        let (_, epubkey, xcvc) = self.calc_ekeys_xcvc(cvc, NewCommand::name());
        let new_command = NewCommand::new(Some(0), Some(chain_code), epubkey, xcvc);
        let new_response: NewResponse = transmit(self.transport(), &new_command).await?;
        self.set_card_nonce(new_response.card_nonce);
        Ok(())
    }

    /// Get the status of the tap signer or sats chip, including the current card nonce
    async fn status(&mut self) -> Result<StatusResponse, CkTapError> {
        let cmd = StatusCommand::default();
        let status_response: StatusResponse = transmit(self.transport(), &cmd).await?;
        self.set_card_nonce(status_response.card_nonce);
        Ok(status_response)
    }

    /// Sign a message digest with the tap signer
    async fn sign(
        &mut self,
        digest: [u8; 32],
        sub_path: Vec<u32>,
        cvc: &str,
    ) -> Result<SignResponse, CkTapError> {
        let (eprivkey, epubkey, xcvc) = self.calc_ekeys_xcvc(cvc, SignCommand::name());

        // Use the same session key to encrypt the new CVC
        let session_key = secp256k1::ecdh::SharedSecret::new(&self.pubkey().inner, &eprivkey);

        // encrypt the new cvc by XORing with the session key
        let xdigest_vec: Vec<u8> = session_key
            .as_ref()
            .iter()
            .zip(digest)
            .map(|(session_key_byte, digest_byte)| session_key_byte ^ digest_byte)
            .collect();

        let xdigest: [u8; 32] = xdigest_vec.try_into().expect("input is also 32 bytes");

        let sign_command =
            SignCommand::for_tapsigner(sub_path.clone(), xdigest, epubkey, xcvc.clone());

        let mut sign_response: Result<SignResponse, CkTapError> =
            transmit(self.transport(), &sign_command).await;

        let mut unlucky_number_retries = 0;
        while let Err(CkTapError::Card(crate::CardError::UnluckyNumber)) = sign_response {
            let sign_command =
                SignCommand::for_tapsigner(sub_path.clone(), xdigest, epubkey, xcvc.clone());

            sign_response = transmit(self.transport(), &sign_command).await;
            unlucky_number_retries += 1;

            if unlucky_number_retries > 3 {
                break;
            }
        }

        let sign_response = sign_response?;
        self.set_card_nonce(sign_response.card_nonce);
        Ok(sign_response)
    }

    /// Sign a BIP84, currently only P2WPKH (BIP84) (Native SegWit) PSBT
    /// This function will return a signed but not finalized PSBT. You will need to finalize the
    /// PSBT yourself before it can be broadcast.
    async fn sign_psbt(
        &mut self,
        mut psbt: bitcoin::Psbt,
        cvc: &str,
    ) -> Result<bitcoin::Psbt, SignPsbtError> {
        use bitcoin::{
            secp256k1::ecdsa,
            sighash::{EcdsaSighashType, SighashCache},
        };

        let unsigned_tx = psbt.unsigned_tx.clone();
        let mut sighash_cache = SighashCache::new(&unsigned_tx);

        for (input_index, input) in psbt.inputs.iter_mut().enumerate() {
            // extract previous output data from the PSBT
            let witness_utxo = input
                .witness_utxo
                .as_ref()
                .ok_or(SignPsbtError::MissingUtxo(input_index as u32))?;

            let amount = witness_utxo.value;

            // extract the P2WPKH script from PSBT
            let script_pubkey = &witness_utxo.script_pubkey;
            if !script_pubkey.is_p2wpkh() {
                return Err(SignPsbtError::InvalidScript(input_index as u32));
            }

            // get the public key from the PSBT
            let key_pairs = &input.bip32_derivation;
            let (psbt_pubkey, (_fingerprint, path)) = key_pairs
                .iter()
                .next()
                .ok_or(SignPsbtError::MissingPubkey(input_index as u32))?;

            let path = path.to_u32_vec();

            if path.len() as u32 != BIP84_PATH_LEN {
                return Err(SignPsbtError::InvalidPath(input_index as u32));
            }

            let sub_path = BIP84_HARDENED_SUBPATH.map(|i| path[i as usize]);
            if sub_path.iter().any(|p| *p > BIP32_HARDENED_MASK) {
                return Err(SignPsbtError::InvalidPath(input_index as u32));
            }

            // calculate sighash
            let script = script_pubkey.as_script();
            let sighash = sighash_cache
                .p2wpkh_signature_hash(input_index, script, amount, EcdsaSighashType::All)
                .map_err(|e| SignPsbtError::SighashError(e.to_string()))?;

            // the digest is the sighash
            let digest: &[u8; 32] = sighash.as_ref();

            // send digest to TAPSIGNER for signing
            let mut sign_response = self.sign(*digest, sub_path.to_vec(), cvc).await?;
            let mut signature_raw = sign_response.sig;

            // verify that TAPSIGNER used the same public key as the PSBT
            if sign_response.pubkey != psbt_pubkey.serialize() {
                // try deriving the TAPSIGNER and try again
                // take the hardened path and remove the hardened bit, because `sign` hardens it
                let path: Vec<u32> = path
                    .into_iter()
                    .map(|p| p ^ BIP32_HARDENED_MASK)
                    .take(BIP84_HARDENED_SUBPATH.len())
                    .collect();
                let derive_response = self.derive(path, cvc).await;
                if derive_response.is_err() {
                    return Err(SignPsbtError::PubkeyMismatch(input_index as u32));
                }

                // update signature to the new one we just derived
                sign_response = self.sign(*digest, sub_path.to_vec(), cvc).await?;
                signature_raw = sign_response.sig;

                // if still not matching, return error
                if sign_response.pubkey != psbt_pubkey.serialize() {
                    return Err(SignPsbtError::PubkeyMismatch(input_index as u32));
                }
            }

            // update the PSBT input with the signature
            let ecdsa_sig = ecdsa::Signature::from_compact(&signature_raw)
                .map_err(|e| SignPsbtError::SignatureError(e.to_string()))?;

            let final_sig = bitcoin::ecdsa::Signature::sighash_all(ecdsa_sig);
            input.partial_sigs.insert((*psbt_pubkey).into(), final_sig);
        }

        Ok(psbt)
    }

    /// Derive a public key at the given hardened path.
    ///
    /// The derive command on the TAPSIGNER is used to perform hardened BIP-32 key derivation.
    /// Wallets are expected to use it for deriving the BIP-44/48/84 prefix of the path; the value
    /// is captured and stored long term. This is effectively calculating the XPUB to be used on the
    /// mobile wallet.
    ///
    /// Ref: <https://github.com/coinkite/coinkite-tap-proto/blob/master/docs/protocol.md#tapsigner-performs-subkey-derivation>
    async fn derive(&mut self, path: Vec<u32>, cvc: &str) -> Result<PublicKey, DeriveError> {
        // set most significant bit to 1 to represent hardened path steps
        let path = path.iter().map(|p| p ^ (1 << 31)).collect::<Vec<_>>();
        let app_nonce = crate::rand_nonce();
        // capture card_nonce BEFORE transmit — the card signs with this nonce,
        // and the response contains a NEW nonce for the next command
        let card_nonce = *self.card_nonce();
        let (_, epubkey, xcvc) = self.calc_ekeys_xcvc(cvc, DeriveCommand::name());
        let cmd = DeriveCommand::for_tapsigner(app_nonce, path, epubkey, xcvc);
        let derive_response: DeriveResponse = transmit(self.transport(), &cmd).await?;
        self.set_card_nonce(derive_response.card_nonce);

        let master_pubkey = PublicKey::from_slice(&derive_response.master_pubkey)?;
        let pubkey = match &derive_response.pubkey {
            Some(pubkey) => PublicKey::from_slice(pubkey)?,
            None => master_pubkey,
        };

        // Verify signature: the TAPSIGNER signs with the DERIVED private key
        // (or the master private key when the path is empty, in which case
        // `pubkey` falls back to `master_pubkey` above).
        // Message: "OPENDIME" || card_nonce (pre-command) || app_nonce || chain_code
        let sig = &derive_response.sig;

        let mut message_bytes: Vec<u8> = Vec::new();
        message_bytes.extend("OPENDIME".as_bytes());
        message_bytes.extend(card_nonce);
        message_bytes.extend(app_nonce);
        message_bytes.extend(&derive_response.chain_code);

        let message_bytes_hash = sha256::Hash::hash(message_bytes.as_slice());
        let message = Message::from_digest(message_bytes_hash.to_byte_array());

        let signature = Signature::from_compact(sig)?;

        self.secp()
            .verify_ecdsa(&message, &signature, &pubkey.inner)?;

        Ok(pubkey)
    }

    /// Change the CVC used for card authentication to a new user provided one
    async fn change(&mut self, new_cvc: &str, cvc: &str) -> Result<(), ChangeError> {
        if new_cvc.len() < 6 {
            return Err(ChangeError::TooShort(new_cvc.len() as u32));
        }

        if new_cvc.len() > 32 {
            return Err(ChangeError::TooLong(new_cvc.len() as u32));
        }

        if new_cvc == cvc {
            return Err(ChangeError::SameAsOld);
        }

        // Create session key and encrypt current CVC
        let (eprivkey, epubkey, xcvc) = self.calc_ekeys_xcvc(cvc, ChangeCommand::name());

        // Use the same session key to encrypt the new CVC
        let session_key = secp256k1::ecdh::SharedSecret::new(&self.pubkey().inner, &eprivkey);

        // encrypt the new cvc by XORing with the session key
        let xnew_cvc: Vec<u8> = session_key
            .as_ref()
            .iter()
            .zip(new_cvc.as_bytes().iter())
            .map(|(session_key_byte, cvc_byte)| session_key_byte ^ cvc_byte)
            .collect();

        let change_command = ChangeCommand::new(xnew_cvc, epubkey, xcvc);
        let change_response: ChangeResponse = transmit(self.transport(), &change_command).await?;

        self.set_card_nonce(change_response.card_nonce);
        Ok(())
    }

    async fn xpub(&mut self, master: bool, cvc: &str) -> Result<Xpub, XpubError> {
        let (_, epubkey, xcvc) = self.calc_ekeys_xcvc(cvc, XpubCommand::name());
        let xpub_command = XpubCommand::new(master, epubkey, xcvc);
        let xpub_response: XpubResponse = transmit(self.transport(), &xpub_command).await?;
        self.set_card_nonce(xpub_response.card_nonce);
        let xpub = Xpub::decode(xpub_response.xpub.as_slice())?;
        Ok(xpub)
    }
}

#[async_trait]
impl Nfc for TapSigner {}

impl TapSignerShared for TapSigner {}

impl TapSigner {
    pub fn card_ident(&self) -> String {
        card_pubkey_to_ident(&self.pubkey)
    }

    pub fn try_from_status(
        transport: Arc<dyn CkTransport>,
        status_response: StatusResponse,
    ) -> Result<Self, StatusError> {
        let pubkey = status_response.pubkey.as_slice();
        let pubkey = PublicKey::from_slice(pubkey)?;

        Ok(TapSigner {
            transport,
            secp: Secp256k1::new(),
            proto: status_response.proto,
            ver: status_response.ver,
            birth: status_response.birth,
            path: status_response.path,
            num_backups: status_response.num_backups,
            pubkey,
            card_nonce: status_response.card_nonce,
            auth_delay: status_response.auth_delay,
        })
    }

    /// Backup the current card, the backup is encrypted with the "Backup Password" on the back of the card
    pub async fn backup(&mut self, cvc: &str) -> Result<Vec<u8>, ChangeError> {
        let (_, epubkey, xcvc) = self.calc_ekeys_xcvc(cvc, "backup");

        let backup_command = BackupCommand::new(epubkey, xcvc);
        let backup_response: BackupResponse = transmit(self.transport(), &backup_command).await?;

        self.card_nonce = backup_response.card_nonce;
        Ok(backup_response.data)
    }
}

#[async_trait]
impl Wait for TapSigner {}

#[async_trait]
impl Read for TapSigner {
    fn requires_auth(&self) -> bool {
        true
    }

    fn slot(&self) -> Option<u8> {
        None
    }
}

#[async_trait]
impl Certificate for TapSigner {
    async fn slot_pubkey(&mut self) -> Result<Option<PublicKey>, ReadError> {
        Ok(None)
    }
}

impl core::fmt::Debug for TapSigner {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("TapSigner")
            .field("proto", &self.proto)
            .field("ver", &self.ver)
            .field("birth", &self.birth)
            .field("path", &self.path)
            .field("num_backups", &self.num_backups)
            .field("card_ident", &self.card_ident())
            .field("pubkey", &self.pubkey)
            .field("card_nonce", &self.card_nonce.to_lower_hex_string())
            .field("auth_delay", &self.auth_delay)
            .finish()
    }
}

#[cfg(feature = "emulator")]
#[cfg(test)]
mod test {
    use crate::emulator::find_emulator;
    use crate::emulator::test::{CardTypeOption, EcardSubprocess};
    use crate::tap_signer::TapSignerShared;
    use crate::{CkTapCard, rand_chaincode};
    use std::path::Path;

    // verify the xpub command works
    #[tokio::test]
    async fn test_tap_signer_xpub() {
        let card_type = CardTypeOption::TapSigner;
        let pipe_path = "/tmp/test-tapsigner-xpub-pipe";
        let pipe_path = Path::new(&pipe_path);
        let python = EcardSubprocess::new(pipe_path, &card_type).unwrap();
        let emulator = find_emulator(pipe_path).await.unwrap();
        if let CkTapCard::TapSigner(mut ts) = emulator {
            ts.init(rand_chaincode(), "123456").await.unwrap();
            let xpub = ts.xpub(false, "123456").await.unwrap();
            assert_eq!(xpub.depth, 3);
            let master_xpub = ts.xpub(true, "123456").await.unwrap();
            assert_eq!(master_xpub.depth, 0);
        }
        drop(python);
    }

    // Regression test for the signature verification fix:
    // `derive` with a non-empty path must still cryptographically verify the
    // response using the master pubkey and the card_nonce captured BEFORE the
    // transmit. If either bug regressed, this call would fail with
    // DeriveError::Secp (signature verification failed).
    #[tokio::test]
    async fn test_tap_signer_derive_with_path() {
        let card_type = CardTypeOption::TapSigner;
        let pipe_path = "/tmp/test-tapsigner-derive-path-pipe";
        let pipe_path = Path::new(&pipe_path);
        let python = EcardSubprocess::new(pipe_path, &card_type).unwrap();
        let emulator = find_emulator(pipe_path).await.unwrap();
        if let CkTapCard::TapSigner(mut ts) = emulator {
            ts.init(rand_chaincode(), "123456").await.unwrap();
            // BIP84 prefix m/84'/0'/0' — non-empty path so the card returns a
            // derived pubkey different from the master pubkey. Pre-fix, this
            // branch skipped verification entirely.
            let derived_pubkey = ts.derive(vec![84, 0, 0], "123456").await.unwrap();
            // Sanity check: derivation succeeded and returned a valid pubkey
            assert_eq!(derived_pubkey.inner.serialize().len(), 33);
        }
        drop(python);
    }

    // Regression test ensuring the empty-path case (pubkey == master_pubkey)
    // also still works after removing the `if pubkey == master_pubkey` guard.
    #[tokio::test]
    async fn test_tap_signer_derive_empty_path() {
        let card_type = CardTypeOption::TapSigner;
        let pipe_path = "/tmp/test-tapsigner-derive-empty-pipe";
        let pipe_path = Path::new(&pipe_path);
        let python = EcardSubprocess::new(pipe_path, &card_type).unwrap();
        let emulator = find_emulator(pipe_path).await.unwrap();
        if let CkTapCard::TapSigner(mut ts) = emulator {
            ts.init(rand_chaincode(), "123456").await.unwrap();
            // Empty path — card returns pubkey == master_pubkey (None in response)
            let master_pubkey = ts.derive(vec![], "123456").await.unwrap();
            assert_eq!(master_pubkey.inner.serialize().len(), 33);
        }
        drop(python);
    }
}
