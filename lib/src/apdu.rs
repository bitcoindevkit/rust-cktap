// Copyright (c) 2025 rust-cktap contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

/// An Application Protocol Data Unit (APDU) is the unit of communication between a smart card
/// reader and a smart card. This file defines the Coinkite APDU and set of command/responses.
pub mod tap_signer;

use crate::CkTapError;
use crate::error::{ErrorResponse, ReadError};
use bitcoin::bip32::ChainCode;
use bitcoin::secp256k1::{self, ecdh::SharedSecret, ecdsa::Signature};
use bitcoin::{Network, PrivateKey, PublicKey};
use bitcoin_hashes::hex::DisplayHex;
use ciborium::de::from_reader;
use ciborium::ser::into_writer;
use ciborium::value::Value;
use serde::{Deserialize, Serialize, Serializer};
use serde_bytes::ByteBuf;
use std::fmt;
use std::fmt::{Debug, Formatter};

const APP_ID: [u8; 15] = *b"\xf0CoinkiteCARDv1";
const SELECT_CLA_INS_P1P2: [u8; 4] = [0x00, 0xA4, 0x04, 0x00];
const CBOR_CLA_INS_P1P2: [u8; 4] = [0x00, 0xCB, 0x00, 0x00];

// Apdu Traits
pub trait CommandApdu {
    fn name() -> &'static str;
    fn apdu_bytes(&self) -> Vec<u8>
    where
        Self: serde::Serialize + Debug,
    {
        let mut command = Vec::new();
        into_writer(&self, &mut command).unwrap();
        build_apdu(&CBOR_CLA_INS_P1P2, command.as_slice())
    }
}

pub trait ResponseApdu {
    fn from_cbor<'a>(cbor: Vec<u8>) -> Result<Self, CkTapError>
    where
        Self: Deserialize<'a> + Debug,
    {
        let cbor_value: Value = from_reader(&cbor[..])?;
        let cbor_struct: Result<ErrorResponse, _> = cbor_value.deserialized();

        if let Ok(error_resp) = cbor_struct {
            return Err(CkTapError::from_status_word(
                error_resp.code,
                error_resp.error,
            ));
        }

        let cbor_struct: Self = cbor_value.deserialized()?;
        Ok(cbor_struct)
    }
}

fn build_apdu(header: &[u8], command: &[u8]) -> Vec<u8> {
    let command_len = command.len();
    assert!(command_len <= 255, "apdu command too long"); // TODO use Err
    [header, &[command_len as u8], command].concat()
}

/// Applet Select.
#[derive(Default, Serialize, Clone, Debug, PartialEq, Eq)]
pub struct AppletSelect {}

impl CommandApdu for AppletSelect {
    fn name() -> &'static str {
        ""
    }

    fn apdu_bytes(&self) -> Vec<u8> {
        build_apdu(&SELECT_CLA_INS_P1P2, &APP_ID)
    }
}

/// Status Command.
#[derive(Serialize, Clone, Debug, PartialEq, Eq)]
pub struct StatusCommand {
    /// 'status' command
    cmd: &'static str,
}

impl Default for StatusCommand {
    fn default() -> Self {
        StatusCommand { cmd: Self::name() }
    }
}

impl CommandApdu for StatusCommand {
    fn name() -> &'static str {
        "status"
    }
}

/// Response value from the [`StatusCommand`].
#[derive(Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct StatusResponse {
    /// Version of CBOR protocol in use.
    pub proto: u32,
    /// Firmware version of the card itself.
    pub ver: String,
    /// Card birth block height (int) (fixed after production).
    pub birth: u32,
    /// SATSCARD Only: Tuple of (active_slot, num_slots).
    pub slots: Option<(u8, u8)>,
    /// SATSCARD Only: Payment address, middle chars blanked out with 3 underscores.
    pub addr: Option<String>,
    /// TAPSIGNER only: will be Some(true).
    pub tapsigner: Option<bool>,
    /// SATSCHIP only: will be Some(true).
    pub satschip: Option<bool>,
    /// TAPSIGNER or SATSCHIP only: a short array of integers, the subkey derivation currently in
    /// effect. It encodes a BIP-32 derivation path, like m/84h/0h/0h, which is a typical value for
    /// segwit usage, although the value is controlled by the wallet application. The field is only
    /// present if a master key has been picked (i.e., setup is complete).
    pub path: Option<Vec<u32>>,
    /// Counts up, when backup command is used.
    pub num_backups: Option<u32>,
    /// Public key unique to this card (fixed for card life) aka: card_pubkey.
    #[serde(with = "serde_bytes")]
    pub pubkey: Vec<u8>,
    /// Random bytes, changed each time we reply to a valid command.
    #[serde(with = "serde_bytes")]
    pub card_nonce: [u8; 16],
    /// A development card will also have a testnet=True field; if false, the field is not provided.
    /// Testnet cannot be enabled after leaving the factory, and those cards are only used by
    /// CoinKite for internal testing.
    pub testnet: Option<bool>,
    /// Shows the number of seconds required between attempts. Use the wait command to pass the
    /// time. Another attempt is allowed after the delay passes. If the CVC value is correct,
    /// normal operation begins. If the CVC value is incorrect, the 15-second delay between
    /// attempts continues.
    #[serde(default)]
    pub auth_delay: Option<u8>,
}

impl ResponseApdu for StatusResponse {}

/// Read Command.
///
/// Apps need to write a CBOR message to read a SATSCARD's current payment address, or a
/// TAPSIGNER's derived public key.
#[derive(Serialize, Clone, Debug, PartialEq, Eq)]
pub struct ReadCommand {
    /// 'read' command
    cmd: &'static str,
    /// provided by app, cannot be all same byte (& should be random), 16 bytes
    #[serde(with = "serde_bytes")]
    nonce: [u8; 16],
    /// (TAPSIGNER only) auth is required, 33 bytes
    #[serde(with = "serde_bytes")]
    epubkey: Option<[u8; 33]>,
    /// (TAPSIGNER only) auth is required encrypted CVC value, 16 to 32 bytes
    #[serde(with = "serde_bytes")]
    xcvc: Option<Vec<u8>>,
}

impl ReadCommand {
    pub fn authenticated(nonce: [u8; 16], epubkey: secp256k1::PublicKey, xcvc: Vec<u8>) -> Self {
        ReadCommand {
            cmd: Self::name(),
            nonce,
            epubkey: Some(epubkey.serialize()),
            xcvc: Some(xcvc),
        }
    }

    pub fn unauthenticated(nonce: [u8; 16]) -> Self {
        ReadCommand {
            cmd: Self::name(),
            nonce,
            epubkey: None,
            xcvc: None,
        }
    }
}

impl CommandApdu for ReadCommand {
    fn name() -> &'static str {
        "read"
    }
}

/// Read Response
///
/// The signature is created from the digest (SHA-256) of these bytes:
///
/// b'OPENDIME' (8 bytes)
/// (card_nonce - 16 bytes)
/// (nonce from read command - 16 bytes)
/// (slot - 1 byte)
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq)]
pub struct ReadResponse {
    /// signature over a bunch of fields using private key of slot, 64 bytes
    #[serde(with = "serde_bytes")]
    sig: Vec<u8>,
    /// public key for this slot/derivation, 33 bytes
    #[serde(with = "serde_bytes")]
    pubkey: Vec<u8>,
    /// new nonce value, for NEXT command (not this one), 16 bytes
    #[serde(with = "serde_bytes")]
    pub(crate) card_nonce: [u8; 16],
}

impl ResponseApdu for ReadResponse {}

impl ReadResponse {
    pub fn signature(&self) -> Result<Signature, ReadError> {
        Signature::from_compact(self.sig.as_slice()).map_err(ReadError::from)
    }

    pub fn pubkey(&self, session_key: Option<SharedSecret>) -> Result<PublicKey, ReadError> {
        if let Some(sk) = session_key {
            let pubkey_bytes = unzip(&self.pubkey, sk);
            return PublicKey::from_slice(pubkey_bytes.as_slice()).map_err(ReadError::from);
        };

        let pubkey_bytes = self.pubkey.as_slice();
        PublicKey::from_slice(pubkey_bytes).map_err(ReadError::from)
    }
}

fn unzip(encoded: &[u8], session_key: SharedSecret) -> Vec<u8> {
    let zipped_bytes = encoded.to_owned().split_off(1);
    let unzipped_bytes = zipped_bytes
        .iter()
        .zip(session_key.as_ref())
        .map(|(x, y)| x ^ y);

    let mut pubkey = encoded.to_owned();
    pubkey.splice(1..33, unzipped_bytes);
    pubkey
}

impl fmt::Display for ReadResponse {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "pubkey: {}", self.pubkey.to_lower_hex_string())
    }
}

impl Debug for ReadResponse {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        f.debug_struct("ReadResponse")
            .field("sig", &self.sig.to_lower_hex_string())
            .field("pubkey", &self.pubkey.to_lower_hex_string())
            .field("card_nonce", &self.card_nonce.to_lower_hex_string())
            .finish()
    }
}

// Checks payment address derivation: https://github.com/coinkite/coinkite-tap-proto/blob/master/docs/protocol.md#satscard-checks-payment-address-derivation
#[derive(Serialize, Clone, Debug, PartialEq, Eq)]
pub struct DeriveCommand {
    cmd: &'static str,
    /// provided by app, cannot be all same byte (& should be random), 16 bytes
    #[serde(with = "serde_bytes")]
    nonce: [u8; 16],
    #[serde(
        skip_serializing_if = "Option::is_none",
        serialize_with = "serialize_some"
    )]
    path: Option<Vec<u32>>, // tapsigner: empty list for `m` case (a no-op)
    /// app's ephemeral public key, 33 bytes
    #[serde(with = "serde_bytes")]
    epubkey: Option<[u8; 33]>,
    /// encrypted CVC value
    #[serde(with = "serde_bytes")]
    xcvc: Option<Vec<u8>>,
}

impl CommandApdu for DeriveCommand {
    fn name() -> &'static str {
        "derive"
    }
}

impl DeriveCommand {
    pub fn for_satscard(nonce: [u8; 16]) -> Self {
        DeriveCommand {
            cmd: Self::name(),
            nonce,
            path: None,
            epubkey: None,
            xcvc: None,
        }
    }

    pub fn for_tapsigner(
        nonce: [u8; 16],
        path: Vec<u32>,
        epubkey: secp256k1::PublicKey,
        xcvc: Vec<u8>,
    ) -> Self {
        DeriveCommand {
            cmd: Self::name(),
            nonce,
            path: Some(path),
            epubkey: Some(epubkey.serialize()),
            xcvc: Some(xcvc),
        }
    }
}

#[derive(Deserialize, Clone)]
pub struct DeriveResponse {
    #[serde(with = "serde_bytes")]
    pub sig: [u8; 64],
    /// chain code of derived subkey
    #[serde(with = "serde_bytes")]
    pub chain_code: [u8; 32],
    /// master public key in effect (`m`)
    #[serde(with = "serde_bytes")]
    pub master_pubkey: [u8; 33],
    /// derived public key for indicated path
    #[serde(with = "serde_bytes")]
    #[serde(default = "Option::default")]
    pub pubkey: Option<[u8; 33]>, //
    /// new nonce value, for NEXT command (not this one)
    #[serde(with = "serde_bytes")]
    pub card_nonce: [u8; 16],
}

impl ResponseApdu for DeriveResponse {}

impl Debug for DeriveResponse {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        f.debug_struct("DeriveResponse")
            .field("sig", &self.sig.to_lower_hex_string())
            .field("chain_code", &self.chain_code.to_lower_hex_string())
            .field("master_pubkey", &self.master_pubkey.to_lower_hex_string())
            .field("pubkey", &self.pubkey.map(|pk| pk.to_lower_hex_string()))
            .field("card_nonce", &self.card_nonce.to_lower_hex_string())
            .finish()
    }
}

/// Certs Command
///
/// This command is used to verify the card was made by Coinkite and is not counterfeit. Two
/// requests are needed: first, fetch the certificates, and then provide a nonce to be signed.
#[derive(Serialize, Clone, Debug, PartialEq, Eq)]
pub struct CertsCommand {
    /// 'certs' command
    cmd: &'static str,
}

impl CommandApdu for CertsCommand {
    fn name() -> &'static str {
        "certs"
    }
}

impl Default for CertsCommand {
    fn default() -> Self {
        CertsCommand { cmd: Self::name() }
    }
}

/// The response is static for any particular card. The values are captured during factory setup.
/// Each entry in the list is a 65-byte signature. The first signature signs the card's public key,
/// and each following signature signs the public key used in the previous signature. Although two
/// levels of signatures are planned, more are possible.
#[derive(Deserialize, Clone)]
pub struct CertsResponse {
    /// list of certificates, from 'batch' to 'root'
    cert_chain: Vec<ByteBuf>,
}

impl ResponseApdu for CertsResponse {}

impl CertsResponse {
    pub fn cert_chain(&self) -> Vec<Vec<u8>> {
        self.clone()
            .cert_chain
            .into_iter()
            .map(|bb| bb.to_vec())
            .collect()
    }
}

impl Debug for CertsResponse {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        let cert_hexes: Vec<String> = self
            .cert_chain()
            .iter()
            .map(|key| key.to_lower_hex_string())
            .collect();
        f.debug_struct("CertsResponse")
            .field("cert_chain", &cert_hexes)
            .finish()
    }
}

/// Check Command
///
/// This command is used to verify the card was made by Coinkite and is not counterfeit. Two
/// requests are needed: first, fetch the certificates (i.e CertsCommand), and then provide a nonce to be signed.
#[derive(Serialize, Clone, Debug, PartialEq, Eq)]
pub struct CheckCommand {
    /// 'check' command
    cmd: &'static str,
    /// random value from app, 16 bytes
    #[serde(with = "serde_bytes")]
    nonce: [u8; 16],
}

impl CommandApdu for CheckCommand {
    fn name() -> &'static str {
        "check"
    }
}

impl CheckCommand {
    pub fn new(nonce: [u8; 16]) -> Self {
        CheckCommand {
            cmd: Self::name(),
            nonce,
        }
    }
}

/// Check Certs Response
/// ref: [certs](https://github.com/coinkite/coinkite-tap-proto/blob/master/docs/protocol.md#certs)
#[derive(Deserialize, Clone)]
pub struct CheckResponse {
    /// signature using card_pubkey, 64 bytes
    #[serde(with = "serde_bytes")]
    pub(crate) auth_sig: Vec<u8>,
    /// new nonce value, for NEXT command (not this one), 16 bytes
    #[serde(with = "serde_bytes")]
    pub(crate) card_nonce: [u8; 16],
}

impl ResponseApdu for CheckResponse {}

impl Debug for CheckResponse {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        f.debug_struct("CheckResponse")
            .field("auth_sig", &self.auth_sig.to_lower_hex_string())
            .field("card_nonce", &self.card_nonce.to_lower_hex_string())
            .finish()
    }
}

/// nfc command to return dynamic url for NFC-enabled smart phone
#[allow(unused)]
#[derive(Serialize, Clone, Debug, PartialEq, Eq)]
pub struct NfcCommand {
    cmd: &'static str,
}

impl Default for NfcCommand {
    fn default() -> Self {
        Self { cmd: Self::name() }
    }
}

impl CommandApdu for NfcCommand {
    fn name() -> &'static str {
        "nfc"
    }
}

/// nfc Response
///
/// URL for smartphone to navigate to
#[derive(Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct NfcResponse {
    /// command result
    pub url: String,
}

impl ResponseApdu for NfcResponse {}

// This function is needed because the subpath field can only be included (and not as an Option)
// when signing with a TAPSIGNER and NOT with a SATSCARD.
pub(crate) fn serialize_some<T, S>(opt: &Option<T>, serializer: S) -> Result<S::Ok, S::Error>
where
    T: Serialize,
    S: Serializer,
{
    opt.as_ref().unwrap().serialize(serializer)
}

/// Sign Command.
#[derive(Serialize, Clone, Debug, PartialEq, Eq)]
pub struct SignCommand {
    /// Command, must be 'sign'.
    cmd: &'static str,
    /// (SATSCARD only) Which slot's to key to use, must be unsealed.
    slot: Option<u8>,
    /// (TAPSIGNER only) Additional derivation key path to be used; must be 0, 1 or 2 length.
    #[serde(
        rename = "subpath",
        skip_serializing_if = "Option::is_none",
        serialize_with = "serialize_some"
    )]
    sub_path: Option<Vec<u32>>,
    /// Message digest to be signed.
    #[serde(with = "serde_bytes")]
    digest: [u8; 32],
    /// App's ephemeral public key.
    #[serde(with = "serde_bytes")]
    epubkey: [u8; 33],
    /// Encrypted CVC value.
    #[serde(with = "serde_bytes")]
    xcvc: Vec<u8>,
}

impl SignCommand {
    pub fn for_satscard(
        slot: u8,
        digest: [u8; 32],
        epubkey: secp256k1::PublicKey,
        xcvc: Vec<u8>,
    ) -> Self {
        SignCommand {
            cmd: Self::name(),
            slot: Some(slot),
            sub_path: None, // field will not be included in serialization
            digest,
            epubkey: epubkey.serialize(),
            xcvc,
        }
    }

    pub fn for_tapsigner(
        sub_path: Vec<u32>,
        digest: [u8; 32],
        epubkey: secp256k1::PublicKey,
        xcvc: Vec<u8>,
    ) -> Self {
        SignCommand {
            cmd: Self::name(),
            slot: Some(0),
            sub_path: Some(sub_path), // field and value will be serialized but without the Option
            digest,
            epubkey: epubkey.serialize(),
            xcvc,
        }
    }
}

impl CommandApdu for SignCommand {
    fn name() -> &'static str {
        "sign"
    }
}

/// Sign Response.
///
/// SATSCARD: Arbitrary signatures can be created for unsealed slots. The app could perform this,
/// since the private key is known, but it's best if the app isn't contaminated with private key
/// information. This could be used for both spending and multisig wallet operations.
///
/// TAPSIGNER: This is its core feature — signing an arbitrary message digest with a tap. Once the
/// card is set up (the key is picked), the command will always be valid.
#[derive(Deserialize, Clone, PartialEq, Eq)]
pub struct SignResponse {
    /// command result
    pub slot: u8,
    #[serde(with = "serde_bytes")]
    pub sig: [u8; 64],
    #[serde(with = "serde_bytes")]
    pub pubkey: [u8; 33],
    #[serde(with = "serde_bytes")]
    pub card_nonce: [u8; 16],
}

impl ResponseApdu for SignResponse {}

impl Debug for SignResponse {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        f.debug_struct("SignResponse")
            .field("slot", &self.slot)
            .field("sig", &self.sig.to_lower_hex_string())
            .field("pubkey", &self.pubkey.to_lower_hex_string())
            .field("card_nonce", &self.card_nonce.to_lower_hex_string())
            .finish()
    }
}

/// Wait Command
///
/// Invalid CVC codes return error 401 (bad auth), through the third incorrect attempt. After the
/// third incorrect attempt, a 15-second delay is required. Any further attempts to authenticate
/// will return error 429 (rate limited) until the delay has passed.
///
/// In rate-limiting mode, the status command returns the auth_delay field with a positive value.
///
/// The wait command takes one second to execute and reduces the auth_delay by one unit. Typically,
/// 15 wait commands need to be executed before retrying a CVC.
#[derive(Serialize, Clone, Debug, PartialEq, Eq)]
pub struct WaitCommand {
    /// 'wait' command
    cmd: &'static str,
    /// app's ephemeral public key (optional), 33 bytes
    #[serde(with = "serde_bytes")]
    epubkey: Option<[u8; 33]>,
    /// encrypted CVC value (optional), 16 to 32 bytes
    #[serde(with = "serde_bytes")]
    xcvc: Option<Vec<u8>>,
}

impl WaitCommand {
    pub fn new(epubkey: Option<secp256k1::PublicKey>, xcvc: Option<Vec<u8>>) -> Self {
        WaitCommand {
            cmd: Self::name(),
            epubkey: epubkey.map(|pk| pk.serialize()),
            xcvc,
        }
    }
}

impl CommandApdu for WaitCommand {
    fn name() -> &'static str {
        "wait"
    }
}

/// Wait Response
///
/// When auth_delay is zero, the CVC can be retried and tested without side effects.
#[derive(Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct WaitResponse {
    /// command result
    pub(crate) success: bool,
    /// how much more delay is now required
    #[serde(default)]
    pub(crate) auth_delay: u8,
}

impl ResponseApdu for WaitResponse {}

/// New Command
///
/// SATSCARD: Use this command to pick a new private key and start a fresh slot. The operation cannot be performed if the current slot is sealed.
///
/// TAPSIGNER: This command is only used once.
///
/// The slot number is included in the request to prevent command replay.
#[derive(Serialize, Clone, Debug, PartialEq, Eq)]
pub struct NewCommand {
    /// 'new' command
    cmd: &'static str,
    /// (use 0 for TapSigner) slot to be affected, must equal currently-active slot number
    slot: u8,
    /// app's entropy share to be applied to new slot (optional on SATSCARD)
    #[serde(with = "serde_bytes")]
    chain_code: Option<[u8; 32]>, // 32 bytes
    /// app's ephemeral public key, 33 bytes
    #[serde(with = "serde_bytes")]
    epubkey: [u8; 33],
    /// encrypted CVC value
    #[serde(with = "serde_bytes")]
    xcvc: Vec<u8>, // 6-32 bytes
}

impl NewCommand {
    pub fn new(
        slot: Option<u8>,
        chain_code: Option<ChainCode>,
        epubkey: secp256k1::PublicKey,
        xcvc: Vec<u8>,
    ) -> Self {
        let slot = slot.unwrap_or_default();
        let chain_code = chain_code.map(|cc| cc.to_bytes());
        NewCommand {
            cmd: Self::name(),
            slot,
            chain_code,
            epubkey: epubkey.serialize(),
            xcvc,
        }
    }
}

impl CommandApdu for NewCommand {
    fn name() -> &'static str {
        "new"
    }
}

/// New Response
///
/// There is a very, very small — 1 in 2128 — chance of arriving at an invalid private key. This
/// returns error 205 (unlucky number). Retries are allowed with no delay. Also, buy a lottery
/// ticket immediately.
///
/// SATSCARD: derived address is generated based on m/0.
///
/// TAPSIGNER: uses the default derivation path of m/84h/0h/0h.
///
/// In either case, the status and read commands are required to learn the details of the new
/// address/key.
#[derive(Deserialize, Clone, Debug)]
pub struct NewResponse {
    /// slot just made
    pub(crate) slot: u8,
    /// new nonce value, for NEXT command (not this one)
    #[serde(with = "serde_bytes")]
    pub(crate) card_nonce: [u8; 16], // 16 bytes
}

impl ResponseApdu for NewResponse {}

impl fmt::Display for NewResponse {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        writeln!(f, "slot {}", self.slot)
    }
}

/// Unseal Command
///
/// Unseal the current slot.
/// NOTE: The slot number is included in the request to prevent command replay. Only the current slot can be unsealed.
#[derive(Serialize, Clone, Debug, PartialEq, Eq)]
pub struct UnsealCommand {
    /// 'unseal' command
    cmd: &'static str,
    /// slot to be unsealed, must equal currently-active slot number
    slot: u8,
    /// app's ephemeral public key, 33 bytes
    #[serde(with = "serde_bytes")]
    epubkey: [u8; 33],
    /// encrypted CVC value, 6-32 bytes
    #[serde(with = "serde_bytes")]
    xcvc: Vec<u8>,
}

impl UnsealCommand {
    pub fn new(slot: u8, epubkey: secp256k1::PublicKey, xcvc: Vec<u8>) -> Self {
        UnsealCommand {
            cmd: Self::name(),
            slot,
            epubkey: epubkey.serialize(),
            xcvc,
        }
    }
}

impl CommandApdu for UnsealCommand {
    fn name() -> &'static str {
        "unseal"
    }
}

/// Unseal Response
#[derive(Deserialize, Clone, Debug)]
pub struct UnsealResponse {
    /// slot just unsealed
    pub slot: u8,
    /// private key for spending (for addr), 32 bytes
    /// The private keys are encrypted, XORed with the session key
    #[serde(with = "serde_bytes")]
    pub privkey: Vec<u8>,
    /// slot's pubkey (convenience, since could be calc'd from privkey), 33 bytes
    #[serde(with = "serde_bytes")]
    pub pubkey: Vec<u8>,
    /// card's master private key, 32 bytes
    #[serde(with = "serde_bytes")]
    pub master_pk: Vec<u8>,
    /// nonce provided by customer
    #[allow(unused)]
    #[serde(with = "serde_bytes")]
    pub chain_code: Vec<u8>, // TODO verify this is same as selected by app
    /// new nonce value, for NEXT command (not this one), 16 bytes
    #[serde(with = "serde_bytes")]
    pub card_nonce: [u8; 16],
}

impl ResponseApdu for UnsealResponse {}

impl fmt::Display for UnsealResponse {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let master = PublicKey::from_slice(self.master_pk.as_slice()).unwrap();
        let pubkey = PublicKey::from_slice(self.pubkey.as_slice()).unwrap();
        let privkey = PrivateKey::from_slice(self.privkey.as_slice(), Network::Bitcoin).unwrap();
        writeln!(f, "slot: {}", self.slot)?;
        writeln!(f, "master_pk: {master}")?;
        writeln!(f, "pubkey: {pubkey}")?;
        writeln!(f, "privkey: {}", privkey.to_wif())
    }
}

/// Dump Command
///
/// This reveals the details for any slot. The current slot is not affected. This is a no-op in
/// terms of response content, if slots aren't available yet, or if a slot hasn't been unsealed.
/// The factory uses this to verify the CVC is printed correctly without side effects.
///
/// If the epubkey or xcvc is absent, the command still works, but the no sensitive information is
/// shared.
///
/// Incorrect auth values for xcvc will fail as normal. Omit the xcvc and epubkey value to proceed
/// without authentication if CVC is unknown.
#[derive(Serialize, Clone, Debug, PartialEq, Eq)]
pub struct DumpCommand {
    /// 'dump' command
    cmd: &'static str,
    /// which slot to dump, must be unsealed.
    slot: u8,
    /// app's ephemeral public key (optional), 33 bytes
    #[serde(with = "serde_bytes")]
    #[serde(skip_serializing_if = "Option::is_none")]
    epubkey: Option<[u8; 33]>,
    /// encrypted CVC value (optional), 6 bytes
    #[serde(with = "serde_bytes")]
    #[serde(skip_serializing_if = "Option::is_none")]
    xcvc: Option<Vec<u8>>,
}

impl DumpCommand {
    pub fn new(slot: u8, epubkey: Option<secp256k1::PublicKey>, xcvc: Option<Vec<u8>>) -> Self {
        DumpCommand {
            cmd: Self::name(),
            slot,
            epubkey: epubkey.map(|pk| pk.serialize()),
            xcvc,
        }
    }
}

impl CommandApdu for DumpCommand {
    fn name() -> &'static str {
        "dump"
    }
}

/// Dump Response
///
/// Without the CVC, the dump command returns just the sealed/unsealed/unused status for each slot,
/// with the exception of unsealed slots where the address in full is also provided.
#[derive(Deserialize, Clone, Debug)]
pub struct DumpResponse {
    /// slot just made
    #[allow(unused)] // TODO verify this is correct slot
    pub slot: u8,
    /// private key for spending (for addr), 32 bytes
    /// The private keys are encrypted, XORed with the session key
    #[serde(with = "serde_bytes")]
    #[serde(default)]
    pub privkey: Option<Vec<u8>>,
    /// public key, 33 bytes
    #[serde(with = "serde_bytes")]
    #[serde(default)]
    pub pubkey: Option<Vec<u8>>,
    /// nonce provided by customer originally
    #[allow(unused)] // TODO verify this is correct chain_code
    #[serde(with = "serde_bytes")]
    #[serde(default)]
    pub chain_code: Option<Vec<u8>>,
    /// master private key for this slot (was picked by card), 32 bytes
    #[allow(unused)] // TODO verify this is correct pubkey
    #[serde(with = "serde_bytes")]
    #[serde(default)]
    pub master_pk: Option<Vec<u8>>,
    /// flag that slots unsealed for unusual reasons (absent if false)
    #[serde(default)]
    pub tampered: Option<bool>,
    /// if no xcvc provided, slot used status
    #[serde(default)]
    pub used: Option<bool>,
    /// if no xcvc provided, slot sealed status
    pub sealed: Option<bool>,
    /// if no xcvc provided, full payment address (not censored)
    #[allow(unused)] // TODO verify this is correct address
    #[serde(default)]
    pub addr: Option<String>,
    /// new nonce value, for NEXT command (not this one), 16 bytes
    #[serde(with = "serde_bytes")]
    pub card_nonce: [u8; 16],
}

impl ResponseApdu for DumpResponse {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{CardError, CkTapError};

    #[derive(Serialize)]
    struct ErrorResponseFixture {
        error: String,
        code: u16,
    }

    fn encode_error_response(code: u16, message: &str) -> Vec<u8> {
        let response = ErrorResponseFixture {
            error: message.to_string(),
            code,
        };
        let mut cbor = Vec::new();
        into_writer(&response, &mut cbor).expect("error response fixture serializes");
        cbor
    }

    #[test]
    fn known_status_word_maps_to_card_error() {
        let error = StatusResponse::from_cbor(encode_error_response(400, "bad arguments"))
            .expect_err("error response must fail to deserialize as status");

        assert_eq!(error, CkTapError::Card(CardError::BadArguments));
    }

    #[test]
    fn unknown_status_word_preserves_code_and_message() {
        let error = StatusResponse::from_cbor(encode_error_response(499, "future protocol error"))
            .expect_err("error response must fail to deserialize as status");

        assert_eq!(
            error,
            CkTapError::UnknownStatusWord {
                code: 499,
                message: "future protocol error".to_string(),
            }
        );
    }
}
