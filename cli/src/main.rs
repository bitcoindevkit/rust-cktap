// Copyright (c) 2025 rust-cktap contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

/// CLI for rust-cktap
use clap::{Parser, Subcommand};
use rpassword::read_password;
#[cfg(feature = "emulator")]
use rust_cktap::emulator;
use rust_cktap::error::{DumpError, StatusError, UnsealError, XpubError};
#[cfg(not(feature = "emulator"))]
use rust_cktap::pcsc;
use rust_cktap::shared::{Authentication, Nfc, Read, Wait};
use rust_cktap::tap_signer::TapSignerShared;
use rust_cktap::{
    CkTapCard, CkTapError, Cvc, CvcError, Psbt, PsbtParseError, SignPsbtError, rand_chaincode,
    shared::Certificate,
};
use std::io;
use std::io::Write;
#[cfg(feature = "emulator")]
use std::path::Path;
use std::str::FromStr;

/// Errors returned by the card, CBOR deserialization or value encoding, or the APDU transport.
#[derive(Debug, thiserror::Error)]
pub enum CliError {
    #[error(transparent)]
    PsbtParse(#[from] PsbtParseError),
    #[error(transparent)]
    Status(#[from] StatusError),
    #[error(transparent)]
    Unseal(#[from] UnsealError),
    #[error(transparent)]
    SignPsbt(#[from] SignPsbtError),
    #[error(transparent)]
    Dump(#[from] DumpError),
    #[error(transparent)]
    CkTap(#[from] CkTapError),
    #[error(transparent)]
    Cvc(#[from] CvcError),
    #[error(transparent)]
    Xpub(#[from] XpubError),
    #[error("unable to read CVC: {0}")]
    CvcInput(String),
}

/// SatsCard CLI
#[derive(Parser)]
#[command(author, version = option_env ! ("CARGO_PKG_VERSION").unwrap_or("unknown"), about,
long_about = None, propagate_version = true)]
struct SatsCardCli {
    #[command(subcommand)]
    command: SatsCardCommand,
}

/// Commands supported by SatsCard cards
#[derive(Subcommand)]
enum SatsCardCommand {
    /// Show the card status
    Status,
    /// Show current deposit address
    Address,
    /// Check this card was made by Coinkite: Verifies a certificate chain up to root factory key.
    Certs,
    /// Read the pubkey
    Read,
    /// Pick a new private key and start a fresh slot. Current slot must be unsealed.
    New,
    /// Unseal the current slot.
    Unseal,
    /// Get the payment address and verify it follows from the chain code and master public key
    Derive,
    /// This reveals the details for any slot. The current slot is not affected.
    Dump { slot: u8 },
    /// Sign a PSBT with the current slot (must be unsealed)
    Sign {
        /// Slot to sign with
        slot: u8,
        /// Unsigned PSBT
        psbt: String,
    },
    /// Call wait command until no auth delay
    Wait,
    /// Get the card's nfc URL
    Nfc,
}

/// TapSigner CLI
#[derive(Parser)]
#[command(author, version = option_env ! ("CARGO_PKG_VERSION").unwrap_or("unknown"), about,
long_about = None, propagate_version = true)]
struct TapSignerCli {
    #[command(subcommand)]
    command: TapSignerCommand,
}

/// Commands supported by TapSigner cards
#[derive(Subcommand)]
enum TapSignerCommand {
    /// Show the card status
    Status,
    /// Check this card was made by Coinkite: Verifies a certificate chain up to root factory key.
    Certs,
    /// Read the pubkey (requires CVC)
    Read,
    /// This command is used once to initialize a new card.
    Init,
    /// Derive a public key at the given hardened path
    Derive {
        /// path, eg. for 84'/0'/0'/* use 84,0,0
        #[clap(short, long, value_delimiter = ',', num_args = 1..)]
        path: Option<Vec<u32>>,
    },
    /// Get an encrypted backup of the card's private key
    Backup,
    /// Change the PIN (CVC) used for card authentication to a new user provided one
    Change { new_cvc: String },
    /// Sign a PSBT
    Sign { psbt: String },
    /// Call wait command until no auth delay
    Wait,
    /// Get the card's nfc URL
    Nfc,
    /// Read the xpub (requires CVC)
    Xpub {
        /// Give master (`m`) XPUB, otherwise derived XPUB
        #[clap(short, long)]
        master: bool,
    },
}

/// TapSigner CLI
#[derive(Parser)]
#[command(author, version = option_env ! ("CARGO_PKG_VERSION").unwrap_or("unknown"), about,
long_about = None, propagate_version = true)]
struct SatsChipCli {
    #[command(subcommand)]
    command: SatsChipCommand,
}

/// Commands supported by SatsChip cards
#[derive(Subcommand)]
enum SatsChipCommand {
    /// Show the card status
    Status,
    /// Check this card was made by Coinkite: Verifies a certificate chain up to root factory key.
    Certs,
    /// Read the pubkey (requires CVC)
    Read,
    /// This command is used once to initialize a new card.
    Init,
    /// Derive a public key at the given hardened path
    Derive {
        /// path, eg. for 84'/0'/0'/* use 84,0,0
        #[clap(short, long, value_delimiter = ',', num_args = 1..)]
        path: Option<Vec<u32>>,
    },
    /// Change the PIN (CVC) used for card authentication to a new user provided one
    Change { new_cvc: String },
    /// Sign a PSBT
    Sign { psbt: String },
    /// Call wait command until no auth delay
    Wait,
    /// Get the card's nfc URL
    Nfc,
    /// Read the xpub (requires CVC)
    Xpub {
        /// Give master (`m`) XPUB, otherwise derived XPUB
        #[clap(short, long)]
        master: bool,
    },
}

#[tokio::main]
async fn main() -> Result<(), CliError> {
    // figure out what type of card we have before parsing cli args
    #[cfg(not(feature = "emulator"))]
    let mut card = pcsc::find_first().await?;

    // if emulator feature enabled override pcsc card
    #[cfg(feature = "emulator")]
    let mut card = emulator::find_emulator(Path::new("/tmp/ecard-pipe")).await?;

    match &mut card {
        CkTapCard::SatsCard(sc) => {
            let cli = SatsCardCli::parse();
            match cli.command {
                SatsCardCommand::Status => {
                    dbg!(&sc);
                }
                SatsCardCommand::Address => println!("Address: {}", sc.address().await.unwrap()),
                SatsCardCommand::Certs => check_cert(sc).await,
                SatsCardCommand::Read => read(sc, None).await,
                SatsCardCommand::New => {
                    let slot = sc.slot().expect("current slot number");
                    let chain_code = Some(rand_chaincode());
                    let cvc = cvc()?;
                    let response = &sc.new_slot(slot, chain_code, &cvc).await?;
                    println!("chain_code: {chain_code:?}");
                    println!("{response}")
                }
                SatsCardCommand::Unseal => {
                    let slot = sc.slot().expect("current slot number");
                    let cvc = cvc()?;
                    let (privkey, pubkey) = &sc.unseal(slot, &cvc).await?;
                    println!("privkey: {}, pubkey: {pubkey}", privkey.to_wif())
                }
                SatsCardCommand::Sign { slot, psbt } => {
                    let psbt = Psbt::from_str(&psbt)?;
                    let cvc = cvc()?;
                    let signed_psbt = sc.sign_psbt(slot, psbt, &cvc).await?;
                    println!("signed_psbt: {signed_psbt}");
                }
                SatsCardCommand::Derive => {
                    dbg!(&sc.derive().await);
                }
                SatsCardCommand::Dump { slot } => {
                    let cvc = optional_cvc()?;
                    let response = sc.dump(slot, cvc).await?;
                    dbg!(response);
                }
                SatsCardCommand::Wait => wait(sc).await,
                SatsCardCommand::Nfc => nfc(sc).await,
            }
        }
        CkTapCard::TapSigner(ts) => {
            let cli = TapSignerCli::parse();
            match cli.command {
                TapSignerCommand::Status => {
                    dbg!(&ts);
                }
                TapSignerCommand::Certs => check_cert(ts).await,
                TapSignerCommand::Read => read(ts, Some(cvc()?)).await,
                TapSignerCommand::Init => {
                    let chain_code = rand_chaincode();
                    let cvc = cvc()?;
                    let response = &ts.init(chain_code, &cvc).await;
                    dbg!(response);
                }
                TapSignerCommand::Derive { path } => {
                    // let test_path:Vec<u32> = ts.path.clone().unwrap().iter().map(|p| p ^ (1 << 31)).collect();
                    // dbg!(test_path);
                    let cvc = cvc()?;
                    dbg!(&ts.derive(path.unwrap_or_default(), &cvc).await);
                }

                TapSignerCommand::Backup => {
                    let cvc = cvc()?;
                    let response = &ts.backup(&cvc).await;
                    println!("{response:?}");
                }

                TapSignerCommand::Change { new_cvc } => {
                    let new_cvc = Cvc::try_from(new_cvc)?;
                    let cvc = cvc()?;
                    let response = &ts.change(&new_cvc, &cvc).await;
                    println!("{response:?}");
                }
                TapSignerCommand::Sign { psbt } => {
                    let psbt = Psbt::from_str(&psbt)?;
                    let cvc = cvc()?;
                    let signed_psbt = ts.sign_psbt(psbt, &cvc).await?;
                    println!("signed_psbt: {signed_psbt}");
                }
                TapSignerCommand::Wait => wait(ts).await,
                TapSignerCommand::Nfc => nfc(ts).await,
                TapSignerCommand::Xpub { master } => xpub(ts, master).await?,
            }
        }
        CkTapCard::SatsChip(sc) => {
            let cli = SatsChipCli::parse();
            match cli.command {
                SatsChipCommand::Status => {
                    dbg!(&sc);
                }
                SatsChipCommand::Certs => check_cert(sc).await,
                SatsChipCommand::Read => read(sc, Some(cvc()?)).await,
                SatsChipCommand::Init => {
                    let chain_code = rand_chaincode();
                    let cvc = cvc()?;
                    let response = &sc.init(chain_code, &cvc).await;
                    dbg!(response);
                }
                SatsChipCommand::Derive { path } => {
                    let cvc = cvc()?;
                    dbg!(&sc.derive(path.unwrap_or_default(), &cvc).await);
                }

                SatsChipCommand::Change { new_cvc } => {
                    let new_cvc = Cvc::try_from(new_cvc)?;
                    let cvc = cvc()?;
                    let response = &sc.change(&new_cvc, &cvc).await;
                    println!("{response:?}");
                }
                SatsChipCommand::Sign { psbt } => {
                    let psbt = Psbt::from_str(&psbt)?;
                    let cvc = cvc()?;
                    let signed_psbt = sc.sign_psbt(psbt, &cvc).await?;
                    println!("signed_psbt: {signed_psbt}");
                }
                SatsChipCommand::Wait => wait(sc).await,
                SatsChipCommand::Nfc => nfc(sc).await,
                SatsChipCommand::Xpub { master } => xpub(sc, master).await?,
            }
        }
    }

    Ok(())
}

// handler functions for each command

async fn check_cert<C>(card: &mut C)
where
    C: Certificate + Send,
{
    if let Ok(k) = card.check_certificate().await {
        println!(
            "Genuine card from Coinkite.\nHas cert signed by: {}",
            k.name()
        )
    } else {
        println!("Card failed to verify. Not a genuine card")
    }
}

async fn read<C>(card: &mut C, cvc: Option<Cvc>)
where
    C: Read + Send,
{
    match card.read(cvc).await {
        Ok(resp) => println!("{resp}"),
        Err(e) => {
            dbg!(&e);
            println!("Failed to read with error: ")
        }
    }
}

fn cvc() -> Result<Cvc, CliError> {
    print!("Enter cvc: ");
    io::stdout().flush().unwrap();
    let cvc = read_password().map_err(|error| CliError::CvcInput(error.to_string()))?;
    Ok(Cvc::try_from(cvc.trim())?)
}

fn optional_cvc() -> Result<Option<Cvc>, CliError> {
    print!("Enter cvc (leave empty for none): ");
    io::stdout().flush().unwrap();
    let cvc = read_password().map_err(|error| CliError::CvcInput(error.to_string()))?;
    Ok(parse_optional_cvc_input(cvc)?)
}

fn parse_optional_cvc_input(cvc: String) -> Result<Option<Cvc>, CvcError> {
    let cvc = cvc.trim();

    if cvc.is_empty() {
        Ok(None)
    } else {
        Ok(Some(Cvc::try_from(cvc)?))
    }
}

async fn wait<C>(card: &mut C)
where
    C: Authentication + Wait + Send,
{
    // if auth delay call wait
    if card.auth_delay().is_some() {
        while card.auth_delay().is_some() {
            print!(" {}", card.auth_delay().unwrap());
            io::stdout().flush().unwrap();
            card.wait(None).await.expect("wait failed");
        }
        println!();
    }
    println!("No auth delay.");
}

async fn nfc<C>(card: &mut C)
where
    C: Nfc + Send,
{
    let nfc = card.nfc().await.expect("nfc failed");
    println!("{nfc}");
}

async fn xpub<C>(card: &mut C, master: bool) -> Result<(), CliError>
where
    C: TapSignerShared + Send,
{
    dbg!(master);
    let cvc = cvc()?;
    let xpub = card.xpub(master, &cvc).await?;
    dbg!(&xpub);
    println!("{xpub}");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn optional_prompt_treats_whitespace_as_no_cvc() {
        let cvc = parse_optional_cvc_input(" \t\n".to_string()).expect("empty CVC is valid");
        assert_eq!(cvc, None);
    }
}
