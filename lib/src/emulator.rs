// Copyright (c) 2025 rust-cktap contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

use crate::apdu::{AppletSelect, CommandApdu, StatusCommand};
use crate::error::StatusError;
use crate::shared::{CkTransport, to_cktap};
use crate::{CkTapCard, CkTapError, Cvc};
use async_trait::async_trait;
use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::string::ToString;
use std::sync::Arc;

/// Return the default emulator CVC
pub fn emulator_default_cvc() -> Cvc {
    Cvc::try_from("123456").expect("the emulator CVC is valid")
}

pub async fn find_emulator(pipe_path: &Path) -> Result<CkTapCard, StatusError> {
    if !pipe_path.exists() {
        return Err(StatusError::CkTap(CkTapError::Transport(
            "Emulator pipe doesn't exist.".to_string(),
        )));
    }
    let stream = UnixStream::connect(pipe_path).expect("unix stream");
    let card_emulator = CardEmulator { stream };
    to_cktap(Arc::new(card_emulator)).await
}

#[derive(Debug)]
pub struct CardEmulator {
    stream: UnixStream,
}

#[async_trait]
impl CkTransport for CardEmulator {
    async fn transmit_apdu(&self, command_apdu: Vec<u8>) -> Result<Vec<u8>, CkTapError> {
        // convert select_apdu into StatusCommand apdu bytes
        let select_apdu: Vec<u8> = AppletSelect::default().apdu_bytes();
        let command_apdu = if command_apdu.eq(&select_apdu) {
            StatusCommand::default().apdu_bytes()
        } else {
            command_apdu
        };

        let mut stream = self.stream.try_clone().expect("clone unix stream");

        // trim first 5 bytes from command apdu bytes to get the cbor data
        stream
            .write_all(&command_apdu.as_slice()[5..])
            .map_err(|e| CkTapError::Transport(e.to_string()))?;
        let mut buffer = [0; 4096];
        // read up to 4096 bytes
        stream
            .read(&mut buffer[..])
            .map_err(|e| CkTapError::Transport(e.to_string()))?;
        Ok(buffer.to_vec())
    }
}

#[cfg(test)]
pub mod test {
    use crate::emulator::find_emulator;
    use std::fmt::Display;
    use std::path::Path;
    use std::process::{Child, Command, Stdio};
    use std::thread::sleep;
    use std::time::Duration;

    pub struct EcardSubprocess {
        pub child: Child,
    }

    #[derive(Debug, Clone, Eq, PartialEq)]
    pub enum CardTypeOption {
        SatsCard,
        TapSigner,
        SatsChip,
    }

    impl CardTypeOption {
        pub fn values() -> [CardTypeOption; 3] {
            [
                CardTypeOption::SatsCard,
                CardTypeOption::TapSigner,
                CardTypeOption::SatsChip,
            ]
        }
    }

    impl Display for CardTypeOption {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            let str = match self {
                CardTypeOption::SatsCard => String::from("--satscard"),
                CardTypeOption::SatsChip => String::from("--satschip"),
                CardTypeOption::TapSigner => String::from("--tapsigner"),
            };
            write!(f, "{str}")
        }
    }

    impl EcardSubprocess {
        pub fn new(
            pipe_path: &Path,
            card_type: &CardTypeOption,
        ) -> Result<Self, Box<dyn std::error::Error>> {
            // Only SatsCard is expected to be initialized
            let no_init = *card_type != CardTypeOption::SatsCard;

            // execute ecard.py python script
            let mut command = Command::new("python3");
            command
                .arg("../coinkite/coinkite-tap-proto/emulator/ecard.py")
                // use rng seed so root cert is always:
                // 0312d005ca1501b1603c3b00412eefe27c6b20a74c29377263b357b3aff12de6fa
                .arg("--rng-seed")
                .arg("1337")
                .arg("emulate")
                .arg(card_type.to_string())
                .arg("--pipe")
                .arg(pipe_path.to_str().unwrap())
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped());
            if no_init {
                // Do not initialize the first slot of card
                command.arg("--no-init");
            }
            let child = command.spawn()?;

            // wait for emulator to start
            sleep(Duration::from_millis(500));
            Ok(EcardSubprocess { child })
        }
    }

    impl Drop for EcardSubprocess {
        fn drop(&mut self) {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }

    #[tokio::test]
    pub async fn test_transmit() {
        let pipe_path = Path::new("/tmp/test-transmit-pipe");
        let _python = EcardSubprocess::new(pipe_path, &CardTypeOption::SatsCard).unwrap();
        let emulator = find_emulator(pipe_path).await;
        assert!(emulator.is_ok());
    }
}
