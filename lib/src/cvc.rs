// Copyright (c) 2025 rust-cktap contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::fmt;

use zeroize::Zeroize;

/// The shortest CVC accepted by the CkTap protocol
pub const MIN_CVC_LENGTH: usize = 6;

/// The longest CVC accepted by the CkTap protocol
pub const MAX_CVC_LENGTH: usize = 32;

/// A numeric secret used to authenticate CkTap commands
///
/// This library supports the numeric CVC behavior in public firmware 1.0.1 and later
///
/// Earlier firmware could retain a nonnumeric TAPSIGNER CVC, but that firmware did not reach
/// public cards, so current and replacement CVCs use one numeric-only type
///
/// See the [firmware 1.0.1 change log]
///
/// [firmware 1.0.1 change log]: https://github.com/coinkite/coinkite-tap-proto/blob/master/docs/change-log.md#101---early-july-2022
#[derive(Clone, PartialEq, Eq)]
pub struct Cvc(String);

impl Cvc {
    /// Return the ASCII bytes in this CVC
    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }

    /// Return the CVC as a string slice
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Return the number of bytes in this CVC
    #[allow(clippy::len_without_is_empty)] // a valid CVC can never be empty
    pub fn len(&self) -> usize {
        self.0.len()
    }
}

impl TryFrom<String> for Cvc {
    type Error = CvcError;

    fn try_from(mut value: String) -> Result<Self, Self::Error> {
        let length = value.len();

        if length < MIN_CVC_LENGTH {
            value.zeroize();
            return Err(CvcError::TooShort { length });
        }

        if length > MAX_CVC_LENGTH {
            value.zeroize();
            return Err(CvcError::TooLong { length });
        }

        if let Some(index) = value.bytes().position(|byte| !byte.is_ascii_digit()) {
            value.zeroize();
            return Err(CvcError::NonAsciiDigit { index });
        }

        Ok(Self(value))
    }
}

impl TryFrom<&str> for Cvc {
    type Error = CvcError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        Self::try_from(value.to_owned())
    }
}

impl AsRef<str> for Cvc {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl fmt::Debug for Cvc {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("Cvc(REDACTED)")
    }
}

impl Drop for Cvc {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

/// Errors returned when a CVC does not satisfy the protocol constraints
#[derive(Debug, Copy, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CvcError {
    /// The CVC contains fewer than [`MIN_CVC_LENGTH`] bytes
    #[error("CVC is too short: {length} bytes; minimum is {MIN_CVC_LENGTH}")]
    TooShort { length: usize },
    /// The CVC contains more than [`MAX_CVC_LENGTH`] bytes
    #[error("CVC is too long: {length} bytes; maximum is {MAX_CVC_LENGTH}")]
    TooLong { length: usize },
    /// The CVC contains a byte that is not an ASCII digit
    #[error("CVC contains a byte that is not an ASCII digit at byte index {index}")]
    NonAsciiDigit { index: usize },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_protocol_boundaries() {
        let minimum = Cvc::try_from("0".repeat(MIN_CVC_LENGTH)).expect("minimum length is valid");
        let maximum = Cvc::try_from("9".repeat(MAX_CVC_LENGTH)).expect("maximum length is valid");

        assert_eq!(minimum.len(), MIN_CVC_LENGTH);
        assert_eq!(maximum.len(), MAX_CVC_LENGTH);
    }

    #[test]
    fn rejects_lengths_outside_protocol_bounds() {
        assert_eq!(
            Cvc::try_from("0".repeat(MIN_CVC_LENGTH - 1)),
            Err(CvcError::TooShort {
                length: MIN_CVC_LENGTH - 1
            })
        );
        assert_eq!(
            Cvc::try_from("9".repeat(MAX_CVC_LENGTH + 1)),
            Err(CvcError::TooLong {
                length: MAX_CVC_LENGTH + 1
            })
        );
    }

    #[test]
    fn rejects_non_numeric_and_non_ascii_values() {
        assert_eq!(
            Cvc::try_from("12345a"),
            Err(CvcError::NonAsciiDigit { index: 5 })
        );
        assert_eq!(
            Cvc::try_from("12345é"),
            Err(CvcError::NonAsciiDigit { index: 5 })
        );
    }

    #[test]
    fn debug_is_redacted() {
        let cvc = Cvc::try_from("123456").expect("valid CVC");
        let debug = format!("{cvc:?}");

        assert!(!debug.contains("123456"));
        assert_eq!(debug, "Cvc(REDACTED)");
    }
}
