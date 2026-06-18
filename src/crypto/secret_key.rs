//! The account **Secret Key** — the high-entropy second factor in the 2SKD
//! (see [`super`]) and the merged "all devices lost" recovery credential. The
//! user writes it down once at owner-bootstrap; the server never sees it.
//!
//! 160 bits, displayed as Crockford base32 in 8 groups of 4 — the same proven,
//! transcription-friendly format as the server recovery code: case-insensitive,
//! hyphens optional, and `I`/`L`/`O` forgiven (→ `1`/`1`/`0`) on input.

use zeroize::{Zeroize, ZeroizeOnDrop};

use super::{CryptoError, Result};

/// Raw entropy size: 160 bits = exactly 32 Crockford base32 symbols, no padding.
const SECRET_KEY_BYTES: usize = 20;

/// Crockford base32 alphabet (excludes `I`, `L`, `O`, `U`).
const ALPHABET: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";

/// The account Secret Key. Zeroized on drop; its `Debug` is redacted so it can't
/// leak into logs. Use [`SecretKey::display`] only for the one-time write-down UI.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SecretKey([u8; SECRET_KEY_BYTES]);

impl SecretKey {
    /// Generate a fresh Secret Key from the OS CSPRNG.
    pub fn generate() -> Self {
        let mut bytes = [0u8; SECRET_KEY_BYTES];
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut bytes);
        Self(bytes)
    }

    /// The raw key bytes — fed into the 2SKD's HKDF leg. Not for display.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// The grouped Crockford rendering for the write-down screen
    /// (e.g. `H8QK-9R4M-NXBP-V2T8-3JDQ-6KWS-MGYF-PE5X`).
    pub fn display(&self) -> String {
        encode_grouped(&self.0)
    }

    /// Parse a user-entered Secret Key — forgiving of case, hyphens/spaces, and
    /// the `I`/`L`/`O` look-alikes.
    pub fn parse(input: &str) -> Result<Self> {
        let decoded = decode_forgiving(input)?;
        let bytes: [u8; SECRET_KEY_BYTES] = decoded
            .try_into()
            .map_err(|_| CryptoError::SecretKey("wrong length"))?;
        Ok(Self(bytes))
    }
}

impl std::fmt::Debug for SecretKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SecretKey(<redacted>)")
    }
}

/// Encode bytes as Crockford base32, hyphenated into groups of 4. For a 160-bit
/// input this is exactly 32 symbols → 8 groups (no padding needed).
fn encode_grouped(bytes: &[u8]) -> String {
    let mut acc: u32 = 0;
    let mut acc_bits = 0u32;
    let mut symbols = 0usize;
    let mut out = String::new();
    for &b in bytes {
        acc = (acc << 8) | u32::from(b);
        acc_bits += 8;
        while acc_bits >= 5 {
            acc_bits -= 5;
            let idx = ((acc >> acc_bits) & 0x1f) as usize;
            out.push(ALPHABET[idx] as char);
            symbols += 1;
            if symbols.is_multiple_of(4) {
                out.push('-');
            }
        }
    }
    if acc_bits > 0 {
        let idx = ((acc << (5 - acc_bits)) & 0x1f) as usize;
        out.push(ALPHABET[idx] as char);
    }
    out.trim_end_matches('-').to_string()
}

/// Decode Crockford base32, forgiving case, `-`/spaces, and `I`/`L`/`O`.
fn decode_forgiving(input: &str) -> Result<Vec<u8>> {
    let mut acc: u32 = 0;
    let mut acc_bits = 0u32;
    let mut out = Vec::new();
    for ch in input.chars() {
        let upper = ch.to_ascii_uppercase();
        if upper == '-' || upper == ' ' {
            continue;
        }
        let value = symbol_value(upper)?;
        acc = (acc << 5) | value;
        acc_bits += 5;
        if acc_bits >= 8 {
            acc_bits -= 8;
            out.push(((acc >> acc_bits) & 0xff) as u8);
        }
    }
    Ok(out)
}

/// Crockford symbol → 5-bit value, forgiving the documented look-alikes.
fn symbol_value(upper: char) -> Result<u32> {
    match upper {
        'O' => Ok(0),
        'I' | 'L' => Ok(1),
        _ => ALPHABET
            .iter()
            .position(|&a| a as char == upper)
            .map(|p| p as u32)
            .ok_or(CryptoError::SecretKey("invalid character")),
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]
    use super::*;

    #[test]
    fn generate_is_160_bits() {
        let sk = SecretKey::generate();
        assert_eq!(sk.as_bytes().len(), SECRET_KEY_BYTES);
    }

    #[test]
    fn display_is_eight_groups_of_four() {
        let sk = SecretKey::generate();
        let shown = sk.display();
        let groups: Vec<&str> = shown.split('-').collect();
        assert_eq!(groups.len(), 8, "got: {shown}");
        assert!(groups.iter().all(|g| g.len() == 4), "got: {shown}");
    }

    #[test]
    fn round_trips_through_display() {
        let sk = SecretKey::generate();
        let parsed = SecretKey::parse(&sk.display()).unwrap();
        assert_eq!(parsed.as_bytes(), sk.as_bytes());
    }

    #[test]
    fn parse_is_forgiving() {
        let sk = SecretKey::generate();
        let canonical = sk.display();
        // Lower-cased, hyphens stripped, spaces inserted — all must decode equal.
        let mangled = canonical.to_lowercase().replace('-', " ");
        let parsed = SecretKey::parse(&mangled).unwrap();
        assert_eq!(parsed.as_bytes(), sk.as_bytes());
    }

    #[test]
    fn look_alikes_map_to_canonical() {
        // I/L → 1, O → 0. A string using look-alikes decodes the same as its
        // canonical form.
        let canonical = SecretKey::parse("1111-1111-0000-0000-2222-2222-3333-3333").unwrap();
        let lookalike = SecretKey::parse("ILIL-LiLi-OOOO-oooo-2222-2222-3333-3333").unwrap();
        assert_eq!(canonical.as_bytes(), lookalike.as_bytes());
    }

    #[test]
    fn rejects_invalid_characters() {
        // 'U' is not in the Crockford alphabet and is not a forgiven look-alike.
        assert!(SecretKey::parse("UUUU-UUUU-UUUU-UUUU-UUUU-UUUU-UUUU-UUUU").is_err());
    }

    #[test]
    fn rejects_wrong_length() {
        assert!(SecretKey::parse("ABCD-EFGH").is_err());
    }

    #[test]
    fn debug_is_redacted() {
        let sk = SecretKey::generate();
        assert_eq!(format!("{sk:?}"), "SecretKey(<redacted>)");
    }

    #[test]
    fn distinct_keys_differ() {
        assert_ne!(
            SecretKey::generate().as_bytes(),
            SecretKey::generate().as_bytes()
        );
    }
}
