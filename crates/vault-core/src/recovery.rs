//! 24-word BIP39 recovery phrase (SPEC §4).

use bip39::{Language, Mnemonic};
use zeroize::{Zeroize, Zeroizing};

use crate::crypto;
use crate::error::{Error, Result};

pub const WORDS: usize = 24;

/// Generate a fresh 24-word phrase from 256 bits of `OsRng` entropy.
pub fn generate() -> Result<Zeroizing<String>> {
    let entropy = Zeroizing::new(crypto::random_bytes::<32>());
    let mut m = Mnemonic::from_entropy_in(Language::English, entropy.as_ref())
        .map_err(|_| Error::Crypto)?;
    let phrase = Zeroizing::new(m.to_string());
    m.zeroize();
    Ok(phrase)
}

/// Canonical form of a user-typed phrase: lowercase, single spaces. Returns
/// `UnlockFailed` (never a more specific reason) when it is not a valid
/// 24-word English BIP39 phrase.
pub fn normalize(input: &str) -> Result<Zeroizing<String>> {
    let lowered = Zeroizing::new(input.to_lowercase());
    let joined = Zeroizing::new(lowered.split_whitespace().collect::<Vec<_>>().join(" "));
    let mut m = Mnemonic::parse_in_normalized(Language::English, &joined)
        .map_err(|_| Error::UnlockFailed)?;
    let ok = m.word_count() == WORDS;
    m.zeroize();
    if !ok {
        return Err(Error::UnlockFailed);
    }
    Ok(joined)
}

/// Words of a phrase, for display (one-time, SPEC §4) and for the 3-word check.
pub fn words(phrase: &str) -> Vec<Zeroizing<String>> {
    phrase
        .split_whitespace()
        .map(|w| Zeroizing::new(w.to_string()))
        .collect()
}

/// Pick `n` distinct 1-based word positions for the confirmation step.
pub fn challenge_positions(n: usize) -> Vec<usize> {
    let mut picked: Vec<usize> = Vec::with_capacity(n);
    while picked.len() < n.min(WORDS) {
        let r = u32::from_le_bytes(crypto::random_bytes::<4>()) as usize;
        // Rejection sampling to avoid modulo bias.
        let limit = (u32::MAX as usize / WORDS) * WORDS;
        if r >= limit {
            continue;
        }
        let pos = r % WORDS + 1;
        if !picked.contains(&pos) {
            picked.push(pos);
        }
    }
    picked.sort_unstable();
    picked
}

/// Check the user's answers (1-based position → word) against the phrase.
pub fn verify_answers(phrase: &str, answers: &[(usize, &str)]) -> bool {
    let w = words(phrase);
    !answers.is_empty()
        && answers.iter().all(|(pos, word)| {
            *pos >= 1 && *pos <= w.len() && w[*pos - 1].as_str() == word.trim().to_lowercase()
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generates_valid_unique_24_word_phrases() {
        let a = generate().unwrap();
        let b = generate().unwrap();
        assert_eq!(a.split(' ').count(), 24);
        assert_ne!(*a, *b);
        assert_eq!(*normalize(&a).unwrap(), *a);
    }

    #[test]
    fn normalize_tolerates_case_and_spacing() {
        let p = generate().unwrap();
        let messy = format!("  {}\n", p.to_uppercase().replace(' ', "   "));
        assert_eq!(*normalize(&messy).unwrap(), *p);
    }

    #[test]
    fn normalize_rejects_bad_phrases_generically() {
        let p = generate().unwrap();
        let mut w: Vec<&str> = p.split(' ').collect();
        // Wrong length.
        assert!(matches!(
            normalize(&w[..12].join(" ")),
            Err(Error::UnlockFailed)
        ));
        // Bad checksum (swap two different words).
        let (i, j) = (0..24)
            .flat_map(|i| (0..24).map(move |j| (i, j)))
            .find(|&(i, j)| w[i] != w[j])
            .unwrap();
        w.swap(i, j);
        let swapped = w.join(" ");
        if normalize(&swapped).is_ok() {
            // Astronomically unlikely but possible: checksum still valid.
            return;
        }
        assert!(matches!(normalize(&swapped), Err(Error::UnlockFailed)));
        // Not a word.
        assert!(matches!(
            normalize("foo ".repeat(24).trim()),
            Err(Error::UnlockFailed)
        ));
    }

    #[test]
    fn challenge_and_verify() {
        let p = generate().unwrap();
        let pos = challenge_positions(3);
        assert_eq!(pos.len(), 3);
        assert!(pos.iter().all(|&x| (1..=24).contains(&x)));
        assert!(pos.windows(2).all(|w| w[0] < w[1]));
        let w = words(&p);
        let good: Vec<(usize, &str)> = pos.iter().map(|&i| (i, w[i - 1].as_str())).collect();
        assert!(verify_answers(&p, &good));
        let mut bad = good.clone();
        bad[1].1 = "zzzz";
        assert!(!verify_answers(&p, &bad));
        assert!(!verify_answers(&p, &[]));
        assert!(!verify_answers(&p, &[(0, "x")]));
        assert!(!verify_answers(&p, &[(25, "x")]));
    }
}
