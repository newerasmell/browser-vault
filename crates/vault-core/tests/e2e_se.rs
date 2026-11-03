//! E2E: the real Secure Enclave (SPEC §4.1, milestone M3).
//!
//! Needs a Mac with a Secure Enclave (Apple Silicon or T2), logged-in user,
//! unlocked screen. No signing or entitlements needed: the key is not stored
//! in the keychain (see `se.rs`). Run manually:
//!
//! ```text
//! cargo test -p vault-core --test e2e_se -- --ignored --nocapture --test-threads=1
//! ```
#![cfg(target_os = "macos")]

use totp_rs::{Algorithm, Builder, Secret};
use vault_core::header::{Slot, VaultSettings};
use vault_core::keyslot::{Draft, KdfCost};
use vault_core::se::{self, SeKeyRef};
use vault_core::{totp, Browser, Error};

const PW: &str = "correct horse battery";

fn code_at(secret_b32: &str, t: u64) -> String {
    let seed = Secret::try_from_base32(secret_b32).unwrap();
    Builder::new()
        .with_algorithm(Algorithm::SHA1)
        .with_secret(seed.as_bytes())
        .build()
        .unwrap()
        .generate(t)
        .to_string()
}

#[test]
#[ignore = "needs a real Secure Enclave"]
fn se_key_roundtrip_and_reopen_from_blob() {
    let se = se::system();
    let key = match se.create_key("com.browservault.e2e-test") {
        Ok(k) => k,
        Err(e) => panic!("create_key failed: {e}"),
    };
    let blob = key.blob.clone().expect("token object id");
    println!("SE key created; token object id: {} bytes", blob.len());

    let ct = se.encrypt(&key, b"hello enclave").expect("encrypt");
    println!("ECIES ciphertext: {} bytes", ct.len());
    let pt = se.decrypt(&key, &ct).expect("decrypt");
    assert_eq!(pt.as_slice(), b"hello enclave");

    // A fresh reference built only from the stored blob (as after a restart).
    let reopened = SeKeyRef {
        tag: "whatever".into(),
        blob: Some(blob.clone()),
    };
    assert_eq!(
        se.decrypt(&reopened, &ct)
            .expect("decrypt via blob")
            .as_slice(),
        b"hello enclave"
    );

    // A corrupted blob must not open.
    let mut bad = blob;
    let last = bad.len() - 1;
    bad[last] ^= 1;
    let bad = SeKeyRef {
        tag: "x".into(),
        blob: Some(bad),
    };
    assert!(se.decrypt(&bad, &ct).is_err());
    se.delete_key(&key).unwrap();
}

#[test]
#[ignore = "needs a real Secure Enclave"]
fn totp_vault_with_real_se() {
    let se = se::system();
    let mut d = Draft::new("E2E SE", Browser::Brave, KdfCost::FAST).unwrap();
    d.set_password(PW).unwrap();
    let setup = totp::begin(&mut d, se.as_ref()).unwrap_or_else(|e| panic!("begin: {e}"));
    println!("{}", setup.uri.as_str());
    let now = vault_core::store::now_unix();
    totp::confirm(&mut d, &code_at(&setup.secret, now), se.as_ref(), now).unwrap();
    d.generate_recovery().unwrap();
    let nv = d.finish(VaultSettings::default()).unwrap();
    let mut h = nv.header;
    assert!(h.slots.iter().any(|s| matches!(
        s,
        Slot::Totp {
            se_key_blob: Some(_),
            ..
        }
    )));

    // Replay of the setup code is refused; the next step's code unlocks.
    assert!(matches!(
        totp::unlock(&mut h, PW, &code_at(&setup.secret, now), se.as_ref(), now),
        Err(Error::UnlockFailed)
    ));
    let next = now + 30;
    let k = totp::unlock(&mut h, PW, &code_at(&setup.secret, next), se.as_ref(), next)
        .unwrap_or_else(|e| panic!("unlock: {e}"));
    assert_eq!(**k.vmk(), **nv.key.vmk());
    assert!(k.header_intact);
}
