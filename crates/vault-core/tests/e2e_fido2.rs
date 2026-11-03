//! M4 hardware E2E: two real FIDO2 keys (e.g. YubiKey 5), each with a PIN.
//!
//! Run manually on a Mac (no other FIDO key plugged in, CI cannot do this):
//!
//! ```text
//! BV_FIDO_PIN_A=<pin of key A> BV_FIDO_PIN_B=<pin of key B> \
//!   cargo test -p vault-core --test e2e_fido2 -- --ignored --nocapture --test-threads=1
//! ```
//!
//! Start with only key A plugged in and follow the prompts on stderr (swap
//! keys when asked; each "touch" prompt means touch the blinking key). The
//! test registers A as main and B as backup in an in-memory vault (no disk
//! image), unlocks with each, checks that removing the keys makes
//! `key_present` false and that unlock without a key fails. It creates two
//! non-resident credentials for RP id `browservault.local` per run; they use
//! no storage on the key.
#![cfg(target_os = "macos")]

use std::time::{Duration, Instant};

use vault_core::events::Event;
use vault_core::fido2::{self, Authenticator};
use vault_core::header::{Header, VaultSettings};
use vault_core::keyslot::{Draft, KdfCost};
use vault_core::{Browser, Error};

const PW: &str = "e2e fido2 password";

fn pin(var: &str) -> String {
    std::env::var(var).unwrap_or_else(|_| panic!("set {var} (see the comment at the top)"))
}

fn notify(e: Event) {
    match e {
        Event::FidoTouchNeeded => eprintln!("  >>> touch the key"),
        Event::FidoTouchDone => eprintln!("  <<< ok"),
        _ => {}
    }
}

/// Wait (up to 90 s) until `cond` holds, prompting the user once.
fn wait_for(prompt: &str, cond: impl Fn() -> bool) {
    eprintln!("\n=== {prompt}");
    let start = Instant::now();
    while !cond() {
        assert!(
            start.elapsed() < Duration::from_secs(90),
            "timed out: {prompt}"
        );
        std::thread::sleep(Duration::from_millis(500));
    }
}

fn one_key_plugged(auth: &dyn Authenticator) -> bool {
    auth.info().is_ok()
}

#[test]
#[ignore = "needs a Mac and two FIDO2 keys with PINs; see the file comment"]
fn two_yubikeys_register_unlock_and_presence() {
    let (pin_a, pin_b) = (pin("BV_FIDO_PIN_A"), pin("BV_FIDO_PIN_B"));
    let auth = fido2::system();
    let auth = auth.as_ref();

    let mut d = Draft::new("E2E fido2", Browser::Brave, KdfCost::FAST).unwrap();
    d.set_password(PW).unwrap();

    wait_for("plug in ONLY key A", || one_key_plugged(auth));
    fido2::register(&mut d, auth, &pin_a, "YubiKey A", &notify).unwrap();
    let id_a = d.slots().iter().find_map(|s| match s {
        vault_core::header::Slot::Fido2 { credential_id, .. } => Some(credential_id.0.clone()),
        _ => None,
    });
    let id_a = id_a.unwrap();

    wait_for("unplug key A and plug in ONLY key B", || {
        one_key_plugged(auth)
            && !matches!(
                auth.find_credential(fido2::RP_ID, std::slice::from_ref(&id_a)),
                Ok(Some(_))
            )
    });
    fido2::register(&mut d, auth, &pin_b, "YubiKey B", &notify).unwrap();
    d.generate_recovery().unwrap();
    let nv = d.finish(VaultSettings::default()).unwrap();
    let header: Header = nv.header;
    assert_eq!(fido2::keys(&header).len(), 2);

    // Key B is plugged in.
    assert!(fido2::key_present(&header, auth));
    let k = fido2::unlock(&header, auth, PW, &pin_b, &notify).unwrap();
    assert_eq!(**k.vmk(), **nv.key.vmk());
    assert!(k.header_intact);
    // Wrong PIN: generic failure (burns one PIN retry; the next success resets it).
    assert!(matches!(
        fido2::unlock(&header, auth, PW, "00000000", &notify),
        Err(Error::UnlockFailed)
    ));

    wait_for("unplug key B and plug in key A", || {
        one_key_plugged(auth)
            && matches!(
                auth.find_credential(fido2::RP_ID, std::slice::from_ref(&id_a)),
                Ok(Some(_))
            )
    });
    let k = fido2::unlock(&header, auth, PW, &pin_a, &notify).unwrap();
    assert_eq!(**k.vmk(), **nv.key.vmk());

    wait_for("unplug ALL keys", || !auth.present());
    assert!(!fido2::key_present(&header, auth));
    assert!(matches!(
        fido2::unlock(&header, auth, PW, &pin_a, &notify),
        Err(Error::UnlockFailed)
    ));
    eprintln!("\nM4 hardware E2E passed.");
}
