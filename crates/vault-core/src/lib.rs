//! Browser Vault core: keys, header, encrypted container and browser process
//! control. See `docs/SPEC.md` — it is the source of truth.

pub mod backup;
pub mod browser;
pub mod chromium;
pub mod crypto;
pub mod error;
pub mod events;
pub mod fido2;
pub mod hdiutil;
pub mod header;
pub mod identity;
pub mod index;
pub mod keyslot;
pub mod lock;
pub mod portable;
pub mod profiles;
pub mod recovery;
pub mod se;
pub mod store;
pub mod totp;
pub mod trace;

pub use browser::Browser;
pub use error::{Error, Result};
pub use header::Header;
pub use keyslot::{KdfCost, UnlockedKey};
pub use store::{Credential, Store};
