//! Browser Vault core: keys, header, encrypted container and browser process
//! control. See `docs/SPEC.md` — it is the source of truth.

pub mod browser;
pub mod crypto;
pub mod error;
pub mod hdiutil;
pub mod header;
pub mod keyslot;
pub mod recovery;
pub mod store;

pub use browser::Browser;
pub use error::{Error, Result};
pub use header::Header;
pub use keyslot::{KdfCost, UnlockedKey};
pub use store::{Credential, Store};
