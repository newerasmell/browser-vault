use std::fmt;

pub type Result<T> = std::result::Result<T, Error>;

/// Errors surfaced by `vault-core`.
///
/// Rules (CLAUDE.md / SPEC §4): no variant may carry key material, passwords,
/// codes or anything that tells the caller *which* unlock factor was wrong.
/// Every credential failure collapses into [`Error::UnlockFailed`].
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("Unlock failed")]
    UnlockFailed,
    #[error("vault not found")]
    NotFound,
    #[error("browser is not installed")]
    BrowserMissing,
    #[error("{0}")]
    Invalid(&'static str),
    #[error("unsupported: {0}")]
    Unsupported(&'static str),
    #[error("header format error: {0}")]
    Format(String),
    #[error("{tool} failed: {detail}")]
    Command { tool: &'static str, detail: String },
    #[error("crypto failure")]
    Crypto,
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
}

impl Error {
    /// Stable machine-readable code, matching the UI contract in `docs/UI.md`.
    pub fn code(&self) -> &'static str {
        match self {
            Error::UnlockFailed | Error::Crypto => "unlock_failed",
            Error::NotFound => "not_found",
            Error::BrowserMissing => "browser_missing",
            Error::Invalid(_) | Error::Unsupported(_) | Error::Format(_) => "invalid",
            Error::Command { .. } | Error::Io(_) => "io",
        }
    }
}

impl From<serde_json::Error> for Error {
    fn from(e: serde_json::Error) -> Self {
        Error::Format(e.to_string())
    }
}

/// Marker used where a value must never be printed (e.g. `Debug` impls).
pub(crate) struct Redacted;

impl fmt::Debug for Redacted {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("<redacted>")
    }
}
