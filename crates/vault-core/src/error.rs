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
    /// Too many failed attempts; retry after this many seconds (SPEC §4.1).
    #[error("too many attempts, retry in {retry_after} s")]
    RateLimited { retry_after: u64 },
    /// SPEC §5.1: the imported copy has not been opened and closed yet.
    #[error("the imported profile has not been reviewed yet")]
    NotReviewed,
    /// The regular (non-vault) browser instance is running.
    #[error("the browser is running; quit it first")]
    BrowserRunning,
    #[error("vault not found")]
    NotFound,
    #[error("browser is not installed")]
    BrowserMissing,
    /// The app a vault opens with changed its major version since the vault
    /// was last opened (e.g. Brave 157 → 158). Opening could rewrite or drop
    /// data the new version no longer reads; the user decides.
    #[error("the app was updated since this vault was last opened")]
    AppVersionChanged,
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
            Error::RateLimited { .. } => "rate_limited",
            Error::NotReviewed => "not_reviewed",
            Error::BrowserRunning => "browser_running",
            Error::NotFound => "not_found",
            Error::BrowserMissing => "browser_missing",
            Error::AppVersionChanged => "app_version_changed",
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
