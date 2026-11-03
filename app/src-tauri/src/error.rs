//! Command error shape from docs/UI.md: `{ code, retryAfter? }`.
//! Never carries detail text: no paths, no secrets, no hint about which
//! factor was wrong.

use serde::Serialize;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CmdError {
    pub code: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub retry_after: Option<u64>,
}

pub type CmdResult<T> = Result<T, CmdError>;

impl CmdError {
    pub const fn new(code: &'static str) -> Self {
        CmdError {
            code,
            retry_after: None,
        }
    }

    pub const fn unsupported() -> Self {
        CmdError::new("unsupported")
    }

    pub const fn not_found() -> Self {
        CmdError::new("not_found")
    }

    pub const fn invalid() -> Self {
        CmdError::new("invalid")
    }
}

impl From<vault_core::Error> for CmdError {
    fn from(e: vault_core::Error) -> Self {
        match e {
            vault_core::Error::RateLimited { retry_after } => CmdError {
                code: "rate_limited",
                retry_after: Some(retry_after),
            },
            // Distinguish "not built yet" from bad input so the UI can say so.
            vault_core::Error::Unsupported(_) => CmdError::unsupported(),
            other => CmdError::new(other.code()),
        }
    }
}

impl From<std::io::Error> for CmdError {
    fn from(_: std::io::Error) -> Self {
        CmdError::new("io")
    }
}

impl From<tauri::Error> for CmdError {
    fn from(_: tauri::Error) -> Self {
        CmdError::new("io")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use vault_core::Error;

    #[test]
    fn shape() {
        let e: CmdError = Error::RateLimited { retry_after: 30 }.into();
        assert_eq!(
            serde_json::to_string(&e).unwrap(),
            r#"{"code":"rate_limited","retryAfter":30}"#
        );
        let e: CmdError = Error::UnlockFailed.into();
        assert_eq!(
            serde_json::to_string(&e).unwrap(),
            r#"{"code":"unlock_failed"}"#
        );
        let e: CmdError = Error::Crypto.into();
        assert_eq!(e.code, "unlock_failed");
        let e: CmdError = Error::Unsupported("x").into();
        assert_eq!(e.code, "unsupported");
        let e: CmdError = Error::BrowserMissing.into();
        assert_eq!(e.code, "browser_missing");
    }
}
