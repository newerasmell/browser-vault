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

/// Key *setup* errors (wizard / add key) are specific, so the user can fix
/// them (set a PIN, insert one key, …). Unlock errors stay generic.
pub fn fido_setup_error(e: vault_core::Error) -> CmdError {
    use vault_core::fido2::*;
    use vault_core::Error::{Invalid, Unsupported};
    let code = match &e {
        Invalid(m) | Unsupported(m) => match *m {
            ERR_PIN_NOT_SET => "fido_pin_not_set",
            ERR_UNSUPPORTED_KEY => "fido_unsupported_key",
            ERR_NO_KEY => "fido_no_key",
            ERR_MULTIPLE_KEYS => "fido_multiple_keys",
            ERR_ALREADY_REGISTERED => "fido_already_registered",
            ERR_WRONG_PIN => "fido_wrong_pin",
            ERR_PIN_BLOCKED => "fido_pin_blocked",
            ERR_PIN_FORMAT => "fido_pin_format",
            ERR_NO_TOUCH => "fido_no_touch",
            ERR_LABEL => "fido_label",
            ERR_LABEL_TAKEN => "fido_label_taken",
            _ => return e.into(),
        },
        _ => return e.into(),
    };
    CmdError::new(code)
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

    #[test]
    fn fido_setup_codes() {
        use vault_core::fido2::*;
        assert_eq!(
            fido_setup_error(Error::Invalid(ERR_PIN_NOT_SET)).code,
            "fido_pin_not_set"
        );
        assert_eq!(
            fido_setup_error(Error::Unsupported(ERR_UNSUPPORTED_KEY)).code,
            "fido_unsupported_key"
        );
        assert_eq!(
            fido_setup_error(Error::Invalid(ERR_NO_TOUCH)).code,
            "fido_no_touch"
        );
        assert_eq!(fido_setup_error(Error::UnlockFailed).code, "unlock_failed");
        assert_eq!(fido_setup_error(Error::Invalid("other")).code, "invalid");
    }
}
