//! The few strings shown natively by Rust (tray menu, notifications,
//! dialogs). Everything else lives in `app/src/i18n.js`.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum T {
    LockAll,
    Quit,
    VaultLocked,
    DetachFailed,
    HeaderModified,
    DeleteConfirm,
    DeleteButton,
    Cancel,
    RecoveredAfterCrash,
    ImportFailed,
    ImportBrowserRunning,
}

pub fn tr(bg: bool, key: T) -> &'static str {
    use T::*;
    match (bg, key) {
        (true, LockAll) => "Заключи всички",
        (false, LockAll) => "Lock all",
        (true, Quit) => "Изход",
        (false, Quit) => "Quit",
        (true, VaultLocked) => "Сейфът е заключен",
        (false, VaultLocked) => "Vault locked",
        (true, DetachFailed) => "Сейфът не можа да се демонтира. Затвори програмите, които го ползват, и опитай „Заключи“ отново.",
        (false, DetachFailed) => "The vault could not be detached. Quit apps using it and try Lock again.",
        (true, HeaderModified) => "Внимание: header-ът на сейфа е бил променен извън приложението.",
        (false, HeaderModified) => "Warning: the vault header was modified outside the app.",
        (true, DeleteConfirm) => "Сейфът и всички данни в него ще бъдат изтрити окончателно. Продължаване?",
        (false, DeleteConfirm) => "The vault and all data in it will be deleted permanently. Continue?",
        (true, DeleteButton) => "Изтрий",
        (false, DeleteButton) => "Delete",
        (true, Cancel) => "Отказ",
        (false, Cancel) => "Cancel",
        (true, RecoveredAfterCrash) => "Сейфове, останали отворени след срив, бяха заключени.",
        (false, RecoveredAfterCrash) => "Vaults left open after a crash were locked.",
        (true, ImportFailed) => "Сейфът е създаден, но импортът на профила не успя. Сейфът е празен и работи; оригиналът не е променян.",
        (false, ImportFailed) => "The vault was created, but importing the profile failed. The vault is empty and works; the original was not changed.",
        (true, ImportBrowserRunning) => "Сейфът е създаден, но профилът не е импортиран, защото браузърът работи. Сейфът е празен и работи.",
        (false, ImportBrowserRunning) => "The vault was created, but the profile was not imported because the browser is running. The vault is empty and works.",
    }
}
