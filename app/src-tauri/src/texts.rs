//! The few strings shown natively by Rust (tray menu, notifications,
//! dialogs). Everything else lives in `app/src/i18n.js`.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum T {
    LockAll,
    Quit,
    VaultLocked,
    DetachFailed,
    HeaderModified,
    NotAvailableYet,
    UnlockFirst,
    DeleteConfirm,
    DeleteButton,
    Cancel,
    RecoveredAfterCrash,
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
        (true, NotAvailableYet) => "Това действие още не е налично в тази версия.",
        (false, NotAvailableYet) => "This action is not available in this version yet.",
        (true, UnlockFirst) => "Първо отключи сейфа, после повтори действието.",
        (false, UnlockFirst) => "Unlock the vault first, then repeat the action.",
        (true, DeleteConfirm) => "Сейфът и всички данни в него ще бъдат изтрити окончателно. Продължаване?",
        (false, DeleteConfirm) => "The vault and all data in it will be deleted permanently. Continue?",
        (true, DeleteButton) => "Изтрий",
        (false, DeleteButton) => "Delete",
        (true, Cancel) => "Отказ",
        (false, Cancel) => "Cancel",
        (true, RecoveredAfterCrash) => "Сейфове, останали отворени след срив, бяха заключени.",
        (false, RecoveredAfterCrash) => "Vaults left open after a crash were locked.",
    }
}
