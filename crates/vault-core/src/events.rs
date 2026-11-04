//! Progress / prompt events emitted by long operations (mirrors `docs/UI.md`).

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CreateStage {
    Disk,
    Keys,
    Profile,
    Import,
    Done,
}

impl CreateStage {
    pub fn as_str(self) -> &'static str {
        match self {
            CreateStage::Disk => "disk",
            CreateStage::Keys => "keys",
            CreateStage::Profile => "profile",
            CreateStage::Import => "import",
            CreateStage::Done => "done",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Event {
    /// The YubiKey is waiting for a touch.
    FidoTouchNeeded,
    FidoTouchDone,
    CreateProgress {
        stage: CreateStage,
        pct: u8,
    },
    CleanupProgress {
        pct: u8,
    },
    /// Backup to / import from a drive, by bytes copied (see `backup`).
    BackupProgress {
        pct: u8,
    },
}

/// Callback for [`Event`]s. Must be cheap and must not block.
pub type Notify<'a> = &'a (dyn Fn(Event) + Sync);

/// A no-op notifier.
pub fn ignore(_: Event) {}
