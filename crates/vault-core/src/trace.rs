//! Optional step tracing for diagnosing hangs (lock procedure, hdiutil).
//! Messages never contain secrets: only step names, vault ids, PIDs and
//! tool error output. The app installs a sink that appends to its log file.

use std::sync::OnceLock;

static SINK: OnceLock<fn(&str)> = OnceLock::new();

/// Install the trace sink (first call wins).
pub fn set_sink(f: fn(&str)) {
    let _ = SINK.set(f);
}

pub fn emit(msg: &str) {
    if let Some(f) = SINK.get() {
        f(msg);
    }
}
