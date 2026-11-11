//! Windows from docs/UI.md, all created from Rust.
//!
//! | label           | hash                    | size      |
//! |-----------------|-------------------------|-----------|
//! | `tray`          | `#tray`                 | 360 × fit |
//! | `unlock-<id>`   | `#unlock?id=<id>`       | 400 × 460 |
//! | `wizard`        | `#wizard`               | 580 × 640 |
//! | `settings`      | `#settings[?tab=…]`     | 760 × 560 |
//! | `cleanup`       | `#cleanup?id=<id>`      | 520 × 720 |

use std::collections::BTreeMap;
use std::time::{Duration, Instant};

use tauri::{
    AppHandle, LogicalSize, Manager, PhysicalPosition, Rect, WebviewUrl, WebviewWindow,
    WebviewWindowBuilder, WindowEvent,
};

use crate::error::{CmdError, CmdResult};
use crate::state::{self, lock};

pub const TRAY: &str = "tray";
pub const TRAY_WIDTH: f64 = 360.0;
const TRAY_INITIAL_HEIGHT: f64 = 420.0;

/// Injected into the tray webview only: keeps the borderless popover exactly
/// as tall as its content ("360 × auto"), via the internal `tray_fit` command.
const TRAY_FIT_JS: &str = r#"
window.addEventListener('DOMContentLoaded', () => {
  const app = document.getElementById('app');
  if (!app) return;
  let last = 0;
  const fit = () => {
    const el = app.firstElementChild;
    if (!el || !window.__TAURI__) return;
    const h = Math.ceil(el.getBoundingClientRect().height);
    if (h > 0 && h !== last) { last = h; window.__TAURI__.core.invoke('tray_fit', { height: h }); }
  };
  const ro = new ResizeObserver(fit);
  new MutationObserver(() => {
    ro.disconnect();
    if (app.firstElementChild) ro.observe(app.firstElementChild);
    fit();
  }).observe(app, { childList: true });
});
"#;

struct Spec {
    label: String,
    hash: String,
    size: (f64, f64),
    always_on_top: bool,
}

/// Values in the hash query are ids / tab names only.
fn safe_value(v: &str) -> bool {
    !v.is_empty()
        && v.len() <= 64
        && v.chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
}

fn spec(view: &str, params: &BTreeMap<String, String>) -> CmdResult<Spec> {
    for (k, v) in params {
        if !safe_value(k) || !safe_value(v) {
            return Err(CmdError::invalid());
        }
    }
    let query = if params.is_empty() {
        String::new()
    } else {
        let q: Vec<String> = params.iter().map(|(k, v)| format!("{k}={v}")).collect();
        format!("?{}", q.join("&"))
    };
    let hash = format!("{view}{query}");
    let id = || params.get("id").cloned().ok_or(CmdError::invalid());
    let (label, size, on_top) = match view {
        TRAY => (TRAY.to_string(), (TRAY_WIDTH, TRAY_INITIAL_HEIGHT), true),
        "unlock" => (format!("unlock-{}", id()?), (400.0, 460.0), true),
        "wizard" => ("wizard".into(), (580.0, 640.0), false),
        "settings" => ("settings".into(), (760.0, 560.0), false),
        "cleanup" => {
            id()?;
            ("cleanup".into(), (520.0, 720.0), false)
        }
        _ => return Err(CmdError::invalid()),
    };
    Ok(Spec {
        label,
        hash,
        size,
        always_on_top: on_top,
    })
}

/// `open_window`: focus the window if it is open (navigating it when the
/// params differ), otherwise create it.
pub fn open(app: &AppHandle, view: &str, params: &BTreeMap<String, String>) -> CmdResult<()> {
    let s = spec(view, params)?;
    if view == TRAY {
        if let Some(w) = app.get_webview_window(TRAY) {
            w.show()?;
            w.set_focus()?;
        }
        return Ok(());
    }
    if let Some(w) = app.get_webview_window(&s.label) {
        if !params.is_empty() {
            let js = format!(
                "if (location.hash !== {h}) location.hash = {h};",
                h = serde_json::to_string(&format!("#{}", s.hash))
                    .map_err(|_| CmdError::invalid())?
            );
            let _ = w.eval(&js);
        }
        let _ = w.unminimize();
        w.show()?;
        w.set_focus()?;
        return Ok(());
    }
    let w = WebviewWindowBuilder::new(
        app,
        &s.label,
        WebviewUrl::App(format!("index.html#{}", s.hash).into()),
    )
    .title(vault_core::identity::display_name())
    .inner_size(s.size.0, s.size.1)
    .resizable(false)
    .maximizable(false)
    .minimizable(view != "unlock")
    .always_on_top(s.always_on_top)
    .center()
    .focused(true)
    .build()?;
    if view == "wizard" {
        let handle = app.clone();
        w.on_window_event(move |e| {
            // docs/UI.md: closing the wizard = wizard_cancel. The UI holds at
            // most one draft, so drop them all (secrets zeroize on drop).
            if let WindowEvent::Destroyed = e {
                lock(&state::get(&handle).drafts).clear();
            }
        });
    }
    w.set_focus()?;
    Ok(())
}

/// The tray popover: borderless, transparent, hidden until the icon is clicked.
pub fn create_tray_window(app: &AppHandle) -> tauri::Result<WebviewWindow> {
    let w = WebviewWindowBuilder::new(app, TRAY, WebviewUrl::App("index.html#tray".into()))
        .title(vault_core::identity::display_name())
        .inner_size(TRAY_WIDTH, TRAY_INITIAL_HEIGHT)
        .decorations(false)
        .transparent(true)
        .resizable(false)
        .skip_taskbar(true)
        .always_on_top(true)
        .visible(false)
        .initialization_script(TRAY_FIT_JS)
        .build()?;
    let handle = app.clone();
    w.on_window_event(move |e| {
        if let WindowEvent::Focused(false) = e {
            if let Some(w) = handle.get_webview_window(TRAY) {
                let _ = w.hide();
            }
            *lock(&state::get(&handle).tray_blurred_at) = Some(Instant::now());
        }
    });
    Ok(w)
}

pub fn fit_tray(app: &AppHandle, height: f64) -> CmdResult<()> {
    if let Some(w) = app.get_webview_window(TRAY) {
        w.set_size(LogicalSize::new(TRAY_WIDTH, height.clamp(80.0, 900.0)))?;
    }
    Ok(())
}

/// Left click on the menu bar icon: toggle the popover right under it.
pub fn toggle_tray(app: &AppHandle, icon: Rect) {
    let Some(w) = app.get_webview_window(TRAY) else {
        return;
    };
    if w.is_visible().unwrap_or(false) {
        let _ = w.hide();
        return;
    }
    // A click on the icon first blurs the open popover (which hides it);
    // don't immediately re-open it in that case.
    let st = state::get(app);
    if lock(&st.tray_blurred_at).is_some_and(|t| t.elapsed() < Duration::from_millis(300)) {
        return;
    }
    let scale = w.scale_factor().unwrap_or(1.0);
    let pos: PhysicalPosition<f64> = icon.position.to_physical(scale);
    let size: tauri::PhysicalSize<f64> = icon.size.to_physical(scale);
    let win = w
        .outer_size()
        .map(|s| s.width as f64)
        .unwrap_or(TRAY_WIDTH * scale);
    let mut x = pos.x + size.width / 2.0 - win / 2.0;
    let y = pos.y + size.height + 4.0 * scale;
    if let Ok(Some(m)) = app.monitor_from_point(pos.x, pos.y) {
        let left = m.position().x as f64 + 8.0 * scale;
        let right = m.position().x as f64 + m.size().width as f64 - win - 8.0 * scale;
        x = x.clamp(left, right.max(left));
    }
    let _ = w.set_position(PhysicalPosition::new(x, y));
    let _ = w.show();
    let _ = w.set_focus();
}

/// Top-left corner (physical px) of the popover when there is no icon to
/// anchor it to: the top-right of the monitor, just under the menu bar.
pub fn corner_position(
    monitor_x: f64,
    monitor_y: f64,
    monitor_w: f64,
    win_w: f64,
    scale: f64,
) -> (f64, f64) {
    const MENU_BAR: f64 = 30.0; // logical px, a little more than the bar itself
    let x = (monitor_x + monitor_w - win_w - 8.0 * scale).max(monitor_x);
    (x, monitor_y + MENU_BAR * scale)
}

/// Reveal hotkey / `--reveal` / relaunch: toggle the popover, placed under
/// the menu bar icon when it is visible, else at the top-right corner.
pub fn reveal_tray(app: &AppHandle) {
    let Some(w) = app.get_webview_window(TRAY) else {
        return;
    };
    if w.is_visible().unwrap_or(false) {
        let _ = w.hide();
        return;
    }
    let ghost = lock(&state::get(app).settings).ghost_mode;
    if !ghost {
        if let Some(Ok(Some(rect))) = app.tray_by_id(crate::tray::ID).map(|t| t.rect()) {
            toggle_tray(app, rect);
            return;
        }
    }
    let scale = w.scale_factor().unwrap_or(1.0);
    let win = w
        .outer_size()
        .map(|s| s.width as f64)
        .unwrap_or(TRAY_WIDTH * scale);
    // The monitor with the menu bar: primary, else whatever we are on.
    let monitor = app
        .primary_monitor()
        .ok()
        .flatten()
        .or_else(|| w.current_monitor().ok().flatten());
    if let Some(m) = monitor {
        let (x, y) = corner_position(
            m.position().x as f64,
            m.position().y as f64,
            m.size().width as f64,
            win,
            m.scale_factor(),
        );
        let _ = w.set_position(PhysicalPosition::new(x, y));
    }
    let _ = w.show();
    let _ = w.set_focus();
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(kv: &[(&str, &str)]) -> BTreeMap<String, String> {
        kv.iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    #[test]
    fn specs() {
        let s = spec("unlock", &p(&[("id", "abc-1")])).unwrap();
        assert_eq!(s.label, "unlock-abc-1");
        assert_eq!(s.hash, "unlock?id=abc-1");
        assert_eq!(s.size, (400.0, 460.0));
        assert!(s.always_on_top);
        let s = spec("settings", &p(&[("tab", "vaults")])).unwrap();
        assert_eq!(
            (s.label.as_str(), s.hash.as_str()),
            ("settings", "settings?tab=vaults")
        );
        assert_eq!(spec("wizard", &p(&[])).unwrap().size, (580.0, 640.0));
        assert_eq!(
            spec("cleanup", &p(&[("id", "x")])).unwrap().size,
            (520.0, 720.0)
        );
    }

    #[test]
    fn corner() {
        // 1440 pt wide Retina display, 360 pt popover.
        assert_eq!(
            corner_position(0.0, 0.0, 2880.0, 720.0, 2.0),
            (2144.0, 60.0)
        );
        // Secondary monitor to the left, scale 1.
        assert_eq!(
            corner_position(-1920.0, 0.0, 1920.0, 360.0, 1.0),
            (-368.0, 30.0)
        );
        // Popover wider than the monitor stays on it.
        assert_eq!(corner_position(0.0, 0.0, 300.0, 360.0, 1.0), (0.0, 30.0));
    }

    #[test]
    fn rejects_bad_input() {
        assert!(spec("unlock", &p(&[])).is_err());
        assert!(spec("cleanup", &p(&[])).is_err());
        assert!(spec("nope", &p(&[])).is_err());
        assert!(spec("unlock", &p(&[("id", "x';alert(1)//")])).is_err());
        assert!(spec("settings", &p(&[("tab", "a&b=c")])).is_err());
    }
}
