//! Menu bar icon (docs/UI.md "Menu bar иконка"): template shield when all
//! vaults are locked, shield with a dot when one is open, red exclamation
//! (non-template, SPEC §7) when a detach failed. Left click toggles the
//! `tray` popover; right click shows "Lock all" / "Quit".

use std::thread;

use tauri::image::Image;
use tauri::menu::{Menu, MenuItem, PredefinedMenuItem};
use tauri::tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent};
use tauri::{AppHandle, Wry};

use crate::lockctl::{self, Reason};
use crate::state::{self, lock};
use crate::texts::{tr, T};
use crate::windows;

pub const ID: &str = "main";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IconState {
    Locked,
    Open,
    Error,
}

fn image(s: IconState) -> Image<'static> {
    let bytes: &'static [u8] = match s {
        IconState::Locked => include_bytes!("../icons/tray-locked.png"),
        IconState::Open => include_bytes!("../icons/tray-open.png"),
        IconState::Error => include_bytes!("../icons/tray-error.png"),
    };
    Image::from_bytes(bytes).expect("bundled tray icon is a valid PNG")
}

fn menu(app: &AppHandle) -> tauri::Result<Menu<Wry>> {
    let bg = state::get(app).is_bg();
    let lock_all = MenuItem::with_id(app, "lock_all", tr(bg, T::LockAll), true, None::<&str>)?;
    let sep = PredefinedMenuItem::separator(app)?;
    let quit = MenuItem::with_id(app, "quit", tr(bg, T::Quit), true, None::<&str>)?;
    Menu::with_items(app, &[&lock_all, &sep, &quit])
}

pub fn quit(app: &AppHandle) {
    let app = app.clone();
    thread::spawn(move || {
        let _ = lockctl::lock_all(&app, Reason::Quit);
        app.exit(0);
    });
}

pub fn create(app: &AppHandle) -> tauri::Result<()> {
    TrayIconBuilder::with_id(ID)
        .icon(image(IconState::Locked))
        .icon_as_template(true)
        .tooltip("Browser Vault")
        .menu(&menu(app)?)
        .show_menu_on_left_click(false)
        .on_menu_event(|app, ev| match ev.id().as_ref() {
            "lock_all" => lockctl::spawn_lock_all(app, Reason::Manual),
            "quit" => quit(app),
            _ => {}
        })
        .on_tray_icon_event(|icon, ev| {
            if let TrayIconEvent::Click {
                button: MouseButton::Left,
                button_state: MouseButtonState::Up,
                rect,
                ..
            } = ev
            {
                windows::toggle_tray(icon.app_handle(), rect);
            }
        })
        .build(app)?;
    refresh(app);
    Ok(())
}

pub fn current_state(app: &AppHandle) -> IconState {
    let st = state::get(app);
    if !lock(&st.errors).is_empty() {
        IconState::Error
    } else if !lock(&st.sessions).is_empty() {
        IconState::Open
    } else {
        IconState::Locked
    }
}

pub fn refresh(app: &AppHandle) {
    if state::get(app).is_quitting() {
        return; // see AppState::quitting
    }
    let Some(tray) = app.tray_by_id(ID) else {
        return;
    };
    let s = current_state(app);
    let _ = tray.set_icon(Some(image(s)));
    let _ = tray.set_icon_as_template(s != IconState::Error);
}

/// After a language change.
pub fn rebuild_menu(app: &AppHandle) {
    if let (Some(tray), Ok(m)) = (app.tray_by_id(ID), menu(app)) {
        let _ = tray.set_menu(Some(m));
    }
}
