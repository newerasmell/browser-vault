//! Panic hotkey (SPEC §6 trigger 5) and the ghost-mode reveal hotkey: parse
//! the UI's display form (`⌃⌥⌘L`) into a global shortcut.

use tauri_plugin_global_shortcut::{Code, Modifiers, Shortcut};

pub const DEFAULT: &str = "⌃⌥⌘L";
/// Ghost mode: shows the tray popover (there is no menu bar icon).
pub const DEFAULT_REVEAL: &str = "⌃⌥⌘B";

/// What a registered global shortcut does.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    LockAll,
    Reveal,
}

/// Whether two display forms name the same key combination.
pub fn same(a: &str, b: &str) -> bool {
    matches!((parse(a), parse(b)), (Some(x), Some(y)) if x == y)
}

/// Which action a fired shortcut belongs to. The reveal hotkey only counts
/// while it is registered (ghost mode); anything else registered is the
/// panic hotkey (or its default fallback).
pub fn dispatch(fired: &Shortcut, reveal: Option<&str>) -> Action {
    match reveal.and_then(parse) {
        Some(r) if r == *fired => Action::Reveal,
        _ => Action::LockAll,
    }
}

/// `⌃` Control, `⌥` Option, `⇧` Shift, `⌘` Command, then one key: a letter,
/// a digit, `F1`..`F20` or `SPACE`. At least one modifier is required.
pub fn parse(s: &str) -> Option<Shortcut> {
    let mut mods = Modifiers::empty();
    let mut rest = s.trim_start();
    loop {
        let mut chars = rest.chars();
        let m = match chars.next()? {
            '⌃' => Modifiers::CONTROL,
            '⌥' => Modifiers::ALT,
            '⇧' => Modifiers::SHIFT,
            '⌘' => Modifiers::SUPER,
            _ => break,
        };
        mods |= m;
        rest = chars.as_str();
    }
    if mods.is_empty() {
        return None;
    }
    let key = if rest == " " {
        "SPACE".to_string()
    } else {
        rest.trim().to_ascii_uppercase()
    };
    let code_name = match key.as_str() {
        "SPACE" => "Space".to_string(),
        k if k.len() == 1 && k.as_bytes()[0].is_ascii_uppercase() => format!("Key{k}"),
        k if k.len() == 1 && k.as_bytes()[0].is_ascii_digit() => format!("Digit{k}"),
        k if k.starts_with('F') && k[1..].parse::<u8>().is_ok_and(|n| (1..=20).contains(&n)) => {
            k.to_string()
        }
        _ => return None,
    };
    let code: Code = code_name.parse().ok()?;
    Some(Shortcut::new(Some(mods), code))
}

/// Whether a combo may be used as the *global* panic hotkey. A global
/// shortcut swallows the keys in every app, so it needs at least two
/// modifiers and must not be ⌘⇧+key (common app shortcuts like ⌘⇧T);
/// this also rules out ⌘Q, ⌘W, ⌘Tab-style single-⌘ combos.
pub fn allowed(s: &str) -> bool {
    let Some(sc) = parse(s) else { return false };
    let m = sc.mods;
    m.bits().count_ones() >= 2 && m != (Modifiers::SUPER | Modifiers::SHIFT)
}

#[cfg(test)]
mod tests {
    #[test]
    fn global_hotkey_policy() {
        assert!(allowed(DEFAULT));
        assert!(allowed("⌃⌘K"));
        assert!(allowed("⌃⇧F5"));
        assert!(!allowed("⌘Q"));
        assert!(!allowed("⌘W"));
        assert!(!allowed("⌃K"));
        assert!(!allowed("⇧⌘T"));
        assert!(!allowed("L"));
    }

    use super::*;

    #[test]
    fn default_parses() {
        let s = parse(DEFAULT).unwrap();
        assert_eq!(
            s,
            Shortcut::new(
                Some(Modifiers::CONTROL | Modifiers::ALT | Modifiers::SUPER),
                Code::KeyL
            )
        );
    }

    #[test]
    fn variants() {
        assert_eq!(
            parse("⌘⇧7"),
            Some(Shortcut::new(
                Some(Modifiers::SUPER | Modifiers::SHIFT),
                Code::Digit7
            ))
        );
        assert_eq!(
            parse("⌃F12"),
            Some(Shortcut::new(Some(Modifiers::CONTROL), Code::F12))
        );
        assert_eq!(
            parse("⌥ "),
            Some(Shortcut::new(Some(Modifiers::ALT), Code::Space))
        );
        assert_eq!(
            parse("⌃k"),
            Some(Shortcut::new(Some(Modifiers::CONTROL), Code::KeyK))
        );
    }

    #[test]
    fn dispatch_by_shortcut() {
        let panic = parse(DEFAULT).unwrap();
        let reveal = parse(DEFAULT_REVEAL).unwrap();
        assert_eq!(dispatch(&panic, Some(DEFAULT_REVEAL)), Action::LockAll);
        assert_eq!(dispatch(&reveal, Some(DEFAULT_REVEAL)), Action::Reveal);
        assert_eq!(dispatch(&reveal, None), Action::LockAll);
        assert_eq!(dispatch(&panic, Some("garbage")), Action::LockAll);
        assert!(same("⌃⌥⌘B", "⌘⌥⌃b"));
        assert!(!same(DEFAULT, DEFAULT_REVEAL));
        assert!(!same("x", "x"));
        assert!(allowed(DEFAULT_REVEAL));
    }

    #[test]
    fn rejects() {
        for bad in ["", "L", "⌃", "⌃⌥¬", "⌃F99", "⌃AB", "⌃ARROWUP"] {
            assert!(parse(bad).is_none(), "{bad:?}");
        }
    }
}
