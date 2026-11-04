//! Panic hotkey (SPEC §6 trigger 5): parse the UI's display form (`⌃⌥⌘L`)
//! into a global shortcut.

use tauri_plugin_global_shortcut::{Code, Modifiers, Shortcut};

pub const DEFAULT: &str = "⌃⌥⌘L";

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
    fn rejects() {
        for bad in ["", "L", "⌃", "⌃⌥¬", "⌃F99", "⌃AB", "⌃ARROWUP"] {
            assert!(parse(bad).is_none(), "{bad:?}");
        }
    }
}
