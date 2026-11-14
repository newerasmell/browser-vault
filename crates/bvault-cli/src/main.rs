//! `bvault` — CLI over `vault-core`, for testing and debugging without the UI.
//!
//! Secrets are read from the TTY without echo (or from stdin with
//! `--password-stdin`), never from argv or the environment.

use std::io::{BufRead, IsTerminal};
use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use vault_core::header::VaultSettings;
use vault_core::keyslot::Draft;
use vault_core::store::{Credential, Devices, DEFAULT_SIZE_GB};
use vault_core::{events, fido2, recovery, se, totp, Browser, Error, KdfCost, Store};
use zeroize::Zeroizing;

#[derive(Parser)]
#[command(name = "bvault", version, about = "Browser Vault command-line tool")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Create a new vault (encrypted sparsebundle + header).
    Create {
        #[arg(long)]
        name: String,
        #[arg(long, default_value = "brave")]
        browser: String,
        #[arg(long, default_value_t = DEFAULT_SIZE_GB)]
        size_gb: u32,
        /// Second factor: `totp` (authenticator app) or `fido2` (YubiKey).
        /// `password-only` exists only in builds with the `test-password-slot` feature.
        #[arg(long, default_value = "fido2")]
        mode: String,
        /// Read the password as one line from stdin (no confirmation prompt).
        #[arg(long)]
        password_stdin: bool,
    },
    /// List vaults and their state.
    List,
    /// Unlock, mount, launch the browser; locks again when the browser exits.
    Unlock {
        /// Vault id or name.
        vault: String,
        /// Unlock with the 24-word recovery phrase instead of password + factor.
        #[arg(long)]
        recovery: bool,
        /// Only mount; do not launch the browser (lock later with `bvault lock`).
        #[arg(long)]
        no_launch: bool,
        /// Explicit browser binary instead of auto-detection.
        #[arg(long)]
        browser_path: Option<PathBuf>,
        #[arg(long)]
        password_stdin: bool,
    },
    /// Stop the vault's browser and unmount the volume.
    Lock { vault: String },
    /// Lock every vault.
    LockAll,
}

fn read_secret(prompt: &str, from_stdin: bool) -> Result<Zeroizing<String>, Error> {
    if from_stdin || !std::io::stdin().is_terminal() {
        let mut line = Zeroizing::new(String::new());
        std::io::stdin().lock().read_line(&mut line)?;
        while line.ends_with('\n') || line.ends_with('\r') {
            line.pop();
        }
        Ok(line)
    } else {
        Ok(Zeroizing::new(rpassword::prompt_password(prompt)?))
    }
}

fn print_recovery(phrase: &str) {
    eprintln!();
    eprintln!("RECOVERY PHRASE — shown once. Write it down on paper and keep it safe.");
    eprintln!("It unlocks this vault on its own, without the password.");
    eprintln!();
    for (i, w) in recovery::words(phrase).iter().enumerate() {
        eprint!("{:>2}. {:<12}", i + 1, w.as_str());
        if i % 4 == 3 {
            eprintln!();
        }
    }
    eprintln!();
}

/// Ask for 3 random words back (SPEC §4) when running interactively.
fn confirm_recovery(phrase: &str) -> Result<(), Error> {
    if !std::io::stdin().is_terminal() {
        return Ok(());
    }
    loop {
        let positions = recovery::challenge_positions(3);
        let mut answers: Vec<(usize, Zeroizing<String>)> = vec![];
        for p in &positions {
            answers.push((*p, read_secret(&format!("Word #{p}: "), false)?));
        }
        let refs: Vec<(usize, &str)> = answers.iter().map(|(p, w)| (*p, w.as_str())).collect();
        if recovery::verify_answers(phrase, &refs) {
            return Ok(());
        }
        eprintln!("Those words don't match. Check your copy and try again.");
    }
}

fn cli_notify(e: events::Event) {
    match e {
        events::Event::FidoTouchNeeded => eprintln!("Touch your YubiKey…"),
        events::Event::FidoTouchDone => eprintln!("OK."),
        _ => {}
    }
}

#[cfg(feature = "test-password-slot")]
fn unlock_password_only(
    store: &Store,
    id: &str,
    password: &str,
    dev: &Devices<'_>,
) -> Result<vault_core::store::Unlocked, Error> {
    store.unlock(id, Credential::Password(password), dev)
}

#[cfg(not(feature = "test-password-slot"))]
fn unlock_password_only(
    _: &Store,
    _: &str,
    _: &str,
    _: &Devices<'_>,
) -> Result<vault_core::store::Unlocked, Error> {
    Err(Error::UnlockFailed)
}

fn add_factor(draft: &mut Draft, mode: &str, from_stdin: bool) -> Result<(), Error> {
    match mode {
        "totp" => {
            let se = se::system();
            let setup = totp::begin(draft, se.as_ref())?;
            eprintln!("Add this account to your authenticator app:");
            eprintln!("  {}", setup.uri.as_str());
            eprintln!("  manual key: {}", setup.secret.as_str());
            loop {
                let code = read_secret("Code from the app: ", from_stdin)?;
                match totp::confirm(draft, &code, se.as_ref(), vault_core::store::now_unix()) {
                    Ok(()) => break,
                    Err(Error::UnlockFailed) if !from_stdin => eprintln!("Wrong code, try again."),
                    Err(e) => return Err(e),
                }
            }
        }
        "fido2" => {
            let auth = fido2::system();
            let pin = read_secret("YubiKey PIN: ", from_stdin)?;
            fido2::register(draft, auth.as_ref(), &pin, "YubiKey main", &cli_notify)?;
            if !from_stdin && std::io::stdin().is_terminal() {
                let ans = read_secret("Register a backup key now? Insert it and type y: ", false)?;
                if ans.trim().eq_ignore_ascii_case("y") {
                    let pin = read_secret("Backup key PIN: ", false)?;
                    fido2::register(draft, auth.as_ref(), &pin, "YubiKey backup", &cli_notify)?;
                }
            }
        }
        #[cfg(feature = "test-password-slot")]
        "password-only" => draft.add_password_only_slot()?,
        _ => return Err(Error::Invalid("mode must be totp or fido2")),
    }
    Ok(())
}

fn run(cli: Cli) -> Result<(), Error> {
    // The CLI only reads the app's name index; it never creates the
    // Keychain item (macOS would then ask the app for access to it).
    let store = Store::default_location()?.with_index_key(vault_core::index::keychain_read_only);
    match cli.cmd {
        Cmd::Create {
            name,
            browser,
            size_gb,
            mode,
            password_stdin,
        } => {
            let browser = Browser::parse(&browser)
                .ok_or(Error::Invalid("browser must be brave or firefox"))?;
            let mut draft = Draft::new(&name, browser, KdfCost::DEFAULT)?;
            let pw = read_secret("Password (min 12 characters): ", password_stdin)?;
            vault_core::keyslot::validate_password(&pw)?;
            if !password_stdin && std::io::stdin().is_terminal() {
                let again = read_secret("Repeat password: ", false)?;
                if *again != *pw {
                    return Err(Error::Invalid("passwords do not match"));
                }
            }
            eprintln!("Deriving keys…");
            draft.set_password(&pw)?;
            drop(pw);
            add_factor(&mut draft, &mode, password_stdin)?;
            draft.generate_recovery()?;
            let phrase = Zeroizing::new(draft.recovery_phrase().unwrap_or_default().to_string());
            eprintln!("Creating encrypted disk…");
            let header = store.create(draft, size_gb, VaultSettings::default(), &events::ignore)?;
            print_recovery(&phrase);
            confirm_recovery(&phrase)?;
            println!("{}", header.vault_id);
        }
        Cmd::List => {
            for l in store.list_labeled()? {
                let h = &l.header;
                let state = if store.is_unlocked(&h.vault_id) {
                    "unlocked"
                } else {
                    "locked"
                };
                // v2 headers keep name and browser encrypted; without this
                // Mac's index entry they are unknown until the next unlock.
                let (browser, name) = match &l.label {
                    Some(e) => (e.browser.as_str(), e.name.as_str()),
                    None => ("?", "(locked)"),
                };
                println!("{}  {:<8} {:<8} {}", h.vault_id, browser, state, name);
            }
        }
        Cmd::Unlock {
            vault,
            recovery,
            no_launch,
            browser_path,
            password_stdin,
        } => {
            let h = store.resolve(&vault)?;
            let se = se::system();
            let fido = fido2::system();
            let dev = Devices {
                se: se.as_ref(),
                fido: fido.as_ref(),
                notify: &cli_notify,
            };
            let unlocked = if recovery {
                let phrase = read_secret("Recovery phrase: ", password_stdin)?;
                store.unlock(&h.vault_id, Credential::Recovery(&phrase), &dev)?
            } else {
                let password = read_secret("Password: ", password_stdin)?;
                let kinds: Vec<&str> = h.slots.iter().map(|s| s.kind()).collect();
                if kinds.contains(&"totp") {
                    let code = read_secret("Authenticator code: ", password_stdin)?;
                    store.unlock(
                        &h.vault_id,
                        Credential::Totp {
                            password: &password,
                            code: &code,
                        },
                        &dev,
                    )?
                } else if kinds.contains(&"fido2") {
                    let pin = read_secret("YubiKey PIN: ", password_stdin)?;
                    store.unlock(
                        &h.vault_id,
                        Credential::Fido2 {
                            password: &password,
                            pin: &pin,
                        },
                        &dev,
                    )?
                } else {
                    unlock_password_only(&store, &h.vault_id, &password, &dev)?
                }
            };
            if !unlocked.header_intact {
                eprintln!(
                    "WARNING: this vault's header.json was modified outside Browser Vault. \
                     Check its settings."
                );
            }
            if no_launch {
                println!("{}", unlocked.mountpoint.display());
                return Ok(());
            }
            let child = match store.launch(&unlocked, browser_path.as_deref()) {
                Ok(c) => c,
                Err(e) => {
                    let _ = store.lock(&h.vault_id);
                    if matches!(e, Error::BrowserMissing) {
                        if let Ok(m) = unlocked.header.meta() {
                            eprintln!("Download: {}", m.browser.download_url());
                        }
                    }
                    return Err(e);
                }
            };
            eprintln!("Vault unlocked. It locks when the browser quits (or run `bvault lock`).");
            child.wait();
            store.lock(&h.vault_id)?;
            drop(unlocked);
            eprintln!("Vault locked.");
        }
        Cmd::Lock { vault } => {
            let h = store.resolve(&vault)?;
            store.lock(&h.vault_id)?;
            eprintln!("Vault locked.");
        }
        Cmd::LockAll => {
            store.lock_all()?;
            eprintln!("All vaults locked.");
        }
    }
    Ok(())
}

fn main() -> ExitCode {
    match run(Cli::parse()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("bvault: {e}");
            ExitCode::FAILURE
        }
    }
}
