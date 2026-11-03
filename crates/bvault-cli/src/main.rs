//! `bvault` — CLI over `vault-core`, for testing and debugging without the UI.
//!
//! Secrets are read from the TTY without echo (or from stdin with
//! `--password-stdin`), never from argv or the environment.

use std::io::{BufRead, IsTerminal};
use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use vault_core::store::{Credential, DEFAULT_SIZE_GB};
use vault_core::{recovery, Browser, Error, KdfCost, Store};
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
        /// Unlock with the 24-word recovery phrase instead of the password.
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

fn run(cli: Cli) -> Result<(), Error> {
    let store = Store::default_location()?;
    match cli.cmd {
        Cmd::Create {
            name,
            browser,
            size_gb,
            password_stdin,
        } => {
            let browser = Browser::parse(&browser)
                .ok_or(Error::Invalid("browser must be brave or firefox"))?;
            let pw = read_secret("Password (min 12 characters): ", password_stdin)?;
            vault_core::keyslot::validate_password(&pw)?;
            if !password_stdin && std::io::stdin().is_terminal() {
                let again = read_secret("Repeat password: ", false)?;
                if *again != *pw {
                    return Err(Error::Invalid("passwords do not match"));
                }
            }
            eprintln!("Creating vault (deriving keys, creating encrypted disk)…");
            let created = store.create(&name, browser, &pw, size_gb, KdfCost::DEFAULT)?;
            drop(pw);
            print_recovery(&created.recovery_phrase);
            confirm_recovery(&created.recovery_phrase)?;
            println!("{}", created.header.vault_id);
        }
        Cmd::List => {
            for h in store.list()? {
                let state = if store.is_unlocked(&h.vault_id) {
                    "unlocked"
                } else {
                    "locked"
                };
                println!(
                    "{}  {:<8} {:<8} {}",
                    h.vault_id,
                    h.browser.as_str(),
                    state,
                    h.name
                );
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
            let prompt = if recovery {
                "Recovery phrase: "
            } else {
                "Password: "
            };
            let secret = read_secret(prompt, password_stdin)?;
            let cred = if recovery {
                Credential::Recovery(&secret)
            } else {
                Credential::Password(&secret)
            };
            let unlocked = store.unlock(&h.vault_id, cred)?;
            drop(secret);
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
            let mut child = match store.launch(&unlocked, browser_path.as_deref()) {
                Ok(c) => c,
                Err(e) => {
                    let _ = store.lock(&h.vault_id);
                    if matches!(e, Error::BrowserMissing) {
                        eprintln!("Download: {}", h.browser.download_url());
                    }
                    return Err(e);
                }
            };
            eprintln!("Vault unlocked. It locks when the browser quits (or run `bvault lock`).");
            let _ = child.wait();
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
