//! Start vault apps through LaunchServices (like a double click), not as
//! child processes of this app.
//!
//! macOS attributes privacy-sensitive actions of a process to its
//! "responsible" app. A directly spawned child is our responsibility, so
//! Telegram's or Brave's microphone/camera requests were checked against
//! this app (and killed without a usage description), and Telegram's or
//! Slack's self-update was reported as "this app was prevented from
//! modifying apps". Launched through `NSWorkspace`, each app is its own
//! responsible process: its own privacy permissions, its own updates.

#[cfg(target_os = "macos")]
pub fn launch(spec: &vault_core::browser::LaunchSpec<'_>) -> Result<u32, String> {
    use std::sync::mpsc;
    use std::time::Duration;

    use block2::RcBlock;
    use objc2::rc::Retained;
    use objc2_app_kit::{NSRunningApplication, NSWorkspace, NSWorkspaceOpenConfiguration};
    use objc2_foundation::{NSArray, NSDictionary, NSError, NSString, NSURL};

    let bundle = spec.app_bundle.as_ref().ok_or("no app bundle")?;
    let url = NSURL::fileURLWithPath(&NSString::from_str(&bundle.to_string_lossy()));
    let cfg = NSWorkspaceOpenConfiguration::configuration();
    let args: Vec<Retained<NSString>> = spec
        .args
        .iter()
        .map(|a| NSString::from_str(&a.to_string_lossy()))
        .collect();
    cfg.setArguments(&NSArray::from_retained_slice(&args));
    if !spec.env.is_empty() {
        // The configured environment replaces the inherited one: pass ours
        // along with the extra variables.
        let mut pairs: Vec<(String, String)> = std::env::vars().collect();
        for (k, v) in &spec.env {
            pairs.retain(|(pk, _)| pk != k);
            pairs.push(((*k).to_string(), (*v).to_string()));
        }
        let keys: Vec<Retained<NSString>> =
            pairs.iter().map(|(k, _)| NSString::from_str(k)).collect();
        let vals: Vec<Retained<NSString>> =
            pairs.iter().map(|(_, v)| NSString::from_str(v)).collect();
        let key_refs: Vec<&NSString> = keys.iter().map(|k| &**k).collect();
        let env = NSDictionary::from_retained_objects(&key_refs, &vals);
        cfg.setEnvironment(&env);
    }
    // A separate instance even when the regular app is running; no entry in
    // Apple menu → Recent Items; no Gatekeeper/app-store prompts on our behalf.
    cfg.setCreatesNewApplicationInstance(true);
    cfg.setActivates(true);
    cfg.setAddsToRecentItems(false);
    cfg.setPromptsUserIfNeeded(false);

    let (tx, rx) = mpsc::sync_channel::<Result<u32, String>>(1);
    let block = RcBlock::new(move |app: *mut NSRunningApplication, err: *mut NSError| {
        // SAFETY: AppKit passes either a valid object or nil for each.
        let pid = unsafe { app.as_ref() }.map(|a| a.processIdentifier());
        let r = match pid {
            Some(p) if p > 0 => Ok(p as u32),
            _ => Err(unsafe { err.as_ref() }
                .map(|e| e.localizedDescription().to_string())
                .unwrap_or_else(|| "no process".into())),
        };
        let _ = tx.try_send(r);
    });
    NSWorkspace::sharedWorkspace().openApplicationAtURL_configuration_completionHandler(
        &url,
        &cfg,
        Some(&block),
    );
    rx.recv_timeout(Duration::from_secs(30))
        .map_err(|_| "LaunchServices did not answer".to_string())?
}
