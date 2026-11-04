// Bridge to the Rust backend. Inside Tauri it calls real commands;
// in a normal browser it falls back to an in-memory mock for UI work.
// The command/event contract is documented in docs/UI.md.

export const isTauri = !!(window.__TAURI__ && window.__TAURI__.core);

export async function api(cmd, args = {}) {
  if (isTauri) return window.__TAURI__.core.invoke(cmd, args);
  if (!mock[cmd]) throw new Error('mock missing: ' + cmd);
  return mock[cmd](args);
}

export function on(event, cb) {
  if (isTauri) {
    const p = window.__TAURI__.event.listen(event, (e) => cb(e.payload));
    return () => p.then((un) => un());
  }
  (bus[event] ||= new Set()).add(cb);
  return () => bus[event].delete(cb);
}

// ---------------- mock ----------------
const bus = {};
const emit = (ev, payload) => (bus[ev] || []).forEach((cb) => cb(payload));
const wait = (ms) => new Promise((r) => setTimeout(r, ms));
const err = (code, extra = {}) => Object.assign(new Error(code), { code, ...extra });

const vaults = [
  { id: 'v1', name: 'Work – Brave', browser: 'brave', mode: 'fido2', status: 'unlocked', sizeGb: 20,
    original: { profileName: 'Default', sizeMb: 842, reviewed: true, state: 'pending' } },
  { id: 'v2', name: 'Ads accounts – Firefox', browser: 'firefox', mode: 'totp', status: 'locked', sizeGb: 20,
    original: { profileName: 'default-release', sizeMb: 516, reviewed: false, state: 'pending' } },
  { id: 'v3', name: 'Personal', browser: 'brave', mode: 'totp', status: 'locked', sizeGb: 10 }
];
let settings = {
  language: 'bg', launchAtLogin: true, idleMinutes: 15,
  lockOnScreenLock: true, lockOnKeyRemoval: true, panicHotkey: '⌃⌥⌘L'
};
const WORDS = 'orbit velvet canyon mirror stable pepper ladder violin thunder cotton harbor magnet ' +
  'silver planet frozen meadow rocket island garden copper winter shadow bamboo lantern';
let fails = 0;
const MOCK_PROFILES = {
  brave: [{ id: 'Default', name: 'Default', sizeMb: 842 }, { id: 'Profile 1', name: 'Work', sizeMb: 311 },
    { id: 'Profile 2', name: 'Ads', sizeMb: 204 }],
  firefox: [{ id: 'default-release', name: 'default-release', sizeMb: 516 }]
};
// Spec 5.1: "reviewed" becomes true after the vault was opened and closed once after import.
const markLocked = (v) => { if (v.status === 'unlocked' && v.original) v.original.reviewed = true; v.status = 'locked'; };

const mock = {
  list_vaults: async () => structuredClone(vaults),
  detect_browsers: async () => ({
    brave: { found: true, path: '/Applications/Brave Browser.app' },
    firefox: { found: true, path: '/Applications/Firefox.app' }
  }),
  open_window: async ({ view, params }) => {
    location.hash = view + (params ? '?' + new URLSearchParams(params) : '');
  },
  close_window: async () => { location.hash = 'tray'; },
  focus_browser: async () => {},
  quit_app: async () => {},

  unlock_vault: async ({ id, password, pin, code }) => {
    const v = vaults.find((x) => x.id === id);
    if (fails >= 5) throw err('rate_limited', { retryAfter: 30 });
    if (v.mode === 'fido2') {
      emit('fido_touch_needed', { id });
      await wait(1600);
      emit('fido_touch_done', { id });
    } else await wait(500);
    const ok = password && (v.mode === 'fido2' ? !!pin : code === '123456');
    if (!ok) { fails++; throw err('unlock_failed'); }
    fails = 0; v.status = 'unlocked'; emit('vaults_changed');
    return { ok: true };
  },
  unlock_with_recovery: async ({ id, phrase }) => {
    await wait(700);
    if (phrase.trim().split(/\s+/).length !== 24) throw err('unlock_failed');
    vaults.find((x) => x.id === id).status = 'unlocked'; emit('vaults_changed');
    return { ok: true };
  },
  lock_vault: async ({ id }) => {
    await wait(300); markLocked(vaults.find((x) => x.id === id)); emit('vaults_changed');
  },
  lock_all: async () => { await wait(300); vaults.forEach(markLocked); emit('vaults_changed'); },

  wizard_begin: async () => ({ draftId: 'd' + Date.now() }),
  wizard_set_password: async () => ({ ok: true }),
  fido_register: async ({ label }) => {
    emit('fido_touch_needed', {}); await wait(1500); emit('fido_touch_done', {});
    return { label };
  },
  totp_begin: async () => ({ secret: 'JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP', qrSvg: fakeQr() }),
  totp_confirm: async ({ code }) => { await wait(300); return { ok: code === '123456' }; },
  recovery_generate: async () => ({ words: WORDS.split(' ') }),
  recovery_verify: async ({ answers }) => {
    const w = WORDS.split(' ');
    return { ok: Object.entries(answers).every(([i, v]) => w[i - 1] === v.trim().toLowerCase()) };
  },
  wizard_finish: async ({ name, browser, mode, sizeGb, options }) => {
    const stages = ['disk', 'keys', 'profile', ...(options.importProfile ? ['import'] : [])];
    for (let i = 0; i < stages.length; i++) {
      emit('create_progress', { stage: stages[i], pct: Math.round((i / stages.length) * 100) });
      await wait(700);
    }
    emit('create_progress', { stage: 'done', pct: 100 });
    const id = 'v' + (vaults.length + 1);
    // Mirrors vault-core: '*' = every Brave profile, recorded as "All profiles (N)".
    const all = options.importProfileId === '*';
    const found = all ? MOCK_PROFILES.brave : [];
    vaults.push({ id, name, browser, mode, status: 'locked', sizeGb,
      original: options.importProfile ? {
        profileName: all ? `All profiles (${found.length})` : options.importProfileId,
        profileIds: all ? found.map((p) => p.id) : [options.importProfileId],
        sizeMb: all ? found.reduce((s, p) => s + p.sizeMb, 0) : 300, reviewed: false, state: 'pending' } : null });
    emit('vaults_changed');
    return { vaultId: id };
  },
  wizard_cancel: async () => {},

  get_settings: async () => ({ ...settings }),
  save_settings: async (s) => { settings = { ...settings, ...s }; return settings; },
  list_factors: async ({ id }) => {
    const v = vaults.find((x) => x.id === id);
    return v.mode === 'fido2'
      ? [{ type: 'fido2', label: 'YubiKey main' }, { type: 'fido2', label: 'YubiKey backup' }, { type: 'recovery', label: 'Recovery phrase' }]
      : [{ type: 'totp', label: 'Authenticator' }, { type: 'recovery', label: 'Recovery phrase' }];
  },
  request_vault_action: async () => ({ ok: true }),
  action_auth: async ({ id, code, pin }) => {
    const v = vaults.find((x) => x.id === id);
    if (v.mode === 'totp' && code !== '123456') throw { code: 'unlock_failed' };
    if (v.mode === 'fido2') { emit('fido_touch_needed'); await wait(900); emit('fido_touch_done'); }
    return { token: 'demo', mode: v.mode, keys: v.mode === 'fido2' ? ['YubiKey main', 'YubiKey backup'] : [] };
  },
  action_change_password: async () => ({ done: true }),
  action_fido_rewrap: async () => ({ done: true, remaining: [] }),
  action_totp_begin: async () => ({ secret: 'JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP', qrSvg: '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 10 10"><rect width="10" height="10" fill="#000"/></svg>' }),
  action_totp_confirm: async ({ code }) => ({ ok: code === '123456' }),
  action_add_fido2: async ({ label }) => { emit('fido_touch_needed'); await wait(900); emit('fido_touch_done'); return { label }; },
  action_recovery_generate: async () => ({ words: 'abandon ability able about above absent absorb abstract absurd abuse access accident account accuse achieve acid acoustic acquire across act action actor actress actual'.split(' ') }),
  action_recovery_confirm: async ({ answers }) => ({ ok: Object.values(answers).every((w) => w.length > 2) }),
  action_end: async () => {},

  detect_profiles: async ({ browser }) => structuredClone(MOCK_PROFILES[browser] || []),
  browser_running: async () => ({ running: false }),
  cleanup_preview: async ({ id }) => {
    const v = vaults.find((x) => x.id === id);
    const home = '/Users/you/Library';
    const items = v.browser === 'brave'
      ? [...(v.original.profileIds || [v.original.profileName]).flatMap((p) => [
          `${home}/Application Support/BraveSoftware/Brave-Browser/${p}`,
          `${home}/Caches/BraveSoftware/Brave-Browser/${p}`]),
         `${home}/Saved Application State/com.brave.Browser.savedState`]
      : [`${home}/Application Support/Firefox/Profiles/x7k2.${v.original.profileName}`,
         `${home}/Caches/Firefox/Profiles/x7k2.${v.original.profileName}`,
         `${home}/Saved Application State/org.mozilla.firefox.savedState`];
    return { items, sizeMb: v.original.sizeMb, reviewed: v.original.reviewed, fileVault: false,
      profileName: v.original.profileName, browser: v.browser };
  },
  cleanup_original: async ({ id, password }) => {
    const v = vaults.find((x) => x.id === id);
    if (!v.original.reviewed) throw err('not_reviewed');
    if (!password) throw err('unlock_failed');
    for (const pct of [20, 55, 85]) { emit('cleanup_progress', { pct }); await wait(450); }
    emit('cleanup_progress', { pct: 100 });
    v.original.state = 'deleted'; emit('vaults_changed');
    return { ok: true };
  },
  keep_original: async ({ id }) => { vaults.find((x) => x.id === id).original.state = 'kept'; emit('vaults_changed'); },
  restore_original_notice: async ({ id }) => { vaults.find((x) => x.id === id).original.state = 'pending'; emit('vaults_changed'); },
  pick_browser_path: async () => null,
  app_info: async () => ({ version: '0.1.0-dev' })
};

// Placeholder QR pattern for UI previews only (real QR comes from the Rust `qrcode` crate).
function fakeQr() {
  const n = 25, s = 8; let r = '';
  let seed = 7;
  const rnd = () => ((seed = (seed * 9301 + 49297) % 233280) / 233280);
  const finder = (x, y) => `<rect x="${x*s}" y="${y*s}" width="${7*s}" height="${7*s}" fill="#000"/>` +
    `<rect x="${(x+1)*s}" y="${(y+1)*s}" width="${5*s}" height="${5*s}" fill="#fff"/>` +
    `<rect x="${(x+2)*s}" y="${(y+2)*s}" width="${3*s}" height="${3*s}" fill="#000"/>`;
  for (let y = 0; y < n; y++) for (let x = 0; x < n; x++) {
    const inF = (x < 8 && y < 8) || (x > n - 9 && y < 8) || (x < 8 && y > n - 9);
    if (!inF && rnd() > 0.5) r += `<rect x="${x*s}" y="${y*s}" width="${s}" height="${s}"/>`;
  }
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${n*s} ${n*s}"><rect width="100%" height="100%" fill="#fff"/>` +
    `<g fill="#000">${r}</g>${finder(0,0)}${finder(n-7,0)}${finder(0,n-7)}</svg>`;
}
