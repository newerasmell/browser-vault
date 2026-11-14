import { t, setLang, getLang, languages } from './i18n.js';
import { api, on, isTauri } from './api.js';

const root = document.getElementById('app');
let cleanup = [];

// ---------- helpers ----------
function h(tag, props, ...kids) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(props || {})) {
    if (v == null || v === false) continue;
    if (k === 'class') el.className = v;
    else if (k === 'value') el.value = v;
    else if (k === 'checked') el.checked = !!v;
    else if (k === 'svg') el.innerHTML = v; // trusted, app-generated SVG only
    else if (k.startsWith('on')) el.addEventListener(k.slice(2), v);
    else el.setAttribute(k, v === true ? '' : v);
  }
  for (const kid of kids.flat(Infinity)) {
    if (kid == null || kid === false) continue;
    el.append(kid instanceof Node ? kid : document.createTextNode(String(kid)));
  }
  return el;
}

const ICONS = {
  shield: '<path d="M12 3l8 3v6c0 5-3.5 8-8 9-4.5-1-8-4-8-9V6z"/>',
  lock: '<rect x="5" y="11" width="14" height="10" rx="2"/><path d="M8 11V7a4 4 0 0 1 8 0v4"/>',
  unlock: '<rect x="5" y="11" width="14" height="10" rx="2"/><path d="M8 11V7a4 4 0 0 1 7.6-1.8"/>',
  key: '<rect x="9" y="2.5" width="6" height="7" rx="1"/><rect x="7" y="9.5" width="10" height="12" rx="2.5"/><circle cx="12" cy="15.5" r="2"/>',
  phone: '<rect x="7" y="2.5" width="10" height="19" rx="2.5"/><path d="M11 18h2"/>',
  sliders: '<path d="M4 7h9M17 7h3M4 17h3M11 17h9"/><circle cx="15" cy="7" r="2"/><circle cx="9" cy="17" r="2"/>',
  plus: '<path d="M12 5v14M5 12h14"/>',
  check: '<path d="M5 12.5l4.5 4.5L19 7"/>',
  alert: '<path d="M12 3l9.5 17h-19z"/><path d="M12 10v4M12 17.5v.01"/>',
  power: '<path d="M12 3v8"/><path d="M6.3 6.8a8 8 0 1 0 11.4 0"/>',
  globe: '<circle cx="12" cy="12" r="9"/><path d="M3 12h18M12 3c3 3.2 3 14.8 0 18M12 3c-3 3.2-3 14.8 0 18"/>',
  copy: '<rect x="8" y="8" width="12" height="12" rx="2"/><path d="M16 8V6a2 2 0 0 0-2-2H6a2 2 0 0 0-2 2v8a2 2 0 0 0 2 2h2"/>'
};
const icon = (name, cls = '') =>
  h('span', { class: 'ico ' + cls, svg: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round">${ICONS[name]}</svg>` });

const BROWSERS = { brave: 'Brave', firefox: 'Firefox', telegram: 'Telegram', whatsapp: 'WhatsApp', slack: 'Slack' };
// Kinds that run inside another installed app (WhatsApp Web runs in Brave).
const ENGINE = { whatsapp: 'brave' };
// Kinds that start with a fresh sign-in (nothing to import).
const NO_IMPORT = new Set(['whatsapp', 'slack']);
const fmtSize = (mb) => (mb >= 1024 ? (mb / 1024).toFixed(1) + ' GB' : Math.round(mb) + ' MB');
// A vault's name/browser are null when its header keeps them encrypted and
// this Mac has no index entry yet (shown as "Locked vault" until unlocked).
const badge = (b) => BROWSERS[b]
  ? h('span', { class: 'badge badge-' + b, 'aria-label': BROWSERS[b] }, BROWSERS[b][0])
  : h('span', { class: 'badge badge-unknown', 'aria-label': t('browser_unknown') }, icon('lock', 'xs'));
const vname = (v) => v.name ?? t('locked_vault');
const bname = (b) => BROWSERS[b] ?? t('browser_unknown');
const vsub = (v, ...rest) => [BROWSERS[v.browser], ...rest].filter(Boolean).join(' · ');

function toast(msg, kind = '') {
  const el = h('div', { class: 'toast ' + kind, role: 'status' }, msg);
  document.body.append(el);
  requestAnimationFrame(() => el.classList.add('show'));
  setTimeout(() => { el.classList.remove('show'); setTimeout(() => el.remove(), 300); }, 2200);
}

function toggle(label, checked, onchange, hint) {
  return h('label', { class: 'toggle-row' },
    h('span', { class: 'toggle-text' }, label, hint && h('small', {}, hint)),
    h('input', { type: 'checkbox', role: 'switch', class: 'switch', checked, onchange: (e) => onchange(e.target.checked) })
  );
}

function idleSelect(value, onchange) {
  return h('select', { class: 'input select', onchange: (e) => onchange(+e.target.value) },
    [0, 5, 10, 15, 30, 60].map((n) =>
      h('option', { value: n, selected: n === value }, n ? t('minutes', { n }) : t('never'))));
}

// Six-box one-time code input with paste support.
function otpInput(onComplete) {
  const boxes = [];
  const wrap = h('div', { class: 'otp' });
  const value = () => boxes.map((b) => b.value).join('');
  for (let i = 0; i < 6; i++) {
    const b = h('input', {
      class: 'otp-box', inputmode: 'numeric', maxlength: 1, autocomplete: 'one-time-code',
      'aria-label': `${i + 1}`,
      oninput: (e) => {
        e.target.value = e.target.value.replace(/\D/g, '').slice(-1);
        if (e.target.value && boxes[i + 1]) boxes[i + 1].focus();
        if (value().length === 6) onComplete?.(value());
      },
      onkeydown: (e) => { if (e.key === 'Backspace' && !e.target.value && boxes[i - 1]) boxes[i - 1].focus(); },
      onpaste: (e) => {
        const d = (e.clipboardData.getData('text') || '').replace(/\D/g, '').slice(0, 6);
        if (!d) return;
        e.preventDefault();
        d.split('').forEach((c, j) => (boxes[j].value = c));
        boxes[Math.min(d.length, 5)].focus();
        if (d.length === 6) onComplete?.(d);
      }
    });
    boxes.push(b); wrap.append(b);
  }
  wrap.getValue = value;
  wrap.clear = () => { boxes.forEach((b) => (b.value = '')); boxes[0].focus(); };
  wrap.focusFirst = () => boxes[0].focus();
  return wrap;
}

function touchPrompt() {
  return h('div', { class: 'touch' },
    h('div', { class: 'touch-key' }, icon('key', 'xl'), h('span', { class: 'pulse' })),
    h('strong', {}, t('touch_key')),
    h('p', { class: 'muted' }, t('touch_key_hint')));
}

function strength(p) {
  let s = 0;
  if (p.length >= 12) s++;
  if (p.length >= 16) s++;
  if (p.length >= 22) s++;
  if (/[a-z]/.test(p) && /[A-Z]/.test(p)) s += 0.5;
  if (/\d/.test(p)) s += 0.5;
  if (/[^\w\s]/.test(p)) s += 0.5;
  if (p.length < 12) s = Math.min(s, 1);
  return Math.min(4, Math.floor(s));
}

// ---------- TRAY ----------
async function viewTray() {
  const vaults = await api('list_vaults');
  const openCount = vaults.filter((v) => v.status === 'unlocked').length;

  const row = (v) => {
    const unlocked = v.status === 'unlocked';
    const busy = h('span', { class: 'spinner hidden' });
    const btn = h('button', {
      class: 'btn sm ' + (unlocked ? 'ghost' : 'primary'),
      onclick: async (e) => {
        e.stopPropagation();
        if (unlocked) { busy.classList.remove('hidden'); btn.disabled = true; await api('lock_vault', { id: v.id }); }
        else api('open_window', { view: 'unlock', params: { id: v.id } });
      }
    }, unlocked ? t('lock') : t('open'));
    return h('li', { class: 'vault-row' + (unlocked ? ' is-open' : ''), onclick: () => unlocked && api('focus_browser', { id: v.id }) },
      badge(v.browser),
      h('div', { class: 'vault-meta' },
        h('strong', { class: v.name == null ? 'muted' : '' }, vname(v)),
        h('small', {}, vsub(v, t('mode_' + v.mode)))),
      h('span', { class: 'status status-' + v.status }, icon(unlocked ? 'unlock' : 'lock', 'sm'), t('status_' + v.status)),
      busy, btn);
  };

  return h('div', { class: 'tray' },
    h('header', { class: 'tray-head' },
      h('div', { class: 'brand ' + (openCount ? 'on' : '') }, icon('shield')),
      h('div', {}, h('strong', {}, t('app_name')),
        h('small', {}, openCount ? t('unlocked_count', { n: openCount }) : t('all_locked'))),
      openCount ? h('button', { class: 'btn sm ghost push', onclick: () => api('lock_all') }, icon('lock', 'sm'), t('lock_all')) : null),
    (() => {
      const pv = vaults.find((v) => v.original?.state === 'pending');
      return pv && h('div', { class: 'banner' }, icon('alert', 'sm'),
        h('span', {}, h('strong', {}, t('original_pending')), h('small', {}, vname(pv))),
        h('button', { class: 'btn sm ghost push', onclick: () => api('open_window', { view: 'settings', params: { tab: 'vaults' } }) }, t('review')));
    })(),
    vaults.length
      ? h('ul', { class: 'vault-list' }, vaults.map(row))
      : h('div', { class: 'empty' }, icon('shield', 'xl'), h('strong', {}, t('empty_title')), h('p', { class: 'muted' }, t('empty_body'))),
    h('footer', { class: 'tray-foot' },
      h('button', { class: 'link', onclick: () => api('open_window', { view: 'wizard' }) }, icon('plus', 'sm'), t('new_vault')),
      h('button', { class: 'link', onclick: () => api('open_window', { view: 'settings' }) }, icon('sliders', 'sm'), t('settings')),
      h('button', { class: 'link push', onclick: () => api('quit_app') }, icon('power', 'sm'), t('quit')))
  );
}

// ---------- UNLOCK ----------
async function viewUnlock(params) {
  const vaults = await api('list_vaults');
  const v = vaults.find((x) => x.id === params.get('id')) || vaults[0];
  const el = h('div', { class: 'pane unlock' });
  let mode = 'normal';

  const render = () => {
    el.replaceChildren(
      h('div', { class: 'unlock-head' },
        h('div', { class: 'lock-art' }, icon('lock', 'lg')),
        h('h1', {}, mode === 'recovery' ? t('recovery_title') : t('unlock_title')),
        h('p', { class: 'vault-chip' }, badge(v.browser), vname(v))),
      mode === 'recovery' ? recoveryForm() : mainForm());
  };

  const errBox = () => h('p', { class: 'error', role: 'alert', 'aria-live': 'assertive' });

  function mainForm() {
    const pw = h('input', { class: 'input', type: 'password', id: 'pw', autocomplete: 'current-password', autofocus: true });
    const pin = v.mode === 'fido2' ? h('input', { class: 'input', type: 'password', id: 'pin', inputmode: 'numeric', autocomplete: 'off' }) : null;
    const otp = v.mode === 'totp' ? otpInput(() => submit()) : null;
    const err = errBox();
    const submitBtn = h('button', { class: 'btn primary block', type: 'submit' }, t('unlock'));
    const form = h('form', { class: 'form', onsubmit: (e) => { e.preventDefault(); submit(); } },
      h('label', { class: 'field' }, h('span', {}, t('password')), pw),
      pin && h('label', { class: 'field' }, h('span', {}, t('yubikey_pin')), pin),
      otp && h('div', { class: 'field' }, h('span', {}, t('auth_code')), otp),
      err, submitBtn,
      h('button', { class: 'link center', type: 'button', onclick: () => { mode = 'recovery'; render(); } }, t('use_recovery')));

    let overlay;
    const offA = on('fido_touch_needed', () => { overlay = h('div', { class: 'overlay' }, touchPrompt()); el.append(overlay); });
    const offB = on('fido_touch_done', () => overlay?.remove());
    cleanup.push(offA, offB);

    async function submit() {
      if (submitBtn.disabled) return;
      err.textContent = '';
      submitBtn.disabled = true; submitBtn.textContent = t('unlocking');
      try {
        await api('unlock_vault', { id: v.id, password: pw.value, pin: pin?.value, code: otp?.getValue() });
        pw.value = ''; if (pin) pin.value = '';
        api('close_window');
      } catch (e) {
        overlay?.remove();
        if (e.code === 'rate_limited') {
          let s = e.retryAfter || 30;
          err.textContent = t('rate_limited', { s });
          const iv = setInterval(() => {
            s--; err.textContent = t('rate_limited', { s });
            if (s <= 0) { clearInterval(iv); err.textContent = ''; submitBtn.disabled = false; submitBtn.textContent = t('unlock'); }
          }, 1000);
          cleanup.push(() => clearInterval(iv));
          return;
        }
        if (['fido_unreachable', 'fido_no_key', 'fido_multiple_keys'].includes(e?.code)) {
          err.textContent = t('err_' + e.code);
          submitBtn.disabled = false; submitBtn.textContent = t('unlock');
          return;
        }
        err.textContent = t('unlock_failed');
        el.querySelector('.unlock-head').classList.add('shake');
        setTimeout(() => el.querySelector('.unlock-head')?.classList.remove('shake'), 500);
        otp?.clear();
      }
      submitBtn.disabled = false; submitBtn.textContent = t('unlock');
    }
    setTimeout(() => pw.focus(), 0);
    return form;
  }

  function recoveryForm() {
    const count = h('small', { class: 'muted' }, t('words_count', { n: 0 }));
    const ta = h('textarea', {
      class: 'input mono', rows: 5, spellcheck: 'false', autocomplete: 'off',
      oninput: () => { count.textContent = t('words_count', { n: ta.value.trim() ? ta.value.trim().split(/\s+/).length : 0 }); }
    });
    const err = errBox();
    const btn = h('button', { class: 'btn primary block', type: 'submit' }, t('unlock'));
    return h('form', { class: 'form', onsubmit: async (e) => {
      e.preventDefault(); err.textContent = ''; btn.disabled = true; btn.textContent = t('unlocking');
      try { await api('unlock_with_recovery', { id: v.id, phrase: ta.value }); ta.value = ''; api('close_window'); }
      catch { err.textContent = t('unlock_failed'); }
      btn.disabled = false; btn.textContent = t('unlock');
    } },
      h('p', { class: 'muted' }, t('recovery_hint')), ta, count, err, btn,
      h('button', { class: 'link center', type: 'button', onclick: () => { mode = 'normal'; render(); } }, t('back')));
  }

  render();
  return el;
}

// Import of every Brave profile: importProfileId '*'; the core records
// profileName "All profiles (N)" (profiles::all_profiles_name).
const ALL_PROFILES = '*';
const allCount = (name) => +(/^All profiles \((\d+)\)$/.exec(name || '') || [])[1] || 0;
const profileLabel = (name) => (allCount(name) ? t('all_profiles', { n: allCount(name) }) : name);

// ---------- WIZARD ----------
const STEPS =['basics', 'password', 'factor', 'recovery', 'options', 'create'];

async function viewWizard() {
  const browsers = await api('detect_browsers');
  const profiles = {
    brave: browsers.brave.found ? await api('detect_profiles', { browser: 'brave' }) : [],
    firefox: browsers.firefox.found ? await api('detect_profiles', { browser: 'firefox' }) : [],
    telegram: browsers.telegram?.found ? await api('detect_profiles', { browser: 'telegram' }) : []
  };
  const w = {
    step: 0, draftId: null, name: '', browser: Object.keys(BROWSERS).find((b) => browsers[b]?.found) ?? 'brave',
    mode: null, keys: [], totpOk: false, words: null, ack: false, verifyIdx: null,
    sizeGb: 20, idleMinutes: 15, lockOnScreenLock: true, lockOnKeyRemoval: true,
    disableFxa: false, importProfile: false, importProfileId: null, progress: null, vaultId: null
  };
  const el = h('div', { class: 'pane wizard' });

  const go = (n) => { w.step = n; render(); };
  const nav = (canNext, onNext, label = t('continue')) =>
    h('div', { class: 'wiz-nav' },
      w.step > 0 && w.step < 5 ? h('button', { class: 'btn ghost', type: 'button', onclick: () => go(w.step - 1) }, t('back'))
        : h('button', { class: 'btn ghost', type: 'button', onclick: async () => { await api('wizard_cancel', { draftId: w.draftId }); api('close_window'); } }, t('cancel')),
      h('button', { class: 'btn primary', type: 'submit', disabled: !canNext, onclick: onNext }, label));

  const stepper = () => h('ol', { class: 'stepper' }, STEPS.map((s, i) =>
    h('li', { class: i < w.step ? 'done' : i === w.step ? 'cur' : '' },
      h('span', { class: 'dot' }, i < w.step ? icon('check', 'xs') : i + 1), h('em', {}, t('step_' + s)))));

  function render() {
    el.replaceChildren(h('header', { class: 'wiz-head' }, h('h1', {}, t('wiz_title')), stepper()),
      h('section', { class: 'wiz-body' }, [basics, password, factor, recovery, options, create][w.step]()));
  }

  // 1. basics
  function basics() {
    const name = h('input', { class: 'input', value: w.name, placeholder: t('vault_name_ph'), maxlength: 60,
      oninput: (e) => { w.name = e.target.value; next.disabled = !w.name.trim(); } });
    const choice = (b) => h('label', { class: 'choice' + (browsers[b].found ? '' : ' disabled') },
      h('input', { type: 'radio', name: 'browser', value: b, checked: w.browser === b, disabled: !browsers[b].found, onchange: () => (w.browser = b) }),
      badge(b), h('span', {}, h('strong', {}, BROWSERS[b]), h('small', {}, browsers[b].found ? browsers[b].path : t('not_installed'))));
    const navEl = nav(!!w.name.trim(), async (e) => {
      e.preventDefault();
      if (!w.draftId) w.draftId = (await api('wizard_begin', { name: w.name.trim(), browser: w.browser })).draftId;
      go(1);
    });
    const next = navEl.querySelector('.primary');
    setTimeout(() => name.focus(), 0);
    return h('form', { class: 'form' },
      h('label', { class: 'field' }, h('span', {}, t('vault_name')), name),
      h('div', { class: 'field' }, h('span', {}, t('app_kind')), h('div', { class: 'choices three' }, Object.keys(BROWSERS).map(choice))),
      navEl);
  }

  // 2. password
  function password() {
    const meter = h('div', { class: 'meter' }, h('i'), h('i'), h('i'), h('i'));
    const label = h('small', { class: 'muted' }, ' ');
    const mismatch = h('small', { class: 'error' });
    const p1 = h('input', { class: 'input', type: 'password', autocomplete: 'new-password', oninput: upd });
    const p2 = h('input', { class: 'input', type: 'password', autocomplete: 'new-password', oninput: upd });
    const navEl = nav(false, async (e) => {
      e.preventDefault();
      await api('wizard_set_password', { draftId: w.draftId, password: p1.value });
      p1.value = p2.value = '';
      go(2);
    });
    const next = navEl.querySelector('.primary');
    function upd() {
      const s = strength(p1.value);
      meter.dataset.s = p1.value ? s : '';
      label.textContent = p1.value ? t('pw_strength')[s] : ' ';
      mismatch.textContent = p2.value && p1.value !== p2.value ? t('pw_mismatch') : '';
      next.disabled = !(p1.value.length >= 12 && s >= 2 && p1.value === p2.value);
    }
    setTimeout(() => p1.focus(), 0);
    return h('form', { class: 'form' },
      h('label', { class: 'field' }, h('span', {}, t('password')), p1, meter, label),
      h('p', { class: 'muted' }, t('pw_hint')),
      h('label', { class: 'field' }, h('span', {}, t('pw_confirm')), p2, mismatch),
      h('div', { class: 'callout warn' }, icon('alert', 'sm'), h('p', {}, t('pw_warning'))),
      navEl);
  }

  // 3. second factor
  function factor() {
    const card = (m, ic, title, desc, rec) => h('button', {
      type: 'button', class: 'factor-card' + (w.mode === m ? ' sel' : ''),
      onclick: () => { if (w.mode !== m) { w.mode = m; w.keys = []; w.totpOk = false; w.totp = null; } render(); }
    }, icon(ic, 'lg'), h('strong', {}, title, rec && h('span', { class: 'tag' }, t('recommended'))), h('small', {}, desc));

    const body = h('div', { class: 'form' },
      h('p', { class: 'q' }, t('factor_q')),
      h('div', { class: 'choices two' },
        card('fido2', 'key', t('yubikey_title'), t('yubikey_desc'), true),
        card('totp', 'phone', t('totp_title'), t('totp_desc'))));

    if (w.mode === 'fido2') body.append(enrollFido());
    if (w.mode === 'totp') body.append(enrollTotp());
    body.append(nav(w.mode === 'fido2' ? w.keys.length > 0 : w.totpOk, async (e) => {
      e.preventDefault();
      if (!w.words) w.words = (await api('recovery_generate', { draftId: w.draftId })).words;
      go(3);
    }));
    return body;
  }

  function enrollFido() {
    const box = h('div', { class: 'enroll' });
    const pin = h('input', { class: 'input', type: 'password', inputmode: 'numeric', autocomplete: 'off' });
    const label = h('input', { class: 'input', value: w.keys.length ? 'YubiKey backup' : 'YubiKey main', maxlength: 40 });
    const err = h('p', { class: 'error', role: 'alert' });
    const btn = h('button', { class: 'btn ' + (w.keys.length ? 'ghost' : 'primary'), type: 'button', onclick: async () => {
      err.textContent = '';
      const overlay = h('div', { class: 'overlay' }, touchPrompt());
      el.append(overlay);
      try {
        const r = await api('fido_register', { draftId: w.draftId, pin: pin.value, label: label.value.trim() || 'YubiKey' });
        w.keys.push(r.label); pin.value = ''; render();
      } catch (e) {
        // Setup errors are specific (no PIN set, wrong key…); unknown codes stay generic.
        const k = 'err_' + (e && e.code);
        err.textContent = t(k) !== k ? t(k) : t('unlock_failed');
      }
      finally { overlay.remove(); }
    } }, icon(w.keys.length ? 'plus' : 'key', 'sm'), w.keys.length ? t('add_backup_key') : t('register_key'));

    if (w.keys.length) box.append(h('div', { class: 'keys' }, h('small', { class: 'muted' }, t('registered_keys')),
      w.keys.map((k) => h('div', { class: 'key-item' }, icon('check', 'sm ok'), k))));
    if (w.keys.length < 5) box.append(h('div', { class: 'grid2' },
      h('label', { class: 'field' }, h('span', {}, t('key_label')), label),
      h('label', { class: 'field' }, h('span', {}, t('yubikey_pin')), pin)), err, btn);
    if (w.keys.length === 1) box.append(h('p', { class: 'muted' }, t('backup_hint')));
    return box;
  }

  function enrollTotp() {
    const box = h('div', { class: 'enroll totp' });
    if (w.totpOk) {
      box.append(h('div', { class: 'callout ok' }, icon('check', 'sm'), h('p', {}, t('code_ok'))),
        h('p', { class: 'muted' }, t('totp_note')));
      return box;
    }
    const qr = h('div', { class: 'qr' });
    const secret = h('code', { class: 'secret' });
    const err = h('p', { class: 'error', role: 'alert' });
    const otp = otpInput(async (code) => {
      const r = await api('totp_confirm', { draftId: w.draftId, code });
      if (r.ok) { w.totpOk = true; render(); } else { err.textContent = t('code_wrong'); otp.clear(); }
    });
    const load = async () => {
      w.totp ||= await api('totp_begin', { draftId: w.draftId });
      qr.innerHTML = w.totp.qrSvg;
      secret.textContent = w.totp.secret.match(/.{1,4}/g).join(' ');
    };
    load();
    box.append(
      h('div', { class: 'totp-grid' }, qr,
        h('div', {},
          h('strong', {}, t('scan_qr')),
          h('small', { class: 'muted block' }, t('manual_key')),
          h('div', { class: 'secret-row' }, secret,
            h('button', { class: 'btn sm ghost', type: 'button', onclick: async () => {
              try { await navigator.clipboard.writeText(w.totp.secret); toast(t('copied')); } catch {}
            } }, icon('copy', 'sm'), t('copy'))))),
      h('div', { class: 'field' }, h('span', {}, t('enter_code')), otp), err,
      h('p', { class: 'muted' }, t('totp_note')));
    return box;
  }

  // 4. recovery
  function recovery() {
    if (w.verifyIdx) return recoveryVerify();
    const navEl = nav(w.ack, (e) => {
      e.preventDefault();
      const set = new Set();
      while (set.size < 3) set.add(1 + Math.floor(Math.random() * 24));
      w.verifyIdx = [...set].sort((a, b) => a - b);
      render();
    });
    return h('form', { class: 'form' },
      h('h2', {}, t('recovery_show_title')),
      h('p', { class: 'muted' }, t('recovery_show_body')),
      h('ol', { class: 'words' }, w.words.map((wd) => h('li', {}, h('span', {}, wd)))),
      toggle(t('recovery_ack'), w.ack, (v) => { w.ack = v; navEl.querySelector('.primary').disabled = !v; }),
      navEl);
  }

  function recoveryVerify() {
    const inputs = w.verifyIdx.map((i) => [i, h('input', { class: 'input mono', autocomplete: 'off', spellcheck: 'false' })]);
    const err = h('p', { class: 'error', role: 'alert' });
    const form = h('form', { class: 'form' },
      h('h2', {}, t('recovery_verify_title')),
      h('p', { class: 'muted' }, t('recovery_verify_body')),
      h('div', { class: 'grid3' }, inputs.map(([i, inp]) => h('label', { class: 'field' }, h('span', {}, t('word_n', { n: i })), inp))),
      err,
      h('div', { class: 'wiz-nav' },
        h('button', { class: 'btn ghost', type: 'button', onclick: () => { w.verifyIdx = null; render(); } }, t('back')),
        h('button', { class: 'btn primary', type: 'submit' }, t('verify'))));
    form.addEventListener('submit', async (e) => {
      e.preventDefault();
      const answers = Object.fromEntries(inputs.map(([i, inp]) => [i, inp.value]));
      const r = await api('recovery_verify', { draftId: w.draftId, answers });
      if (r.ok) { w.words = null; go(4); } else err.textContent = t('verify_failed');
    });
    setTimeout(() => inputs[0][1].focus(), 0);
    return form;
  }

  // 5. options
  // Brave with ≥2 profiles: first choice imports all of them into this vault.
  function importChoices() {
    const list = profiles[w.browser] ?? [];
    const out = list.map((pr) => ({ id: pr.id, label: `${pr.name} · ${fmtSize(pr.sizeMb)}` }));
    if (w.browser === 'brave' && list.length >= 2) {
      const total = list.reduce((s, pr) => s + pr.sizeMb, 0);
      out.unshift({ id: ALL_PROFILES, label: `${t('import_all_option', { n: list.length })} · ${fmtSize(total)}` });
    }
    return out;
  }

  function options() {
    const choices = importChoices();
    if (!choices.some((c) => c.id === w.importProfileId)) w.importProfileId = choices[0]?.id ?? null;
    const sizeVal = h('output', {}, w.sizeGb + ' GB');
    return h('form', { class: 'form' },
      h('div', { class: 'field' },
        h('span', {}, t('size'), sizeVal),
        h('input', { type: 'range', min: 5, max: 200, step: 5, value: w.sizeGb, class: 'range',
          oninput: (e) => { w.sizeGb = +e.target.value; sizeVal.textContent = w.sizeGb + ' GB'; } }),
        h('small', { class: 'muted' }, t('size_hint'))),
      h('div', { class: 'group' },
        h('div', { class: 'toggle-row' }, h('span', { class: 'toggle-text' }, t('idle_lock')), idleSelect(w.idleMinutes, (v) => (w.idleMinutes = v))),
        toggle(t('lock_screen'), w.lockOnScreenLock, (v) => (w.lockOnScreenLock = v)),
        w.mode === 'fido2' && toggle(t('lock_key_removal'), w.lockOnKeyRemoval, (v) => (w.lockOnKeyRemoval = v)),
        w.browser === 'firefox' && toggle(t('disable_fxa'), w.disableFxa, (v) => (w.disableFxa = v)),
        NO_IMPORT.has(w.browser) ? null
          : w.browser === 'telegram'
          ? toggle(t('import_telegram'), w.importProfile, (v) => { w.importProfile = v; render(); }, t('import_telegram_hint'))
          : toggle(t('import_profile', { browser: BROWSERS[w.browser] }), w.importProfile, (v) => { w.importProfile = v; render(); }, t('import_hint')),
        w.importProfile && choices.length && h('div', { class: 'toggle-row' },
          h('span', { class: 'toggle-text' }, t('import_which')),
          h('select', { class: 'input select', onchange: (e) => { w.importProfileId = e.target.value; render(); } },
            choices.map((c) => h('option', { value: c.id, selected: c.id === w.importProfileId }, c.label)))),
        w.importProfile && w.importProfileId === ALL_PROFILES &&
          h('small', { class: 'muted block', style: 'padding:0 12px 10px;margin-top:-4px' }, t('import_all_hint', { browser: BROWSERS[w.browser] }))),
      w.browser === 'whatsapp'
        ? h('div', { class: 'callout' }, icon('alert', 'sm'), h('p', {}, h('strong', {}, t('wa_note_title')), ' ', t('wa_note_body')))
        : w.browser === 'slack'
        ? h('div', { class: 'callout' }, icon('alert', 'sm'), h('p', {}, h('strong', {}, t('slack_note_title')), ' ', t('slack_note_body')))
        : w.browser === 'telegram'
        ? h('div', { class: 'callout' }, icon('alert', 'sm'), h('p', {}, h('strong', {}, t('tg_notify_title')), ' ', t('tg_notify_body')))
        : h('div', { class: 'callout' }, icon('alert', 'sm'), h('p', {}, h('strong', {}, t('sync_warn_title')), ' ', t('sync_warn_body'))),
      nav(true, (e) => { e.preventDefault(); go(5); }, t('create_vault')));
  }

  // 6. create
  function create() {
    if (w.vaultId) {
      return h('div', { class: 'finish' },
        h('div', { class: 'finish-art' }, icon('check', 'xl')),
        h('h2', {}, t('done_title')),
        h('p', { class: 'muted' }, t('done_body', { name: w.name })),
        w.importProfile && h('div', { class: 'callout' }, icon('alert', 'sm'), h('p', {},
          w.importProfileId === ALL_PROFILES
            ? t('done_import_all_note', { n: profiles[w.browser].length, browser: BROWSERS[w.browser] })
            : t('done_import_note'))),
        h('div', { class: 'wiz-nav center' },
          h('button', { class: 'btn ghost', onclick: () => api('close_window') }, t('close')),
          h('button', { class: 'btn primary', onclick: () => api('open_window', { view: 'unlock', params: { id: w.vaultId } }) }, t('open_now'))));
    }
    // SPEC §5.1 step 2: copying a profile the browser is writing to would
    // give a broken copy. Ask the user to quit the regular browser and wait.
    if (w.importProfile && !w.started && !w.browserClosedChecked) {
      const box = h('div', { class: 'creating' },
        h('div', { class: 'lock-art' }, icon('alert', 'lg')),
        h('h2', {}, t('import_quit_title', { browser: BROWSERS[w.browser] })),
        h('p', { class: 'muted' }, t('import_quit_body', { browser: BROWSERS[w.browser] })),
        h('p', { class: 'muted' }, h('span', { class: 'spinner', style: 'display:inline-block;vertical-align:-2px' }), ' ', t('import_waiting')),
        h('div', { class: 'wiz-nav center' },
          h('button', { class: 'btn ghost', type: 'button', onclick: () => { stop(); go(4); } }, t('back')),
          h('button', { class: 'btn ghost', type: 'button', onclick: () => { stop(); w.importProfile = false; render(); } }, t('import_skip'))));
      let iv = null;
      const stop = () => { if (iv) clearInterval(iv); iv = null; };
      const check = async () => {
        let running = true;
        try { running = (await api('browser_running', { browser: w.browser })).running; } catch {}
        if (!running) { stop(); w.browserClosedChecked = true; render(); }
      };
      iv = setInterval(check, 1500);
      cleanup.push(stop);
      check();
      return box;
    }
    const bar = h('div', { class: 'progress' }, h('i'));
    const stage = h('p', { class: 'muted' }, t('stage_disk'));
    const off = on('create_progress', ({ stage: s, pct }) => {
      bar.firstChild.style.width = pct + '%';
      if (s !== 'done') stage.textContent = t('stage_' + s);
    });
    cleanup.push(off);
    if (!w.started) {
      w.started = true;
      if (NO_IMPORT.has(w.browser)) w.importProfile = false;
      api('wizard_finish', {
        draftId: w.draftId, name: w.name.trim(), browser: w.browser, mode: w.mode, sizeGb: w.sizeGb,
        options: { idleMinutes: w.idleMinutes, lockOnScreenLock: w.lockOnScreenLock, lockOnKeyRemoval: w.lockOnKeyRemoval,
          disableFxa: w.disableFxa, importProfile: w.importProfile, importProfileId: w.importProfile ? w.importProfileId : null }
      }).then((r) => { w.vaultId = r.vaultId; render(); })
        .catch(() => { w.started = false; toast(t('status_error'), 'bad'); go(4); });
    }
    return h('div', { class: 'creating' }, h('div', { class: 'lock-art spin-slow' }, icon('shield', 'lg')),
      h('h2', {}, t('creating')), bar, stage);
  }

  render();
  return el;
}

// ---------- SETTINGS ----------
async function viewSettings(params) {
  const [s, vaults, browsers, info] = await Promise.all([
    api('get_settings'), api('list_vaults'), api('detect_browsers'), api('app_info')]);
  let tab = params.get('tab') || 'general';
  const el = h('div', { class: 'pane settings' });
  const save = async (patch) => { await api('save_settings', patch); Object.assign(s, patch); toast(t('saved')); };

  const tabs = [['general', 'sliders'], ['vaults', 'shield'], ['browsers', 'globe'], ['about', 'alert']];
  const render = async () => {
    const content = h('section', { class: 'set-body' });
    el.replaceChildren(
      h('nav', { class: 'side' }, tabs.map(([id, ic]) =>
        h('button', { class: 'side-item' + (tab === id ? ' cur' : ''), onclick: () => { tab = id; render(); } }, icon(ic, 'sm'), t('tab_' + id)))),
      content);
    content.append(await ({ general, vaultsTab, browsersTab, about })[tab === 'vaults' ? 'vaultsTab' : tab === 'browsers' ? 'browsersTab' : tab]());
  };

  // Global hotkey recorder: `field` is 'panicHotkey' or 'revealHotkey'.
  function hotkeyRow(label, field, hint) {
    const hk = h('kbd', {}, s[field]);
    const rec = h('button', { class: 'btn sm ghost', onclick: () => {
      hk.textContent = t('press_keys'); rec.disabled = true;
      const handler = (e) => {
        if (['Meta', 'Control', 'Alt', 'Shift'].includes(e.key)) return;
        e.preventDefault();
        // Physical key (e.code): with ⌥ held, e.key is the alternate character (⌥L → "¬").
        const key = /^Key[A-Z]$/.test(e.code) ? e.code.slice(3) : /^Digit\d$/.test(e.code) ? e.code.slice(5)
          : e.code === 'Space' ? 'SPACE' : /^F\d{1,2}$/.test(e.code) ? e.code : e.key.toUpperCase();
        const combo = (e.ctrlKey ? '⌃' : '') + (e.altKey ? '⌥' : '') + (e.shiftKey ? '⇧' : '') + (e.metaKey ? '⌘' : '') + key;
        window.removeEventListener('keydown', handler, true);
        rec.disabled = false;
        // Global hotkeys swallow the keys in every app: require ≥2 modifiers and
        // not ⌘⇧ alone (rules out ⌘Q, ⌘W, ⌘⇧T…). Rust enforces the same rule.
        const mods = [e.ctrlKey, e.altKey, e.shiftKey, e.metaKey].filter(Boolean).length;
        const cmdShiftOnly = mods === 2 && e.metaKey && e.shiftKey;
        if (mods < 2 || cmdShiftOnly || !key || key.length > 3) {
          hk.textContent = s[field]; toast(t('hotkey_invalid')); return;
        }
        const other = field === 'panicHotkey' ? s.revealHotkey : s.panicHotkey;
        if (combo === other) { hk.textContent = s[field]; toast(t('hotkey_clash')); return; }
        hk.textContent = combo;
        save({ [field]: combo }).catch((err) => {
          hk.textContent = s[field]; toast(t(err?.code === 'hotkey_clash' ? 'hotkey_clash' : 'hotkey_invalid'));
        });
      };
      window.addEventListener('keydown', handler, true);
      cleanup.push(() => window.removeEventListener('keydown', handler, true));
    } }, t('change'));
    return h('div', { class: 'toggle-row' },
      h('span', { class: 'toggle-text' }, label, hint && h('small', {}, hint)), h('span', { class: 'row' }, hk, rec));
  }

  // Recovery when the reveal hotkey is forgotten (handled in main.rs).
  const revealCmd = (name) => h('code', { class: 'cmd' }, `open -n -a "${name}" --args --reveal`);

  // Disguise: pick, confirm inside the window (no native dialog), apply.
  function disguiseRow(dg) {
    const cur = dg.items.find((d) => d.id === dg.current) || dg.items[0];
    let picked = cur.id;
    const apply = h('button', { class: 'btn sm', disabled: true, onclick: () => confirmDisguise(dg.items.find((d) => d.id === picked)) }, t('disguise_apply'));
    const sel = h('select', { class: 'input select', disabled: !dg.supported, onchange: (e) => { picked = e.target.value; apply.disabled = picked === cur.id; } },
      dg.items.map((d) => h('option', { value: d.id, selected: d.id === cur.id }, d.id === 'none' ? t('disguise_none') : d.name)));
    return h('div', { class: 'toggle-row' },
      h('span', { class: 'toggle-text' }, t('disguise'),
        h('small', {}, dg.supported ? t('disguise_hint', { name: cur.name }) : t('disguise_unsupported_hint'))),
      h('span', { class: 'row' }, sel, apply));
  }

  function confirmDisguise(d) {
    const sheet = h('div', { class: 'sheet form' });
    const overlay = h('div', { class: 'overlay sheet-overlay' }, sheet);
    const err = h('p', { class: 'error', role: 'alert' });
    const close = () => overlay.remove();
    const go = h('button', { class: 'btn primary', type: 'button', onclick: async () => {
      err.textContent = ''; go.disabled = true;
      try {
        const r = await api('apply_disguise', { disguise: d.id });
        sheet.replaceChildren(h('h2', {}, t('disguise_restarting', { name: r.name })),
          h('p', { class: 'muted' }, t('disguise_restarting_body')));
      } catch (e) {
        const k = 'err_' + (e && e.code);
        err.textContent = t(k) !== k ? t(k) : t('err_disguise_failed');
        go.disabled = false;
      }
    } }, t('disguise_apply'));
    const name = d.id === 'none' ? 'Browser Vault' : d.name;
    sheet.append(h('h2', {}, t('disguise_confirm_title', { name })),
      h('ul', { class: 'checklist steps' }, t('disguise_confirm_steps').map((x) => h('li', {}, icon('check', 'sm'), h('span', {}, x.replaceAll('{name}', name))))),
      h('div', { class: 'callout' }, icon('alert', 'sm'), h('p', {}, t('disguise_recovery'), ' ', revealCmd(name))),
      err,
      h('div', { class: 'wiz-nav' }, h('button', { class: 'btn ghost', type: 'button', onclick: close }, t('cancel')), go));
    el.append(overlay);
    cleanup.push(close);
  }

  async function general() {
    const dg = await api('list_disguises');
    const appName = (dg.items.find((d) => d.id === dg.current) || dg.items[0]).name;
    return h('div', { class: 'form' },
      h('h2', {}, t('tab_general')),
      h('div', { class: 'group' },
        h('div', { class: 'toggle-row' }, h('span', { class: 'toggle-text' }, t('language')),
          h('select', { class: 'input select', onchange: (e) => { setLang(e.target.value); save({ language: e.target.value }); route(); } },
            languages.map(([v, n]) => h('option', { value: v, selected: v === getLang() }, n)))),
        toggle(t('launch_login'), s.launchAtLogin, (v) => save({ launchAtLogin: v })),
        hotkeyRow(t('panic_hotkey'), 'panicHotkey')),
      h('h3', {}, t('lock_triggers')),
      h('div', { class: 'group' },
        h('div', { class: 'toggle-row' }, h('span', { class: 'toggle-text' }, t('idle_lock')), idleSelect(s.idleMinutes, (v) => save({ idleMinutes: v }))),
        toggle(t('lock_screen'), s.lockOnScreenLock, (v) => save({ lockOnScreenLock: v })),
        toggle(t('lock_key_removal'), s.lockOnKeyRemoval, (v) => save({ lockOnKeyRemoval: v }))),
      h('h3', {}, t('privacy')),
      h('div', { class: 'group' },
        toggle(t('ghost_mode'), s.ghostMode, (v) => save({ ghostMode: v }), t('ghost_hint')),
        hotkeyRow(t('reveal_hotkey'), 'revealHotkey', [t('reveal_hint'), ' ', revealCmd(appName)]),
        disguiseRow(dg)),
      h('p', { class: 'muted' }, h('small', {}, t('privacy_limits'))));
  }

  function originalBlock(v) {
    const o = v.original;
    if (!o || o.state === 'deleted') return null;
    const del = h('button', { class: 'btn sm danger-solid', disabled: !o.reviewed,
      onclick: () => api('open_window', { view: 'cleanup', params: { id: v.id } }) }, t('delete_original'));
    if (o.state === 'kept') {
      return h('div', { class: 'callout' }, icon('alert', 'sm'),
        h('div', { class: 'grow' }, h('p', {}, t('original_kept'))), del);
    }
    return h('div', { class: 'callout warn col' },
      h('div', { class: 'row' }, icon('alert', 'sm'), h('strong', {}, t('original_pending'))),
      h('p', {}, t(allCount(o.profileName) ? 'original_pending_all_body' : 'original_pending_body',
        { browser: bname(v.browser), profile: o.profileName, n: allCount(o.profileName), size: fmtSize(o.sizeMb) })),
      !o.reviewed && h('p', { class: 'muted' }, t('not_reviewed_hint')),
      h('div', { class: 'row' }, del,
        h('button', { class: 'btn sm ghost', onclick: async () => { await api('keep_original', { id: v.id }); route(); } }, t('keep_original'))));
  }

  // Settings → vault actions, inline (no native dialogs): re-authenticate
  // with the full credential, then the action. Secrets are cleared from the
  // inputs right after each request; nothing is kept in JS state.
  function actionFlow(v, action) {
    let token = null;
    const sheet = h('div', { class: 'sheet form' });
    const overlay = h('div', { class: 'overlay sheet-overlay' }, sheet);
    let touch;
    const offA = on('fido_touch_needed', () => { touch = h('div', { class: 'overlay' }, touchPrompt()); el.append(touch); });
    const offB = on('fido_touch_done', () => touch?.remove());
    const close = async () => {
      offA(); offB(); touch?.remove(); overlay.remove();
      if (token) { try { await api('action_end', { token }); } catch {} }
      render();
    };
    cleanup.push(() => { offA(); offB(); });
    const errMsg = (e) => {
      if (e?.code === 'expired') return t('act_expired');
      if (e?.code === 'header_modified') return t('act_header_modified');
      if (e?.code === 'rate_limited') return t('rate_limited', { s: e.retryAfter || 30 });
      const k = 'err_' + (e && e.code);
      return t(k) !== k ? t(k) : t('unlock_failed');
    };
    const head = (title, body) => [h('h2', {}, title), body && h('p', { class: 'muted' }, body)];
    const navRow = (primary) => h('div', { class: 'wiz-nav' },
      h('button', { class: 'btn ghost', type: 'button', onclick: close }, t('cancel')), primary);
    const show = (...kids) => sheet.replaceChildren(h('p', { class: 'vault-chip' }, badge(v.browser), vname(v)), ...kids);
    const done = (msg) => show(h('div', { class: 'callout ok' }, icon('check', 'sm'), h('p', {}, msg)),
      h('div', { class: 'wiz-nav center' }, h('button', { class: 'btn primary', type: 'button', onclick: close }, t('close'))));

    function recoveryAuthStep() {
      const ta = h('textarea', { class: 'input mono', rows: 4, spellcheck: 'false', autocomplete: 'off' });
      const err = h('p', { class: 'error', role: 'alert' });
      const btn = h('button', { class: 'btn primary', type: 'submit' }, t('act_continue'));
      show(...head(t('act_rec_auth_title'), v.mode === 'totp' ? t('act_rec_auth_body_totp') : t('act_rec_auth_body_fido')),
        h('form', { class: 'form', onsubmit: async (e) => {
          e.preventDefault(); err.textContent = ''; btn.disabled = true;
          try {
            const r = await api('action_auth_recovery', { id: v.id, phrase: ta.value });
            ta.value = ''; token = r.token;
            if (v.mode === 'totp') resetStep(); else passwordStep();
          } catch (e2) { err.textContent = errMsg(e2); btn.disabled = false; }
        } }, ta, err, navRow(btn)));
      setTimeout(() => ta.focus(), 0);
    }

    function resetStep() {
      const meter = h('div', { class: 'meter' }, h('i'), h('i'), h('i'), h('i'));
      const label = h('small', { class: 'muted' }, ' ');
      const mismatch = h('small', { class: 'error' });
      const err = h('p', { class: 'error', role: 'alert' });
      const btn = h('button', { class: 'btn primary', type: 'submit', disabled: true }, t('act_continue'));
      const upd = () => {
        const sc = strength(p1.value);
        meter.dataset.s = p1.value ? sc : '';
        label.textContent = p1.value ? t('pw_strength')[sc] : ' ';
        mismatch.textContent = p2.value && p1.value !== p2.value ? t('pw_mismatch') : '';
        btn.disabled = !(p1.value.length >= 12 && sc >= 2 && p1.value === p2.value);
      };
      const p1 = h('input', { class: 'input', type: 'password', autocomplete: 'new-password', oninput: upd });
      const p2 = h('input', { class: 'input', type: 'password', autocomplete: 'new-password', oninput: upd });
      show(...head(t('act_pw_title'), t('act_reset_pw_body')),
        h('form', { class: 'form', onsubmit: async (e) => {
          e.preventDefault(); btn.disabled = true; err.textContent = '';
          try {
            const setup = await api('action_reset_begin', { token, newPassword: p1.value });
            p1.value = p2.value = '';
            resetTotpStep(setup);
          } catch (e2) { err.textContent = errMsg(e2); btn.disabled = false; }
        } },
          h('label', { class: 'field' }, h('span', {}, t('password')), p1, meter, label),
          h('label', { class: 'field' }, h('span', {}, t('pw_confirm')), p2, mismatch),
          err, navRow(btn)));
      setTimeout(() => p1.focus(), 0);
    }

    function resetTotpStep(setup) {
      const qr = h('div', { class: 'qr' });
      qr.innerHTML = setup.qrSvg;
      const err = h('p', { class: 'error', role: 'alert' });
      const otp = otpInput(async (code) => {
        err.textContent = '';
        try {
          const r = await api('action_reset_confirm', { token, code });
          if (r.ok) done(t('act_reset_done')); else { err.textContent = t('code_wrong'); otp.clear(); }
        } catch (e) { err.textContent = errMsg(e); otp.clear(); }
      });
      show(...head(t('act_totp_title'), t('act_reset_totp_body')),
        h('div', { class: 'totp-grid' }, qr,
          h('div', {}, h('strong', {}, t('scan_qr')), h('small', { class: 'muted block' }, t('manual_key')),
            h('div', { class: 'secret-row' }, h('code', { class: 'secret' }, setup.secret.match(/.{1,4}/g).join(' '))))),
        h('div', { class: 'field' }, h('span', {}, t('enter_code')), otp), err,
        h('div', { class: 'wiz-nav' }, h('button', { class: 'btn ghost', type: 'button', onclick: close }, t('cancel'))));
      setTimeout(() => otp.focusFirst(), 0);
    }

    async function portableStep() {
      const bar = h('div', { class: 'progress' }, h('i', { style: 'width:100%' }));
      show(...head(t('act_portable_title'), t('act_portable_working')), bar);
      try {
        const r = await api('action_make_portable', { token });
        done(t('act_portable_done', { n: r.converted }));
      } catch (e) {
        const msg = e?.code === 'lock_first' ? t('act_lock_first') : e?.code === 'keychain_denied' ? t('act_keychain_denied') : errMsg(e);
        show(h('div', { class: 'callout warn' }, icon('alert', 'sm'), h('p', {}, msg)),
          h('div', { class: 'wiz-nav center' }, h('button', { class: 'btn primary', type: 'button', onclick: close }, t('close'))));
      }
    }

    function authStep() {
      if (action === 'recovery_reset') return recoveryAuthStep();
      const pw = h('input', { class: 'input', type: 'password', autocomplete: 'current-password' });
      const pin = v.mode === 'fido2' ? h('input', { class: 'input', type: 'password', inputmode: 'numeric', autocomplete: 'off' }) : null;
      const otp = v.mode === 'totp' ? otpInput(() => submit()) : null;
      const err = h('p', { class: 'error', role: 'alert' });
      const btn = h('button', { class: 'btn primary', type: 'submit' }, t('act_continue'));
      async function submit() {
        if (btn.disabled) return;
        err.textContent = ''; btn.disabled = true;
        try {
          const r = await api('action_auth', { id: v.id, password: pw.value, pin: pin?.value, code: otp?.getValue() });
          pw.value = ''; if (pin) pin.value = '';
          token = r.token; next(r);
        } catch (e) { touch?.remove(); err.textContent = errMsg(e); otp?.clear(); btn.disabled = false; }
      }
      show(...head(t('act_auth_title'), v.mode === 'fido2' ? t('act_auth_body_fido') : t('act_auth_body')),
        h('form', { class: 'form', onsubmit: (e) => { e.preventDefault(); submit(); } },
          h('label', { class: 'field' }, h('span', {}, t('password')), pw),
          pin && h('label', { class: 'field' }, h('span', {}, t('yubikey_pin')), pin),
          otp && h('div', { class: 'field' }, h('span', {}, t('auth_code')), otp),
          err, navRow(btn)));
      setTimeout(() => pw.focus(), 0);
    }

    function next(r) {
      if (action === 'change_password') return passwordStep();
      if (action === 'replace_totp') return totpStep();
      if (action === 'new_recovery') return recoveryStep();
      if (action === 'add_fido2') return addKeyStep(r.keys || []);
      if (action === 'make_portable') return portableStep();
    }

    function passwordStep() {
      const meter = h('div', { class: 'meter' }, h('i'), h('i'), h('i'), h('i'));
      const label = h('small', { class: 'muted' }, ' ');
      const mismatch = h('small', { class: 'error' });
      const err = h('p', { class: 'error', role: 'alert' });
      const btn = h('button', { class: 'btn primary', type: 'submit', disabled: true }, t('act_continue'));
      const upd = () => {
        const sc = strength(p1.value);
        meter.dataset.s = p1.value ? sc : '';
        label.textContent = p1.value ? t('pw_strength')[sc] : ' ';
        mismatch.textContent = p2.value && p1.value !== p2.value ? t('pw_mismatch') : '';
        btn.disabled = !(p1.value.length >= 12 && sc >= 2 && p1.value === p2.value);
      };
      const p1 = h('input', { class: 'input', type: 'password', autocomplete: 'new-password', oninput: upd });
      const p2 = h('input', { class: 'input', type: 'password', autocomplete: 'new-password', oninput: upd });
      show(...head(t('act_pw_title'), t('pw_hint')),
        h('form', { class: 'form', onsubmit: async (e) => {
          e.preventDefault(); btn.disabled = true; err.textContent = '';
          try {
            const r = await api('action_change_password', { token, newPassword: p1.value });
            p1.value = p2.value = '';
            if (r.done) done(t('act_pw_done')); else rewrapStep(r.remaining);
          } catch (e2) { err.textContent = errMsg(e2); btn.disabled = false; }
        } },
          h('label', { class: 'field' }, h('span', {}, t('password')), p1, meter, label),
          h('label', { class: 'field' }, h('span', {}, t('pw_confirm')), p2, mismatch),
          h('div', { class: 'callout warn' }, icon('alert', 'sm'), h('p', {}, t('pw_warning'))),
          err, navRow(btn)));
      setTimeout(() => p1.focus(), 0);
    }

    function rewrapStep(remaining) {
      const pin = h('input', { class: 'input', type: 'password', inputmode: 'numeric', autocomplete: 'off' });
      const err = h('p', { class: 'error', role: 'alert' });
      const btn = h('button', { class: 'btn primary', type: 'submit' }, icon('key', 'sm'), t('act_rewrap_btn'));
      show(...head(t('act_rewrap_title'), t('act_rewrap_body', { label: remaining[0] })),
        h('div', { class: 'keys' }, remaining.map((k) => h('div', { class: 'key-item' }, icon('key', 'sm'), k))),
        h('form', { class: 'form', onsubmit: async (e) => {
          e.preventDefault(); btn.disabled = true; err.textContent = '';
          try {
            const r = await api('action_fido_rewrap', { token, pin: pin.value });
            pin.value = '';
            if (r.done) done(t('act_pw_done')); else rewrapStep(r.remaining);
          } catch (e2) { touch?.remove(); err.textContent = errMsg(e2); btn.disabled = false; }
        } },
          h('label', { class: 'field' }, h('span', {}, t('yubikey_pin')), pin), err, navRow(btn)));
      setTimeout(() => pin.focus(), 0);
    }

    async function totpStep() {
      const qr = h('div', { class: 'qr' });
      const secret = h('code', { class: 'secret' });
      const err = h('p', { class: 'error', role: 'alert' });
      let setup;
      const otp = otpInput(async (code) => {
        err.textContent = '';
        try {
          const r = await api('action_totp_confirm', { token, code });
          if (r.ok) done(t('act_totp_done')); else { err.textContent = t('code_wrong'); otp.clear(); }
        } catch (e) { err.textContent = errMsg(e); otp.clear(); }
      });
      show(...head(t('act_totp_title'), t('act_totp_body')),
        h('div', { class: 'totp-grid' }, qr,
          h('div', {},
            h('strong', {}, t('scan_qr')),
            h('small', { class: 'muted block' }, t('manual_key')),
            h('div', { class: 'secret-row' }, secret,
              h('button', { class: 'btn sm ghost', type: 'button', onclick: async () => {
                try { await navigator.clipboard.writeText(setup.secret); toast(t('copied')); } catch {}
              } }, icon('copy', 'sm'), t('copy'))))),
        h('div', { class: 'field' }, h('span', {}, t('enter_code')), otp), err,
        h('div', { class: 'wiz-nav' }, h('button', { class: 'btn ghost', type: 'button', onclick: close }, t('cancel'))));
      try {
        setup = await api('action_totp_begin', { token });
        qr.innerHTML = setup.qrSvg;
        secret.textContent = setup.secret.match(/.{1,4}/g).join(' ');
        otp.focusFirst();
      } catch (e) { err.textContent = errMsg(e); }
    }

    async function recoveryStep() {
      let words;
      try { words = (await api('action_recovery_generate', { token })).words; }
      catch (e) { show(h('p', { class: 'error' }, errMsg(e)), navRow(null)); return; }
      let ack = false;
      const btn = h('button', { class: 'btn primary', type: 'button', disabled: true, onclick: () => {
        const set = new Set();
        while (set.size < 3) set.add(1 + Math.floor(Math.random() * 24));
        verifyStep([...set].sort((a, b) => a - b));
      } }, t('act_continue'));
      show(...head(t('recovery_show_title'), t('recovery_show_body')),
        h('ol', { class: 'words' }, words.map((wd) => h('li', {}, h('span', {}, wd)))),
        toggle(t('recovery_ack'), false, (val) => { ack = val; btn.disabled = !ack; }),
        navRow(btn));
      words = null;
    }

    function verifyStep(idx) {
      const inputs = idx.map((i) => [i, h('input', { class: 'input mono', autocomplete: 'off', spellcheck: 'false' })]);
      const err = h('p', { class: 'error', role: 'alert' });
      show(...head(t('recovery_verify_title'), t('recovery_verify_body')),
        h('form', { class: 'form', onsubmit: async (e) => {
          e.preventDefault(); err.textContent = '';
          const answers = Object.fromEntries(inputs.map(([i, inp]) => [String(i), inp.value]));
          try {
            const r = await api('action_recovery_confirm', { token, answers });
            if (r.ok) done(t('act_rec_done')); else err.textContent = t('verify_failed');
          } catch (e2) { err.textContent = errMsg(e2); }
        } },
          h('div', { class: 'grid3' }, inputs.map(([i, inp]) => h('label', { class: 'field' }, h('span', {}, t('word_n', { n: i })), inp))),
          err, navRow(h('button', { class: 'btn primary', type: 'submit' }, t('verify')))));
      setTimeout(() => inputs[0][1].focus(), 0);
    }

    function addKeyStep(keys) {
      const pin = h('input', { class: 'input', type: 'password', inputmode: 'numeric', autocomplete: 'off' });
      let n = keys.length + 1;
      while (keys.includes('YubiKey ' + n)) n++;
      const label = h('input', { class: 'input', value: 'YubiKey ' + n, maxlength: 40 });
      const err = h('p', { class: 'error', role: 'alert' });
      const btn = h('button', { class: 'btn primary', type: 'submit' }, icon('plus', 'sm'), t('register_key'));
      show(...head(t('act_key_title'), t('backup_hint')),
        keys.length && h('div', { class: 'keys' }, h('small', { class: 'muted' }, t('registered_keys')),
          keys.map((k) => h('div', { class: 'key-item' }, icon('check', 'sm ok'), k))),
        h('form', { class: 'form', onsubmit: async (e) => {
          e.preventDefault(); btn.disabled = true; err.textContent = '';
          try {
            const r = await api('action_add_fido2', { token, pin: pin.value, label: label.value.trim() || 'YubiKey' });
            pin.value = '';
            done(t('act_key_done', { label: r.label }));
          } catch (e2) { touch?.remove(); err.textContent = errMsg(e2); btn.disabled = false; }
        } },
          h('div', { class: 'grid2' },
            h('label', { class: 'field' }, h('span', {}, t('key_label')), label),
            h('label', { class: 'field' }, h('span', {}, t('yubikey_pin')), pin)),
          err, navRow(btn)));
    }

    el.append(overlay);
    authStep();
  }

  // Backup to a drive / add a vault from a drive. Results stay in this
  // window (callouts + toasts); only the folder picker is native.
  const bk = {};        // vault id -> { busy, pct, path, err }
  let driveNote = null; // { busy, pct } | { err } | { name, totp }
  const bkErr = (e) => { const k = 'err_' + (e && e.code); return t(k) !== k ? t(k) : t('err_backup_io'); };
  const bar = (pct) => { const b = h('div', { class: 'progress' }, h('i')); b.firstChild.style.width = (pct || 0) + '%'; return b; };

  // The app itself inside the vault (only while unlocked).
  function appBlock(v) {
    // WhatsApp runs in the shared Brave: never offer to move or remove it here.
    if (v.status !== 'unlocked' || v.app_in_vault == null || !BROWSERS[v.browser] || ENGINE[v.browser]) return null;
    const app = BROWSERS[v.browser];
    // Browsers are also used for normal browsing: removing one needs a second, explicit click.
    const isBrowser = v.browser === 'brave' || v.browser === 'firefox';
    const box = h('div', { class: 'backup-box' });
    let busy = false, err = '', confirming = false, shown = false;
    const errText = (e) => { const k = 'err_' + (e && e.code); return t(k) !== k ? t(k) : t('err_app_copy_failed'); };
    const paint = () => {
      const rows = [];
      if (!v.app_in_vault) {
        rows.push(h('div', { class: 'row' },
          h('button', { class: 'btn sm ghost', disabled: busy || !v.app_outside, onclick: async () => {
            busy = true; err = ''; paint();
            try { await api('move_app_into_vault', { id: v.id }); v.app_in_vault = true; toast(t('app_in_vault_done', { app })); }
            catch (e) { err = errText(e); }
            busy = false; paint();
          } }, busy ? t('app_copying') : t('app_into_vault', { app })),
          h('small', { class: 'muted' }, t('app_into_vault_hint', { app }))));
      } else {
        rows.push(h('div', { class: 'row' }, icon('check', 'sm'), h('small', { class: 'grow' }, t('app_is_in_vault', { app })),
          v.app_outside && h('button', { class: 'btn sm ghost', disabled: busy, onclick: async () => {
            busy = true; err = ''; paint();
            try { await api('move_app_into_vault', { id: v.id }); toast(t('app_refreshed_done', { app })); }
            catch (e) { err = errText(e); }
            busy = false; paint();
          } }, busy ? t('app_copying') : t('app_refresh'))));
        if (v.app_outside) {
          const remove = async () => {
            busy = true; err = ''; confirming = false; paint();
            try { await api('remove_app_outside', { id: v.id }); shown = true; }
            catch (e) { err = errText(e); }
            busy = false; paint();
          };
          if (isBrowser && confirming) {
            rows.push(h('div', { class: 'callout warn col' },
              h('p', {}, t('app_remove_browser_warn', { app })),
              h('div', { class: 'row' },
                h('button', { class: 'btn sm danger-solid', disabled: busy, onclick: remove }, t('app_remove_browser_yes', { app })),
                h('button', { class: 'btn sm ghost', onclick: () => { confirming = false; paint(); } }, t('cancel')))));
          } else {
            rows.push(h('div', { class: 'row' },
              h('button', { class: 'btn sm ghost', disabled: busy, onclick: () => {
                if (isBrowser) { confirming = true; paint(); } else remove();
              } }, t('app_remove_outside', { app })),
              h('small', { class: 'muted' }, t('app_remove_outside_hint', { app }))));
          }
        }
      }
      if (shown) rows.push(h('div', { class: 'callout ok' }, icon('check', 'sm'), h('p', {}, t('app_drag_to_trash', { app }))));
      if (err) rows.push(h('div', { class: 'callout warn' }, icon('alert', 'sm'), h('p', {}, err)));
      box.replaceChildren(...rows);
    };
    paint();
    return box;
  }

  function backupBlock(v) {
    const box = h('div', { class: 'backup-box' });
    const paint = () => {
      const st = bk[v.id] || {};
      const locked = v.status === 'locked';
      const btn = h('button', { class: 'btn sm ghost', disabled: !locked || st.busy, onclick: run },
        st.busy ? t('backing_up') : t('backup_to_drive'));
      box.replaceChildren(...[
        h('div', { class: 'row' }, btn,
          !locked && h('small', { class: 'muted' }, t('backup_lock_first')),
          st.busy && st.pct == null && h('small', { class: 'muted' }, t('pick_folder_hint')),
          st.busy && st.pct != null && h('span', { class: 'row grow' }, bar(st.pct), h('small', { class: 'muted' }, st.pct + '%'))),
        st.path && h('div', { class: 'callout ok' }, icon('check', 'sm'),
          h('div', { class: 'grow' }, h('p', {}, t('backup_done')), h('small', { class: 'path' }, st.path))),
        st.err && h('div', { class: 'callout warn' }, icon('alert', 'sm'), h('p', {}, st.err))].filter(Boolean));
    };
    async function run() {
      bk[v.id] = { busy: true, pct: null }; paint();
      const off = on('backup_progress', (p) => { if (p.id === v.id) { bk[v.id].pct = p.pct; paint(); } });
      cleanup.push(off);
      try {
        const r = await api('backup_vault', { id: v.id });
        bk[v.id] = r.cancelled ? {} : { path: r.path };
        if (!r.cancelled) toast(t('backup_done_toast'));
      } catch (e) { bk[v.id] = { err: bkErr(e) }; }
      off(); paint();
    }
    paint();
    return box;
  }

  async function addFromDrive() {
    driveNote = { busy: true, pct: null }; render();
    const off = on('backup_progress', (p) => { if (!p.id && driveNote?.busy) { driveNote.pct = p.pct; render(); } });
    cleanup.push(off);
    try {
      const r = await api('add_vault_from_drive');
      if (r.cancelled) driveNote = null;
      else {
        vaults.splice(0, vaults.length, ...(await api('list_vaults')));
        driveNote = { name: r.name, totp: r.mode === 'totp' };
        toast(r.name == null ? t('add_done_locked') : t('add_done', { name: r.name }));
      }
    } catch (e) { driveNote = { err: bkErr(e) }; }
    off(); render();
  }

  function driveCallout() {
    const n = driveNote;
    if (!n) return null;
    const dismiss = h('button', { class: 'btn sm ghost', onclick: () => { driveNote = null; render(); } }, t('close'));
    if (n.busy) {
      return h('div', { class: 'callout col' }, h('strong', {}, t('adding_from_drive')),
        n.pct == null ? h('small', { class: 'muted' }, t('pick_backup_hint')) : bar(n.pct));
    }
    if (n.err) return h('div', { class: 'callout warn' }, icon('alert', 'sm'), h('p', { class: 'grow' }, n.err), dismiss);
    return h('div', { class: 'callout ok col' },
      h('div', { class: 'row' }, icon('check', 'sm'), h('strong', { class: 'grow' }, n.name == null ? t('add_done_locked') : t('add_done', { name: n.name })), dismiss),
      n.name == null && h('p', {}, t('add_locked_note')),
      n.totp && h('p', {}, t('add_totp_note')));
  }

  async function vaultsTab() {
    const cards = await Promise.all(vaults.map(async (v) => {
      const factors = await api('list_factors', { id: v.id });
      const act = (action, label, cls = 'ghost') => h('button', { class: 'btn sm ' + cls, onclick: async () => {
        if (action !== 'delete') { actionFlow(v, action); return; }
        await api('request_vault_action', { id: v.id, action });
        if (!isTauri) toast(t('auth_required'));
      } }, label);
      return h('article', { class: 'vault-card' },
        h('header', {}, badge(v.browser), h('div', {}, h('strong', {}, vname(v)), h('small', {}, vsub(v, `${v.sizeGb} GB`))),
          h('span', { class: 'status status-' + v.status + ' push' }, t('status_' + v.status))),
        originalBlock(v),
        h('div', { class: 'factors' }, h('small', { class: 'muted' }, t('factors')),
          factors.map((f) => h('span', { class: 'chip' }, icon(f.type === 'fido2' ? 'key' : f.type === 'totp' ? 'phone' : 'shield', 'xs'), f.type === 'recovery' ? t('chip_recovery') : f.type === 'totp' ? t('chip_totp') : f.label))),
        h('div', { class: 'row wrap' },
          act('change_password', t('change_password')),
          v.mode === 'fido2' ? act('add_fido2', t('add_yubikey')) : act('replace_totp', t('replace_authenticator')),
          act('new_recovery', t('new_recovery')),
          v.browser === 'brave' && !v.portable && act('make_portable', t('act_portable_btn')),
          act('recovery_reset', t('act_recovery_link')),
          act('delete', t('delete_vault'), 'danger push')),
        appBlock(v),
        backupBlock(v));
    }));
    return h('div', { class: 'form' },
      h('div', { class: 'row' }, h('h2', {}, t('tab_vaults')),
        h('button', { class: 'btn sm ghost push', disabled: !!driveNote?.busy, onclick: addFromDrive }, t('add_from_drive')),
        h('button', { class: 'btn sm primary', onclick: () => api('open_window', { view: 'wizard' }) }, icon('plus', 'sm'), t('new_vault'))),
      h('p', { class: 'muted' }, t('auth_required')),
      h('p', { class: 'muted small' }, icon('lock', 'xs'), ' ', t('vaults_names_hint')),
      driveCallout(),
      cards);
  }

  function browsersTab() {
    return h('div', { class: 'form' }, h('h2', {}, t('tab_browsers')),
      h('div', { class: 'group' }, Object.keys(BROWSERS).map((b) =>
        h('div', { class: 'toggle-row' },
          h('span', { class: 'row' }, badge(b), h('span', { class: 'toggle-text' }, BROWSERS[b],
            h('small', {}, browsers[b].found ? browsers[b].path : t('not_installed')))),
          h('span', { class: 'row' },
            browsers[b].found && h('span', { class: 'status status-unlocked' }, icon('check', 'xs'), t('found')),
            h('button', { class: 'btn sm ghost', onclick: async () => {
              const p = await api('pick_browser_path', { browser: b });
              if (p) { browsers[b] = { found: true, path: p }; render(); }
            } }, t('choose')))))));
  }

  function about() {
    const updErr = h('p', { class: 'error', role: 'alert' });
    const upd = h('button', { class: 'btn', type: 'button', onclick: async () => {
      updErr.textContent = ''; upd.disabled = true;
      try {
        const r = await api('install_update');
        if (r) { upd.textContent = t('update_restarting'); return; }
      } catch (e) {
        const k = 'err_' + (e && e.code);
        updErr.textContent = t(k) !== k ? t(k) : t('err_update_failed');
      }
      upd.disabled = false;
    } }, t('update_btn'));
    return h('div', { class: 'form' },
      h('div', { class: 'about-head' }, h('div', { class: 'brand on lg' }, icon('shield', 'lg')),
        h('div', {}, h('h2', {}, t('app_name')), h('small', { class: 'muted' }, `${t('version')} ${info.version}${info.build ? ' · build ' + info.build : ''}`))),
      h('div', { class: 'group' }, h('div', { class: 'toggle-row' },
        h('span', { class: 'toggle-text' }, t('update_title'), h('small', {}, t('update_hint'))), upd), updErr),
      h('h3', {}, t('limits_title')),
      h('ul', { class: 'limits' }, t('limits').map((l, i) => h('li', { class: i === 0 ? 'good' : '' }, icon(i === 0 ? 'check' : 'alert', 'sm'), l))));
  }

  await render();
  return el;
}

// ---------- CLEANUP (delete original profile, spec 5.1) ----------
async function viewCleanup(params) {
  const id = params.get('id');
  const vaults = await api('list_vaults');
  const v = vaults.find((x) => x.id === id);
  const el = h('div', { class: 'pane cleanup' });
  let info = await api('cleanup_preview', { id });
  let running = (await api('browser_running', { browser: v.browser })).running;
  const B = bname(v.browser);
  let ack = false;

  const render = () => {
    const pw = h('input', { class: 'input', type: 'password', autocomplete: 'current-password', oninput: upd });
    const err = h('p', { class: 'error', role: 'alert' });
    const btn = h('button', { class: 'btn danger-solid block', type: 'submit', disabled: true }, t('delete_forever'));
    const req = (ok, label, extra) => h('li', { class: ok ? 'ok' : 'no' }, icon(ok ? 'check' : 'alert', 'sm'), h('span', {}, label), extra);
    function upd() { btn.disabled = !(info.reviewed && !running && ack && pw.value); }

    const form = h('form', { class: 'form', onsubmit: async (e) => {
      e.preventDefault(); err.textContent = ''; btn.disabled = true; btn.textContent = t('deleting');
      const bar = h('div', { class: 'progress' }, h('i'));
      btn.after(bar);
      const off = on('cleanup_progress', ({ pct }) => (bar.firstChild.style.width = pct + '%'));
      try {
        await api('cleanup_original', { id, password: pw.value });
        pw.value = ''; off();
        el.replaceChildren(h('div', { class: 'finish' },
          h('div', { class: 'finish-art' }, icon('check', 'xl')),
          h('h2', {}, t('cleanup_done')), h('p', { class: 'muted' }, t('cleanup_done_body')),
          h('button', { class: 'btn primary', onclick: () => api('close_window') }, t('close'))));
      } catch (e2) {
        off(); bar.remove(); err.textContent = t(e2.code === 'not_reviewed' ? 'not_reviewed_hint' : 'unlock_failed');
        btn.textContent = t('delete_forever'); upd();
      }
    } },
      h('div', { class: 'row' }, h('div', { class: 'lock-art danger' }, icon('alert', 'lg')),
        h('div', {}, h('h1', {}, t('cleanup_title')), h('p', { class: 'vault-chip' }, badge(v.browser), `${B} · ${profileLabel(info.profileName)}`))),
      h('p', {}, t('cleanup_intro')),
      h('div', { class: 'field' }, h('span', {}, t('will_delete', { size: fmtSize(info.sizeMb) })),
        h('ul', { class: 'paths' }, info.items.map((p) => h('li', {}, p))),
        h('small', { class: 'muted' }, t(allCount(info.profileName) ? 'other_profiles_later_safe' : 'other_profiles_safe', { browser: B }))),
      h('ul', { class: 'checklist' },
        req(info.reviewed, t('req_reviewed'), !info.reviewed && h('small', { class: 'muted block' }, t('not_reviewed_hint'))),
        req(!running, t('req_closed', { browser: B }), running && h('button', { class: 'btn sm ghost', type: 'button', onclick: async () => {
          running = (await api('browser_running', { browser: v.browser })).running; render();
        } }, t('recheck')))),
      !info.fileVault && h('div', { class: 'callout' }, icon('alert', 'sm'), h('p', {}, t('fv_warn'))),
      toggle(t('req_ack'), ack, (val) => { ack = val; upd(); }),
      h('label', { class: 'field' }, h('span', {}, t('confirm_pw')), pw),
      err, btn,
      h('button', { class: 'link center', type: 'button', onclick: () => api('close_window') }, t('cancel')));
    el.replaceChildren(form);
  };
  render();
  return el;
}

// ---------- router ----------
const VIEWS = { tray: viewTray, unlock: viewUnlock, wizard: viewWizard, settings: viewSettings, cleanup: viewCleanup };
let routeSeq = 0;

async function route() {
  cleanup.forEach((f) => { try { f(); } catch {} });
  cleanup = [];
  const [name, qs] = (location.hash.slice(1) || 'tray').split('?');
  const view = VIEWS[name] ? name : 'tray';
  const seq = ++routeSeq;
  document.body.dataset.view = view;
  // Rust settings are the single source of truth for the language (the
  // tray menu uses them too); localStorage is only a cache.
  if (isTauri) {
    try { const st = await api('get_settings'); if (st.language && st.language !== getLang()) setLang(st.language); } catch {}
    if (seq !== routeSeq) return;
  }
  document.documentElement.lang = getLang();
  const node = await VIEWS[view](new URLSearchParams(qs));
  if (seq !== routeSeq) return; // a newer navigation won
  root.replaceChildren(node);
  document.title = t('app_name');
  if (view === 'tray') cleanup.push(on('vaults_changed', () => route()));
}

window.addEventListener('hashchange', route);
if (isTauri) {
  const report = (m) => { try { api('ui_log', { view: document.body.dataset.view || '?', msg: String(m) }); } catch {} };
  window.addEventListener('error', (e) => report(e.message + ' @' + (e.filename || '').split('/').pop() + ':' + e.lineno));
  window.addEventListener('unhandledrejection', (e) => report('rejection: ' + (e.reason?.code || e.reason?.message || e.reason)));
}
if (isTauri) on('settings_changed', () => route());
window.addEventListener('keydown', (e) => {
  if (e.key === 'Escape' && document.body.dataset.view !== 'tray' && isTauri) api('close_window');
});

// Dev bar (only outside Tauri) for previewing all views.
if (!isTauri) {
  const bar = h('div', { class: 'devbar' },
    h('strong', {}, 'Preview'),
    ['tray', 'unlock?id=v2', 'unlock?id=v1', 'wizard', 'settings', 'cleanup?id=v1'].map((v) => h('a', { href: '#' + v }, v)),
    h('button', { onclick: () => document.documentElement.classList.toggle('dark') }, 'theme'),
    h('button', { onclick: () => { setLang(getLang() === 'bg' ? 'en' : 'bg'); route(); } }, 'BG/EN'),
    h('small', {}, 'demo code: 123456'));
  document.body.prepend(bar);
  document.body.classList.add('preview');
}

route();
