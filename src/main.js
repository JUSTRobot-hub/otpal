import { api, bindingAvailable, inTauri } from './api.js';
import { importFromText } from './migration.js';
import { decodeQrImage, decodeQrPixels, drawQr } from './qr.js';
import { newKey, decryptText } from './channel.js';
import { h } from './dom.js';
import { logo } from './logo.js';
import { checkPassword } from './password.js';
import { helloAvailable, helloEnabled, enableHello, passwordFromHello, disableHello } from './hello.js';
import '@fontsource/sora/600.css';
import '@fontsource/sora/700.css';
import '@fontsource/jetbrains-mono/600.css';

const REVEAL_MS = 8000;
const IDLE_CHOICES = [1, 2, 5, 10];
const app = document.getElementById('app');
const state = { accounts: [], info: null, filter: '', rows: new Map(), batches: new Map() };
let tickTimer = null;

const idleMinutes = () => {
  try {
    const saved = Number(localStorage.getItem('otpal.idle'));
    return IDLE_CHOICES.includes(saved) ? saved : 2;
  } catch {
    return 2;
  }
};

// The soft glow behind the form belongs to the whole window, so it has no visible edge.
const show = (view) => {
  document.body.classList.toggle('glow', view.firstChild?.classList?.contains('card') ?? false);
  app.replaceChildren(view);
};

function toast(text) {
  const t = h('div', { class: 'toast', role: 'status' }, text);
  document.body.append(t);
  setTimeout(() => t.remove(), 1600);
}

// ---------- screens ----------

/** "Made by" line; opens the author's GitHub page in the browser. */
const credit = () => h('button', { class: 'link credit', type: 'button', onclick: () => api.openAuthorPage() }, 'Made by JUSTRobot-hub');

function passwordScreen({ title, sub, confirm, submitLabel, onSubmit, extra = null }) {
  const pw = h('input', { type: 'password', placeholder: 'Master password', autocomplete: 'off', required: true, autofocus: true });
  const pw2 = confirm ? h('input', { type: 'password', placeholder: 'Repeat password', autocomplete: 'off', required: true }) : null;
  const err = h('p', { class: 'error', role: 'alert' });
  const btn = h('button', { class: 'btn primary', type: 'submit' }, submitLabel);
  const form = h('form', { onsubmit: async (e) => {
    e.preventDefault();
    err.textContent = '';
    const weak = confirm && checkPassword(pw.value);
    if (weak) return void (err.textContent = weak);
    if (confirm && pw.value !== pw2.value) return void (err.textContent = 'Passwords do not match.');
    btn.disabled = true;
    btn.textContent = 'Working…';
    try {
      await onSubmit(pw.value);
    } catch (ex) {
      err.textContent = ex.message;
      btn.disabled = false;
      btn.textContent = submitLabel;
      pw.select();
    }
  } }, pw, pw2, extra, err, btn);
  show(h('div', { class: 'center' }, h('div', { class: 'card hero' }, logo(72), h('h1', {}, title), h('p', { class: 'sub' }, sub), form), credit()));
  pw.focus();
}

const BIND_TEXT = 'Bind this vault to my Windows account (recommended). The file then only opens on this PC under your login, even with the right password. If you reinstall Windows you would import again from your phone.';

function bindCheckbox() {
  return h('label', { class: 'check' }, h('input', { type: 'checkbox', checked: true }), h('span', {}, BIND_TEXT));
}

async function setupScreen() {
  const canBind = await bindingAvailable();
  const bindBox = canBind ? bindCheckbox() : null;
  passwordScreen({
    title: 'Create your vault',
    sub: 'This password encrypts your codes on this PC (9+ characters; a few random words work well). It cannot be recovered; if you forget it, you would import again from your phone.',
    confirm: true,
    submitLabel: 'Create vault',
    extra: bindBox,
    onSubmit: async (password) => {
      state.info = await api.create(password, canBind && bindBox.querySelector('input').checked);
      state.accounts = [];
      await disableHello();
      mainScreen();
    },
  });
}

async function openVault(password) {
  state.info = await api.unlock(password);
  state.accounts = await api.list();
  mainScreen();
}

async function unlockScreen() {
  const hello = (await helloEnabled().catch(() => false))
    ? h('button', { class: 'btn', type: 'button', onclick: async (e) => {
      const btn = e.currentTarget;
      const err = document.querySelector('.hero .error');
      err.textContent = '';
      btn.disabled = true;
      try {
        await openVault(await passwordFromHello());
      } catch (ex) {
        err.textContent = String(ex.message ?? ex);
        btn.disabled = false;
      }
    } }, 'Unlock with Windows Hello')
    : null;
  passwordScreen({
    title: 'Unlock',
    sub: 'Enter your master password.',
    submitLabel: 'Unlock',
    extra: hello,
    onSubmit: openVault,
  });
}

/** Clears everything shown and returns to the unlock screen. Safe to call twice. */
function showLocked() {
  if (!state.info) return;
  clearInterval(tickTimer);
  state.accounts = [];
  state.info = null;
  state.rows.clear();
  state.batches.clear();
  state.filter = '';
  document.querySelector('.overlay')?.dispatchEvent(new Event('unflag-close'));
  document.querySelector('.overlay')?.remove();
  unlockScreen();
}

async function lock() {
  showLocked();
  await api.lock();
}

function idleSelect() {
  return h('select', { class: 'idle-select', 'aria-label': 'Lock after being idle for', onchange: (e) => {
    try { localStorage.setItem('otpal.idle', e.target.value); } catch { /* the choice just will not persist */ }
    api.setIdle(Number(e.target.value));
  } }, ...IDLE_CHOICES.map((m) => h('option', { value: String(m), selected: m === idleMinutes() }, `Lock after ${m} min idle`)));
}

function mainScreen() {
  const list = h('div', { class: 'list' });
  const search = h('input', { type: 'search', placeholder: 'Search', 'aria-label': 'Search accounts', oninput: (e) => {
    state.filter = e.target.value.toLowerCase();
    renderList(list);
  } });
  show(h('div', { style: 'display:flex;flex-direction:column;height:100%' },
    h('header', { class: 'bar' },
      logo(28, { smile: false }),
      h('h1', {}, 'Otpal'),
      h('button', { class: 'btn primary', onclick: openImport }, 'Import'),
      h('button', { class: 'btn', onclick: lock }, 'Lock')),
    upgradeBanner(),
    h('div', { class: 'search' }, search),
    list,
    h('footer', { class: 'note' }, 'Codes stay hidden until you click one. Keep your phone app until you have checked that the codes match.',
      h('div', { class: 'settings' }, helloToggle(), idleSelect()), credit())));
  renderList(list);
  clearInterval(tickTimer);
  tickTimer = setInterval(tick, 500);
  api.setIdle(idleMinutes());
}

// ---------- Windows Hello (always an explicit user action) ----------

function helloToggle() {
  const btn = h('button', { class: 'link hello-toggle', hidden: true });
  const refresh = async () => {
    if (!(await helloAvailable().catch(() => false))) return;
    const on = await helloEnabled().catch(() => false);
    btn.textContent = on ? 'Windows Hello: on (turn off)' : 'Turn on Windows Hello';
    btn.onclick = on
      ? async () => { await disableHello(); toast('Windows Hello turned off'); refresh(); }
      : () => openHelloSetup(refresh);
    btn.hidden = false;
  };
  refresh();
  return h('div', {}, btn);
}

function openHelloSetup(done) {
  const pw = h('input', { type: 'password', placeholder: 'Master password', autocomplete: 'off' });
  const err = h('p', { class: 'error', role: 'alert' });
  const go = h('button', { class: 'btn primary' }, 'Turn on');
  const close = () => overlay.remove();
  go.addEventListener('click', async () => {
    err.textContent = '';
    go.disabled = true;
    go.textContent = 'Waiting for Windows Hello…';
    try {
      try {
        await api.verify(pw.value);
      } catch {
        throw new Error('Wrong password.');
      }
      await enableHello(pw.value);
      close();
      toast('Windows Hello turned on');
      done();
    } catch (e) {
      err.textContent = String(e.message ?? e);
      go.disabled = false;
      go.textContent = 'Turn on';
    }
  });
  const overlay = h('div', { class: 'overlay', onclick: (e) => e.target === overlay && close() },
    h('div', { class: 'card dialog', role: 'dialog', 'aria-label': 'Windows Hello' },
      h('h1', {}, 'Windows Hello'),
      h('p', { class: 'sub' }, 'Unlock with your fingerprint, face or Windows PIN instead of typing the master password. Your password is kept encrypted under a key that only Windows Hello can release. Your master password still works, and you can turn this off at any time.'),
      pw, err,
      h('div', { class: 'actions' }, h('button', { class: 'btn', onclick: close }, 'Cancel'), go)));
  document.body.append(overlay);
  pw.focus();
}

// ---------- vault upgrade (always an explicit user action) ----------

const needsUpgrade = () => state.info?.kdf === 'pbkdf2';

function upgradeBanner() {
  if (!needsUpgrade()) return null;
  return h('div', { class: 'banner' },
    h('span', {}, 'Your vault uses an older, weaker password protection.'),
    h('button', { class: 'btn', onclick: openUpgrade }, 'Upgrade vault'));
}

async function openUpgrade() {
  const canBind = await bindingAvailable();
  const bindBox = canBind ? bindCheckbox() : null;
  const pw = h('input', { type: 'password', placeholder: 'Master password', autocomplete: 'off' });
  const err = h('p', { class: 'error', role: 'alert' });
  const go = h('button', { class: 'btn primary' }, 'Upgrade');
  const close = () => overlay.remove();
  go.addEventListener('click', async () => {
    err.textContent = '';
    go.disabled = true;
    go.textContent = 'Working…';
    try {
      state.info = await api.upgrade(pw.value, canBind && bindBox.querySelector('input').checked);
      close();
      mainScreen();
      toast('Vault upgraded');
    } catch (e) {
      err.textContent = e.message;
      go.disabled = false;
      go.textContent = 'Upgrade';
    }
  });
  const overlay = h('div', { class: 'overlay', onclick: (e) => e.target === overlay && close() },
    h('div', { class: 'card dialog', role: 'dialog', 'aria-label': 'Upgrade vault' },
      h('h1', {}, 'Upgrade vault'),
      h('p', { class: 'sub' }, 'This re-encrypts your vault with Argon2id, which is much harder to crack with graphics cards. Your codes do not change. Older versions of this app will no longer be able to open the vault afterwards.'),
      pw, bindBox, err,
      h('div', { class: 'actions' }, h('button', { class: 'btn', onclick: close }, 'Cancel'), go)));
  document.body.append(overlay);
  pw.focus();
}

function renderList(list) {
  state.rows.clear();
  const items = state.accounts.filter((a) => `${a.issuer} ${a.name}`.toLowerCase().includes(state.filter));
  if (!items.length) {
    list.replaceChildren(h('div', { class: 'empty' }, state.accounts.length ? 'No matches.' : 'No accounts yet. Press Import to add your codes.'));
    return;
  }
  list.replaceChildren(...items.map(accountCard));
  tick();
}

const mask = (digits) => `${'•'.repeat(digits / 2)} ${'•'.repeat(digits - digits / 2)}`;
const counterOf = (a, now) => Math.floor(now / 1000 / a.period);

function accountCard(a) {
  const who = a.issuer || a.name || 'Unnamed';
  const row = { a, code: null, hideAt: 0, counter: null, who };
  const codeBtn = h('button', { class: 'code masked', title: 'Click to show the code', 'aria-label': `Show code for ${who}`, onclick: async () => {
    try {
      if (row.code) {
        await navigator.clipboard.writeText(row.code);
        row.hideAt = Date.now() + REVEAL_MS;
        toast('Copied');
        return;
      }
      await reveal(row);
    } catch {
      toast('Could not get the code');
    }
  } }, mask(a.digits));
  const fill = h('div', { class: 'bar-fill' });
  const remove = h('button', { class: 'link', onclick: async () => {
    if (!remove.dataset.armed) {
      remove.dataset.armed = '1';
      remove.textContent = 'Confirm remove?';
      setTimeout(() => { delete remove.dataset.armed; remove.textContent = 'Remove'; }, 3000);
      return;
    }
    await api.remove(a.id);
    state.accounts = state.accounts.filter((x) => x.id !== a.id);
    renderList(document.querySelector('.list'));
  } }, 'Remove');
  const card = h('div', { class: 'acct' },
    h('div', { class: 'row' },
      h('div', { class: 'who' }, h('div', { class: 'issuer' }, who), a.issuer && h('div', { class: 'name' }, a.name)),
      codeBtn, remove),
    h('div', { class: 'bar-track' }, fill));
  Object.assign(row, { card, codeBtn, fill });
  state.rows.set(a.id, row);
  return card;
}

/** Asks the Rust side for the current code and shows it for a few seconds. */
async function reveal(row) {
  row.code = await api.code(row.a.id);
  row.counter = counterOf(row.a, Date.now());
  row.hideAt = Date.now() + REVEAL_MS;
  paint(row);
}

function paint(row) {
  const { a, codeBtn, code, who } = row;
  codeBtn.classList.toggle('masked', !code);
  codeBtn.textContent = code ? `${code.slice(0, a.digits / 2)} ${code.slice(a.digits / 2)}` : mask(a.digits);
  codeBtn.title = code ? 'Click to copy' : 'Click to show the code';
  codeBtn.setAttribute('aria-label', `${code ? 'Copy' : 'Show'} code for ${who}`);
}

async function tick() {
  const now = Date.now();
  for (const row of state.rows.values()) {
    const { period } = row.a;
    const left = period - ((now / 1000) % period);
    row.fill.style.width = `${(left / period) * 100}%`;
    row.card.classList.toggle('low', left <= 5);
    if (!row.code) continue;
    if (now >= row.hideAt) {
      row.code = null;
      paint(row);
    } else if (row.counter !== counterOf(row.a, now)) {
      try {
        row.code = await api.code(row.a.id);
        row.counter = counterOf(row.a, now);
      } catch {
        row.code = null;
      }
      paint(row);
    }
  }
}

// ---------- import ----------

/** Hands a parse result to the Rust side, which keeps the secrets. Reports what happened through `say`. */
async function addAccounts(result, say) {
  let added = 0;
  if (result.accounts.length) {
    const r = await api.add(result.accounts);
    added = r.added;
    if (r.added) say('ok', `Added ${r.added} account${r.added === 1 ? '' : 's'}.`);
    if (r.dupes) say('warn', `${r.dupes} already in the vault, skipped.`);
    if (r.rejected) say('bad', `${r.rejected} account${r.rejected === 1 ? ' uses' : 's use'} settings Otpal does not support.`);
  }
  result.skipped.forEach((s) => say('warn', `Skipped ${s}`));
  result.errors.forEach((e) => say('bad', e));
  for (const b of result.batches) {
    const got = state.batches.get(b.id) ?? { size: b.size, indexes: new Set() };
    got.indexes.add(b.index);
    state.batches.set(b.id, got);
    if (b.size > 1) say('warn', got.indexes.size < b.size
      ? `This transfer has ${b.size} QR codes; ${got.indexes.size} imported so far. Add the rest.`
      : 'All QR codes of this transfer imported.');
  }
  if (added) {
    state.accounts = await api.list();
    renderList(document.querySelector('.list'));
  }
}

const transferIncomplete = () => [...state.batches.values()].some((b) => b.indexes.size < b.size);

function webcamPanel(say, setPanel) {
  const video = h('video', { playsinline: true, muted: true, 'aria-label': 'Camera preview', style: 'width:100%;border-radius:12px;background:#000' });
  const hint = h('div', { class: 'sub' }, 'On your phone open Google Authenticator, Transfer accounts, Export accounts, then hold the QR code in front of the camera.');
  const canvas = document.createElement('canvas');
  const ctx = canvas.getContext('2d', { willReadFrequently: true });
  let stream;
  let timer;
  let stopped = false;
  let last = '';

  const stop = () => {
    stopped = true;
    clearTimeout(timer);
    stream?.getTracks().forEach((t) => t.stop());
  };
  setPanel(h('div', { style: 'display:grid;gap:8px' }, video, hint), stop);

  async function loop() {
    if (stopped) return;
    if (video.readyState >= 2 && video.videoWidth) {
      const scale = Math.min(1, 960 / video.videoWidth);
      canvas.width = Math.round(video.videoWidth * scale);
      canvas.height = Math.round(video.videoHeight * scale);
      ctx.drawImage(video, 0, 0, canvas.width, canvas.height);
      const { data, width, height } = ctx.getImageData(0, 0, canvas.width, canvas.height);
      const text = decodeQrPixels(data, width, height);
      if (text && text !== last && /^otpauth(-migration)?:\/\//.test(text)) {
        last = text;
        await addAccounts(importFromText(text), say);
        if (!transferIncomplete()) {
          say('ok', 'Done. Camera closed.');
          stop();
          setPanel(null);
          return;
        }
      }
    }
    timer = setTimeout(loop, 120);
  }

  navigator.mediaDevices.getUserMedia({ video: { width: { ideal: 1280 }, height: { ideal: 720 } } })
    .then(async (s) => {
      if (stopped) return s.getTracks().forEach((t) => t.stop());
      stream = s;
      video.srcObject = s;
      await video.play();
      loop();
    })
    .catch((e) => {
      const why = e.name === 'NotAllowedError' ? 'Camera access was blocked. Allow it in Windows Settings, Privacy, Camera.'
        : e.name === 'NotFoundError' ? 'No camera found on this PC.' : 'Could not start the camera.';
      say('bad', why);
      setPanel(null);
    });
}

async function phonePanel(say, setPanel) {
  if (!inTauri()) return say('warn', 'Receiving from a phone works in the desktop app only.');
  const { invoke } = await import('@tauri-apps/api/core');
  const { listen } = await import('@tauri-apps/api/event');
  const token = [...crypto.getRandomValues(new Uint8Array(16))].map((b) => b.toString(16).padStart(2, '0')).join('');
  const key = newKey();

  let base;
  try {
    base = await invoke('start_receiver', { token });
  } catch (e) {
    return say('bad', `Could not start: ${e}`);
  }
  const unlisten = await listen('phone-payload', async (event) => {
    try {
      await addAccounts(importFromText(decryptText(event.payload, key)), say);
    } catch {
      say('bad', 'Received data that could not be verified. Ignored.');
    }
  });
  const stop = () => { unlisten(); invoke('stop_receiver'); };

  setPanel(h('div', { style: 'display:grid;gap:8px;justify-items:center;text-align:center' },
    drawQr(`${base}#${key}`),
    h('div', { class: 'sub' }, 'Scan this with your phone camera (same Wi-Fi). It opens a page where you upload a screenshot of the Google Authenticator QR code. The image is read on the phone and only encrypted text is sent.'),
      h('div', { class: 'sub' }, 'If Windows asks about network access, allow it for private networks. This link stops working when you close this dialog or after 10 minutes.'),
      h('div', { class: 'sub' }, 'QR code will not scan? Type this address into your phone browser:'),
      h('code', { class: 'link-text' }, `${base}#${key}`)), stop);
}

function openImport() {
  const msgs = h('div', { class: 'msgs', 'aria-live': 'polite' });
  const say = (cls, text) => msgs.append(h('div', { class: cls }, text));
  const text = h('textarea', { placeholder: 'otpauth-migration://… or otpauth://totp/…', 'aria-label': 'Paste links' });
  const picker = h('input', { type: 'file', accept: 'image/*', multiple: true, hidden: true });
  const panel = h('div');
  let cleanup = null;

  const setPanel = (node, fn = null) => {
    cleanup?.();
    cleanup = fn;
    panel.replaceChildren(...(node ? [node] : []));
  };

  async function handleFiles(files) {
    for (const file of files) {
      try {
        const data = await decodeQrImage(file);
        if (data) await addAccounts(importFromText(data), say);
        else say('bad', `No QR code found in ${file.name || 'the image'}. Try a larger, sharper image.`);
      } catch {
        say('bad', `Could not read ${file.name || 'the image'}.`);
      }
    }
  }

  const drop = h('div', { class: 'drop', tabindex: '0', role: 'button', onclick: () => picker.click(),
    onkeydown: (e) => (e.key === 'Enter' || e.key === ' ') && picker.click(),
    ondragover: (e) => { e.preventDefault(); drop.classList.add('over'); },
    ondragleave: () => drop.classList.remove('over'),
    ondrop: (e) => { e.preventDefault(); drop.classList.remove('over'); handleFiles(e.dataTransfer.files); } },
    'Or drop a screenshot or photo of the QR code here, click to choose a file, or press Ctrl+V to paste');
  picker.addEventListener('change', () => { handleFiles(picker.files); picker.value = ''; });

  const onPaste = (e) => {
    const files = [...(e.clipboardData?.files ?? [])].filter((f) => f.type.startsWith('image/'));
    if (files.length) { e.preventDefault(); handleFiles(files); }
  };
  const onKey = (e) => e.key === 'Escape' && close();
  function close() {
    cleanup?.();
    document.removeEventListener('paste', onPaste);
    document.removeEventListener('keydown', onKey);
    overlay.remove();
  }
  document.addEventListener('paste', onPaste);
  document.addEventListener('keydown', onKey);

  const overlay = h('div', { class: 'overlay', onclick: (e) => e.target === overlay && close() },
    h('div', { class: 'card dialog', role: 'dialog', 'aria-label': 'Import accounts' },
      h('h1', {}, 'Import accounts'),
      h('p', { class: 'sub' }, 'In Google Authenticator on your phone: menu, Transfer accounts, Export accounts. Then choose how to bring the QR code to this PC.'),
      h('div', { class: 'actions', style: 'justify-content:flex-start;flex-wrap:wrap' },
        h('button', { class: 'btn primary', onclick: () => webcamPanel(say, setPanel) }, 'Scan with webcam'),
        h('button', { class: 'btn', onclick: () => phonePanel(say, setPanel) }, 'Receive from phone (Wi-Fi)')),
      panel, drop, picker,
      h('div', {}, text, h('div', { class: 'actions', style: 'margin-top:8px' },
        h('button', { class: 'btn', onclick: async () => { if (text.value.trim()) { await addAccounts(importFromText(text.value), say); text.value = ''; } } }, 'Add from text'))),
      msgs,
      h('p', { class: 'sub' }, 'If you saved a photo of the QR code, delete it afterwards: it contains your secrets.'),
      h('div', { class: 'actions' }, h('button', { class: 'btn primary', onclick: close }, 'Done'))));
  overlay.addEventListener('unflag-close', close);
  document.body.append(overlay);
}

// ---------- boot ----------

// No right-click menu in the desktop app (the native one is turned off as well).
if (inTauri()) document.addEventListener('contextmenu', (e) => e.preventDefault());

// Activity is reported to the Rust side, which does the idle timing (throttled to every 5 s).
let lastTouch = 0;
for (const ev of ['pointerdown', 'keydown']) {
  document.addEventListener(ev, () => {
    const now = Date.now();
    if (state.info && now - lastTouch > 5000) {
      lastTouch = now;
      api.touch();
    }
  }, { capture: true });
}

if (!inTauri()) {
  app.append(h('div', { class: 'center' }, h('div', { class: 'card hero' }, h('h1', {}, 'Otpal'), h('p', { class: 'sub' }, 'Otpal runs as a desktop app. Start it with npm run tauri dev.'))));
} else {
  api.onLocked(showLocked);
  api.exists().then((exists) => (exists ? unlockScreen() : setupScreen()));
}
