// Runs in the phone's browser. Reads a QR code from a photo, encrypts the text
// with the session key from the URL fragment, and posts it to the desktop app.
import { h } from './dom.js';
import { decodeQrImage } from './qr.js';
import { encryptText } from './channel.js';
import '@fontsource/sora/600.css';
import '@fontsource/sora/700.css';

const app = document.getElementById('app');
const key = location.hash.slice(1);
let sent = 0;

const status = h('div', { class: 'msgs', 'aria-live': 'polite' });
const say = (cls, text) => status.append(h('div', { class: cls }, text));

async function handle(file) {
  try {
    const text = await decodeQrImage(file);
    if (!text) return say('bad', 'No QR code found. Move closer, hold steady, and fill the frame.');
    if (!/^otpauth(-migration)?:\/\//.test(text)) return say('bad', 'That QR code is not an authenticator export.');
    const res = await fetch('submit', { method: 'POST', body: encryptText(text, key) });
    if (!res.ok) throw new Error(String(res.status));
    sent++;
    say('ok', `Sent (${sent}). Check the desktop app. If Google Authenticator showed more than one QR code, send the next one too.`);
  } catch {
    say('bad', 'Could not send. Is the desktop dialog still open and your phone on the same Wi-Fi?');
  }
}

// No `capture` attribute: that would force the camera and hide the gallery.
const picker = h('input', { type: 'file', accept: 'image/*', hidden: true });
picker.addEventListener('change', async () => {
  for (const f of picker.files) await handle(f);
  picker.value = '';
});

app.replaceChildren(
  h('div', { class: 'center' }, h('div', { class: 'card dialog' },
    h('h1', {}, 'Send to Otpal'),
    key
      ? h('p', { class: 'sub' }, 'In Google Authenticator open the menu, Transfer accounts, Export accounts, and take a screenshot of the QR code. Then upload that screenshot with the button below. If your phone blocks screenshots there, photograph the screen with another device and upload that picture.')
      : h('p', { class: 'error' }, 'Open this page by scanning the QR code shown in the desktop app.'),
    key && h('button', { class: 'btn primary', onclick: () => picker.click() }, 'Upload photo of QR code'),
    picker,
    status,
    h('p', { class: 'sub' }, 'The image is read on this phone and only encrypted text leaves it. Delete the screenshot afterwards.'))),
);
