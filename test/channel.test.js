import { test } from 'node:test';
import assert from 'node:assert/strict';
import qrcode from 'qrcode-generator';
import { newKey, encryptText, decryptText } from '../src/channel.js';
import { decodeQrPixels } from '../src/qr.js';

test('encrypts and decrypts, and nothing readable is left in the payload', () => {
  const key = newKey();
  const secret = 'otpauth://totp/x?secret=JBSWY3DPEHPK3PXP';
  const payload = encryptText(secret, key);
  assert.ok(!payload.includes('JBSWY3DPEHPK3PXP'));
  assert.equal(decryptText(payload, key), secret);
  assert.notEqual(encryptText(secret, key), payload, 'nonce must differ every time');
});

test('rejects wrong keys, tampering and junk', () => {
  const payload = encryptText('hello', newKey());
  assert.throws(() => decryptText(payload, newKey()), /Invalid payload/);

  const key = newKey();
  const good = encryptText('hello', key);
  const raw = Uint8Array.from(atob(good), (c) => c.charCodeAt(0));
  raw[raw.length - 1] ^= 1;
  assert.throws(() => decryptText(btoa(String.fromCharCode(...raw)), key), /Invalid payload/);
  assert.throws(() => decryptText('!!!', key), /Invalid payload/);
  assert.throws(() => decryptText('', key), /Invalid payload/);
});

test('keys are 32 random bytes in URL-safe base64', () => {
  const k = newKey();
  assert.match(k, /^[A-Za-z0-9_-]{43}$/);
  assert.notEqual(k, newKey());
});

// Renders a QR with the same generator the app uses into raw RGBA, then decodes
// it with the same reader the webcam and photo paths use.
function qrPixels(text, scale = 6, quiet = 4) {
  const qr = qrcode(0, 'M');
  qr.addData(text);
  qr.make();
  const n = qr.getModuleCount();
  const side = (n + quiet * 2) * scale;
  const data = new Uint8ClampedArray(side * side * 4).fill(255);
  for (let y = 0; y < side; y++) {
    for (let x = 0; x < side; x++) {
      const r = Math.floor(y / scale) - quiet;
      const c = Math.floor(x / scale) - quiet;
      if (r >= 0 && c >= 0 && r < n && c < n && qr.isDark(r, c)) {
        const i = (y * side + x) * 4;
        data[i] = data[i + 1] = data[i + 2] = 0;
      }
    }
  }
  return { data, side };
}

test('QR reader decodes what the QR writer produces, including a long migration link', () => {
  const phoneUrl = `http://192.168.1.20:49152/s/${'a'.repeat(32)}/#${newKey()}`;
  const a = qrPixels(phoneUrl);
  assert.equal(decodeQrPixels(a.data, a.side, a.side), phoneUrl);

  const migration = 'otpauth-migration://offline?data=' + encodeURIComponent('A'.repeat(300));
  const b = qrPixels(migration, 4);
  assert.equal(decodeQrPixels(b.data, b.side, b.side), migration);

  const blank = new Uint8ClampedArray(100 * 100 * 4).fill(255);
  assert.equal(decodeQrPixels(blank, 100, 100), null);
});
