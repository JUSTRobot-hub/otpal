// Encrypted channel between the phone page and the desktop app.
//
// The phone talks to the PC over plain HTTP on the local network, and browsers
// disable WebCrypto on such pages, so this uses TweetNaCl (pure JS). The key is
// generated on the PC and travels only in the URL fragment of the QR code shown
// on the PC screen. Fragments are never sent over the network, so someone
// sniffing the Wi-Fi sees only ciphertext and cannot forge a payload.
import nacl from 'tweetnacl';

const toBase64 = (bytes) => {
  let s = '';
  for (let i = 0; i < bytes.length; i += 0x8000) s += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
  return btoa(s);
};
const fromBase64 = (text) => Uint8Array.from(atob(text), (c) => c.charCodeAt(0));
const toUrlSafe = (b64) => b64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
const fromUrlSafe = (s) => s.replace(/-/g, '+').replace(/_/g, '/').padEnd(Math.ceil(s.length / 4) * 4, '=');

/** A fresh random session key, URL-safe base64. */
export function newKey() {
  return toUrlSafe(toBase64(nacl.randomBytes(nacl.secretbox.keyLength)));
}

/** Returns base64(nonce || box). */
export function encryptText(text, key) {
  const nonce = nacl.randomBytes(nacl.secretbox.nonceLength);
  const box = nacl.secretbox(new TextEncoder().encode(text), nonce, fromBase64(fromUrlSafe(key)));
  const out = new Uint8Array(nonce.length + box.length);
  out.set(nonce);
  out.set(box, nonce.length);
  return toBase64(out);
}

/** Throws if the payload was not produced with this key or was altered. */
export function decryptText(payload, key) {
  let bytes;
  try {
    bytes = fromBase64(payload);
  } catch {
    throw new Error('Invalid payload');
  }
  const n = nacl.secretbox.nonceLength;
  const plain = bytes.length > n ? nacl.secretbox.open(bytes.subarray(n), bytes.subarray(0, n), fromBase64(fromUrlSafe(key))) : null;
  if (!plain) throw new Error('Invalid payload');
  return new TextDecoder().decode(plain);
}
