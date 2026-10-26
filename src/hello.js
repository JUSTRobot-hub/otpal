// Windows Hello unlock. Hello (fingerprint, face or PIN) releases a key that protects a copy
// of the master password in hello.json, so the password does not have to be typed each time.
// The vault itself is unchanged: Hello is only another way to supply the same password.
import { inTauri } from './api.js';

const toB64 = (bytes) => btoa(String.fromCharCode(...bytes));
const fromB64 = (text) => Uint8Array.from(atob(text), (c) => c.charCodeAt(0));
// Tauri rejects with plain strings; callers expect Error objects with a message.
const call = async (command, args) => {
  try {
    return await (await import('@tauri-apps/api/core')).invoke(command, args);
  } catch (e) {
    throw e instanceof Error ? e : new Error(String(e));
  }
};

async function keyFrom(signatureB64, usage) {
  const digest = await crypto.subtle.digest('SHA-256', fromB64(signatureB64));
  return crypto.subtle.importKey('raw', digest, 'AES-GCM', false, [usage]);
}

export async function helloAvailable() {
  return inTauri() && (await call('hello_available'));
}

export async function helloEnabled() {
  return inTauri() && (await call('read_hello')) !== null;
}

/** Asks Windows Hello to verify the user, then stores the password under the Hello key. */
export async function enableHello(password) {
  const key = await keyFrom(await call('hello_enroll'), 'encrypt');
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, new TextEncoder().encode(password)));
  await call('write_hello', { data: JSON.stringify({ v: 1, iv: toB64(iv), ct: toB64(ct) }) });
}

/** Asks Windows Hello to verify the user and returns the stored master password. */
export async function passwordFromHello() {
  const stored = JSON.parse(await call('read_hello'));
  const key = await keyFrom(await call('hello_unlock'), 'decrypt');
  try {
    const plain = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: fromB64(stored.iv) }, key, fromB64(stored.ct));
    return new TextDecoder().decode(plain);
  } catch {
    throw new Error('Windows Hello data is out of date. Use your password, then turn Hello on again.');
  }
}

export async function disableHello() {
  await call('hello_forget');
}
