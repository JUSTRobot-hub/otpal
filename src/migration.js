// Parses otpauth:// links and Google Authenticator "Transfer accounts"
// (otpauth-migration://) payloads. Nothing here touches the network.
import { base32Encode, base32Decode } from './base32.js';

const ALGORITHMS = { 0: 'SHA1', 1: 'SHA1', 2: 'SHA256', 3: 'SHA512', 4: 'MD5' };
const DIGITS = { 0: 6, 1: 6, 2: 8 };

function readVarint(buf, pos) {
  let result = 0;
  let shift = 0;
  let b;
  do {
    if (pos >= buf.length) throw new Error('Truncated data');
    b = buf[pos++];
    result += (b & 0x7f) * 2 ** shift;
    shift += 7;
  } while (b & 0x80);
  return [result, pos];
}

/** Minimal protobuf reader: yields { field, value } for varint and bytes fields. */
function* fields(buf) {
  let pos = 0;
  while (pos < buf.length) {
    let key;
    [key, pos] = readVarint(buf, pos);
    const field = Math.floor(key / 8);
    const wire = key % 8;
    let value;
    if (wire === 0) {
      [value, pos] = readVarint(buf, pos);
    } else if (wire === 2) {
      let len;
      [len, pos] = readVarint(buf, pos);
      if (pos + len > buf.length) throw new Error('Truncated data');
      value = buf.subarray(pos, pos + len);
      pos += len;
    } else if (wire === 1 || wire === 5) {
      const size = wire === 1 ? 8 : 4;
      value = buf.subarray(pos, pos + size);
      pos += size;
    } else {
      throw new Error('Unsupported data format');
    }
    yield { field, value };
  }
}

function fromBase64(text) {
  const b64 = text.replace(/ /g, '+').replace(/-/g, '+').replace(/_/g, '/');
  const bin = atob(b64.padEnd(Math.ceil(b64.length / 4) * 4, '='));
  return Uint8Array.from(bin, (c) => c.charCodeAt(0));
}

const utf8 = new TextDecoder();

function splitLabel(name, issuer) {
  // Labels are often "Issuer:account", sometimes alongside a separate issuer field.
  if (issuer && name.startsWith(`${issuer}:`)) {
    return { issuer, name: name.slice(issuer.length + 1).trim() };
  }
  if (!issuer && name.includes(':')) {
    const i = name.indexOf(':');
    return { issuer: name.slice(0, i).trim(), name: name.slice(i + 1).trim() };
  }
  return { issuer, name };
}

/** Returns { accounts, skipped, batch } for one otpauth-migration:// link. */
export function parseMigration(link) {
  const match = /[?&]data=([^&\s]+)/.exec(link);
  if (!match) throw new Error('Not a valid transfer link');
  const payload = fromBase64(decodeURIComponent(match[1]));

  const accounts = [];
  const skipped = [];
  const batch = { index: 0, size: 1, id: 0 };

  for (const { field, value } of fields(payload)) {
    if (field === 3) batch.size = value;
    else if (field === 4) batch.index = value;
    else if (field === 5) batch.id = value;
    else if (field === 1) {
      const p = { secret: null, name: '', issuer: '', algorithm: 0, digits: 0, type: 0 };
      for (const f of fields(value)) {
        if (f.field === 1) p.secret = f.value;
        else if (f.field === 2) p.name = utf8.decode(f.value);
        else if (f.field === 3) p.issuer = utf8.decode(f.value);
        else if (f.field === 4) p.algorithm = f.value;
        else if (f.field === 5) p.digits = f.value;
        else if (f.field === 6) p.type = f.value;
      }
      const label = splitLabel(p.name, p.issuer);
      const display = label.issuer ? `${label.issuer} (${label.name})` : label.name || 'Unnamed';
      if (p.type === 1) skipped.push(`${display}: counter-based (HOTP) is not supported`);
      else if (ALGORITHMS[p.algorithm] === 'MD5') skipped.push(`${display}: MD5 is not supported`);
      else if (!p.secret?.length) skipped.push(`${display}: no secret`);
      else {
        accounts.push({
          issuer: label.issuer,
          name: label.name,
          secret: base32Encode(p.secret),
          algorithm: ALGORITHMS[p.algorithm],
          digits: DIGITS[p.digits] ?? 6,
          period: 30,
        });
      }
    }
  }
  return { accounts, skipped, batch };
}

/** Parses a standard otpauth://totp/Label?secret=... link. */
export function parseOtpauth(link) {
  const url = new URL(link);
  if (url.hostname === 'hotp') throw new Error('Counter-based (HOTP) accounts are not supported');
  if (url.hostname !== 'totp') throw new Error('Not a TOTP link');
  const secret = url.searchParams.get('secret');
  if (!secret) throw new Error('Link has no secret');
  base32Decode(secret); // throws on invalid characters
  const algorithm = (url.searchParams.get('algorithm') || 'SHA1').toUpperCase();
  if (!['SHA1', 'SHA256', 'SHA512'].includes(algorithm)) throw new Error(`Unsupported algorithm: ${algorithm}`);
  const label = splitLabel(decodeURIComponent(url.pathname.slice(1)), url.searchParams.get('issuer') || '');
  return {
    issuer: label.issuer,
    name: label.name,
    secret: secret.toUpperCase().replace(/[\s=-]/g, ''),
    algorithm,
    digits: Number(url.searchParams.get('digits')) === 8 ? 8 : 6,
    period: Number(url.searchParams.get('period')) || 30,
  };
}

/**
 * Accepts any pasted text or decoded QR contents containing one or more links.
 * Returns { accounts, skipped, errors, batches }.
 */
export function importFromText(text) {
  const result = { accounts: [], skipped: [], errors: [], batches: [] };
  const links = text.match(/otpauth(?:-migration)?:\/\/\S+/g) ?? [];
  if (!links.length) result.errors.push('No otpauth:// or otpauth-migration:// link found');
  for (const link of links) {
    try {
      if (link.startsWith('otpauth-migration://')) {
        const r = parseMigration(link);
        result.accounts.push(...r.accounts);
        result.skipped.push(...r.skipped);
        result.batches.push(r.batch);
      } else {
        result.accounts.push(parseOtpauth(link));
      }
    } catch (e) {
      result.errors.push(e.message);
    }
  }
  return result;
}
