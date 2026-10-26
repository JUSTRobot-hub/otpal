import { test } from 'node:test';
import assert from 'node:assert/strict';
import { base32Encode, base32Decode } from '../src/base32.js';
import { importFromText, parseOtpauth } from '../src/migration.js';

const ascii = (s) => new TextEncoder().encode(s);

test('base32 round trips and matches known value', () => {
  assert.equal(base32Encode(ascii('12345678901234567890')), 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ');
  assert.deepEqual(base32Decode('GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ'), ascii('12345678901234567890'));
  assert.throws(() => base32Decode('not*valid'));
});

// Builds the same protobuf Google Authenticator emits, to test the parser.
const varint = (n) => {
  const out = [];
  while (n > 127) { out.push((n & 127) | 128); n = Math.floor(n / 128); }
  out.push(n);
  return out;
};
const lenField = (field, bytes) => [...varint(field * 8 + 2), ...varint(bytes.length), ...bytes];
const intField = (field, n) => [...varint(field * 8), ...varint(n)];

function migrationLink({ secret, name, issuer, algorithm = 1, digits = 1, type = 2 }, extra = []) {
  const otp = [
    ...lenField(1, secret), ...lenField(2, ascii(name)), ...lenField(3, ascii(issuer)),
    ...intField(4, algorithm), ...intField(5, digits), ...intField(6, type),
  ];
  const payload = [...lenField(1, otp), ...extra, ...intField(2, 1), ...intField(3, 1), ...intField(4, 0), ...intField(5, 7)];
  return `otpauth-migration://offline?data=${encodeURIComponent(btoa(String.fromCharCode(...payload)))}`;
}

test('imports a Google Authenticator transfer link', () => {
  const link = migrationLink({ secret: ascii('12345678901234567890'), name: 'alice@example.com', issuer: 'Example' });
  const r = importFromText(`scanned: ${link}`);
  assert.deepEqual(r.errors, []);
  assert.equal(r.accounts.length, 1);
  assert.deepEqual(r.accounts[0], {
    issuer: 'Example', name: 'alice@example.com',
    secret: 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ', algorithm: 'SHA1', digits: 6, period: 30,
  });
  assert.deepEqual(r.batches, [{ index: 0, size: 1, id: 7 }]);
});

test('migration: splits "Issuer:name" labels, skips HOTP, reads SHA256 and 8 digits', () => {
  const a = importFromText(migrationLink({ secret: ascii('abc'), name: 'GitHub:bob', issuer: '', algorithm: 2, digits: 2 }));
  assert.equal(a.accounts[0].issuer, 'GitHub');
  assert.equal(a.accounts[0].name, 'bob');
  assert.equal(a.accounts[0].algorithm, 'SHA256');
  assert.equal(a.accounts[0].digits, 8);

  const b = importFromText(migrationLink({ secret: ascii('abc'), name: 'x', issuer: 'Y', type: 1 }));
  assert.equal(b.accounts.length, 0);
  assert.match(b.skipped[0], /HOTP/);
});

test('imports otpauth:// links and rejects bad input', () => {
  const a = parseOtpauth('otpauth://totp/ACME%20Co:john@acme.com?secret=jbswy3dpehpk3pxp&issuer=ACME%20Co&digits=8&algorithm=SHA256');
  assert.equal(a.issuer, 'ACME Co');
  assert.equal(a.name, 'john@acme.com');
  assert.equal(a.secret, 'JBSWY3DPEHPK3PXP');
  assert.equal(a.digits, 8);
  assert.equal(a.algorithm, 'SHA256');
  assert.ok(importFromText('hello').errors.length);
  assert.ok(importFromText('otpauth://totp/x?secret=!!!').errors.length);
  assert.ok(importFromText('otpauth-migration://offline?data=%%%').errors.length);
});

test('new master passwords: length and common-password rules', async () => {
  const { checkPassword } = await import('../src/password.js');
  assert.match(checkPassword('short'), /at least 9/);
  assert.match(checkPassword('password12345'.padEnd(14, '1')), /common/);
  assert.match(checkPassword('Password1234567'), /common/);
  assert.match(checkPassword('aaaaaaaaaaaaaaaa'), /few different|easy/);
  assert.match(checkPassword('12345678901234'), /easy|common/);
  assert.equal(checkPassword('correct horse battery staple'), null);
  assert.equal(checkPassword('e2e-test-vault-pass-77'), null);
  assert.equal(checkPassword('Tulip-Granite-Lantern-42'), null);
});
