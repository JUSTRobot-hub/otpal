import jsQR from 'jsqr';
import qrcode from 'qrcode-generator';

const MAX_SIDE = 1600; // phone photos are huge; downscaling keeps decoding fast

/** Decodes a QR code from raw RGBA pixels. Returns the text, or null. */
export function decodeQrPixels(data, width, height) {
  return jsQR(data, width, height, { inversionAttempts: 'attemptBoth' })?.data ?? null;
}

/** Decodes a QR code from an image File/Blob. Returns the text, or null if none found. */
export async function decodeQrImage(file) {
  const bitmap = await createImageBitmap(file);
  const scale = Math.min(1, MAX_SIDE / Math.max(bitmap.width, bitmap.height));
  const canvas = document.createElement('canvas');
  canvas.width = Math.round(bitmap.width * scale);
  canvas.height = Math.round(bitmap.height * scale);
  const ctx = canvas.getContext('2d', { willReadFrequently: true });
  ctx.drawImage(bitmap, 0, 0, canvas.width, canvas.height);
  bitmap.close();
  const { data, width, height } = ctx.getImageData(0, 0, canvas.width, canvas.height);
  return decodeQrPixels(data, width, height);
}

/** Draws `text` as a QR code onto a new canvas element. */
export function drawQr(text, size = 220) {
  const qr = qrcode(0, 'M');
  qr.addData(text);
  qr.make();
  const count = qr.getModuleCount();
  const quiet = 2;
  const cell = Math.floor(size / (count + quiet * 2));
  const canvas = document.createElement('canvas');
  canvas.width = canvas.height = cell * (count + quiet * 2);
  const ctx = canvas.getContext('2d');
  ctx.fillStyle = '#fff';
  ctx.fillRect(0, 0, canvas.width, canvas.height);
  ctx.fillStyle = '#000';
  for (let r = 0; r < count; r++) {
    for (let c = 0; c < count; c++) {
      if (qr.isDark(r, c)) ctx.fillRect((c + quiet) * cell, (r + quiet) * cell, cell, cell);
    }
  }
  canvas.setAttribute('role', 'img');
  canvas.setAttribute('aria-label', 'QR code to open on your phone');
  return canvas;
}
