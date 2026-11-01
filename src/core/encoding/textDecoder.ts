import * as zlib from 'zlib';

function decodeUtf32(buf: Buffer, littleEndian: boolean): string {
  let str = '';
  const len = buf.length - (buf.length % 4);
  for (let i = 0; i < len; i += 4) {
    const cp = littleEndian ? buf.readUInt32LE(i) : buf.readUInt32BE(i);
    if (cp === 0) continue;
    if (cp <= 0x10ffff && !(cp >= 0xd800 && cp <= 0xdfff)) {
      str += String.fromCodePoint(cp);
    }
  }
  return str;
}

/**
 * Decodes buffer into string, transparently supporting UTF-8, UTF-16, UTF-32, gzip,
 * and text files with sparse NUL bytes or embedded binary sections.
 * Returns null only if the buffer is genuinely a non-text asset with zero extractable text.
 */
export function decodeTextBuffer(buf: Buffer): string | null {
  if (buf.length === 0) return '';

  // 1. gzip decompression: 0x1F 0x8B (capped to 64MB output to prevent zip bomb DoS)
  if (buf.length >= 2 && buf[0] === 0x1f && buf[1] === 0x8b) {
    try {
      const decompressed = zlib.gunzipSync(buf, {
        maxOutputLength: 64 * 1024 * 1024,
        finishFlush: zlib.constants.Z_SYNC_FLUSH,
      });
      const decoded = decodeTextBuffer(decompressed);
      if (decoded !== null) return decoded;
    } catch {}
  }

  // 2. UTF-32 BOM: 0xFF 0xFE 0x00 0x00 (LE) or 0x00 0x00 0xFE 0xFF (BE)
  if (buf.length >= 4) {
    if (buf[0] === 0xff && buf[1] === 0xfe && buf[2] === 0x00 && buf[3] === 0x00) {
      return decodeUtf32(buf.subarray(4), true);
    }
    if (buf[0] === 0x00 && buf[1] === 0x00 && buf[2] === 0xfe && buf[3] === 0xff) {
      return decodeUtf32(buf.subarray(4), false);
    }
  }

  // 3. UTF-16LE BOM: 0xFF 0xFE
  if (buf.length >= 2 && buf[0] === 0xff && buf[1] === 0xfe) {
    return buf.subarray(2).toString('utf16le');
  }

  // 4. UTF-16BE BOM: 0xFE 0xFF
  if (buf.length >= 2 && buf[0] === 0xfe && buf[1] === 0xff) {
    const swapped = Buffer.from(buf.subarray(2));
    swapped.swap16();
    return swapped.toString('utf16le');
  }

  // 5. UTF-32 without BOM (3 nulls out of every 4 bytes for ASCII chars)
  if (buf.length >= 8) {
    const sampleSize = Math.min(buf.length - (buf.length % 4), 256);
    let le3NullCount = 0;
    let be3NullCount = 0;
    for (let i = 0; i < sampleSize; i += 4) {
      if (buf[i + 1] === 0 && buf[i + 2] === 0 && buf[i + 3] === 0 && buf[i] !== 0) le3NullCount++;
      if (buf[i] === 0 && buf[i + 1] === 0 && buf[i + 2] === 0 && buf[i + 3] !== 0) be3NullCount++;
    }
    const words = sampleSize / 4;
    if (le3NullCount > words * 0.3) {
      return decodeUtf32(buf, true);
    }
    if (be3NullCount > words * 0.3) {
      return decodeUtf32(buf, false);
    }
  }

  // 6. UTF-16 without BOM (alternating null bytes for ASCII chars)
  if (buf.length >= 4) {
    let nullOdds = 0;
    let nullEvens = 0;
    const sampleSize = Math.min(buf.length, 512);
    for (let i = 0; i < sampleSize; i++) {
      if (buf[i] === 0) {
        if (i % 2 === 1) nullOdds++;
        else nullEvens++;
      }
    }
    // UTF-16LE: nulls at odd indices
    if (nullOdds >= 2 && nullOdds > nullEvens * 2 && nullOdds / (sampleSize / 2) > 0.25) {
      return buf.toString('utf16le');
    }
    // UTF-16BE: nulls at even indices
    if (nullEvens >= 2 && nullEvens > nullOdds * 2 && nullEvens / (sampleSize / 2) > 0.25) {
      const swapped = Buffer.from(buf);
      swapped.swap16();
      return swapped.toString('utf16le');
    }
  }

  // 7. Content-based binary check: count non-printable control bytes vs printable text
  // Text with sparse NUL bytes (e.g. NUL byte in first 1 KB) is treated as text
  const checkLen = Math.min(buf.length, 8192);
  let controlCount = 0;
  for (let i = 0; i < checkLen; i++) {
    const b = buf[i];
    // Control bytes: 0x00-0x08, 0x0B, 0x0C, 0x0E-0x1F (exclude \t=0x09, \n=0x0A, \r=0x0D)
    if ((b >= 0 && b <= 8) || b === 11 || b === 12 || (b >= 14 && b <= 31)) {
      controlCount++;
    }
  }

  // If control bytes are <= 20%, the file is predominantly text with minor binary/NUL artifacts
  if (controlCount <= checkLen * 0.20) {
    // Replace raw nulls with spaces so tokens across null boundaries can still be matched
    return buf.toString('utf8').replace(/\0/g, ' ');
  }

  // 8. Dense binary buffer (e.g. real image, binary database, compiled asset):
  // Extract printable string runs of length >= 8 so any embedded secrets are still inspected
  const rawStr = buf.toString('latin1');
  const printableRuns = rawStr.match(/[\x20-\x7E\t]{8,}/g);
  if (printableRuns && printableRuns.length > 0) {
    return printableRuns.join('\n');
  }

  return null;
}

