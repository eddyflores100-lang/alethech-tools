/**
 * alethech-tools — CLI tools for .aleth encrypted memory files.
 *
 * Zero dependencies. Uses Node.js built-in crypto.
 */

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const MAGIC_V1 = Buffer.from('ALETH001');
const MAGIC_V2 = Buffer.from('ALETH002');
const MAX_HEADER = 16 * 1024;
const MAX_CONTAINER = 512 * 1024 * 1024;

/**
 * Read the header of a .aleth file without decrypting.
 * Returns format version and metadata visible without passphrase.
 */
function inspect(filePath) {
  const blob = fs.readFileSync(filePath);
  if (blob.length < 12) throw new Error('File too small to be a .aleth container');

  const magic = blob.subarray(0, 8);
  let version, format, headerFields;

  if (magic.equals(MAGIC_V1)) {
    version = 1;
    const hlen = blob.readUInt32BE(8);
    if (hlen === 0 || hlen > MAX_HEADER || 12 + hlen >= blob.length) {
      throw new Error('Invalid header length');
    }
    const headerBytes = blob.subarray(12, 12 + hlen);
    const header = JSON.parse(headerBytes.toString('utf8'));
    format = header.format;
    headerFields = {
      format: header.format,
      kdf: header.kdf,
      cipher: header.cipher,
      scrypt_n: header.scrypt_n,
      scrypt_r: header.scrypt_r,
      scrypt_p: header.scrypt_p,
      version: header.version,
    };
  } else if (magic.equals(MAGIC_V2)) {
    version = 2;
    const hlen = blob.readUInt32BE(8);
    if (hlen === 0 || hlen > MAX_HEADER || 12 + hlen >= blob.length) {
      throw new Error('Invalid header length');
    }
    const headerBytes = blob.subarray(12, 12 + hlen);
    const header = JSON.parse(headerBytes.toString('utf8'));
    format = header.format;
    headerFields = {
      format: header.format,
      version: header.version,
      container_id: header.container_id,
      payload_cipher: header.payload_cipher,
      slots: (header.slots || []).map(s => ({
        id: s.id,
        type: s.type,
        kdf: s.kdf,
      })),
    };
  } else {
    throw new Error('Not a .aleth file (invalid magic bytes)');
  }

  const fileSize = blob.length;
  const headerSize = 12 + (version === 1 ? 0 : 0) + (blob.readUInt32BE(8));
  const encryptedSize = blob.length - headerSize;

  return {
    file: path.basename(filePath),
    path: filePath,
    size: fileSize,
    format_version: version,
    header: headerFields,
    encrypted_payload_size: encryptedSize,
    has_recovery_slot: version === 2 && (headerFields.slots || []).some(s => s.type === 'recovery-secret'),
    slot_count: version === 2 ? (headerFields.slots || []).length : 1,
  };
}

/**
 * Verify the integrity of a .aleth file (magic bytes + header structure).
 * Does NOT verify the encrypted payload (that requires the passphrase).
 */
function verify(filePath) {
  try {
    const info = inspect(filePath);
    return {
      valid: true,
      file: info.file,
      format_version: info.format_version,
      has_recovery: info.has_recovery_slot,
      slots: info.slot_count,
      message: `✓ Valid .aleth v${info.format_version} file with ${info.slot_count} slot(s)`,
    };
  } catch (e) {
    return {
      valid: false,
      file: path.basename(filePath),
      message: `✗ ${e.message}`,
    };
  }
}

/**
 * Compute SHA-256 of a file (for integrity checking).
 */
function checksum(filePath) {
  const blob = fs.readFileSync(filePath);
  return crypto.createHash('sha256').update(blob).digest('hex');
}

module.exports = { inspect, verify, checksum, MAGIC_V1, MAGIC_V2 };
