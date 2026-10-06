const { inspect, verify, checksum, MAGIC_V1, MAGIC_V2 } = require('../src/index');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const os = require('os');

let passed = 0, failed = 0;

function assert(condition, message) {
  if (condition) { passed++; console.log(`  ✓ ${message}`); }
  else { failed++; console.log(`  ✗ ${message}`); }
}

// Create a fake v1 .aleth file for testing
function createFakeV1() {
  const header = {
    cipher: 'AES-256-GCM', format: 'aleth', kdf: 'scrypt',
    nonce: 'dGVzdA', salt: 'dGVzdHNhbHQ',
    scrypt_n: 32768, scrypt_p: 1, scrypt_r: 8, version: 1
  };
  const headerBytes = Buffer.from(JSON.stringify(header), 'utf8');
  const hlen = Buffer.alloc(4);
  hlen.writeUInt32BE(headerBytes.length, 0);
  const encrypted = Buffer.alloc(32); // fake ciphertext
  return Buffer.concat([MAGIC_V1, hlen, headerBytes, encrypted]);
}

function createFakeV2() {
  const header = {
    container_id: 'dGVzdGlk',
    format: 'aleth', payload_cipher: 'AES-256-GCM',
    payload_nonce: 'dGVzdA',
    slots: [
      { id: 'passphrase-1', type: 'passphrase', kdf: 'scrypt', nonce: 'dGVzdA', salt: 'dGVzdA', scrypt_n: 32768, scrypt_p: 1, scrypt_r: 8, wrapped_key: 'dGVzdA' },
      { id: 'recovery-1', type: 'recovery-secret', kdf: 'HKDF-SHA256', nonce: 'dGVzdA', salt: 'dGVzdA', wrapped_key: 'dGVzdA' },
    ],
    version: 2
  };
  const headerBytes = Buffer.from(JSON.stringify(header), 'utf8');
  const hlen = Buffer.alloc(4);
  hlen.writeUInt32BE(headerBytes.length, 0);
  const encrypted = Buffer.alloc(32);
  return Buffer.concat([MAGIC_V2, hlen, headerBytes, encrypted]);
}

// Tests
console.log('alethech-tools tests\n');

// Test 1: inspect v1
{
  const tmpDir = os.tmpdir();
  const filePath = path.join(tmpDir, 'test-v1.aleth');
  fs.writeFileSync(filePath, createFakeV1());
  const info = inspect(filePath);
  assert(info.format_version === 1, 'inspect v1: format_version is 1');
  assert(info.header.kdf === 'scrypt', 'inspect v1: kdf is scrypt');
  assert(info.header.cipher === 'AES-256-GCM', 'inspect v1: cipher is AES-256-GCM');
  assert(info.slot_count === 1, 'inspect v1: slot_count is 1');
  assert(info.has_recovery_slot === false, 'inspect v1: no recovery slot');
  fs.unlinkSync(filePath);
}

// Test 2: inspect v2
{
  const tmpDir = os.tmpdir();
  const filePath = path.join(tmpDir, 'test-v2.aleth');
  fs.writeFileSync(filePath, createFakeV2());
  const info = inspect(filePath);
  assert(info.format_version === 2, 'inspect v2: format_version is 2');
  assert(info.slot_count === 2, 'inspect v2: slot_count is 2');
  assert(info.has_recovery_slot === true, 'inspect v2: has recovery slot');
  assert(info.header.container_id === 'dGVzdGlk', 'inspect v2: container_id matches');
  fs.unlinkSync(filePath);
}

// Test 3: verify
{
  const tmpDir = os.tmpdir();
  const filePath = path.join(tmpDir, 'test-verify.aleth');
  fs.writeFileSync(filePath, createFakeV1());
  const result = verify(filePath);
  assert(result.valid === true, 'verify: valid .aleth returns true');
  fs.unlinkSync(filePath);
}

// Test 4: verify invalid
{
  const tmpDir = os.tmpdir();
  const filePath = path.join(tmpDir, 'test-invalid.aleth');
  fs.writeFileSync(filePath, Buffer.from('not an aleth file'));
  const result = verify(filePath);
  assert(result.valid === false, 'verify: invalid file returns false');
  fs.unlinkSync(filePath);
}

// Test 5: checksum
{
  const tmpDir = os.tmpdir();
  const filePath = path.join(tmpDir, 'test-checksum.aleth');
  const data = createFakeV1();
  fs.writeFileSync(filePath, data);
  const hash = checksum(filePath);
  assert(hash === crypto.createHash('sha256').update(data).digest('hex'), 'checksum: SHA-256 matches');
  assert(hash.length === 64, 'checksum: hash is 64 chars');
  fs.unlinkSync(filePath);
}

// Test 6: error on non-aleth file
{
  const tmpDir = os.tmpdir();
  const filePath = path.join(tmpDir, 'test-error.txt');
  fs.writeFileSync(filePath, 'hello world');
  try {
    inspect(filePath);
    assert(false, 'inspect: should throw on non-aleth file');
  } catch (e) {
    assert(e.message.includes('invalid magic bytes'), 'inspect: throws on non-aleth file');
  }
  fs.unlinkSync(filePath);
}

console.log(`\n${passed} passed, ${failed} failed`);
process.exit(failed > 0 ? 1 : 0);
