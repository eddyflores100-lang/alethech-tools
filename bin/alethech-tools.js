#!/usr/bin/env node
const { inspect, verify, checksum } = require('../src/index');
const path = require('path');

const command = process.argv[2];
const file = process.argv[3];

function usage() {
  console.log(`
alethech-tools — CLI for .aleth encrypted memory files

Usage:
  alethech-tools inspect <file.aleth>    Show metadata without decrypting
  alethech-tools verify <file.aleth>     Verify file integrity
  alethech-tools checksum <file.aleth>  Compute SHA-256 checksum

Options:
  -h, --help    Show this help
  -j, --json    Output as JSON (for inspect/verify)

Examples:
  alethech-tools inspect memory.aleth
  alethech-tools verify memory.aleth --json
  alethech-tools checksum memory.aleth
`);
}

if (!command || command === '-h' || command === '--help') {
  usage();
  process.exit(0);
}

if (!file) {
  console.error('Error: file path required');
  usage();
  process.exit(1);
}

const asJson = process.argv.includes('--json') || process.argv.includes('-j');

try {
  switch (command) {
    case 'inspect': {
      const info = inspect(file);
      if (asJson) {
        console.log(JSON.stringify(info, null, 2));
      } else {
        console.log(`File:       ${info.file}`);
        console.log(`Size:       ${info.size} bytes`);
        console.log(`Format:     .aleth v${info.format_version}`);
        console.log(`Slots:      ${info.slot_count}`);
        console.log(`Recovery:   ${info.has_recovery_slot ? 'Yes' : 'No'}`);
        console.log(`Encrypted:  ${info.encrypted_payload_size} bytes`);
        console.log(`Header:     ${JSON.stringify(info.header, null, 2)}`);
      }
      break;
    }
    case 'verify': {
      const result = verify(file);
      if (asJson) {
        console.log(JSON.stringify(result, null, 2));
      } else {
        console.log(result.message);
      }
      process.exit(result.valid ? 0 : 1);
      break;
    }
    case 'checksum': {
      const hash = checksum(file);
      console.log(hash);
      break;
    }
    default:
      console.error(`Unknown command: ${command}`);
      usage();
      process.exit(1);
  }
} catch (e) {
  console.error(`Error: ${e.message}`);
  process.exit(1);
}
