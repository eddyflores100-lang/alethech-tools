# alethech-tools

CLI tools for working with `.aleth` encrypted memory files. Inspect, verify, and checksum `.aleth` containers without decrypting them.

## Install

```bash
npm install -g alethech-tools
```

## Usage

### Inspect a .aleth file (metadata only, no passphrase needed)

```bash
alethech-tools inspect memory.aleth
```

Output:
```
File:       memory.aleth
Size:       742 bytes
Format:     .aleth v2
Slots:      2
Recovery:   Yes
Encrypted:  480 bytes
Header:     { ... }
```

### Verify file integrity

```bash
alethech-tools verify memory.aleth
```

Output:
```
✓ Valid .aleth v2 file with 2 slot(s)
```

### Compute SHA-256 checksum

```bash
alethech-tools checksum memory.aleth
```

### JSON output (for scripting)

```bash
alethech-tools inspect memory.aleth --json
alethech-tools verify memory.aleth --json
```

## What it does

- **inspect**: Reads the header of a `.aleth` file without the passphrase. Shows format version, slot count, recovery slot presence, encryption parameters, and payload size. No content is decrypted.
- **verify**: Checks that the file is a valid `.aleth` container (magic bytes + header structure). Does NOT verify the encrypted payload (that requires the passphrase).
- **checksum**: Computes SHA-256 of the entire file for integrity tracking.

## What it does NOT do

- Does NOT decrypt content (no passphrase handling)
- Does NOT modify files (read-only)
- Does NOT connect to any server (fully offline)
- Does NOT require Python or any runtime

## Zero dependencies

This package has **zero** runtime dependencies. It uses only Node.js built-in modules (`crypto`, `fs`, `path`).

## License

MIT — © 2026 AliceLabs
