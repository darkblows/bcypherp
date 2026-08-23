<img width="1435" height="914" alt="scr1" src="https://github.com/user-attachments/assets/cd208c81-2238-4013-9bbf-d64fc96faa8e" />

# BastetCipher — Desktop Edition

**Sacred Chamber** · High-entropy password generator + encrypted vault

A single-file Python/CustomTkinter desktop port of the original `BastetCipher.html`.  
Byte-for-byte compatible with the JavaScript original for password generation, and 100% interoperable with existing `.bca` vaults created by the HTML version (tested in both directions).

```
pyinstaller --onefile bastetcipher.py
```

---

## Table of Contents

- [Features](#features)
- [Security Model](#security-model)
- [Cipher Generator (Password Pipeline)](#cipher-generator-password-pipeline)
- [Vault Format (`.bca`)](#vault-format-bca)
- [Secure In-Memory Viewer](#secure-in-memory-viewer)
- [Memory Hygiene & Anti-Swap](#memory-hygiene--anti-swap)
- [UI / Theming](#ui--theming)
- [Dependencies](#dependencies)
- [Building the Executable](#building-the-executable)
- [Usage](#usage)
- [Important Security Notes](#important-security-notes)
- [Limitations (Honest)](#limitations-honest)
- [Architecture Overview](#architecture-overview)
- [File Layout](#file-layout)

---

## Features

| Feature | Description |
|---------|-------------|
| **Cipher Generator** | Deterministic high-entropy password from secret phrase + PIM + optional amplifier |
| **Byte-identical to HTML** | Same output as the original JavaScript for any phrase / PIM / amplifier (verified on 11 cross-test vectors) |
| **Sacred Vault (`.bca`)** | Double-layer encrypted archive (AES-256-GCM + AES-256-CBC) |
| **Fully interoperable** | Create vaults in HTML → open in desktop (and vice-versa) |
| **RAM-only decryption** | Decrypted content never touches disk unless the user explicitly exports |
| **Secure preview** | Images, PDFs, text, audio (and best-effort video) previewed entirely in memory |
| **Memory wiping** | All sensitive buffers (`bytearray`) are explicitly zeroed after use |
| **Anti-swap locking** | Best-effort `mlock` / `VirtualLock` on sensitive pages |
| **Core-dump disabled** | `RLIMIT_CORE = 0` on POSIX at startup |
| **Responsive UI** | Automatically scales fonts and window size to screen resolution |
| **Egyptian temple aesthetic** | Gold / stone / deep-night palette carried over from the original CSS |

---

## Security Model

### Design Goals

1. **No sensitive data in swap / pagefile**
2. **No sensitive data left in RAM after use** (explicit zeroing, not relying on GC)
3. **No immutable `str` / `bytes` for secrets** — everything sensitive lives in mutable `bytearray`
4. **Decrypted vault content never written to disk** unless the user consciously exports a file
5. **Authentication** of vault contents via AES-GCM

### Cryptographic Primitives Used

| Component | Algorithm |
|-----------|-----------|
| Password derivation (cipher generator) | PBKDF2-HMAC-SHA-512 |
| Vault key derivation | PBKDF2-HMAC-SHA-512 (200 000 iterations) |
| Vault encryption layer 1 | AES-256-GCM |
| Vault encryption layer 2 | AES-256-CBC (PKCS#7) |
| Compression | raw deflate (`zlib` wbits=-15) |
| Integrity (per file) | CRC32 of original uncompressed data |
| Hashing inside generator | SHA-256 / SHA-384 / SHA-512 |

---

## Cipher Generator (Password Pipeline)

Exact port of the original JavaScript pipeline (`runCipherPipeline` / `transformHash` / `createPRNG` / etc.).

### Inputs

- **Secret Phrase** — arbitrary Unicode string
- **PIM** (Personal Iteration Modifier) — 1–32 decimal digits
- **Amplifier** — 0–9999 extra characters appended

### Pipeline Steps

1. **Sacred Salt**  
   `SHA-256("BastetCipher" + phrase + pim + PEPPER + "SacredSalt")`

2. **Base hashes**  
   - `h1 = SHA-256(phrase + salt + pim + PEPPER)`  
   - `h2 = SHA-384(salt + phrase + pim + PEPPER)`  
   - `h3 = SHA-512(phrase + ":" + salt + ":" + pim + ":" + PEPPER)`

3. **Transformation seed**  
   `SHA-256(phrase + pim + PEPPER)`

4. **Proprietary transform** (`transform_hash`) on each hash:  
   - Rotation by seed  
   - Pairwise swaps  
   - LCG-driven hex remapping  
   - Chunk reversing  

5. **Combine** → `.,` + t1 + t2 + t3 + `,.`

6. **Iteration count** (reproduces JS `parseInt` precision loss for large PIMs):  
   ```
   base = 50 000 + (hash_int / 16 777 215) * 550 000
   twist = (pim_num % 65 537) * 7
   iterations = base + twist
   ```
   Range ≈ 50 k – 600 k.

7. **PBKDF2-HMAC-SHA-512** (64-byte derived key)

8. **Insert special characters** + **mixed case** (seeded LCG)

9. **Amplification** (optional extra characters from another LCG seeded by phrase/PIM/derived key/PEPPER)

10. **Final cipher** = `.,` + mixed-case-key + amplification + `,.`

### Pepper

```python
PEPPER = "Bastet_Secret_Temple_Key_\U00013060"
```

Hard-coded (inherited from the original HTML for output compatibility).  
**Not a cryptographic secret** — it is recoverable by decompiling a PyInstaller binary. Treat it as a fixed brand salt that differentiates this generator from a plain PBKDF2.

### JavaScript Compatibility Notes

- All 32-bit unsigned arithmetic is reproduced with `& 0xFFFFFFFF`.
- LCG: `state = (state * 1664525 + 1013904223) & 0xFFFFFFFF`
- For PIM ≥ 16 digits, Python deliberately uses `int(float(digits))` to match JavaScript’s IEEE-754 `parseInt` precision loss.

---

## Vault Format (`.bca`)

**BastetCipher Archive** — binary, little-endian.

### Header (69 bytes)

| Offset | Size | Field |
|--------|------|-------|
| 0 | 4 | Magic `0x42 0x43 0x41 0x01` (`BCA\x01`) |
| 4 | 1 | Version (= 1) |
| 5 | 32 | Random salt (PBKDF2) |
| 37 | 4 | PBKDF2 iterations (uint32 LE) — currently fixed at 200 000 |
| 41 | 12 | IV1 (AES-GCM nonce) |
| 53 | 16 | IV2 (AES-CBC IV) |
| 69 | N | Ciphertext |

### Plaintext Structure (before encryption)

```
uint16 LE   number of files
for each file:
  uint16 LE   name length
  bytes       name (UTF-8)
  uint32 LE   CRC32 of original uncompressed data
  uint32 LE   original size
  uint32 LE   compressed size
  bytes       deflate-raw compressed data
```

### Encryption Cascade

1. Compress each file with raw deflate (level 9).
2. Pack plaintext structure.
3. **Layer 1**: AES-256-GCM encrypt (key = first 32 bytes of PBKDF2).
4. **Layer 2**: AES-256-CBC encrypt the GCM ciphertext (key = second 32 bytes of PBKDF2, PKCS#7 padding).

### Key Derivation

```
PBKDF2-HMAC-SHA-512(password, salt, 200_000, 64 bytes)
→ k1 = derived[0:32]   # AES-GCM
→ k2 = derived[32:64]  # AES-CBC
```

Password is kept as `bytearray` and never converted to `str` after encoding.

---

## Secure In-Memory Viewer

Decrypted files are never written to disk for preview.

| Type | Method |
|------|--------|
| **Images** (png/jpg/gif/bmp/webp/tiff) | Pillow → `ImageTk` on a zoomable Canvas |
| **SVG** | Rasterized via PyMuPDF → Pillow |
| **PDF** | PyMuPDF rasterizes pages in RAM (max 30 pages @ 100 dpi by default) |
| **Text** | UTF-8 / latin-1 decode → read-only Textbox |
| **Audio** (mp3/ogg/wav/flac/aac) | `pygame.mixer` from `BytesIO` (seekable where the backend supports it) |
| **Video** | Temporary file on `/dev/shm` (Linux RAM-disk) when available; otherwise normal temp + clear warning. Cleaned up on window/app close. |
| **Other** | No preview — only explicit “Export” |

### Audio Session Isolation

`pygame.mixer.music` is a process-wide singleton. A generation counter prevents one preview window from displaying the playback position of another window’s audio.

---

## Memory Hygiene & Anti-Swap

### SecureBuffer

```python
with SecureBuffer(64) as buf:
    buf.data[:] = sensitive_bytes
    # use buf.data
# automatically wiped + unlocked
```

- Allocates a fixed-size `bytearray`
- Attempts `mlock` (POSIX) or `VirtualLock` (Windows)
- Guaranteed zeroing via `ctypes.memset` on exit / `__del__`

### wipe_bytearray

Uses native `ctypes.memset` (≈ 500× faster than a Python byte loop on large buffers). Falls back to slice assignment if needed.

### Process Hardening

```python
harden_process()  # called at startup
→ resource.setrlimit(RLIMIT_CORE, (0, 0))  # POSIX only
```

### Ownership & Cleanup Guarantees

- File contents are wiped even if compression / encryption fails mid-loop (`try/finally` per entry).
- Partial decryption failures wipe already-decrypted entries before re-raising.
- App exit wipes all open vault entries, pending create buffers, password fields, audio, and video temp files.

---

## UI / Theming

Dark “Egyptian temple” palette taken from the original CSS custom properties:

| Token | Hex |
|-------|-----|
| Gold | `#c9a84c` |
| Gold Bright | `#f0c040` |
| Stone | `#2a2318` |
| Deep | `#0f0c06` |
| Emerald | `#00c896` |
| Sand | `#d4b483` |
| Danger | `#ff5555` |

### Adaptive Scaling

- Reference resolution: 1920×1080 → scale 1.0
- Scale clamped to `[0.65, 1.35]`
- All fonts and many widget heights are multiplied by the scale factor
- Window size = 75 % × 82 % of screen (capped)

Georgia for UI text, Consolas for mono output.

---

## Dependencies

```
customtkinter
cryptography
pillow
pymupdf          # lazy-imported (only when PDF/SVG preview is used)
pygame           # lazy-imported (audio)
mutagen          # lazy-imported (audio duration)
```

Optional / platform:

- `resource` (stdlib, POSIX core-dump disable)
- `ctypes` (stdlib, mlock / memset)

---

## Building the Executable

```bash
pip install -r requirements.txt
pyinstaller --onefile bastetcipher.py
```

The resulting binary contains the hard-coded PEPPER. Anyone who decompiles it can recover that value.

---

## Usage

### Cipher Generator

1. Enter a secret phrase.
2. Enter a PIM (1–32 digits).
3. Optionally set an amplifier (0–9999).
4. Click **Generate Cipher**.
5. Copy to clipboard or wipe from memory.

### Create Vault

1. Add one or more files (read into RAM on a background thread).
2. Set and confirm a password.
3. Choose destination `.bca` path.
4. Archive is built entirely in memory, then written once.

### Open Vault

1. Select a `.bca` file.
2. Enter password.
3. Contents appear only in RAM.
4. Preview (image / PDF / text / audio / video) or Export individually.
5. **Close Vault** zeros every buffer.

---

## Important Security Notes

- **PEPPER is not secret.** It is present in the source and therefore in any PyInstaller binary.
- **StringVar passwords** (Tkinter) are ordinary Python/Tcl strings — they cannot be securely wiped. They are cleared as soon as possible, but residual copies may exist until process exit.
- **Clipboard** is cleared only when the user clicks “Wipe from Memory” *and* the clipboard still contains the generated cipher.
- **Video preview** on Windows/macOS writes a temporary file (no universal RAM-disk). The file is deleted on window/app close, but exists for the duration of playback.
- **Framebuffer / compositor** caches (Windows DWM, macOS window server) are outside application control.

---

## Limitations (Honest)

| Limitation | Reality |
|------------|---------|
| Anti-swap | `mlock`/`VirtualLock` prevent ordinary swap; they do **not** protect against hibernation files or core dumps that were not disabled at OS level. |
| Core dumps | Best-effort only; requires the process to have permission to lower `RLIMIT_CORE`. |
| Large archives | Whole archive lives in RAM during create/open. Multi-GB vaults need sufficient physical memory. |
| Audio seek | Reliable mainly for MP3/OGG; other formats depend on SDL_mixer backend. |
| PDF preview | Capped at 30 pages by default to keep memory reasonable. |
| SVG | Rasterized; complex SVGs may lose fidelity. |

---

## Architecture Overview

```
bastetcipher.py
├── Section 1  Memory management (SecureBuffer, mlock, wipe, core-dump)
├── Section 2  Cipher generator pipeline (byte-identical to JS)
├── Section 3  .bca format (build / parse / double encryption)
├── Section 4  In-memory viewers (image, PDF, text, audio, video)
├── Section 5  Theme & adaptive UI scaling
├── Section 6  GeneratorView (CustomTkinter)
├── Section 7  VaultView (create / open / preview / export)
└── Section 8  BastetCipherApp (main window + navigation)
```

All cryptographic work and large file I/O run on daemon threads; progress is marshalled back to the UI thread via `after()`.

---

## File Layout

```
bastetcipher.py          # entire application (single file)
requirements.txt         # dependencies (not included in the source dump)
README.md                # this file
```

Designed to be packaged with:

```bash
pyinstaller --onefile bastetcipher.py
```

---

*“The temple keeps what is given to it — nothing more, nothing less.”*
```
