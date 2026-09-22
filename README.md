<img width="1433" height="928" alt="img" src="https://github.com/user-attachments/assets/b9f6f24d-24a8-4713-88bc-94aba4b1a4e8" />


# BastetCipher — Desktop Edition

**Sacred Chamber** · High-entropy password generator + encrypted vault

A single-file Python/CustomTkinter desktop port of the original `BastetCipher.html`.  

> **Current implementation notice (added to the original README)**
>
> This README retains the original project documentation below and adds a detailed update for the current desktop implementation. The current source is the authoritative reference for behavior.
>
> The desktop application has evolved beyond the earlier CustomTkinter description: the main application UI is now implemented with **PySide6 / Qt**, while the integrated **Bastet Verification Tool** uses Tkinter/ttk in its own audit window. The cryptographic subsystem now supports **PBKDF2-HMAC-SHA-512 and Argon2id**, the archive format supports **BCA v1 and v2**, the preferred archive extension is now **`.bstarc`** while **`.bca`** remains supported for legacy compatibility, and an opened vault can now be edited in RAM and explicitly saved back to disk.
>
> The current implementation also expands media support, adds hardened preview paths and parser resource limits, implements cross-platform screen-capture protection on a best-effort basis, and embeds a multi-stage security/audit workflow covering dependency auditing, static analysis, entropy/statistical testing, memory-behavior testing, and Atheris fuzzing.

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

- [Current Implementation Update](#current-implementation-update)
- [Key Derivation Update: PBKDF2 and Argon2id](#key-derivation-update-pbkdf2-and-argon2id)
- [Current Vault Format and `.bstarc` / BCA v2](#current-vault-format-and-bstarc--bca-v2)
- [Vault Editing and Safe Rewrite Workflow](#vault-editing-and-safe-rewrite-workflow)
- [Expanded Secure Media Viewer](#expanded-secure-media-viewer)
- [HTML Preview Sanitization](#html-preview-sanitization)
- [Process Hardening and Screen-Capture Protection](#process-hardening-and-screen-capture-protection)
- [Integrated Bastet Verification Tool](#integrated-bastet-verification-tool)
- [Current Dependencies and Optional Components](#current-dependencies-and-optional-components)
- [Current Build / Packaging Notes](#current-build--packaging-notes)
- [Source-of-Truth and Documentation Notes](#source-of-truth-and-documentation-notes)

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
---

# Current Implementation Update

This section is an additive update to the original README. Nothing from the original documentation above is intentionally removed; where an older statement describes a previous implementation, the newer source behavior is documented here as the current source-of-truth.

## 1. Current Desktop UI Architecture

The main desktop application is currently built with **PySide6 / Qt**.

The single source file contains the full application, including:

- secure memory helpers and process hardening;
- the password/cipher generation pipeline;
- the Bastet archive builder/parser;
- image, SVG, PDF, text, HTML, audio, and video previewers;
- responsive/adaptive Qt theming;
- the Generator view;
- the Vault view;
- the main navigation/hub;
- the integrated Bastet Verification Tool.

The main application uses a Qt event loop and performs long cryptographic/file/media operations in worker threads so that the UI remains responsive. Progress messages are emitted back to the Qt UI thread through signals.

The **audit window is intentionally separate from the main Qt visual layer**. The integrated audit tool is implemented with `tkinter`/`ttk` because the audit workflow launches external analysis tools and subprocess-driven test environments. It can still be opened directly from the main application by activating the Bastet emblem/logo on the hub screen.

### Main current components

```text
BastetCipher.py
├── Secure memory / process hardening
├── Cipher generator
│   ├── PBKDF2-HMAC-SHA-512
│   └── Argon2id
├── Bastet Archive format
│   ├── BCA v1
│   └── BCA v2
├── In-memory media viewers
│   ├── Images
│   ├── SVG
│   ├── PDF
│   ├── Text
│   ├── HTML
│   ├── Audio
│   └── Video
├── Qt visual shell / adaptive scaling
├── GeneratorView
├── VaultView
├── BastetCipherApp
└── Integrated Bastet Verification Tool
    ├── isolated virtual environment
    ├── dependency audit
    ├── static analysis
    ├── entropy/statistical tests
    ├── memory-behavior test
    └── Atheris fuzzing
```

The exact source filename may differ between distributions. The existing README packaging examples use `bastetcipher.py`; substitute the actual source filename used by your release when invoking PyInstaller.

---

# Key Derivation Update: PBKDF2 and Argon2id

The current implementation supports two selectable KDFs. The **cipher generator** and the **vault encryption layer** both expose KDF selection where applicable.

## Cipher Generator KDF selection

The visible Generator UI now contains a **Key Derivation** selector:

```text
PBKDF2-HMAC-SHA512 (variable iterations) — classic
Argon2id (m=64MiB, t=3, p=4) — memory-intensive
```

When `argon2-cffi` is installed, Argon2id is available and is selected by default in the current UI. When the package is unavailable, the Argon2id option remains visible but reports that `argon2-cffi` must be installed before it can be used.

### Important compatibility property

Selecting Argon2id does **not** replace the whole BastetCipher generator design. The earlier stages remain the same:

1. Sacred Salt generation.
2. SHA-256 / SHA-384 / SHA-512 base hashes.
3. Transformation seed.
4. Proprietary hash transformation.
5. Sacred hash combination.
6. KDF input construction.
7. Selected KDF.
8. Special-character insertion.
9. Deterministic mixed-case transformation.
10. Optional amplifier generation.
11. Final `., ... ,.` cipher framing.

Only the key-derivation stage is changed by the KDF selection.

## PBKDF2-HMAC-SHA-512 path

The PBKDF2 path continues to use the deterministic Bastet iteration calculation:

```text
pim_num  = JavaScript-compatible parseInt(PIM)
pim_hash = SHA-256(PIM + PEPPER + "IterSeed")

base_iter = 50,000
            + floor((hash_int / 16,777,215) * 550,000)

twist     = (pim_num mod 65,537) * 7

iterations = base_iter + twist
```

The original README describes the base range as approximately 50k–600k. The current implementation also adds the PIM-derived `twist`, so the **final PBKDF2 iteration count can be substantially higher than 600,000** for some PIM values.

The current code deliberately retains the JavaScript compatibility behavior:

```python
int(float(digits))
```

for PIM conversion, matching the precision behavior relevant to very large decimal strings.

## Argon2id path

The current implementation uses:

```text
Algorithm:      Argon2id
Memory:         64 MiB
Time cost:      3
Parallelism:    4
Hash length:    64 bytes
```

The Argon2id-derived 64-byte key is then processed by the same post-KDF Bastet steps used by the generator:

- deterministic special-character insertion;
- deterministic mixed-case transformation;
- optional amplifier extension.

The current code reports Argon2id separately from PBKDF2 because “iteration count” is not the right way to communicate the cost of a memory-hard Argon2id configuration.

### Argon2id availability

Argon2id is provided through:

```text
argon2-cffi
```

If it is missing, the application does not silently install it. The user receives a visible installation requirement instead.

---

# Current Vault Format and `.bstarc` / BCA v2

The current archive implementation expands the original BCA format while keeping the old format readable.

## Archive extensions

The current UI recognizes:

```text
.bstarc   Preferred/current Bastet archive extension
.bca      Legacy Bastet archive extension
```

The file dialogs accept both extensions.

The save dialog prefers:

```text
.bstarc
```

while the parser continues to accept existing `.bca` archives.

## BCA versions

The current source defines:

```python
BCA_VERSION = 1
BCA_VERSION_V2 = 2
```

### BCA v1

The original 69-byte header remains supported:

| Offset | Size | Field |
|--------|------|-------|
| 0 | 4 | Magic `BCA\x01` |
| 4 | 1 | Version `1` |
| 5 | 32 | Random salt |
| 37 | 4 | PBKDF2 iteration count (little-endian uint32) |
| 41 | 12 | AES-GCM nonce / IV1 |
| 53 | 16 | AES-CBC IV2 |
| 69 | N | Ciphertext |

The current writer uses **310,000 PBKDF2 iterations** for newly created PBKDF2 archives.

The parser still accepts older v1 archives containing legacy iteration counts, provided the value passes the current validation range:

```text
Minimum accepted: 100,000
Maximum accepted: 5,000,000
```

The source retains an explicit legacy constant for the historical 200,000-iteration format.

### BCA v2

The current source adds a 70-byte header for KDF-aware archives:

| Offset | Size | Field |
|--------|------|-------|
| 0 | 4 | Magic `BCA\x01` |
| 4 | 1 | Version `2` |
| 5 | 1 | KDF identifier |
| 6 | 32 | Random salt |
| 38 | 4 | KDF parameter / iteration field |
| 42 | 12 | AES-GCM nonce / IV1 |
| 54 | 16 | AES-CBC IV2 |
| 70 | N | Ciphertext |

Current KDF identifiers are:

```text
0 = PBKDF2
1 = Argon2id
```

The current writer emits **v2 for Argon2id archives**. The Argon2id parameters are fixed in the source (`64 MiB`, `t=3`, `p=4`) and therefore the v2 parameter field is written as zero for the Argon2id path.

The parser understands the KDF identifier and selects the correct key-derivation procedure when unlocking the vault.

## Current vault encryption cascade

The current cascade is still:

```text
KDF
  ↓
64-byte derived material
  ├── first 32 bytes → AES-256-GCM key
  └── second 32 bytes → AES-256-CBC key
```

Then:

```text
file bytes
  ↓
raw deflate compression (level 9)
  ↓
BCA plaintext structure
  ↓
AES-256-GCM
  ↓
AES-256-CBC
  ↓
archive ciphertext
```

The GCM layer provides authentication. The CBC layer is the second encryption layer and uses PKCS#7 padding.

## Per-file metadata

Each file entry still stores:

```text
uint16 LE   filename length
bytes       UTF-8 filename
uint32 LE   CRC32(original uncompressed content)
uint32 LE   original size
uint32 LE   compressed size
bytes       raw-deflate compressed content
```

CRC32 is used as a per-file integrity indicator after decompression. It is not a replacement for the authenticated encryption layer.

---

# Vault Editing and Safe Rewrite Workflow

The current desktop implementation no longer treats an opened vault as read-only.

After unlocking an archive, the user can now:

```text
Add files
Remove files
Preview files
Export files
Save / Apply changes
Close the vault
```

## Add files to an opened vault

Additional files are read into memory and added to the in-memory entry list.

Duplicate base filenames are detected and ignored rather than silently replacing an existing entry.

The vault is marked:

```text
Unsaved changes
```

until the user explicitly selects **SAVE / APPLY**.

## Remove files from an opened vault

Removing a file:

1. asks for confirmation;
2. removes the entry from the in-memory list;
3. explicitly wipes that entry's byte buffer;
4. marks the vault dirty;
5. leaves the existing archive on disk unchanged until SAVE / APPLY is selected.

## Save / Apply

Saving an edited vault:

1. copies the current entries into fresh mutable buffers;
2. re-builds the entire archive in memory;
3. uses the KDF associated with the currently opened archive;
4. writes the rebuilt archive to a temporary sibling file;
5. flushes and `fsync()`s the temporary file;
6. replaces the original archive with `os.replace()`;
7. wipes temporary archive/password buffers.

This provides a clear transactional boundary: the disk archive is not modified merely because the user edited the in-memory vault.

## Unsaved-change warning

Closing a vault with unsaved modifications triggers a confirmation dialog.

Choosing to close without saving:

- discards the in-memory modifications;
- wipes the opened entries;
- leaves the existing disk archive unchanged.

---

# Expanded Secure Media Viewer

The viewer subsystem is substantially broader than the original README table.

## Supported image extensions

The current source recognizes:

```text
.png
.jpg
.jpeg
.gif
.bmp
.webp
.tiff
.svg
.ico
.heic
.heif
.avif
.psd
.raw
.cr2
.nef
```

Raster images are loaded through Pillow.

SVG input is detected and rasterized with PyMuPDF before display.

## Image safety limits

The current source defines:

```text
Maximum image dimension: 16,384 px per side
Maximum pixel count:     80,000,000 pixels
```

These checks are performed before expensive decoding is allowed to proceed.

Preview-specific byte limits also apply:

```text
Images: 400 MiB
PDF:    350 MiB
Audio:  500 MiB
Video:  1 GiB
Text:    32 MiB
HTML:   256 MiB
```

Files larger than their type-specific preview limit must be explicitly exported instead of previewed.

## PDF viewer

The current PDF viewer is lazy and interactive.

It supports:

- page navigation;
- page count;
- next/previous navigation;
- text search;
- match navigation;
- visual match highlighting;
- zoom controls;
- in-memory rasterization;
- a small page cache to reduce repeated rendering cost;
- pre-rendering of the next page as a performance optimization.

The source defines a soft PDF page limit of:

```text
5,000 pages
```

and a maximum PDF render DPI of:

```text
150 DPI
```

The interactive preview currently opens PDFs at 120 DPI.

Encrypted PDF streams are explicitly rejected from the in-application preview path.

## Text viewer

Text is decoded with:

```text
UTF-8
```

with a fallback to:

```text
Latin-1
```

The resulting content is shown in a read-only Qt text widget.

## Audio viewer

Recognized audio extensions include:

```text
.mp3
.ogg
.wav
.flac
.aac
.m4a
.wma
.opus
.alac
.m4b
.mid
.midi
.ape
```

The audio viewer provides:

- playback;
- pause / resume;
- stop;
- seek;
- position display;
- duration display;
- volume control.

Audio duration is detected with `mutagen` when possible.

Some formats are transcoded to a playback-friendly format through FFmpeg entirely from memory when the backend requires it. The source explicitly marks these formats for transcoding:

```text
.m4a
.wma
.opus
.aac
.alac
.m4b
.ape
.mid
.midi
```

The audio playback layer uses a session counter because `pygame.mixer.music` is process-wide. This prevents a stale preview window from confusing its playback-position state with another audio preview session.

## Video viewer

Recognized video extensions include:

```text
.mp4
.webm
.mov
.avi
.mkv
.wmv
.3gp
.flv
.ts
.m2ts
.vob
.divx
```

The current video path uses FFmpeg supplied through `imageio-ffmpeg`.

The implementation:

- probes video metadata;
- validates the media signature first;
- reads dimensions, frame rate, duration, and audio presence;
- decodes frames as raw RGB data;
- streams frames to the Qt UI;
- supports play/pause;
- supports stop;
- supports timeline seeking;
- scales decoding to the visible area;
- caps the long side of decoded frames at 1920 px;
- can separately extract audio for playback;
- stops child decoding processes when the viewer closes.

### Video fallback

If the in-memory FFmpeg probe/decoder cannot read the media, the application can fall back to the operating system's media opener.

Because Windows and macOS do not provide a universal RAM-disk equivalent that the application can depend on, the fallback may use a temporary file on disk.

The application:

- warns the user before using this fallback on Windows/macOS;
- writes the file with restrictive permissions where supported;
- tracks the temporary path;
- securely overwrites/deletes the temporary file during cleanup;
- repeats cleanup attempts when necessary.

On Linux, `/dev/shm` is used when it exists and is writable, providing the intended RAM-backed path.

---

# HTML Preview Sanitization

The current application recognizes:

```text
.html
.htm
```

HTML is **not** displayed as an unrestricted web page.

The preview pipeline first decodes and sanitizes the document, then renders the sanitized result in `QTextBrowser`.

The sanitization layer strips or neutralizes dangerous/active constructs including:

```text
script
style
iframe
frame
frameset
object
embed
applet
form
input
button
textarea
select
option
link
meta
base
svg
math
video
audio
source
track
noscript
template
```

Event-handler attributes such as:

```text
onclick
onload
onerror
...
```

are removed.

URL-bearing HTML attributes are also screened for dangerous or externally resolving schemes including:

```text
javascript:
data:
vbscript:
http:
https:
ftp:
file:
```

The HTML viewer disables unrestricted external-link opening and search paths.

Internal document fragments/anchors can still be navigated, allowing an exported HTML document's internal table of contents and same-document links to remain useful without turning the viewer into an unrestricted browser.

This is intentionally a **preview feature**, not a general-purpose secure browser.

---

# Process Hardening and Screen-Capture Protection

The current startup path performs multiple best-effort hardening actions before the Qt event loop begins.

## Core-dump reduction

On POSIX systems the application requests:

```text
RLIMIT_CORE = 0
```

to prevent ordinary core-dump generation.

This is permission-dependent and therefore remains best-effort.

## Windows hardening

The Windows startup path attempts to:

- restrict DLL search behavior using `SetDefaultDllDirectories`;
- configure process mitigation policies through `SetProcessMitigationPolicy`.

## Linux hardening

The Linux path attempts process-level restrictions via `prctl`, including disabling the dumpable state and enabling the no-new-privileges mechanism.

## `mlockall`

At startup, Linux/macOS also attempt:

```text
mlockall(MCL_CURRENT | MCL_FUTURE)
```

in addition to the per-buffer `mlock` / `VirtualLock` mechanism.

This is a best-effort mitigation against ordinary memory swapping. It is not a guarantee against hibernation snapshots, kernel-level compromise, hardware acquisition, or every possible memory disclosure path.

## SecureBuffer

Sensitive mutable data can be held by `SecureBuffer`.

Its lifecycle is designed to:

1. allocate a fixed-size mutable `bytearray`;
2. determine the buffer address;
3. attempt `mlock` on POSIX or `VirtualLock` on Windows;
4. explicitly zero the memory with `ctypes.memset`;
5. unlock it on close;
6. automatically perform cleanup on context-manager exit and object destruction.

## Generic bytearray wiping

`wipe_bytearray()` performs native memory zeroing with `ctypes.memset` and falls back to slice assignment if the native path fails.

The source uses this actively for:

- file contents;
- passwords;
- derived keys;
- decrypted archive buffers;
- temporary media buffers;
- intermediate archive buffers;
- edited vault entries.

## Screen-capture protection

The main Qt window also attempts platform-specific capture protection.

### Windows

The application first tries:

```text
WDA_EXCLUDEFROMCAPTURE
```

and falls back to:

```text
WDA_MONITOR
```

if necessary.

### macOS

The implementation attempts:

```text
NSWindowSharingNone
```

through AppKit / Objective-C APIs.

### Linux

There is no universal equivalent available to the application across all window/compositor combinations. Linux therefore exposes a fallback state rather than falsely claiming that capture protection is active.

The UI displays the current capture-protection state in the navigation area.

## Important scope limitation

Application-level capture protection cannot control every layer of the operating system or compositor. Desktop screenshots, compositor caches, remote desktop systems, camera capture of the physical display, virtualization, and privileged operating-system tooling remain outside the application's complete control.

---

# Current Dependency Behavior

The current dependency architecture is intentionally mixed between required, optional, lazy, and audit-only components.

## Core desktop dependencies

The main desktop application imports:

```text
PySide6
cryptography
Pillow
```

These are core runtime components for the main UI and cryptographic/archive pipeline.

## Optional / lazy runtime dependencies

```text
argon2-cffi
pymupdf
pygame
mutagen
imageio-ffmpeg
```

Their roles are:

| Package | Role |
|---------|------|
| `argon2-cffi` | Enables Argon2id KDF support |
| `pymupdf` | PDF rendering, PDF text extraction, SVG rasterization |
| `pygame` | In-memory audio playback |
| `mutagen` | Audio duration/metadata detection |
| `imageio-ffmpeg` | FFmpeg discovery and media processing for video/audio |

The source performs these imports lazily where possible so that unsupported media types do not unnecessarily initialize the associated subsystem.

## Standard-library capabilities

The implementation also uses standard-library modules for:

```text
ctypes
hashlib
zlib
struct
io
contextlib
re
gc
threading
queue
subprocess
tempfile
json
platform
resource (POSIX only)
```

These power the secure-memory layer, archive packing, media subprocess management, resource limits, and audit workflow.

---

# Integrated Bastet Verification Tool

The application now includes a substantial **Bastet Verification Tool** designed to let users inspect and exercise the source code against several classes of automated checks.

It is intentionally described as a verification aid rather than a replacement for a human cryptographic audit.

## Opening the tool

From the main BastetCipher hub, activate the Bastet emblem/logo.

The audit tool opens in a separate window.

The first launch can show a welcome/limitations splash explaining:

- what the tool verifies;
- what it does not verify;
- why automated testing is not equivalent to a full cryptographic review.

The user may choose not to display that splash again on the same computer.

The skip marker is stored as:

```text
.bastet_audit_skip_welcome
```

next to the application source.

Deleting that marker causes the welcome screen to appear again.

## Source selection

The audit tool accepts a Python source file selected through:

```text
Browse
Drag & Drop (when tkinterdnd2 is available)
```

The source is read for analysis; the tool does not intentionally modify the original source file.

## Isolated audit environment

The tool creates:

```text
bastet_audit_env/
├── venv/
├── bca_core_standalone.py
├── fuzz_target.py
├── entropy_test.py
├── memory_test.py
└── fuzz_corpus/
```

The extracted crypto module and generated test scripts are used to exercise isolated parts of the application.

The core extraction is based on known source markers for the Bastet archive implementation. After extraction, the module is imported in the audit environment as a basic sanity check.

## Environment setup

The **1) Configure environment** action:

1. creates an isolated Python virtual environment;
2. upgrades pip;
3. installs:
   - `cryptography`
   - `argon2-cffi`
   - `pip-audit`
   - `bandit`
4. attempts to install `atheris`;
5. extracts the cryptographic archive core;
6. writes the generated entropy, memory, and fuzzing scripts.

If Atheris cannot be installed, the tool reports that fuzzing is unavailable while allowing the other tests to continue.

The setup uses the virtual environment for the generated audit workloads rather than silently changing the system Python installation.

## Test 2 — Dependency audit

The dependency test runs:

```text
pip-audit
```

against the isolated environment.

Its purpose is to detect known published vulnerabilities associated with installed package versions.

The tool records a concise result while preserving the raw command output in the audit console.

## Test 3 — Static analysis

The source is scanned by:

```text
bandit
```

The source is treated as source text for this check; the audit action itself does not intentionally execute the target source as part of Bandit's static scan.

The result summarizes findings by severity:

```text
High
Medium
Low
```

Static analysis is heuristic and should be read as a list of review candidates, not as a mathematical proof of safety or insecurity.

## Test 4 — Entropy / statistical analysis

The generated entropy script exercises the encrypted archive output with several deliberately different plaintext classes, including:

```text
all-zero bytes
all-identical bytes
highly repetitive text
random / incompressible bytes
empty input
single-byte input
```

It then measures the ciphertext for:

- Shannon entropy in bits per byte;
- chi-square deviation from uniform byte frequencies;
- maximum byte-frequency deviation;
- longest run of an identical repeated byte.

For sufficiently large samples, the current script uses thresholds such as:

```text
entropy > 7.9 bits/byte
chi-square < 340
longest repeated run < 12
```

The test is intended to detect obvious statistical anomalies. Passing it does not prove that an encryption design is cryptographically secure.

## Test 5 — Memory-behavior test

The memory test uses Python's:

```text
tracemalloc
```

It performs a warm-up phase followed by:

```text
300 test cycles
```

The current script alternates between:

```text
PBKDF2
Argon2id (when available)
```

It compares memory snapshots before and after the repeated cycles.

The summary reports:

```text
cycles run
KDFs exercised
memory after warm-up
memory after all cycles
total growth
growth per cycle
top allocation differences
```

The script flags growth above approximately:

```text
2 KiB per cycle
```

for review.

This is explicitly a Python-level test. It cannot replace tools such as AddressSanitizer, MemorySanitizer, or Valgrind for inspecting compiled native code.

## Test 6 — Atheris fuzzing

The fuzzing engine uses:

```text
atheris
```

which provides a Python fuzzing workflow built around libFuzzer concepts.

The tool generates a seed corpus containing several archive shapes, including:

- very small files;
- empty files;
- repetitive content;
- random binary content;
- multiple-file archives;
- Unicode-oriented filenames;
- many-entry archives;
- mixed empty/non-empty archives;
- larger test content.

The fuzz target repeatedly calls the actual `parse_bca()` logic from the extracted archive core.

Expected format/decryption failures are treated as normal fuzzing outcomes. Unexpected exceptions are surfaced as failures.

The UI allows the user to configure:

```text
Duration: default 60 seconds
Maximum input size: default 65,536 bytes
```

Examples exposed by the UI include:

```text
600 seconds  = 10 minutes
28,800 seconds = 8 hours / overnight
```

The maximum input length controls how large malformed test cases may become. Raising it exercises parser paths associated with larger archives and larger payloads.

The fuzzing operation can be interrupted from the GUI.

A live log is written to:

```text
fuzzing_log.txt
```

The final summary records:

```text
number of executions
duration
unexpected-exception status
whether the run completed or was interrupted
```

## Audit reports and logs

The audit interface provides:

```text
Save log...
Generate summary report
Clear
```

The summary report includes:

- the selected source file;
- timestamps;
- completed test summaries;
- a reminder that automated checks do not replace a human cryptographic review.

---

# Audit Tool: What It Does Not Prove

The integrated audit workflow is deliberately conservative about its scope.

A clean result does **not** establish that:

- the cryptographic construction is optimally designed;
- the order of encryption layers is globally optimal;
- the selected KDF cost is ideal against future attacker hardware;
- the application is immune to timing or cache side channels;
- a compiled C/C++ dependency contains no native memory bug;
- the threat model is appropriate for every use case;
- a malicious operating system or privileged attacker cannot recover secrets;
- hibernation, DMA, virtualization, or hardware-level acquisition cannot expose sensitive data.

The included tests are implementation-oriented evidence.

A professional cryptographic review remains a separate activity.

---

# Preview Security Limits and Resource Controls

The current implementation adds several defensive limits around expensive media operations.

## Image limits

```text
16,384 px maximum per side
80,000,000 maximum pixels
```

## PDF limits

```text
5,000-page soft limit
150 DPI maximum render setting
120 DPI used by the interactive preview path
350 MiB preview input limit
```

## Video limits

Video subprocesses are constrained on POSIX platforms using child-process resource limits.

The code calculates an address-space cap from the input size, with:

```text
2 GiB minimum floor
12 GiB maximum ceiling
```

when the platform and existing hard limit allow this.

CPU time limits are also requested for these child processes:

```text
90 s media-operation timeout
120 s soft CPU limit
150 s hard CPU limit
```

and the child core-dump limit is set to zero.

A file-descriptor ceiling of 256 is also requested where supported.

These controls are intended to reduce exposure to pathological/malicious media inputs. They are not a general sandbox equivalent to a separate operating-system sandbox or virtual machine.

---

# Main Application UI and Adaptive Scaling

The current Qt interface is built around a dark Egyptian-temple visual system.

The current palette includes:

| Token | Current value |
|-------|---------------|
| Background | `#060504` |
| Card | `#14100b` |
| Elevated card | `#1e1810` |
| Hover card | `#2a2216` |
| Lapis | `#081424` |
| Bright lapis | `#0f2a4a` |
| Antique gold | `#c9a84c` |
| Sun gold | `#f4c847` |
| Pale gold | `#ffe9a8` |
| Amber | `#ff9f1c` |
| Hot amber | `#ffb347` |
| Bronze | `#7a5c1e` |
| Emerald | `#1fd8a4` |
| Body text | `#ecdcae` |
| Gold text | `#f4c847` |
| Muted text | `#9c8656` |
| Obsidian | `#0a0806` |
| Deep lapis | `#061018` |

The hub includes the animated sacred backdrop and navigates into the Generator and Vault views through a fade stack.

## Current scaling rules

The UI uses:

```text
Reference resolution: 1920 × 1080
Minimum scale:       0.65
Maximum scale:       1.35
```

The main window targets approximately:

```text
75% of available screen width
82% of available screen height
```

subject to the current maximum and minimum bounds implemented in the source.

Fonts include combinations of:

```text
Segoe UI
Georgia
Consolas
```

depending on whether the element is normal UI text, thematic headings, or monospaced technical/cipher output.

---

# Generator UX Improvements

The current generator UI includes more than the original basic three-field flow.

It now provides:

```text
Secret phrase
PIM
Amplifier
Key Derivation
```

Additional usability features include:

- secret-phrase visibility toggle;
- validation of PIM to 1–32 digits;
- amplifier clamping to 0–9999;
- minimum secret phrase length check of 8 characters;
- background-thread generation;
- progress reporting;
- generated-output statistics;
- direct copy to clipboard;
- explicit output wipe;
- direct handoff of the generated cipher to the Vault;
- automatic population of vault password fields from the generated cipher when requested.

Generated output statistics currently display:

```text
cipher length
KDF / iteration information
amplifier state
a short salt preview
```

The full generated cipher can be explicitly wiped, and the clipboard is cleared when it still contains the exact generated cipher.

---

# Current Password Handling Notes

The vault password is converted to a mutable `bytearray` before cryptographic use.

The source explicitly wipes password buffers after the related operation.

However, GUI entry widgets necessarily interact with ordinary Qt text storage. Therefore:

> **No desktop GUI application can honestly claim that every transient copy of a password string is guaranteed to vanish immediately from every layer of the Qt/process memory model.**

The current implementation minimizes exposure by clearing the input widget promptly and moving cryptographic processing to mutable buffers, but residual copies may exist in framework/application memory until process cleanup.

This is the current implementation-specific counterpart to the older README note about Tkinter `StringVar`.

---

# Current Clipboard Behavior

The generated cipher can be copied through the GUI.

When the user explicitly clears/wipes the generated result, the application checks whether the system clipboard still contains that exact cipher value.

Only when the clipboard contents match the last generated cipher does the application clear it.

This avoids blindly destroying unrelated clipboard content.

---

# Current Video Temporary-File Policy

Video preview is the area where “RAM-only” operation has the strongest platform-specific caveat.

The primary decoder path uses a temporary source path because the FFmpeg executable is an external process and needs a file-like input.

The application tries to place that temporary path in:

```text
/dev/shm
```

on Linux when available and writable.

For Windows/macOS, no universal in-memory mount can be assumed, so the operating-system fallback may use normal disk-backed temporary storage.

The application explicitly warns the user before that fallback path is used.

Temporary media files are:

- tracked;
- securely overwritten/deleted where possible;
- cleaned on preview closure;
- cleaned again during vault/app shutdown.

This does not change the fact that platform-level filesystem, storage-device, filesystem-journal, SSD wear-leveling, or forensic recovery behavior is outside the application's complete control.

---

# Archive Lifecycle: RAM vs Disk

The current implementation follows this general model:

```text
CREATE
User files → RAM bytearrays → compression → encryption → RAM archive → single disk write

OPEN
Disk archive → RAM bytearray → decryption → decompression → RAM entry buffers

PREVIEW
RAM entry buffers → decoder/viewer → UI

EXPORT
RAM entry buffer → explicit user-selected disk path

CLOSE
RAM entry buffers → explicit wipe
```

For edited vaults:

```text
OPENED RAM ENTRIES
    ↓
add/remove changes
    ↓
dirty in-memory state
    ↓
SAVE / APPLY
    ↓
rebuild archive in RAM
    ↓
temporary disk file
    ↓
fsync
    ↓
atomic replacement
```

This separation is important: opening and previewing do not implicitly export decrypted files.

---

# Current Error-Handling and Validation Behavior

The parser rejects malformed archives for a range of conditions, including:

- invalid magic bytes;
- unsupported archive version;
- unsupported KDF identifier;
- invalid PBKDF2 iteration parameters;
- truncated headers;
- truncated file metadata;
- invalid UTF-8 filenames;
- inconsistent compressed sizes;
- invalid deflate streams;
- unexpected trailing plaintext data;
- invalid CBC padding;
- GCM authentication/decryption failure.

The user-facing vault error path intentionally collapses many cryptographic corruption/authentication failures into a generic message such as:

```text
Wrong password or corrupted/tampered archive.
```

This reduces unnecessary disclosure about the exact stage at which authentication/decryption failed.

---

# Current Archive Password Policy

The current vault creation UI requires a minimum password length of:

```text
12 characters
```

The source also advises users that longer, unique passphrases provide substantially better resistance to offline guessing attempts.

This is a user-interface policy in addition to the cryptographic KDF itself.

---

# Current File-Type Classification

The viewer uses extension-based classification for:

```text
IMAGE
PDF
TEXT
HTML
AUDIO
VIDEO
UNSUPPORTED
```

Unsupported files remain valid vault entries. They simply do not receive an in-app preview button and must be explicitly exported for external inspection.

The classifier is intentionally conservative: a file extension alone does not grant unrestricted parser access. For the main binary media types, the implementation also performs a lightweight format-signature check before passing data to the associated parser/decoder.

---

# Current Threading Model

The application uses Qt `QThread`-based workers for long operations in the main desktop UI.

Examples include:

```text
cipher generation
file loading
archive creation
archive opening/decryption
PDF document initialization
HTML sanitization
audio/video-related work
archive saving
```

Video decoding uses a dedicated decoding thread.

The audit tool uses standard Python background threads and subprocesses for longer-running verification commands.

UI updates are marshalled back to the GUI thread rather than directly manipulating Qt widgets from worker threads.

---

# Current Source-Embedded Audit Architecture

The current source contains the audit documentation and test-generator templates directly inside the application file.

This means the release does not depend on shipping a separate `bastet_audit_gui.py` source file merely to expose the audit feature.

Instead, the audit tool can generate:

```text
bca_core_standalone.py
fuzz_target.py
entropy_test.py
memory_test.py
```

inside its isolated environment.

Those generated files are test artifacts, not replacements for the canonical application source.

---

# Current Security Model: Practical Interpretation

The current implementation is best understood as applying multiple layers of mitigation rather than relying on a single feature:

```text
Authenticated encryption
        +
KDF selection
        +
mutable secret buffers
        +
explicit zeroing
        +
memory locking attempts
        +
core-dump reduction
        +
media signature checks
        +
preview size limits
        +
child-process resource limits
        +
restricted HTML preview
        +
screen-capture mitigation
        +
transactional vault rewrite
        +
independent verification/audit tooling
```

Each layer addresses a different class of failure.

None of these layers should be interpreted as a universal guarantee against a privileged attacker or compromised host operating system.

---

# Current Build / Packaging Notes

The original PyInstaller commands remain in the README for compatibility with the historical project documentation:

```bash
pip install -r requirements.txt
pyinstaller --onefile bastetcipher.py
```

For the current implementation, the packaging environment must include the **PySide6** stack used by the main GUI.

For deployments that expose Argon2id, the final environment must also include:

```text
argon2-cffi
```

For full media functionality, the relevant lazy dependencies should also be present:

```text
pymupdf
pygame
mutagen
imageio-ffmpeg
```

The source contains explicit logic for finding an FFmpeg binary inside a PyInstaller `_MEIPASS` bundle when such binaries have been packaged into the executable environment.

The audit tool has its own isolated environment and therefore should not be confused with the main application's runtime dependency set.

---

# Current Deployment Checklist

Before publishing a release, verify:

```text
[ ] Main application launches with the intended Python version
[ ] PySide6 is included
[ ] cryptography is included
[ ] Pillow is included
[ ] Argon2id works when argon2-cffi is present
[ ] PBKDF2 vault creation still works
[ ] legacy .bca archives open correctly
[ ] .bstarc archives create and open correctly
[ ] BCA v2 / Argon2id archives round-trip correctly
[ ] vault editing / SAVE / APPLY round-trips correctly
[ ] PDF preview works
[ ] HTML preview sanitization works
[ ] audio playback works
[ ] video playback works where FFmpeg support is available
[ ] video fallback warning appears on Windows/macOS when required
[ ] screen-capture status is reported correctly
[ ] audit tool can create its environment
[ ] dependency audit runs
[ ] static analysis runs
[ ] entropy test runs
[ ] memory test runs
[ ] Atheris fuzzing runs when installable
[ ] generated audit reports can be saved
[ ] application shutdown wipes vault memory buffers
```

---

# Current Documentation Notes

The original README remains preserved above by design.

Some original statements refer to the earlier CustomTkinter-era implementation or older fixed cryptographic/archive parameters. Those statements are retained so historical documentation is not silently discarded.

For current behavior, use the additive sections in this update together with the current source code as the authoritative reference.

In particular, the following current facts should be treated as the present implementation baseline:

```text
Main UI:              PySide6 / Qt
Audit UI:             Tkinter / ttk
Generator KDFs:       PBKDF2-HMAC-SHA-512 + Argon2id
Argon2id parameters:  64 MiB / t=3 / p=4 / 64-byte output
Preferred archive:    .bstarc
Legacy archive:       .bca
Archive versions:     BCA v1 + BCA v2
New PBKDF2 vaults:     310,000 iterations
Vault password min:   12 characters
PDF soft page limit:  5,000
PDF max render DPI:   150
Image max dimension:   16,384 px
Image max pixels:      80,000,000
Integrated audit:      dependency + static + entropy + memory + fuzzing
```

The documentation should be updated again whenever the source-level values or algorithms change.

---

# Release-Focused Feature Summary

For end users, the current BastetCipher desktop edition can be summarized as follows:

**Generate**

Create a deterministic, high-entropy Bastet cipher from a secret phrase, PIM, optional amplification, and a selectable KDF.

**Protect**

Create encrypted Bastet vaults using a two-layer AES encryption cascade with authenticated AES-GCM, plus the existing CBC second layer.

**Choose KDF strength characteristics**

Use the classic PBKDF2-HMAC-SHA-512 path or the memory-hard Argon2id path when `argon2-cffi` is available.

**Open securely**

Decrypt the vault into memory and keep decrypted entries out of ordinary disk preview workflows.

**Inspect**

Preview a broad range of images, SVGs, PDFs, text, HTML, audio, and video with resource and parser restrictions.

**Edit**

Add and remove files from an opened vault entirely in memory, then explicitly SAVE / APPLY the rebuilt archive.

**Export deliberately**

Write an individual decrypted file to disk only when the user explicitly requests an export.

**Harden**

Use secure buffer wiping, memory-lock attempts, core-dump reduction, child resource limits, and best-effort screen-capture protection.

**Verify**

Run an integrated verification environment covering known dependency vulnerabilities, static-analysis findings, ciphertext statistical behavior, repeated-operation memory growth, and parser fuzzing.

**Stay honest**

The verification tool is designed to produce inspectable evidence. It is not a substitute for a dedicated cryptographic review, side-channel assessment, or hostile-host threat analysis.

---

# Source-of-Truth and Documentation Notes

This README intentionally follows an additive update strategy: the original documentation remains present, and the current implementation is documented in the sections above.

The source file remains the final authority for exact constants, edge-case behavior, platform availability, and implementation details.

When a README statement conflicts with the current source, the current source should be treated as the authoritative implementation for the latest release, and this README should be amended rather than relying on readers to infer the difference.
