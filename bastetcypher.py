from __future__ import annotations
import base64
import ctypes
import ctypes.util
import platform
import sys
import time
import subprocess
import hashlib
import os
import struct
import zlib
import io
import threading
import queue
import contextlib
import re
import tkinter as tk
from tkinter import messagebox, filedialog
from dataclasses import dataclass
from enum import Enum, auto
from typing import Callable, List, Optional
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from PIL import Image, ImageTk, ImageDraw
import PIL._tkinter_finder
import customtkinter as ctk

_SYSTEM = platform.system()

class MlockError(RuntimeError):
    pass

class _MemoryLocker:
    def __init__(self) -> None:
        self.available = False
        self.last_error: Optional[str] = None
        self._libc = None
        self._kernel32 = None
        try:
            if _SYSTEM in ("Linux", "Darwin"):
                libc_name = ctypes.util.find_library("c")
                if libc_name is None:
                    libc_name = "libc.so.6" if _SYSTEM == "Linux" else "libc.dylib"
                self._libc = ctypes.CDLL(libc_name, use_errno=True)
                self.available = True
            elif _SYSTEM == "Windows":
                self._kernel32 = ctypes.windll.kernel32
                self.available = True
        except Exception as exc:
            self.available = False
            self.last_error = f"Could not initialize the memory locker: {exc}"

    def lock(self, address: int, size: int) -> bool:
        if not self.available:
            return False
        try:
            if _SYSTEM in ("Linux", "Darwin"):
                ret = self._libc.mlock(ctypes.c_void_p(address), ctypes.c_size_t(size))
                if ret != 0:
                    errno = ctypes.get_errno()
                    self.last_error = f"mlock failed (errno={errno})"
                    return False
                return True
            elif _SYSTEM == "Windows":
                ret = self._kernel32.VirtualLock(ctypes.c_void_p(address), ctypes.c_size_t(size))
                if not ret:
                    self.last_error = f"VirtualLock failed (GetLastError={ctypes.GetLastError()})"
                    return False
                return True
        except Exception as exc:
            self.last_error = f"Eccezione durante il lock: {exc}"
            return False
        return False

    def unlock(self, address: int, size: int) -> None:
        if not self.available:
            return
        try:
            if _SYSTEM in ("Linux", "Darwin"):
                self._libc.munlock(ctypes.c_void_p(address), ctypes.c_size_t(size))
            elif _SYSTEM == "Windows":
                self._kernel32.VirtualUnlock(ctypes.c_void_p(address), ctypes.c_size_t(size))
        except Exception:
            pass

_LOCKER = _MemoryLocker()

def memory_lock_available() -> bool:
    return _LOCKER.available

def last_lock_error() -> Optional[str]:
    return _LOCKER.last_error

class SecureBuffer:
    __slots__ = ("data", "_size", "_addr", "locked", "_closed")
    def __init__(self, size: int) -> None:
        if size <= 0:
            raise ValueError("size deve essere positivo")
        self._size = size
        self.data = bytearray(size)
        self._addr = ctypes.addressof((ctypes.c_char * size).from_buffer(self.data))
        self.locked = _LOCKER.lock(self._addr, size)
        self._closed = False

    def wipe(self) -> None:
        if not self._closed and self._size > 0:
            ctypes.memset(self._addr, 0, self._size)

    def close(self) -> None:
        if self._closed:
            return
        self.wipe()
        if self.locked:
            _LOCKER.unlock(self._addr, self._size)
        self._closed = True

    def __enter__(self) -> "SecureBuffer":
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self.close()

    def __del__(self) -> None:
        try:
            self.close()
        except Exception:
            pass

    def __len__(self) -> int:
        return self._size

def wipe_bytearray(buf: bytearray) -> None:
    if not buf:
        return
    try:
        ctypes.memset((ctypes.c_char * len(buf)).from_buffer(buf), 0, len(buf))
    except Exception:
        buf[:] = bytes(len(buf))

def disable_core_dumps() -> None:
    if _SYSTEM in ("Linux", "Darwin"):
        try:
            import resource
            resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        except Exception:
            pass

def _harden_windows_process() -> None:
    if _SYSTEM != "Windows":
        return
    try:
        kernel32 = ctypes.windll.kernel32
        set_default_dll_directories = kernel32.SetDefaultDllDirectories
        set_default_dll_directories.argtypes = [ctypes.c_uint32]
        set_default_dll_directories.restype = ctypes.c_bool
        set_default_dll_directories(0x00001000)
        set_mitigation_policy = kernel32.SetProcessMitigationPolicy
        set_mitigation_policy.argtypes = [ctypes.c_int, ctypes.c_void_p, ctypes.c_size_t]
        set_mitigation_policy.restype = ctypes.c_bool
        def set_policy(policy: int, flags: int) -> None:
            data = ctypes.c_uint32(flags)
            set_mitigation_policy(
                policy, ctypes.byref(data), ctypes.sizeof(data)
            )
        set_policy(0, 0x00000001)
        set_policy(1, 0x00000005)
        set_policy(6, 0x00000001)
        set_policy(10, 0x00000003)
    except Exception:
        pass

def _harden_linux_process() -> None:
    if _SYSTEM != "Linux":
        return
    try:
        libc = ctypes.CDLL(ctypes.util.find_library("c") or "libc.so.6", use_errno=True)
        prctl = libc.prctl
        prctl.argtypes = [ctypes.c_int, ctypes.c_ulong, ctypes.c_ulong,
                           ctypes.c_ulong, ctypes.c_ulong]
        prctl.restype = ctypes.c_int
        prctl(4, 0, 0, 0, 0)
        prctl(38, 1, 0, 0, 0)
    except Exception:
        pass

def harden_process() -> None:
    disable_core_dumps()
    _harden_windows_process()
    _harden_linux_process()

_APP_ICON_DATA = "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAABgAAAAYBAMAAAASWSDLAAAAFVBMVEVHcEz8wy391zT90zP+1TP91DP+1DSEP1O5AAAAB3RSTlMA/v7WsHQ6xsYBGAAAAIBJREFUGNN1zkEOgkAMBdAmwqxpNe7/B/Yj4wGMEtfICVxw/zNAkBkxSFd9aftTkanc49hJrJ48xd7xOeC9IC9FLn5BVou8ijV8uhFBimuqu6boA3GOS6GFtWEOd6DCjNrNAGhqH7C8wkITf3DQ76MTbv+R/4Dq15MdZNBiB8QWIyQQEAnysTsdAAAAAElFTkSuQmCC"

def apply_app_icon(root):
    try:
        encoded = _APP_ICON_DATA.split(",", 1)[1]
        raw_png = base64.b64decode(encoded, validate=True)
        photo = tk.PhotoImage(data=base64.b64encode(raw_png).decode("ascii"))
    except Exception:
        photo = tk.PhotoImage(width=1, height=1)
        raw_png = None
    root.iconphoto(True, photo)
    root._app_icon_photo = photo
    if sys.platform.startswith("win"):
        try:
            ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID("BastetCipher.SacredChamber")
        except Exception:
            pass
        if raw_png is not None:
            try:
                import tempfile
                img = Image.open(io.BytesIO(raw_png))
                fd, temp_ico = tempfile.mkstemp(suffix=".ico")
                os.close(fd)
                img.save(temp_ico, format="ICO", sizes=[(64, 64)])
                root.iconbitmap(temp_ico)
                root.after(1000, lambda: os.remove(temp_ico) if os.path.exists(temp_ico) else None)
            except Exception:
                pass
    return photo

def _secure_shred_file(path: str) -> None:
    if not path or not os.path.exists(path):
        return
    try:
        size = os.path.getsize(path)
        if size > 0:
            with open(path, "r+b") as f:
                f.write(b'\x00' * size)
                f.flush()
                os.fsync(f.fileno())
    except Exception:
        pass
    finally:
        try:
            os.remove(path)
        except OSError:
            pass

def apply_screen_capture_protection(root) -> bool:
    system = platform.system()
    if system == "Windows":
        try:
            user32 = ctypes.windll.user32
            hwnd = ctypes.c_void_p(int(root.winfo_id()))
            set_affinity = user32.SetWindowDisplayAffinity
            set_affinity.argtypes = [ctypes.c_void_p, ctypes.c_uint]
            set_affinity.restype = ctypes.c_bool
            if set_affinity(hwnd, 0x11):
                root._capture_protection = "WDA_EXCLUDEFROMCAPTURE"
                return True
            if set_affinity(hwnd, 0x01):
                root._capture_protection = "WDA_MONITOR"
                return True
        except Exception:
            pass
        root._capture_protection = "unavailable"
        return False
    if system == "Darwin":
        target = int(root.winfo_id())
        try:
            from AppKit import NSApp, NSWindowSharingNone
            for window in NSApp().windows():
                try:
                    window_number = int(window.windowNumber())
                except Exception:
                    window_number = -1
                try:
                    content_view_id = int(window.contentView())
                except Exception:
                    content_view_id = -1
                if target in (window_number, content_view_id):
                    window.setSharingType_(NSWindowSharingNone)
                    root._capture_protection = "NSWindowSharingNone"
                    return True
        except Exception:
            pass
        try:
            objc = ctypes.CDLL(ctypes.util.find_library("objc") or "/usr/lib/libobjc.A.dylib")
            objc.objc_getClass.argtypes = [ctypes.c_char_p]
            objc.objc_getClass.restype = ctypes.c_void_p
            objc.sel_registerName.argtypes = [ctypes.c_char_p]
            objc.sel_registerName.restype = ctypes.c_void_p
            msg_send_addr = ctypes.cast(objc.objc_msgSend, ctypes.c_void_p).value
            send_obj = ctypes.CFUNCTYPE(ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p)(msg_send_addr)
            send_ulong = ctypes.CFUNCTYPE(ctypes.c_ulong, ctypes.c_void_p, ctypes.c_void_p)(msg_send_addr)
            send_index = ctypes.CFUNCTYPE(ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_ulong)(msg_send_addr)
            send_ptr = ctypes.CFUNCTYPE(ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p)(msg_send_addr)
            send_set = ctypes.CFUNCTYPE(None, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_ulong)(msg_send_addr)
            ns_app = send_obj(objc.objc_getClass(b"NSApplication"), objc.sel_registerName(b"sharedApplication"))
            windows = send_obj(ns_app, objc.sel_registerName(b"windows"))
            count = send_ulong(windows, objc.sel_registerName(b"count"))
            window_number_sel = objc.sel_registerName(b"windowNumber")
            content_view_sel = objc.sel_registerName(b"contentView")
            set_sharing_sel = objc.sel_registerName(b"setSharingType:")
            for index in range(count):
                window = send_index(windows, objc.sel_registerName(b"objectAtIndex:"), index)
                if not window:
                    continue
                window_number = send_ulong(window, window_number_sel)
                content_view = send_ptr(window, content_view_sel)
                if target in (int(window_number), int(content_view or 0)):
                    send_set(window, set_sharing_sel, 0)
                    root._capture_protection = "NSWindowSharingNone"
                    return True
        except Exception:
            pass
        root._capture_protection = "unavailable"
        return False
    if system == "Linux":
        session = os.environ.get("XDG_SESSION_TYPE", "").strip().lower()
        if not session and os.environ.get("WAYLAND_DISPLAY"):
            session = "wayland"
        root._capture_protection = f"linux-{session or 'unknown'}-fallback"
        return False
    root._capture_protection = "unsupported"
    return False

MASK32 = 0xFFFFFFFF
PEPPER = "Bastet_Secret_Temple_Key_\U00013060"
RUNE_POOL = "𓃠𓂀𓊹𓆣𓇯𓋹𓅓𓁟𓆙𓊪𓏏𓎛"
SPECIAL_CHARS = "!@#$%^&*_-+=~?"
AMP_ALPHABET = (
    "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!@#$%^&*_-+=~?"
)
HEX_CHARS = "0123456789abcdef"
ProgressCallback = Callable[[int, str], None]

def _noop_progress(pct: int, msg: str) -> None:
    return None

def sha256_hex(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()

def sha384_hex(s: str) -> str:
    return hashlib.sha384(s.encode("utf-8")).hexdigest()

def sha512_hex(s: str) -> str:
    return hashlib.sha512(s.encode("utf-8")).hexdigest()

def pbkdf2_hex(password: str, salt_str: str, iterations: int, key_length: int) -> str:
    derived = hashlib.pbkdf2_hmac(
        "sha512",
        password.encode("utf-8"),
        salt_str.encode("utf-8"),
        iterations,
        dklen=key_length,
    )
    return derived.hex()

def _lcg_next(state: int) -> int:
    return (state * 1664525 + 1013904223) & MASK32

def _js_parse_int_decimal(digits: str) -> int:
    return int(float(digits))

def transform_hash(hash_hex: str, seed_hex: str) -> str:
    length = len(hash_hex)
    seed_num = int(seed_hex[0:8], 16) & MASK32
    rot_amt = seed_num % length
    s = hash_hex[rot_amt:] + hash_hex[:rot_amt]
    swap_step = (seed_num % 7) + 2
    arr = list(s)
    i = 0
    while i + swap_step < length:
        j = i + swap_step
        if j < length:
            arr[i], arr[j] = arr[j], arr[i]
        i += swap_step * 2
    s = "".join(arr)
    hex_map = list(range(16))
    rng = seed_num
    for i in range(15, 0, -1):
        rng = _lcg_next(rng)
        j = rng % (i + 1)
        hex_map[i], hex_map[j] = hex_map[j], hex_map[i]
    def remap(c: str) -> str:
        idx = HEX_CHARS.find(c.lower())
        if idx == -1:
            return c
        return HEX_CHARS[hex_map[idx]]
    s = "".join(remap(c) for c in s)
    sec_len = (seed_num % 12) + 4
    chunks = [s[i : i + sec_len] for i in range(0, length, sec_len)]
    chunks = [c[::-1] if idx % 2 == 1 else c for idx, c in enumerate(chunks)]
    return "".join(chunks)

class _PRNG:
    def __init__(self, seed_hex: str) -> None:
        self.state = int(seed_hex[0:8], 16) & MASK32

    def next(self) -> float:
        self.state = _lcg_next(self.state)
        return self.state / 0xFFFFFFFF

def insert_special_chars(s: str, seed_hex: str) -> str:
    rng = _PRNG(seed_hex)
    insert_count = 8 + int(rng.next() * 8)
    arr = list(s)
    for _ in range(insert_count):
        pos = int(rng.next() * (len(arr) + 1))
        char = SPECIAL_CHARS[int(rng.next() * len(SPECIAL_CHARS))]
        arr.insert(pos, char)
    return "".join(arr)

def apply_mixed_case(s: str, seed_hex: str) -> str:
    rng = _PRNG(seed_hex[::-1])
    alpha_indices = [i for i, c in enumerate(s) if c.isalpha()]
    half = -(-len(alpha_indices) // 2)
    shuffled = list(alpha_indices)
    for i in range(len(shuffled) - 1, 0, -1):
        j = int(rng.next() * (i + 1))
        shuffled[i], shuffled[j] = shuffled[j], shuffled[i]
    upper_set = set(shuffled[:half])
    out = []
    for i, c in enumerate(s):
        if not c.isalpha():
            out.append(c)
        else:
            out.append(c.upper() if i in upper_set else c.lower())
    return "".join(out)

def generate_amplification(input_str: str, pim: str, derived_key: str, amplifier: int) -> str:
    if amplifier == 0:
        return ""
    amp_seed_hex = sha512_hex(
        input_str
        + "\u00A7"
        + pim
        + "\u00A7"
        + str(amplifier)
        + "\u00A7"
        + derived_key
        + "\u00A7"
        + PEPPER
        + ".,\u00A7Sacrum\U000104CF"
        + "Amplificatorsky\U00013060\U0001F4AB,."
    )
    state = (int(amp_seed_hex[0:8], 16) ^ int(amp_seed_hex[8:16], 16)) & MASK32
    result = []
    for _ in range(amplifier):
        state = _lcg_next(state)
        result.append(AMP_ALPHABET[state % len(AMP_ALPHABET)])
    return "".join(result)

@dataclass
class CipherResult:
    final_cipher: str
    iterations: int
    salt_hex: str
    amplifier: int

def run_cipher_pipeline(
    input_str: str,
    pim: str,
    amplifier: int,
    on_progress: Optional[ProgressCallback] = None,
) -> CipherResult:
    progress = on_progress or _noop_progress
    progress(10, "Invoking the Sacred Salt...")
    salt = sha256_hex("BastetCipher" + input_str + pim + PEPPER + "SacredSalt")
    progress(20, "Forging base hashes...")
    h1 = sha256_hex(input_str + salt + pim + PEPPER)
    h2 = sha384_hex(salt + input_str + pim + PEPPER)
    h3 = sha512_hex(input_str + ":" + salt + ":" + pim + ":" + PEPPER)
    progress(30, "Deriving transformation seed...")
    seed = sha256_hex(input_str + pim + PEPPER)
    progress(40, "Applying proprietary transformation...")
    t1 = transform_hash(h1, seed)
    t2 = transform_hash(h2, seed)
    t3 = transform_hash(h3, seed)
    progress(50, "Combining sacred hashes...")
    combined = ".," + t1 + t2 + t3 + ",."
    pim_num = _js_parse_int_decimal(pim)
    pim_hash = sha256_hex(pim + PEPPER + "IterSeed")
    hash_int = int(pim_hash[0:6], 16)
    base_iter = 50000 + int((hash_int / 16777215) * 550000)
    twist = (pim_num % 65537) * 7
    iters = base_iter + twist
    progress(60, f"PBKDF2 · {iters:,} iterations...")
    pbkdf2_salt = sha256_hex("BastetCipher" + input_str + pim + PEPPER)
    derived_key = pbkdf2_hex(combined + PEPPER, pbkdf2_salt, iters, 64)
    progress(85, "Key derived. Inserting sacred glyphs...")
    with_special = insert_special_chars(derived_key, seed)
    with_case = apply_mixed_case(with_special, seed)
    progress(
        97,
        f"Amplifying by {amplifier} sacred characters..."
        if amplifier > 0
        else "Sealing with Bastet's blessing...",
    )
    amp_extension = generate_amplification(input_str, pim, derived_key, amplifier)
    progress(100, "Cipher completed.")
    final_cipher = ".," + with_case + amp_extension + ",."
    return CipherResult(
        final_cipher=final_cipher,
        iterations=iters,
        salt_hex=salt,
        amplifier=amplifier,
    )

BCA_MAGIC = bytes([0x42, 0x43, 0x41, 0x01])
BCA_VERSION = 1
BCA_ITERS = 200_000
HEADER_LEN = 69

class BCAFormatError(ValueError):
    pass

class BCADecryptError(ValueError):
    pass

def crc32(data: "bytes | bytearray") -> int:
    return zlib.crc32(data) & 0xFFFFFFFF

def deflate_raw_compress(data: "bytes | bytearray") -> bytes:
    co = zlib.compressobj(level=9, wbits=-15)
    out = co.compress(data) + co.flush()
    return out

def deflate_raw_decompress(data: bytes) -> bytes:
    do = zlib.decompressobj(wbits=-15)
    out = do.decompress(data)
    out += do.flush()
    if not do.eof or do.unused_data or do.unconsumed_tail:
        raise BCAFormatError("Compressed entry has an invalid or trailing deflate stream.")
    return out

def derive_vault_keys(password: bytearray, salt: bytes, iterations: int) -> tuple[bytearray, bytearray]:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA512(),
        length=64,
        salt=salt,
        iterations=iterations,
        backend=default_backend(),
    )
    derived = kdf.derive(bytes(password))
    k1 = bytearray(derived[0:32])
    k2 = bytearray(derived[32:64])
    del derived
    return k1, k2

@dataclass
class VaultFileEntry:
    name: str
    data: bytearray

@dataclass
class VaultDecryptedEntry:
    name: str
    data: bytearray
    crc_ok: bool

def build_bca(
    file_entries: List[VaultFileEntry],
    password: bytearray,
    on_progress: Optional[ProgressCallback] = None,
) -> bytearray:
    progress = on_progress or _noop_progress
    salt = os.urandom(32)
    iv1 = os.urandom(12)
    iv2 = os.urandom(16)
    progress(5, "Deriving 512-bit keys...")
    k1, k2 = derive_vault_keys(password, salt, BCA_ITERS)
    progress(22, "Keys ready · Isolated cascade")
    try:
        parts: List[bytes] = [struct.pack("<H", len(file_entries) & 0xFFFF)]
        for i, entry in enumerate(file_entries):
            progress(
                22 + int(48 * i / max(1, len(file_entries))),
                f"Secure processing: {entry.name}",
            )
            try:
                name_bytes = entry.name.encode("utf-8")
                compressed = deflate_raw_compress(entry.data)
                crc = crc32(entry.data)
                parts.append(struct.pack("<H", len(name_bytes)))
                parts.append(name_bytes)
                parts.append(struct.pack("<I", crc))
                parts.append(struct.pack("<I", len(entry.data)))
                parts.append(struct.pack("<I", len(compressed)))
                parts.append(compressed)
            finally:
                wipe_bytearray(entry.data)
        plaintext = bytearray(b"".join(parts))
        del parts
        progress(74, "Layer 1 encryption (GCM)...")
        aesgcm = AESGCM(bytes(k1))
        ct1 = aesgcm.encrypt(iv1, plaintext, None)
        wipe_bytearray(plaintext)
        progress(85, "Layer 2 encryption (CBC)...")
        ct2 = _aes_cbc_encrypt(bytes(k2), iv2, ct1)
        progress(92, "Finalizing and wiping RAM residuals...")
        header = (
            BCA_MAGIC
            + bytes([BCA_VERSION])
            + salt
            + struct.pack("<I", BCA_ITERS)
            + iv1
            + iv2
        )
        return bytearray(header + ct2)
    finally:
        wipe_bytearray(k1)
        wipe_bytearray(k2)
        for entry in file_entries:
            wipe_bytearray(entry.data)

def _aes_cbc_encrypt(key: bytes, iv: bytes, data: bytes) -> bytes:
    pad_len = 16 - (len(data) % 16)
    padded = bytearray(data)
    padded.extend(bytes([pad_len]) * pad_len)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    result = encryptor.update(padded) + encryptor.finalize()
    wipe_bytearray(padded)
    return result

def _aes_cbc_decrypt(key: bytes, iv: bytes, data: bytes) -> bytes:
    if len(data) % 16 != 0:
        raise BCADecryptError("Lunghezza ciphertext non valida (Livello 2).")
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded = decryptor.update(data) + decryptor.finalize()
    if not padded:
        raise BCADecryptError("Payload vuoto (Livello 2).")
    pad_len = padded[-1]
    if pad_len < 1 or pad_len > 16 or len(padded) < pad_len:
        raise BCADecryptError("Invalid padding (wrong password or corrupted file).")
    return padded[:-pad_len]

def parse_bca(
    buffer: bytearray,
    password: bytearray,
    on_progress: Optional[ProgressCallback] = None,
) -> List[VaultDecryptedEntry]:
    progress = on_progress or _noop_progress
    d = buffer
    if len(d) < HEADER_LEN:
        raise BCAFormatError("File troppo corto per essere un archivio .bca valido.")
    if d[0:4] != BCA_MAGIC:
        raise BCAFormatError("File non riconosciuto (magic bytes non corrispondenti).")
    if d[4] != BCA_VERSION:
        raise BCAFormatError("Versione archivio non supportata.")
    salt = bytes(d[5:37])
    iterations = struct.unpack("<I", d[37:41])[0]
    if iterations != BCA_ITERS:
        raise BCAFormatError("Parametro PBKDF2 non valido per questo archivio.")
    iv1 = bytes(d[41:53])
    iv2 = bytes(d[53:69])
    ct = d[69:]
    progress(10, "Re-deriving 512-bit keys...")
    k1, k2 = derive_vault_keys(password, salt, iterations)
    try:
        progress(30, "Layer 2 decryption...")
        try:
            ct1 = _aes_cbc_decrypt(bytes(k2), iv2, ct)
        except BCADecryptError:
            raise
        except Exception as exc:
            raise BCADecryptError(f"Layer 2 error: {exc}") from exc
        progress(45, "Layer 1 decryption...")
        try:
            aesgcm = AESGCM(bytes(k1))
            plain = bytearray(aesgcm.decrypt(iv1, ct1, None))
        except Exception as exc:
            raise BCADecryptError(
                "Layer 1 error: wrong password or tampered file (authenticity check failed)."
            ) from exc
        progress(54, "Analyzing structure...")
        entries: List[VaultDecryptedEntry] = []
        try:
            pos = 0
            def require_bytes(size: int, field: str) -> None:
                if size < 0 or pos > len(plain) - size:
                    raise BCAFormatError(f"Archivio troncato durante la lettura di {field}.")

            require_bytes(2, "the file count")
            file_count = struct.unpack_from("<H", plain, pos)[0]
            pos += 2
            for i in range(file_count):
                require_bytes(2, "the file name length")
                name_len = struct.unpack_from("<H", plain, pos)[0]
                pos += 2
                require_bytes(name_len, "the file name")
                try:
                    name = plain[pos : pos + name_len].decode("utf-8")
                except UnicodeDecodeError as exc:
                    raise BCAFormatError("Nome file non valido nell'archivio.") from exc
                pos += name_len
                require_bytes(12, "the file metadata")
                crc_expected = struct.unpack_from("<I", plain, pos)[0]
                pos += 4
                orig_size = struct.unpack_from("<I", plain, pos)[0]
                pos += 4
                comp_size = struct.unpack_from("<I", plain, pos)[0]
                pos += 4
                require_bytes(comp_size, "the compressed file data")
                compressed = bytes(plain[pos : pos + comp_size])
                pos += comp_size
                progress(54 + int(18 * i / max(1, file_count)), f"Verifying: {name}")
                decompressed = bytearray(deflate_raw_decompress(compressed))
                crc_actual = crc32(bytes(decompressed))
                if len(decompressed) != orig_size:
                    crc_ok = False
                else:
                    crc_ok = crc_actual == crc_expected
                entries.append(VaultDecryptedEntry(name=name, data=decompressed, crc_ok=crc_ok))
            if pos != len(plain):
                raise BCAFormatError("Archivio contiene dati non previsti.")
        except Exception:
            for leaked_entry in entries:
                wipe_bytearray(leaked_entry.data)
            raise
        finally:
            wipe_bytearray(plain)
        progress(72, "Vault unlocked.")
        return entries
    finally:
        wipe_bytearray(k1)
        wipe_bytearray(k2)
        wipe_bytearray(buffer)

class ViewerKind(Enum):
    IMAGE = auto()
    PDF = auto()
    TEXT = auto()
    AUDIO = auto()
    VIDEO = auto()
    UNSUPPORTED = auto()

IMAGE_EXTENSIONS = {".png", ".jpg", ".jpeg", ".gif", ".bmp", ".webp", ".tiff", ".svg"}
TEXT_EXTENSIONS = {
    ".txt", ".md", ".csv", ".json", ".log", ".py", ".js", ".html", ".css",
    ".xml", ".yaml", ".yml", ".ini", ".cfg", ".sh", ".c", ".cpp", ".h",
    ".java", ".rs", ".go", ".rb", ".php", ".sql",
}
PDF_EXTENSIONS = {".pdf"}
AUDIO_EXTENSIONS = {".mp3", ".ogg", ".wav", ".flac", ".aac"}
VIDEO_EXTENSIONS = {".mp4", ".webm", ".mov", ".avi", ".mkv"}

def classify_extension(filename: str) -> ViewerKind:
    ext = "." + filename.rsplit(".", 1)[-1].lower() if "." in filename else ""
    if ext in IMAGE_EXTENSIONS:
        return ViewerKind.IMAGE
    if ext in PDF_EXTENSIONS:
        return ViewerKind.PDF
    if ext in TEXT_EXTENSIONS:
        return ViewerKind.TEXT
    if ext in AUDIO_EXTENSIONS:
        return ViewerKind.AUDIO
    if ext in VIDEO_EXTENSIONS:
        return ViewerKind.VIDEO
    return ViewerKind.UNSUPPORTED

@dataclass
class RenderedPage:
    index: int
    png_bytes: bytes
    width: int
    height: int
    text: str

def _looks_like_svg(data: bytes) -> bool:
    head = data[:512].lstrip(b"\xef\xbb\xbf \t\r\n")
    return head.startswith(b"<?xml") or head.startswith(b"<svg") or b"<svg" in head[:200]

def render_image_in_memory(data: bytes) -> Image.Image:
    if _looks_like_svg(data):
        import fitz
        doc = fitz.open(stream=data, filetype="svg")
        try:
            page = doc.load_page(0)
            pix = page.get_pixmap()
            data = pix.tobytes("png")
        finally:
            doc.close()
    buf = io.BytesIO(data)
    img = Image.open(buf)
    img.load()
    return img

def render_pdf_pages_in_memory(
    data: bytes, dpi: int = 110, max_pages: Optional[int] = None
) -> List[RenderedPage]:
    import fitz
    pages: List[RenderedPage] = []
    doc = fitz.open(stream=data, filetype="pdf")
    try:
        zoom = dpi / 72.0
        matrix = fitz.Matrix(zoom, zoom)
        count = doc.page_count if max_pages is None else min(max_pages, doc.page_count)
        for i in range(count):
            page = doc.load_page(i)
            pix = page.get_pixmap(matrix=matrix, alpha=False)
            png_bytes = pix.tobytes("png")
            pages.append(
                RenderedPage(
                    index=i,
                    png_bytes=png_bytes,
                    width=pix.width,
                    height=pix.height,
                    text=page.get_text("text"),
                )
            )
    finally:
        doc.close()
    return pages

def decode_text_in_memory(data: bytes) -> str:
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        return data.decode("latin-1")

@dataclass
class VideoInfo:
    width: int
    height: int
    fps: float
    duration: float
    has_audio: bool

def _get_ffmpeg_exe() -> str:
    meipass = getattr(sys, "_MEIPASS", None)
    if meipass:
        candidate = os.path.join(
            meipass, "imageio_ffmpeg", "binaries", f"ffmpeg-{_ffmpeg_platform_tag()}"
        )
        if os.path.isfile(candidate):
            try:
                os.chmod(candidate, 0o755)
            except OSError:
                pass
            return candidate
        binaries_dir = os.path.join(meipass, "imageio_ffmpeg", "binaries")
        if os.path.isdir(binaries_dir):
            for fname in os.listdir(binaries_dir):
                if fname.startswith("ffmpeg-"):
                    candidate = os.path.join(binaries_dir, fname)
                    try:
                        os.chmod(candidate, 0o755)
                    except OSError:
                        pass
                    return candidate
    import imageio_ffmpeg
    return imageio_ffmpeg.get_ffmpeg_exe()

def _ffmpeg_platform_tag() -> str:
    machine = platform.machine().lower()
    if sys.platform.startswith("win"):
        return "win32.exe" if "64" not in machine else "win64.exe"
    if sys.platform == "darwin":
        return "osx64" if "arm" not in machine else "osx-arm64"
    if "aarch64" in machine or "arm64" in machine:
        return "linux-aarch64"
    return "linux-x86_64"

@contextlib.contextmanager
def _video_input_source(data: bytes):
    import tempfile
    ram_disk = "/dev/shm" if os.path.isdir("/dev/shm") and os.access("/dev/shm", os.W_OK) else None
    fd, tmp_path = tempfile.mkstemp(suffix=".vidsrc", dir=ram_disk)
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
        yield tmp_path
    finally:
        removed = False
        for attempt in range(5):
            if not os.path.exists(tmp_path):
                removed = True
                break
            _secure_shred_file(tmp_path)
            if not os.path.exists(tmp_path):
                removed = True
                break
            time.sleep(0.1)
        if not removed:
            _secure_shred_file(tmp_path)

def probe_video_in_memory(data: bytes) -> VideoInfo:
    import re
    ffmpeg = _get_ffmpeg_exe()
    with _video_input_source(data) as video_path:
        proc = subprocess.Popen(
            [ffmpeg, "-hide_banner", "-i", video_path],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        _, stderr = proc.communicate()
    text = stderr.decode("utf-8", errors="ignore")
    video_line = ""
    for line in text.split("\n"):
        if re.search(r"Stream.*Video:", line):
            video_line = line
            break
    width = height = 0
    for pattern in (
        r"(\d{2,5})x(\d{2,5})(?:\s|,|\[)",
        r"(\d{2,5})x(\d{2,5})$",
    ):
        m = re.search(pattern, video_line)
        if m:
            width, height = int(m.group(1)), int(m.group(2))
            break
    if width <= 0 or height <= 0:
        raise RuntimeError("Could not determine video dimensions.")
    fps = 25.0
    for pattern in (
        r"([\d.]+)\s*fps",
        r"(\d+)/(\d+)\s*fps",
    ):
        m = re.search(pattern, video_line)
        if m:
            try:
                if len(m.groups()) == 2:
                    num, den = float(m.group(1)), float(m.group(2))
                    fps = num / den if den else fps
                else:
                    fps = float(m.group(1))
                if fps <= 0 or fps > 300:
                    fps = 25.0
                else:
                    break
            except (ValueError, ZeroDivisionError):
                pass
    duration = 0.0
    duration_match = re.search(r"Duration:\s*(\d+):(\d+):(\d+(?:\.\d+)?)", text)
    if duration_match:
        try:
            h, m, s = duration_match.groups()
            duration = int(h) * 3600 + int(m) * 60 + float(s)
        except ValueError:
            duration = 0.0
    has_audio = bool(re.search(r"Stream.*Audio:", text))
    return VideoInfo(width=width, height=height, fps=fps, duration=duration, has_audio=has_audio)

def _fit_decode_size(src_w: int, src_h: int, target_w: int, target_h: int) -> tuple[int, int]:
    if target_w <= 0 or target_h <= 0 or src_w <= 0 or src_h <= 0:
        return src_w, src_h
    if src_w <= target_w and src_h <= target_h:
        return src_w, src_h
    scale = min(target_w / src_w, target_h / src_h)
    out_w = max(2, int(src_w * scale) // 2 * 2)
    out_h = max(2, int(src_h * scale) // 2 * 2)
    return out_w, out_h

def stream_video_frames_in_memory(
    data: bytes, info: VideoInfo, start_seconds: float = 0.0,
    process_holder: Optional[list] = None,
    decode_size: Optional[tuple[int, int]] = None,
):
    ffmpeg = _get_ffmpeg_exe()
    out_w, out_h = decode_size if decode_size else (info.width, info.height)
    frame_size = out_w * out_h * 3
    if frame_size <= 0:
        raise RuntimeError("Invalid video dimensions.")
    with _video_input_source(data) as video_path:
        cmd = [ffmpeg, "-hide_banner"]
        if start_seconds > 0:
            cmd += ["-ss", f"{start_seconds:.3f}"]
        vf = f"fps={info.fps}"
        if (out_w, out_h) != (info.width, info.height):
            vf += f",scale={out_w}:{out_h}:flags=fast_bilinear"
        cmd += [
            "-i", video_path,
            "-map", "0:v:0",
            "-f", "rawvideo", "-pix_fmt", "rgb24",
            "-vf", vf,
            "pipe:1",
        ]
        proc = subprocess.Popen(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            bufsize=frame_size * 2,
        )
        if process_holder is not None:
            process_holder.append(proc)
        try:
            while True:
                chunk = proc.stdout.read(frame_size)
                if len(chunk) < frame_size:
                    break
                yield chunk
        finally:
            try:
                proc.stdout.close()
            except OSError:
                pass
            try:
                proc.kill()
            except OSError:
                pass
            proc.wait(timeout=5)

def extract_video_audio_as_wav(data: bytes) -> Optional[bytes]:
    import io as _io
    import wave
    ffmpeg = _get_ffmpeg_exe()
    with _video_input_source(data) as video_path:
        cmd = [
            ffmpeg, "-hide_banner", "-i", video_path, "-vn",
            "-f", "s16le", "-ar", "44100", "-ac", "2",
            "pipe:1",
        ]
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, _ = proc.communicate()
    if not stdout:
        return None
    buf = _io.BytesIO()
    with wave.open(buf, "wb") as w:
        w.setnchannels(2)
        w.setsampwidth(2)
        w.setframerate(44100)
        w.writeframes(stdout)
    return buf.getvalue()

def get_audio_duration_seconds(data: bytes) -> Optional[float]:
    import io as _io
    import mutagen
    try:
        f = mutagen.File(_io.BytesIO(data))
        if f is not None and f.info is not None:
            return float(f.info.length)
    except Exception:
        pass
    return None

_AUDIO_SESSION_COUNTER = 0

def current_audio_session() -> int:
    return _AUDIO_SESSION_COUNTER

def play_audio_in_memory(data: bytes, start_seconds: float = 0.0) -> int:
    global _AUDIO_SESSION_COUNTER
    import io as _io
    import pygame
    if not pygame.mixer.get_init():
        pygame.mixer.init()
    pygame.mixer.music.load(_io.BytesIO(data))
    if start_seconds > 0:
        try:
            pygame.mixer.music.play(start=start_seconds)
        except Exception:
            pygame.mixer.music.play()
    else:
        pygame.mixer.music.play()
    _AUDIO_SESSION_COUNTER += 1
    return _AUDIO_SESSION_COUNTER

def get_audio_position_seconds() -> float:
    import pygame
    if not pygame.mixer.get_init():
        return 0.0
    pos_ms = pygame.mixer.music.get_pos()
    return max(0.0, pos_ms / 1000.0) if pos_ms >= 0 else 0.0

def is_audio_playing() -> bool:
    import pygame
    if not pygame.mixer.get_init():
        return False
    return bool(pygame.mixer.music.get_busy())

def pause_audio() -> None:
    import pygame
    if pygame.mixer.get_init():
        pygame.mixer.music.pause()

def unpause_audio() -> None:
    import pygame
    if pygame.mixer.get_init():
        pygame.mixer.music.unpause()

def stop_audio() -> None:
    import pygame
    if pygame.mixer.get_init():
        pygame.mixer.music.stop()

def set_audio_volume(volume: float) -> None:
    import pygame
    if pygame.mixer.get_init():
        pygame.mixer.music.set_volume(max(0.0, min(1.0, float(volume))))

DANGER = "#ff5555"
DANGER_DARK = "#4a1414"

# --- Sacred Temple Color Palette ---
TEMPLE_BG = "#0a0806"
TEMPLE_CARD = "#17130d"
TEMPLE_CARD_ELEVATED = "#241d13"
TEMPLE_CARD_HOVER = "#2e2517"
TEMPLE_LAPIS = "#0f233a"
TEMPLE_LAPIS_BRIGHT = "#1a3f66"
TEMPLE_GOLD_ANTIQUE = "#c9a84c"
TEMPLE_GOLD_SUN = "#f4c847"
TEMPLE_GOLD_PALE = "#ffe9a8"
TEMPLE_AMBER = "#ff9f1c"
TEMPLE_AMBER_HOT = "#ffb347"
TEMPLE_GOLD_BRONZE = "#7a5c1e"
TEMPLE_EMERALD = "#1fd8a4"
TEMPLE_TEXT_BODY = "#ecdcae"
TEMPLE_TEXT_GOLD = "#f4c847"
TEMPLE_TEXT_MUTED = "#9c8656"
TEMPLE_BORDER = "#7a5c1e"

# --- Font Configuration ---
FONT_TITLE = ("Georgia", 42, "bold")
FONT_HEADER = ("Georgia", 26, "bold")
FONT_SUBHEADER = ("Georgia", 20, "bold")
FONT_BODY = ("Georgia", 18)
FONT_BODY_ITALIC = ("Georgia", 16, "italic")
FONT_MONO = ("Consolas", 18)
FONT_MONO_SMALL = ("Consolas", 15)
FONT_BUTTON = ("Georgia", 19, "bold")

CURRENT_UI_SCALE = 1.0
RUNES = "𓃠 𓂀 𓊹 𓆣 𓇯 𓋹"

def apply_base_appearance() -> None:
    ctk.set_appearance_mode("dark")
    ctk.set_default_color_theme("dark-blue")

def compute_ui_scale(screen_width: int, screen_height: int) -> float:
    reference_w, reference_h = 1920, 1080
    scale_w = screen_width / reference_w
    scale_h = screen_height / reference_h
    scale = min(scale_w, scale_h)
    return max(0.65, min(scale, 1.35))

def apply_ui_scale(scale: float) -> None:
    global FONT_TITLE, FONT_HEADER, FONT_SUBHEADER, FONT_BODY
    global FONT_BODY_ITALIC, FONT_MONO, FONT_MONO_SMALL, FONT_BUTTON
    global CURRENT_UI_SCALE
    CURRENT_UI_SCALE = scale
    def s(base_size: int) -> int:
        return max(8, round(base_size * scale))
    FONT_TITLE = ("Georgia", s(42), "bold")
    FONT_HEADER = ("Georgia", s(26), "bold")
    FONT_SUBHEADER = ("Georgia", s(20), "bold")
    FONT_BODY = ("Georgia", s(18))
    FONT_BODY_ITALIC = ("Georgia", s(16), "italic")
    FONT_MONO = ("Consolas", s(18))
    FONT_MONO_SMALL = ("Consolas", s(15))
    FONT_BUTTON = ("Georgia", s(19), "bold")

def scaled_font(base_size: int, family: str = "Georgia", *style: str) -> tuple:
    size = max(8, round(base_size * CURRENT_UI_SCALE))
    return (family, size, *style) if style else (family, size)

def configure_style(root: ctk.CTk) -> None:
    root.configure(fg_color=TEMPLE_BG)

def make_radial_glow(size: int, color: str, max_alpha: int = 140) -> "Image.Image":
    """Render a soft radial glow as an RGBA image, purely with PIL's C-level
    ellipse drawing (no per-pixel Python loop) so it stays fast even though
    it's used at hover-time cache-build. Concentric semi-transparent rings
    fading outward approximate a smooth radial gradient cheaply."""
    def hex_to_rgb(h: str) -> tuple:
        h = h.lstrip("#")
        return tuple(int(h[i:i + 2], 16) for i in (0, 2, 4))
    r, g, b = hex_to_rgb(color)
    size = max(2, size)
    img = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    draw = ImageDraw.Draw(img)
    cx = cy = size / 2
    steps = 28
    for i in range(steps, 0, -1):
        t = i / steps
        radius = (size / 2) * t
        alpha = int(max_alpha * ((1 - t) ** 1.6))
        if alpha <= 0:
            continue
        draw.ellipse(
            [cx - radius, cy - radius, cx + radius, cy + radius],
            fill=(r, g, b, alpha)
        )
    return img

# ============================================================================
# SECTION BACKGROUNDS — paste base64 WebP/PNG/JPEG strings into the values
# below to give a section its own background image. Leave a value as "" (or
# None) to keep that section's plain color background. Nothing else in the
# file needs to change: every section already reads from this dict.
#
#   SECTION_BACKGROUNDS_B64["hub"]       -> Main Menu / Portal Hub
#   SECTION_BACKGROUNDS_B64["generator"] -> Cipher Generator
#   SECTION_BACKGROUNDS_B64["vault"]     -> Sacred Vault
#
# The string can be a raw base64 payload, or a full data URL
# ("data:image/webp;base64,...."); both are accepted.
# ============================================================================
SECTION_BACKGROUNDS_B64: dict[str, str] = {
    "hub": "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",
    "generator": "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",
    "vault": "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",
}

# How strongly to darken a section's background image so gold text and card
# borders stay legible on top of it. 0.0 = no scrim (raw image), 1.0 = fully
# opaque TEMPLE_BG. Tune per-section here if one image needs to be dimmer.
SECTION_BACKGROUND_SCRIM: dict[str, float] = {
    "hub": 0.45,
    "generator": 0.55,
    "vault": 0.55,
}

def _hex_to_rgb(h: str) -> tuple:
    h = h.lstrip("#")
    return tuple(int(h[i:i + 2], 16) for i in (0, 2, 4))

def _decode_background_b64(raw: str, section_key: str = "") -> Optional["Image.Image"]:
    """Decode a base64 (optionally data-URL-prefixed) image string into a PIL
    image. Returns None on empty input or decode failure. On failure (but not
    on simply being empty), prints a diagnostic to the console so a bad paste
    is visible instead of silently doing nothing."""
    if not raw:
        return None
    payload = raw.strip()
    if payload.startswith("data:"):
        try:
            payload = payload.split(",", 1)[1]
        except IndexError:
            print(f"[BastetCipher] Background '{section_key}': found 'data:' prefix but no comma "
                  f"separating it from the base64 payload. Expected format: "
                  f"'data:image/webp;base64,<data>'.")
            return None
    # Strip whitespace/newlines that copy-paste commonly introduces into long
    # base64 strings — these are invisible in most editors but break decoding.
    payload = re.sub(r"\s+", "", payload)
    try:
        raw_bytes = base64.b64decode(payload, validate=True)
    except Exception as exc:
        print(f"[BastetCipher] Background '{section_key}': base64 decoding failed ({exc}). "
              f"The pasted text likely got truncated, had characters altered, or wasn't "
              f"valid base64 to begin with. Payload length was {len(payload)} characters.")
        return None
    try:
        img = Image.open(io.BytesIO(raw_bytes))
        img.load()
        return img.convert("RGB")
    except Exception as exc:
        print(f"[BastetCipher] Background '{section_key}': base64 decoded fine ({len(raw_bytes)} "
              f"bytes) but PIL could not open it as an image ({exc}). The bytes may not actually "
              f"be a WebP/PNG/JPEG file, or the file got corrupted before encoding.")
        return None

class SectionBackground:
    """Attaches an optional cover-fit background image (with a darkening
    scrim for legibility) behind a section frame. Pass the raw content frame
    (the widget all of the section's real UI is packed into) plus a section
    key that matches SECTION_BACKGROUNDS_B64. If no image is configured for
    that key, this is a complete no-op — the frame's own fg_color shows as
    before, so sections without a background are unaffected.

    The image is decoded once at construction. Cover-fit crops/scales are
    cheap PIL resizes and are only recomputed when the frame is actually
    resized to a new pixel size (debounced), so this stays fast even while
    the window is being dragged.

    CustomTkinter frames paint their solid fg_color on an internal `_canvas`
    that sits at the bottom of the stacking order. A naive lower() of the
    background label puts it *under* that canvas (invisible). We therefore
    lift the label just above the host's internal canvas so the image is
    visible, while packed UI widgets remain above it.
    """
    def __init__(self, host: "ctk.CTkFrame", section_key: str) -> None:
        self.host = host
        self.section_key = section_key
        raw_value = SECTION_BACKGROUNDS_B64.get(section_key, "")
        self._source_img = _decode_background_b64(raw_value, section_key)
        self._scrim_alpha = SECTION_BACKGROUND_SCRIM.get(section_key, 0.5)
        self._label: Optional["tk.Widget"] = None
        self._last_size: tuple[int, int] = (0, 0)
        self._resize_job = None
        self._photo_ref = None
        if self._source_img is not None:
            print(f"[BastetCipher] Background '{section_key}': loaded successfully "
                  f"({self._source_img.width}x{self._source_img.height}px).")
            # Plain tk.Label is more reliable as a full-bleed background under
            # CTk packing than CTkLabel.
            self._label = tk.Label(host, text="", bd=0, highlightthickness=0,
                                   borderwidth=0, bg=TEMPLE_BG)
            self._label.place(x=0, y=0, relwidth=1, relheight=1)
            self._stack_correctly()
            host.bind("<Configure>", self._on_configure, add="+")
            host.bind("<Map>", self._stack_correctly, add="+")
            self._render_attempts = 0
            self._schedule_initial_render()
        elif raw_value.strip():
            # A non-empty string was provided but failed to decode — the
            # detailed reason was already printed by _decode_background_b64.
            pass

    def _host_canvas(self):
        """Return CustomTkinter's internal drawing canvas, if present."""
        return getattr(self.host, "_canvas", None)

    def _stack_correctly(self, _event=None) -> None:
        """Keep the background image above the solid CTk fill canvas but
        below every real UI child (which are packed later and stay higher)."""
        if self._label is None:
            return
        try:
            canvas = self._host_canvas()
            if canvas is not None:
                # Just above the opaque frame fill — image becomes visible.
                self._label.lift(canvas)
            else:
                # Non-CTk host: send to back of the widget stack.
                self._label.lower()
        except tk.TclError:
            pass

    def _schedule_initial_render(self) -> None:
        """The frame may not have its final size yet on the very first render
        attempt (winfo_width()/height() can report 1px before the window is
        mapped), and <Configure> only fires on an actual size *change* — so a
        frame that's born already at its final size would otherwise never
        render. Retry a handful of times with short delays until a real size
        shows up, instead of a single fire-and-forget attempt."""
        self._render_attempts += 1
        rendered = self._render()
        if not rendered and self._render_attempts < 40:
            self.host.after(50, self._schedule_initial_render)

    @property
    def active(self) -> bool:
        return self._source_img is not None

    def _on_configure(self, _event=None) -> None:
        if self._resize_job is not None:
            try:
                self.host.after_cancel(self._resize_job)
            except Exception:
                pass
        self._resize_job = self.host.after(60, self._render)

    def _render(self) -> bool:
        """Render the cover-fit crop at the host's current size. Returns True
        once a real (non-degenerate) size has been rendered at least once —
        either just now or previously — and False if the host still has no
        usable size yet, so callers can decide whether to retry."""
        self._resize_job = None
        if self._source_img is None or self._label is None:
            return False
        w = max(1, self.host.winfo_width())
        h = max(1, self.host.winfo_height())
        if w <= 1 or h <= 1:
            return False
        if (w, h) == self._last_size:
            self._stack_correctly()
            return True
        self._last_size = (w, h)

        src_w, src_h = self._source_img.size
        scale = max(w / src_w, h / src_h)
        new_w, new_h = max(1, round(src_w * scale)), max(1, round(src_h * scale))
        resized = self._source_img.resize((new_w, new_h), Image.Resampling.LANCZOS)
        left = (new_w - w) // 2
        top = (new_h - h) // 2
        cropped = resized.crop((left, top, left + w, top + h)).convert("RGBA")

        if self._scrim_alpha > 0:
            scrim = Image.new("RGBA", (w, h), (*_hex_to_rgb(TEMPLE_BG), int(255 * self._scrim_alpha)))
            cropped = Image.alpha_composite(cropped, scrim)

        # ImageTk.PhotoImage needs RGB (no alpha) for reliable display.
        rgb = cropped.convert("RGB")
        photo = ImageTk.PhotoImage(rgb)
        self._photo_ref = photo  # keep a strong reference alive
        try:
            self._label.configure(image=photo)
            self._label.image = photo  # extra ref on the widget itself
            self._stack_correctly()
        except tk.TclError:
            return False
        if self._last_size == (w, h) and not getattr(self, "_printed_render", False):
            self._printed_render = True
            print(f"[BastetCipher] Background '{self.section_key}': rendered at {w}x{h}px.")
        return True


class Styled:
    @staticmethod
    def frame_kwargs(border: bool = True) -> dict:
        kw = dict(fg_color=TEMPLE_CARD, corner_radius=16)
        if border:
            kw.update(border_width=1, border_color=TEMPLE_GOLD_ANTIQUE)
        return kw

    @staticmethod
    def primary_button_kwargs() -> dict:
        return dict(
            fg_color=TEMPLE_GOLD_SUN,
            hover_color=TEMPLE_AMBER,
            text_color=TEMPLE_BG,
            font=FONT_BUTTON,
            corner_radius=12,
            height=max(38, round(56 * CURRENT_UI_SCALE)),
        )

    @staticmethod
    def secondary_button_kwargs() -> dict:
        return dict(
            fg_color=TEMPLE_CARD_ELEVATED,
            hover_color=TEMPLE_CARD_HOVER,
            text_color=TEMPLE_TEXT_BODY,
            font=FONT_BODY,
            corner_radius=12,
            height=max(32, round(48 * CURRENT_UI_SCALE)),
            border_width=1,
            border_color=TEMPLE_GOLD_ANTIQUE,
        )

    @staticmethod
    def danger_button_kwargs() -> dict:
        return dict(
            fg_color=DANGER_DARK,
            hover_color="#6a1c1c",
            text_color="#ffb3b3",
            font=FONT_BODY,
            corner_radius=10,
            height=max(32, round(48 * CURRENT_UI_SCALE)),
        )

    @staticmethod
    def entry_kwargs() -> dict:
        return dict(
            fg_color=TEMPLE_BG,
            border_color=TEMPLE_GOLD_ANTIQUE,
            text_color=TEMPLE_TEXT_BODY,
            font=FONT_BODY,
            corner_radius=8,
            height=max(30, round(44 * CURRENT_UI_SCALE)),
        )

    @staticmethod
    def label_title_kwargs() -> dict:
        return dict(text_color=TEMPLE_GOLD_SUN, font=FONT_TITLE)

    @staticmethod
    def label_header_kwargs() -> dict:
        return dict(text_color=TEMPLE_TEXT_GOLD, font=FONT_HEADER)

    @staticmethod
    def label_body_kwargs() -> dict:
        return dict(text_color=TEMPLE_TEXT_BODY, font=FONT_BODY)

    @staticmethod
    def label_muted_kwargs() -> dict:
        return dict(text_color=TEMPLE_GOLD_BRONZE, font=FONT_BODY_ITALIC)

class ButtonSpinner:
    _FRAMES = ("◐", "◓", "◑", "◒")

    def __init__(self, button: ctk.CTkButton) -> None:
        self.button = button
        self._active = False
        self._job = None
        self._original_text = ""
        self._original_state = "normal"
        self._label = ""
        self.canvas = tk.Canvas(self.button.master, width=30, height=30,
                                bg=TEMPLE_CARD, highlightthickness=0)
        self._angle = 0
        self._frame_idx = 0

    def start(self, label: str) -> None:
        if self._active:
            return
        self._active = True
        self._label = label
        self._original_text = self.button.cget("text")
        self._original_state = self.button.cget("state")
        self.button.configure(text=f"       {self._label}", state="disabled")
        self.canvas.place(in_=self.button, relx=0.05, rely=0.5, anchor="w")
        self._tick()

    @property
    def active(self) -> bool:
        return self._active

    def _tick(self) -> None:
        if not self._active:
            return
        try:
            self.canvas.delete("all")
            cx, cy, r = 15, 15, 10
            import math
            for i in range(3):
                a = math.radians(self._angle + i * 120)
                x = cx + r * math.cos(a)
                y = cy + r * math.sin(a)
                self.canvas.create_oval(x-3, y-3, x+3, y+3, fill=TEMPLE_GOLD_SUN, outline=TEMPLE_AMBER)
            self._angle = (self._angle + 15) % 360
            self._job = self.button.after(40, self._tick)
        except tk.TclError:
            self._active = False
            self._job = None

    def stop(self) -> None:
        if not self._active:
            return
        self._active = False
        if self._job is not None:
            try:
                self.button.after_cancel(self._job)
            except tk.TclError:
                pass
            self._job = None
        try:
            self.canvas.place_forget()
            self.button.configure(text=self._original_text, state=self._original_state)
        except tk.TclError:
            pass

PIM_RE = re.compile(r"^\d{1,32}$")

class GeneratorView(ctk.CTkFrame):
    def __init__(self, master, **kwargs):
        super().__init__(master, fg_color="transparent", **kwargs)
        self._background = SectionBackground(self, "generator")
        self._build()

    def _build(self) -> None:
        header_wrap = ctk.CTkFrame(self, fg_color="transparent")
        header_wrap.pack(pady=(26, 2), fill="x")
        ctk.CTkLabel(
            header_wrap, text="🔒   CIPHER GENERATOR   🔒",
            font=scaled_font(34, "Georgia", "bold"), text_color=TEMPLE_GOLD_SUN
        ).pack()
        ctk.CTkLabel(
            self, text="✦  Turn a secret phrase into a high-entropy password  ✦",
            font=FONT_BODY_ITALIC, text_color=TEMPLE_GOLD_ANTIQUE
        ).pack(pady=(4, 24))

        outer = ctk.CTkFrame(self, fg_color="transparent")
        outer.pack(fill="x")

        card = ctk.CTkFrame(
            outer, fg_color=TEMPLE_CARD_ELEVATED,
            border_color=TEMPLE_GOLD_ANTIQUE, border_width=1, corner_radius=20
        )
        card.pack(padx=52, pady=8, fill="x")

        ctk.CTkLabel(
            card, text="𓂀  SACRED INPUTS", font=scaled_font(14, "Georgia", "bold"),
            text_color=TEMPLE_GOLD_ANTIQUE
        ).pack(anchor="w", padx=26, pady=(20, 2))
        ctk.CTkFrame(card, fg_color=TEMPLE_GOLD_BRONZE, height=1).pack(fill="x", padx=26, pady=(0, 6))

        def create_field(parent, label_text, var, show="", placeholder=""):
            ctk.CTkLabel(parent, text=label_text, font=FONT_BODY, text_color=TEMPLE_TEXT_BODY).pack(
                anchor="w", padx=26, pady=(14, 5)
            )
            container = ctk.CTkFrame(
                parent, fg_color=TEMPLE_BG, corner_radius=12, height=46,
                border_width=1, border_color=TEMPLE_GOLD_ANTIQUE
            )
            container.pack(fill="x", padx=26, pady=(0, 2))
            container.pack_propagate(False)
            entry = ctk.CTkEntry(
                container, textvariable=var, show=show, placeholder_text=placeholder,
                fg_color="transparent", border_width=0, text_color=TEMPLE_TEXT_BODY,
                placeholder_text_color=TEMPLE_TEXT_MUTED,
                font=FONT_MONO, height=42
            )
            entry.pack(side="left", fill="both", expand=True, padx=(14, 4))
            return container, entry

        self.phrase_var = tk.StringVar()
        p_container, self.phrase_entry = create_field(
            card, "Secret Phrase / Word", self.phrase_var, "•", "Your secret phrase..."
        )

        self._show_phrase = False
        self.toggle_btn = ctk.CTkButton(
            p_container, text="𓁹", width=38, height=32, corner_radius=8,
            fg_color="transparent", hover_color=TEMPLE_CARD_HOVER,
            text_color=TEMPLE_GOLD_SUN, command=self._toggle_phrase_visibility
        )
        self.toggle_btn.pack(side="right", padx=6)

        self.pim_var = tk.StringVar()
        self.pim_var.trace_add("write", self._sanitize_pim)
        _, self.pim_entry = create_field(
            card, "PIM (Personal Iteration Modifier — digits only)", self.pim_var, "", "E.g. 1234"
        )

        self.amp_var = tk.StringVar(value="0")
        self.amp_var.trace_add("write", self._sanitize_amp)
        _, self.amp_entry = create_field(
            card, "Amplifier (0–9999 extra characters)", self.amp_var
        )

        self.error_label = ctk.CTkLabel(card, text="", text_color=TEMPLE_AMBER, font=FONT_BODY)
        self.error_label.pack(padx=26, pady=(10, 0))

        self.generate_btn = ctk.CTkButton(
            card, text="𓅓  INITIALIZE SEQUENCE  𓅓", command=self._on_generate,
            font=scaled_font(20, "Georgia", "bold"),
            fg_color=TEMPLE_GOLD_SUN, hover_color=TEMPLE_AMBER,
            text_color=TEMPLE_BG, corner_radius=12,
            border_color=TEMPLE_GOLD_PALE, border_width=1, height=52
        )
        self.generate_btn.pack(pady=(24, 10), padx=26, fill="x")
        self.generate_spinner = ButtonSpinner(self.generate_btn)

        self.phrase_entry.bind("<Return>", lambda e: self._on_generate())
        self.pim_entry.bind("<Return>", lambda e: self._on_generate())

        self.status_label = ctk.CTkLabel(card, text="", text_color=TEMPLE_GOLD_ANTIQUE, font=FONT_BODY_ITALIC)
        self.status_label.pack(pady=(0, 6))
        self.progress = ctk.CTkProgressBar(card, progress_color=TEMPLE_GOLD_SUN,
                                           fg_color=TEMPLE_CARD, height=5, corner_radius=3)
        self.progress.set(0)
        ctk.CTkFrame(card, fg_color="transparent", height=16).pack()

        self.output_card = ctk.CTkFrame(
            outer, fg_color=TEMPLE_CARD_ELEVATED,
            border_color=TEMPLE_GOLD_SUN, border_width=1, corner_radius=20
        )
        out_header = ctk.CTkFrame(self.output_card, fg_color="transparent")
        out_header.pack(fill="x", padx=26, pady=(20, 6))
        ctk.CTkLabel(
            out_header, text="✧ THE GENERATED STRING", font=FONT_HEADER, text_color=TEMPLE_EMERALD
        ).pack(side="left")

        self.output_box = ctk.CTkTextbox(
            self.output_card, height=78, fg_color=TEMPLE_BG, text_color=TEMPLE_EMERALD,
            font=FONT_MONO, wrap="word", corner_radius=12,
            border_color=TEMPLE_GOLD_BRONZE, border_width=1
        )
        self.output_box.pack(fill="x", padx=26)
        self.output_box.configure(state="disabled")

        btn_row = ctk.CTkFrame(self.output_card, fg_color="transparent")
        btn_row.pack(fill="x", padx=26, pady=16)

        def btn_kw(): return dict(font=FONT_BODY, corner_radius=12,
                                  border_width=1, border_color=TEMPLE_GOLD_ANTIQUE, height=42)

        self.copy_btn = ctk.CTkButton(btn_row, text="📋 COPY", command=self._copy_output,
                                      fg_color=TEMPLE_CARD, hover_color=TEMPLE_CARD_HOVER,
                                      text_color=TEMPLE_TEXT_BODY, **btn_kw())
        self.copy_btn.pack(side="left", expand=True, fill="x", padx=(0, 6))

        self.open_vault_btn = ctk.CTkButton(btn_row, text="𓁹 BRIDGE TO VAULT",
                                            command=self._open_in_vault,
                                            fg_color=TEMPLE_CARD, hover_color=TEMPLE_CARD_HOVER,
                                            text_color=TEMPLE_TEXT_BODY, **btn_kw())
        self.open_vault_btn.pack(side="left", expand=True, fill="x", padx=6)

        self.clear_btn = ctk.CTkButton(btn_row, text="🗑 PURGE", command=self._clear_output,
                                       fg_color=DANGER_DARK, hover_color="#6a1c1c",
                                       text_color="#ffb3b3", **btn_kw())
        self.clear_btn.pack(side="left", expand=True, fill="x", padx=(6, 0))

        self.stats_label = ctk.CTkLabel(self.output_card, text="",
                                        font=FONT_MONO_SMALL, text_color=TEMPLE_GOLD_ANTIQUE,
                                        justify="left")
        self.stats_label.pack(anchor="w", padx=26, pady=(0, 20))

        self._last_cipher = ""

    def _sanitize_pim(self, *_args) -> None:
        v = self.pim_var.get()
        digits_only = "".join(c for c in v if c.isdigit())[:32]
        if digits_only.startswith("0") and len(digits_only) > 1:
            digits_only = digits_only.lstrip("0") or "0"
        if digits_only != v:
            self.pim_var.set(digits_only)

    def _sanitize_amp(self, *_args) -> None:
        v = self.amp_var.get()
        digits = "".join(c for c in v if c.isdigit())
        if digits == "":
            return
        n = min(int(digits), 9999)
        s = str(n)
        if s != v:
            self.amp_var.set(s)

    def _toggle_phrase_visibility(self) -> None:
        self._show_phrase = not self._show_phrase
        self.phrase_entry.configure(show="" if self._show_phrase else "•")
        self.toggle_btn.configure(text="𓁹" if self._show_phrase else "𓁹")

    def _on_generate(self) -> None:
        if self.generate_spinner.active:
            return
        phrase = self.phrase_var.get().strip()
        pim = self.pim_var.get().strip()
        amp_raw = self.amp_var.get().strip() or "0"
        if not phrase or not pim or not PIM_RE.match(pim):
            self.error_label.configure(
                text="⚠ Enter a valid phrase and a PIM of 1-32 digits."
            )
            return
        try:
            amp = int(amp_raw)
        except ValueError:
            amp = 0
        amp = max(0, min(9999, amp))
        self.error_label.configure(text="")
        self.generate_spinner.start("Generating...")
        self.progress.pack(fill="x", padx=26, pady=(0, 10))
        self.progress.set(0)
        self.output_card.pack_forget()

        def worker():
            def on_progress(pct: int, msg: str):
                self.after(0, lambda: self._update_progress(pct, msg))
            try:
                result = run_cipher_pipeline(phrase, pim, amp, on_progress)
                self.after(0, lambda: self._on_success(result))
            except Exception as exc:
                error_message = str(exc)
                self.after(0, lambda: self._on_error(error_message))
        threading.Thread(target=worker, daemon=True).start()

    def _update_progress(self, pct: int, msg: str) -> None:
        self.progress.set(pct / 100)
        self.status_label.configure(text=msg)

    def _on_success(self, result) -> None:
        self._last_cipher = result.final_cipher
        self.output_box.configure(state="normal")
        self.output_box.delete("1.0", "end")
        self.output_box.insert("1.0", result.final_cipher)
        self.output_box.configure(state="disabled")
        self.stats_label.configure(
            text=(
                f"Length: {len(result.final_cipher)} characters   ·   "
                f"PBKDF2 iterations: {result.iterations:,}   ·   "
                f"Amplifier: {'+' + str(result.amplifier) if result.amplifier else 'disabled'}   ·   "
                f"Salt: {result.salt_hex[:12]}…"
            )
        )
        self.output_card.pack(padx=52, pady=(14, 24), fill="x")
        self.generate_spinner.stop()
        self.progress.pack_forget()
        self.status_label.configure(text="")

    def _on_error(self, message: str) -> None:
        self.generate_spinner.stop()
        self.progress.pack_forget()
        self.status_label.configure(text="")
        messagebox.showerror("Error", f"Generation failed: {message}")

    def _copy_output(self) -> None:
        if not self._last_cipher:
            return
        self.clipboard_clear()
        self.clipboard_append(self._last_cipher)
        self.copy_btn.configure(text="✓ Copied!")
        self.after(1800, lambda: self.copy_btn.configure(text="📋 COPY"))

    def _open_in_vault(self) -> None:
        if not self._last_cipher:
            return
        app = self.winfo_toplevel()
        if hasattr(app, "_open_cipher_in_vault"):
            app._open_cipher_in_vault(self._last_cipher)

    def _clear_output(self) -> None:
        cipher_to_wipe = self._last_cipher
        self._last_cipher = ""
        self.output_box.configure(state="normal")
        self.output_box.delete("1.0", "end")
        self.output_box.configure(state="disabled")
        self.stats_label.configure(text="")
        if cipher_to_wipe:
            try:
                if self.clipboard_get() == cipher_to_wipe:
                    self.clipboard_clear()
            except Exception:
                pass
        self.output_card.pack_forget()

class VaultView(ctk.CTkFrame):
    def __init__(self, master, **kwargs):
        super().__init__(master, fg_color="transparent", **kwargs)
        self._background = SectionBackground(self, "vault")
        self._open_entries: list[VaultDecryptedEntry] = []
        self._pending_create_entries: list[VaultFileEntry] = []
        self._active_video_tmp_paths: list[str] = []
        self._build()

    def _build(self) -> None:
        header = ctk.CTkLabel(
            self, text="𓁹   SACRED VAULT   𓁹",
            font=scaled_font(34, "Georgia", "bold"), text_color=TEMPLE_GOLD_SUN
        )
        header.pack(pady=(26, 4))
        ctk.CTkLabel(
            self,
            text="AES-256-GCM · AES-256-CBC · PBKDF2-HMAC-SHA512 · All in RAM",
            font=FONT_BODY_ITALIC, text_color=TEMPLE_GOLD_ANTIQUE
        ).pack(pady=(0, 22))

        self.tabs = ctk.CTkTabview(
            self, fg_color="transparent",
            segmented_button_selected_color=TEMPLE_GOLD_SUN,
            segmented_button_selected_hover_color=TEMPLE_AMBER,
            segmented_button_fg_color=TEMPLE_CARD,
            segmented_button_unselected_color=TEMPLE_CARD,
            segmented_button_unselected_hover_color=TEMPLE_CARD_HOVER,
            text_color=TEMPLE_BG,
            border_color=TEMPLE_GOLD_ANTIQUE,
            border_width=1,
            corner_radius=18
        )
        self.tabs._segmented_button.configure(font=FONT_BUTTON, height=46, corner_radius=13)
        self.tabs.pack(padx=52, pady=(8, 24), fill="both", expand=True)
        self.tab_create = self.tabs.add("Create Archive")
        self.tab_open = self.tabs.add("Open Archive")
        # CTkSegmentedButton applies a single text_color to every segment regardless of
        # selected state, so a color tuned for the bright gold "selected" pill reads as
        # near-invisible on the dark "unselected" pill. Give each button its own
        # text color directly so both states stay legible.
        for value, btn in self.tabs._segmented_button._buttons_dict.items():
            is_selected = value == self.tabs._segmented_button.get()
            btn.configure(text_color=TEMPLE_BG if is_selected else TEMPLE_TEXT_BODY)
        self._tab_buttons = self.tabs._segmented_button._buttons_dict
        self.tabs.configure(command=self._on_tab_changed)
        self._build_create_tab()
        self._build_open_tab()

    def _on_tab_changed(self) -> None:
        current = self.tabs._segmented_button.get()
        for value, btn in self._tab_buttons.items():
            btn.configure(text_color=TEMPLE_BG if value == current else TEMPLE_TEXT_BODY)

    def _create_bottom_line_entry(self, parent, label_text, var, show="", placeholder=""):
        ctk.CTkLabel(parent, text=label_text, font=FONT_BODY,
                     text_color=TEMPLE_TEXT_BODY).pack(anchor="w", padx=16, pady=(14, 5))
        container = ctk.CTkFrame(
            parent, fg_color=TEMPLE_CARD, corner_radius=12, height=46,
            border_width=1, border_color=TEMPLE_GOLD_ANTIQUE
        )
        container.pack(fill="x", padx=16, pady=(0, 4))
        container.pack_propagate(False)
        entry = ctk.CTkEntry(
            container, textvariable=var, show=show, placeholder_text=placeholder,
            fg_color="transparent", border_width=0, text_color=TEMPLE_TEXT_BODY,
            placeholder_text_color=TEMPLE_TEXT_MUTED,
            font=FONT_MONO, height=42
        )
        entry.pack(side="left", fill="both", expand=True, padx=(14, 4))
        return container, entry

    def _build_create_tab(self) -> None:
        t = self.tab_create
        ctk.CTkLabel(t, text="Files to protect", font=FONT_BODY,
                     text_color=TEMPLE_TEXT_BODY).pack(anchor="w", padx=16, pady=(14, 5))
        self.file_list_box = ctk.CTkTextbox(
            t, height=140, fg_color=TEMPLE_BG, text_color=TEMPLE_TEXT_BODY,
            font=FONT_MONO_SMALL, corner_radius=12,
            border_color=TEMPLE_GOLD_BRONZE, border_width=1
        )
        self.file_list_box.pack(fill="x", padx=16)
        self.file_list_box.configure(state="disabled")

        btn_row = ctk.CTkFrame(t, fg_color="transparent")
        btn_row.pack(fill="x", padx=16, pady=10)

        def btn_kw(): return dict(font=FONT_BODY, corner_radius=12,
                                  border_width=1, border_color=TEMPLE_GOLD_ANTIQUE, height=40)

        self.add_files_btn_ref = ctk.CTkButton(
            btn_row, text="➕ ADD FILES", command=self._add_files,
            fg_color=TEMPLE_CARD, hover_color=TEMPLE_CARD_HOVER,
            text_color=TEMPLE_TEXT_BODY, **btn_kw()
        )
        self.add_files_btn_ref.pack(side="left", padx=(0, 6))
        self.add_files_spinner = ButtonSpinner(self.add_files_btn_ref)

        ctk.CTkButton(
            btn_row, text="🗑 CLEAR LIST", command=self._clear_create_list,
            fg_color=DANGER_DARK, hover_color="#6a1c1c", text_color="#ffb3b3", **btn_kw()
        ).pack(side="left", padx=(6, 0))

        self.create_pw_var = tk.StringVar()
        _, self.create_pw_entry = self._create_bottom_line_entry(
            t, "Archive password", self.create_pw_var, "•", "Password to encrypt..."
        )

        self.create_pw_confirm_var = tk.StringVar()
        _, self.create_pw_confirm_entry = self._create_bottom_line_entry(
            t, "Confirm password", self.create_pw_confirm_var, "•", "Repeat the password..."
        )

        self.create_status = ctk.CTkLabel(t, text="", font=FONT_BODY_ITALIC,
                                          text_color=TEMPLE_GOLD_ANTIQUE)
        self.create_status.pack(pady=(10, 0))
        self.create_progress = ctk.CTkProgressBar(t, progress_color=TEMPLE_GOLD_SUN,
                                                  fg_color=TEMPLE_CARD, height=5, corner_radius=3)

        self.create_btn = ctk.CTkButton(
            t, text="🔒  FORGE ARCHIVE  🔒", command=self._on_create_archive,
            font=scaled_font(20, "Georgia", "bold"),
            fg_color=TEMPLE_GOLD_SUN, hover_color=TEMPLE_AMBER,
            text_color=TEMPLE_BG, corner_radius=12,
            border_color=TEMPLE_GOLD_PALE, border_width=1, height=50
        )
        self.create_btn.pack(fill="x", padx=16, pady=(12, 20))
        self.create_spinner = ButtonSpinner(self.create_btn)

    def _add_files(self) -> None:
        paths = filedialog.askopenfilenames(title="Select files to protect")
        if not paths:
            return
        self.add_files_spinner.start("Loading files...")

        def worker():
            new_entries: List[VaultFileEntry] = []
            errors: List[tuple] = []
            for p in paths:
                try:
                    with open(p, "rb") as f:
                        raw = f.read()
                except OSError as exc:
                    errors.append((p, str(exc)))
                    continue
                name = os.path.basename(p)
                new_entries.append(VaultFileEntry(name=name, data=bytearray(raw)))
            self.after(0, lambda: self._on_files_loaded(new_entries, errors))
        threading.Thread(target=worker, daemon=True).start()

    def _on_files_loaded(self, new_entries: List["VaultFileEntry"], errors: List[tuple]) -> None:
        self._pending_create_entries.extend(new_entries)
        self._refresh_create_list()
        self.add_files_spinner.stop()
        for path, error_message in errors:
            messagebox.showerror("File read error", f"{path}: {error_message}")

    def _refresh_create_list(self) -> None:
        self.file_list_box.configure(state="normal")
        self.file_list_box.delete("1.0", "end")
        for entry in self._pending_create_entries:
            size_kb = len(entry.data) / 1024
            self.file_list_box.insert("end", f"📄 {entry.name}  ({size_kb:.1f} KB)\n")
        self.file_list_box.configure(state="disabled")

    def _clear_create_list(self) -> None:
        for entry in self._pending_create_entries:
            wipe_bytearray(entry.data)
        self._pending_create_entries.clear()
        self._refresh_create_list()

    def _on_create_archive(self) -> None:
        if self.create_spinner.active:
            return
        if not self._pending_create_entries:
            messagebox.showwarning("Vault", "Add at least one file to protect.")
            return
        pw1 = self.create_pw_var.get()
        pw2 = self.create_pw_confirm_var.get()
        if not pw1:
            messagebox.showwarning("Vault", "Enter a password.")
            return
        if pw1 != pw2:
            messagebox.showwarning("Vault", "The two passwords do not match.")
            return
        save_path = filedialog.asksaveasfilename(
            title="Save archive as...",
            defaultextension=".bca",
            filetypes=[("BastetCipher Archive", "*.bca")],
        )
        if not save_path:
            return
        password_buf = bytearray(pw1.encode("utf-8"))
        entries = self._pending_create_entries
        self._pending_create_entries = []
        self.create_spinner.start("Creating archive...")
        self.create_progress.pack(fill="x", padx=16, pady=(0, 10))
        self.create_progress.set(0)

        def worker():
            def on_progress(pct, msg):
                self.after(0, lambda: self._update_create_progress(pct, msg))
            try:
                archive = build_bca(entries, password_buf, on_progress)
                with open(save_path, "wb") as f:
                    f.write(bytes(archive))
                wipe_bytearray(archive)
                self.after(0, lambda: self._on_create_success(save_path))
            except Exception as exc:
                error_message = str(exc)
                self.after(0, lambda: self._on_create_error(error_message))
            finally:
                wipe_bytearray(password_buf)
                self.after(0, lambda: (
                    self.create_pw_var.set(""),
                    self.create_pw_confirm_var.set(""),
                ))
        threading.Thread(target=worker, daemon=True).start()

    def _update_create_progress(self, pct: int, msg: str) -> None:
        self.create_progress.set(pct / 100)
        self.create_status.configure(text=msg)

    def _on_create_success(self, path: str) -> None:
        self.create_spinner.stop()
        self.create_progress.pack_forget()
        self.create_status.configure(text=f"✓ Archive created: {path}", text_color=TEMPLE_EMERALD)
        self._refresh_create_list()

    def _on_create_error(self, message: str) -> None:
        self.create_spinner.stop()
        self.create_progress.pack_forget()
        self.create_status.configure(text="")
        messagebox.showerror("Error", f"Archive creation failed: {message}")

    def _build_open_tab(self) -> None:
        t = self.tab_open
        self.open_dropzone = ctk.CTkFrame(t, fg_color=TEMPLE_CARD_ELEVATED,
                                          border_color=TEMPLE_GOLD_ANTIQUE, border_width=1, corner_radius=16)
        self.open_dropzone.pack(fill="x", padx=16, pady=(16, 8))
        self.open_dz_label = ctk.CTkLabel(
            self.open_dropzone, text="📁  SELECT A .BCA ARCHIVE",
            font=FONT_HEADER, text_color=TEMPLE_GOLD_SUN,
        )
        self.open_dz_label.pack(pady=(24, 6))
        self.open_dz_sub = ctk.CTkLabel(
            self.open_dropzone,
            text="Will be opened only in memory: no data written to disk",
            font=FONT_BODY_ITALIC, text_color=TEMPLE_GOLD_ANTIQUE
        )
        self.open_dz_sub.pack(pady=(0, 16))
        ctk.CTkButton(
            self.open_dropzone, text="BROWSE...", command=self._choose_bca_file,
            fg_color=TEMPLE_CARD, hover_color=TEMPLE_CARD_HOVER,
            text_color=TEMPLE_TEXT_BODY, corner_radius=12,
            border_color=TEMPLE_GOLD_ANTIQUE, border_width=1, height=40
        ).pack(pady=(0, 22))
        self._bca_path: str | None = None

        self.open_pw_var = tk.StringVar()
        _, self.open_pw_entry = self._create_bottom_line_entry(
            t, "Archive password", self.open_pw_var, "•", "Password used to encrypt it..."
        )
        self.open_pw_entry.bind("<Return>", lambda e: self._on_open_archive())

        self.open_status = ctk.CTkLabel(t, text="", font=FONT_BODY_ITALIC,
                                        text_color=TEMPLE_GOLD_ANTIQUE)
        self.open_status.pack(pady=(10, 0))
        self.open_progress = ctk.CTkProgressBar(t, progress_color=TEMPLE_GOLD_SUN,
                                                fg_color=TEMPLE_CARD, height=5, corner_radius=3)

        self.open_btn = ctk.CTkButton(
            t, text="𓁹  UNSEAL THE VAULT  𓁹", command=self._on_open_archive,
            font=scaled_font(20, "Georgia", "bold"),
            fg_color=TEMPLE_GOLD_SUN, hover_color=TEMPLE_AMBER,
            text_color=TEMPLE_BG, corner_radius=12,
            border_color=TEMPLE_GOLD_PALE, border_width=1, height=50
        )
        self.open_btn.pack(fill="x", padx=16, pady=(14, 20))
        self.open_spinner = ButtonSpinner(self.open_btn)

        self.entries_frame = ctk.CTkScrollableFrame(
            t, fg_color=TEMPLE_CARD,
            border_color=TEMPLE_GOLD_ANTIQUE, border_width=1, corner_radius=16, height=220,
        )
        self.close_vault_btn = ctk.CTkButton(
            t, text="🔒 PURGE VAULT FROM RAM",
            command=self._close_vault,
            fg_color=DANGER_DARK, hover_color="#6a1c1c",
            text_color="#ffb3b3", corner_radius=12,
            border_width=1, border_color=TEMPLE_GOLD_ANTIQUE, height=40
        )

    def _choose_bca_file(self) -> None:
        path = filedialog.askopenfilename(
            title="Select .bca archive",
            filetypes=[("BastetCipher Archive", "*.bca"), ("All files", "*.*")],
        )
        if not path:
            return
        self._bca_path = path
        self.open_dz_label.configure(text=f"📦  {os.path.basename(path)}")
        self.open_dz_sub.configure(text="Ready to unlock — will be read only once")

    def _on_open_archive(self) -> None:
        if self.open_spinner.active:
            return
        if not self._bca_path:
            messagebox.showwarning("Vault", "Select a .bca archive first.")
            return
        pw = self.open_pw_var.get()
        if not pw:
            messagebox.showwarning("Vault", "Enter the password.")
            return
        bca_path = self._bca_path
        password_buf = bytearray(pw.encode("utf-8"))
        self.open_pw_var.set("")
        self.open_spinner.start("Unlocking vault...")
        self.open_progress.pack(fill="x", padx=16, pady=(0, 10))
        self.open_progress.set(0)
        self.open_status.configure(text="Reading file...")

        def worker():
            def on_progress(pct, msg):
                self.after(0, lambda: self._update_open_progress(pct, msg))
            try:
                try:
                    with open(bca_path, "rb") as f:
                        raw = bytearray(f.read())
                except OSError as exc:
                    error_message = str(exc)
                    self.after(0, lambda: self._on_open_error(f"Could not read the file: {error_message}"))
                    return
                entries = parse_bca(raw, password_buf, on_progress)
                self.after(0, lambda: self._on_open_success(entries))
            except (BCADecryptError, BCAFormatError) as exc:
                error_message = str(exc)
                self.after(0, lambda: self._on_open_error(error_message))
            except Exception as exc:
                error_message = f"Unexpected error: {exc}"
                self.after(0, lambda: self._on_open_error(error_message))
            finally:
                wipe_bytearray(password_buf)
        threading.Thread(target=worker, daemon=True).start()

    def _update_open_progress(self, pct: int, msg: str) -> None:
        self.open_progress.set(pct / 100)
        self.open_status.configure(text=msg)

    def _on_open_success(self, entries: list[VaultDecryptedEntry]) -> None:
        self.open_spinner.stop()
        self.open_progress.pack_forget()
        self.open_status.configure(
            text=f"✓ Vault unlocked · {len(entries)} file(s) · data only in RAM",
            text_color=TEMPLE_EMERALD,
        )
        self._open_entries = entries
        self._render_entries_list()
        self.entries_frame.pack(fill="both", expand=True, padx=16, pady=(10, 6))
        self.close_vault_btn.pack(fill="x", padx=16, pady=(0, 16))
        self.entries_frame.update_idletasks()

    def _on_open_error(self, message: str) -> None:
        self.open_spinner.stop()
        self.open_progress.pack_forget()
        self.open_status.configure(text="")
        friendly = message
        if "Layer 1" in message or "Layer 2" in message:
            friendly = "Wrong password or corrupted/tampered archive."
        messagebox.showerror("Vault", friendly)

    def _render_entries_list(self) -> None:
        for child in self.entries_frame.winfo_children():
            child.destroy()
        for entry in self._open_entries:
            row = ctk.CTkFrame(
                self.entries_frame, fg_color=TEMPLE_CARD_ELEVATED, corner_radius=12,
                border_width=1, border_color=TEMPLE_GOLD_BRONZE
            )
            row.pack(fill="x", pady=4, padx=4)
            status_text = "✓ Integrity Verified" if entry.crc_ok else "⚠ Integrity Warning"
            color = TEMPLE_EMERALD if entry.crc_ok else TEMPLE_AMBER
            name_col = ctk.CTkFrame(row, fg_color="transparent")
            name_col.pack(side="left", padx=12, pady=9, fill="x", expand=True)
            ctk.CTkLabel(
                name_col, text=entry.name, text_color=TEMPLE_TEXT_BODY, font=FONT_BODY, anchor="w"
            ).pack(anchor="w")
            badge_row = ctk.CTkFrame(name_col, fg_color="transparent")
            badge_row.pack(anchor="w", pady=(2, 0))
            ctk.CTkLabel(
                badge_row, text=status_text, text_color=color, font=FONT_MONO_SMALL,
            ).pack(side="left")
            ctk.CTkLabel(
                badge_row, text=f"   ·   {len(entry.data)/1024:.1f} KB", text_color=TEMPLE_GOLD_BRONZE,
                font=FONT_MONO_SMALL,
            ).pack(side="left")
            btns = ctk.CTkFrame(row, fg_color="transparent")
            btns.pack(side="right", padx=8, pady=6)
            kind = classify_extension(entry.name)
            if kind != ViewerKind.UNSUPPORTED:
                preview_btn = ctk.CTkButton(
                    btns, text="👁 Preview", width=100,
                    **Styled.secondary_button_kwargs(),
                )
                preview_spinner = ButtonSpinner(preview_btn)
                preview_btn.configure(
                    command=lambda e=entry, spinner=preview_spinner: self._preview_entry(e, spinner)
                )
                preview_btn.pack(side="left", padx=4)
            export_btn = ctk.CTkButton(
                btns, text="💾 Export", width=90,
                **Styled.secondary_button_kwargs(),
            )
            export_spinner = ButtonSpinner(export_btn)
            export_btn.configure(
                command=lambda e=entry, spinner=export_spinner: self._export_entry(e, spinner)
            )
            export_btn.pack(side="left", padx=4)

    def _preview_entry(
        self, entry: VaultDecryptedEntry, source_spinner: Optional[ButtonSpinner] = None
    ) -> None:
        kind = classify_extension(entry.name)
        if source_spinner is not None:
            source_spinner.start("Opening...")
        if kind == ViewerKind.VIDEO and _SYSTEM in ("Windows", "Darwin"):
            proceed = messagebox.askyesno(
                "Security Notice — Video Preview",
                f"Notice regarding '{entry.name}':\n\n"
                "On this operating system (Windows/macOS), video playback requires creating a temporary file on disk.\n\n"
                "• While the file will be securely shredded with zeroes upon closing, data will briefly touch the disk.\n"
                "• On Linux, playback runs 100% in RAM via /dev/shm.\n\n"
                "Do you want to proceed with previewing this video?",
                icon="warning",
                parent=self
            )
            if not proceed:
                if source_spinner is not None:
                    source_spinner.stop()
                return
        win = ctk.CTkToplevel(self)
        win.title(f"Preview — {entry.name}")
        win.geometry("800x700")
        win.configure(fg_color=TEMPLE_BG)
        win.attributes("-topmost", True)
        win.after(150, lambda: [win.attributes("-topmost", False), win.focus_force()])
        app = self.winfo_toplevel()
        if hasattr(app, "_app_icon_photo"):
            win.after(250, lambda: win.iconphoto(False, app._app_icon_photo))
        win.after(100, lambda: apply_screen_capture_protection(win))

        if kind == ViewerKind.PDF:
            pdf_data = bytes(entry.data)
            win.after(1, lambda: self._preview_pdf(win, pdf_data, source_spinner))
            return

        try:
            if kind == ViewerKind.IMAGE:
                self._preview_image(win, bytes(entry.data))
            elif kind == ViewerKind.TEXT:
                self._preview_text(win, bytes(entry.data))
            elif kind == ViewerKind.AUDIO:
                self._preview_audio(win, bytes(entry.data), entry.name)
            elif kind == ViewerKind.VIDEO:
                self._preview_video(win, bytes(entry.data), entry.name)
            else:
                ctk.CTkLabel(
                    win, text="No preview available for this file type.\n"
                    "Use 'Export' to save it explicitly to disk.",
                    **Styled.label_body_kwargs(),
                ).pack(pady=40)
        except Exception as exc:
            error_message = str(exc)
            ctk.CTkLabel(
                win, text=f"Could not display preview:\n{error_message}",
                text_color=TEMPLE_AMBER,
            ).pack(pady=40)
        finally:
            if source_spinner is not None:
                source_spinner.stop()

    def _preview_image(self, win: ctk.CTkToplevel, data: bytes) -> None:
        original_img = render_image_in_memory(data)
        animated = bool(getattr(original_img, "is_animated", False) and original_img.n_frames > 1)

        zoom_label = ctk.CTkLabel(
            win,
            text="Zoom: —  •  Use mouse wheel to zoom",
            **Styled.label_muted_kwargs(),
        )
        zoom_label.pack(fill="x", padx=10, pady=(8, 0))

        canvas = tk.Canvas(win, bg=TEMPLE_BG, highlightthickness=0)
        canvas.pack(expand=True, fill="both", padx=10, pady=10)

        max_w, max_h = 760, 640
        orig_w, orig_h = original_img.size
        fit_scale = min(max_w / orig_w, max_h / orig_h, 1.0)

        PROXY_MAX_DIM = 1600
        proxy_img = None
        if not animated and max(orig_w, orig_h) > PROXY_MAX_DIM:
            proxy_scale = PROXY_MAX_DIM / max(orig_w, orig_h)
            proxy_img = original_img.resize(
                (max(1, round(orig_w * proxy_scale)), max(1, round(orig_h * proxy_scale))),
                Image.BILINEAR,
            )

        state = {
            "scale": fit_scale,
            "photo": None,
            "job": None,
            "animation_job": None,
            "frame_index": 0,
            "canvas_image_id": None,
            "settle_job": None,
            "pending_job": None,
        }

        MIN_SCALE = 0.05
        MAX_SCALE = 8.0

        def active_frame() -> Image.Image:
            if not animated:
                return original_img
            original_img.seek(state["frame_index"])
            return original_img.convert("RGBA")

        def render_at_scale(fast: bool = False) -> None:
            scale = state["scale"]
            new_w = max(1, round(orig_w * scale))
            new_h = max(1, round(orig_h * scale))
            if fast and proxy_img is not None:
                source_img = proxy_img
                resample = Image.BILINEAR
            else:
                source_img = active_frame()
                resample = Image.BILINEAR if fast else Image.LANCZOS
            if source_img.size == (new_w, new_h):
                resized = source_img
            else:
                resized = source_img.resize((new_w, new_h), resample)
            photo = ImageTk.PhotoImage(resized)
            state["photo"] = photo
            canvas_w = max(canvas.winfo_width(), 1)
            canvas_h = max(canvas.winfo_height(), 1)
            if state["canvas_image_id"] is None:
                state["canvas_image_id"] = canvas.create_image(
                    canvas_w // 2, canvas_h // 2, image=photo, anchor="center"
                )
            else:
                canvas.coords(state["canvas_image_id"], canvas_w // 2, canvas_h // 2)
                canvas.itemconfigure(state["canvas_image_id"], image=photo)
            canvas.configure(scrollregion=(0, 0, new_w, new_h))
            suffix = "  •  GIF animated" if animated else ""
            zoom_label.configure(
                text=f"Zoom: {round(scale * 100)}%  •  Use mouse wheel to zoom{suffix}"
            )

        def animate_gif() -> None:
            if not animated:
                return
            try:
                render_at_scale()
                original_img.seek(state["frame_index"])
                delay_ms = max(20, int(original_img.info.get("duration", 100)))
                state["frame_index"] = (state["frame_index"] + 1) % original_img.n_frames
                state["animation_job"] = win.after(delay_ms, animate_gif)
            except (tk.TclError, EOFError):
                state["animation_job"] = None

        def on_mousewheel(event) -> None:
            direction = 1 if event.delta > 0 else -1
            zoom_step(direction)

        def on_scroll_up(_event=None) -> None:
            zoom_step(1)

        def on_scroll_down(_event=None) -> None:
            zoom_step(-1)

        def render_settled() -> None:
            state["settle_job"] = None
            render_at_scale(fast=False)

        def render_throttled() -> None:
            state["pending_job"] = None
            render_at_scale(fast=True)
            if state["settle_job"] is not None:
                win.after_cancel(state["settle_job"])
            state["settle_job"] = win.after(140, render_settled)

        def zoom_step(direction: int) -> None:
            factor = 1.1 if direction > 0 else (1 / 1.1)
            new_scale = state["scale"] * factor
            state["scale"] = max(MIN_SCALE, min(MAX_SCALE, new_scale))
            if state["settle_job"] is not None:
                win.after_cancel(state["settle_job"])
                state["settle_job"] = None
            if state["pending_job"] is not None:
                win.after_cancel(state["pending_job"])
            state["pending_job"] = win.after(16, render_throttled)

        def on_resize(_event=None) -> None:
            if state["pending_job"] is not None:
                win.after_cancel(state["pending_job"])
                state["pending_job"] = None
            render_at_scale(fast=True)
            if state["settle_job"] is not None:
                win.after_cancel(state["settle_job"])
            state["settle_job"] = win.after(120, render_settled)

        canvas.bind("<MouseWheel>", on_mousewheel)
        canvas.bind("<Button-4>", on_scroll_up)
        canvas.bind("<Button-5>", on_scroll_down)
        canvas.bind("<Configure>", on_resize)

        win.after(50, render_at_scale)
        if animated:
            win.after(60, animate_gif)

        def on_close() -> None:
            if state["job"] is not None:
                try:
                    win.after_cancel(state["job"])
                except tk.TclError:
                    pass
            if state["pending_job"] is not None:
                try:
                    win.after_cancel(state["pending_job"])
                except tk.TclError:
                    pass
            if state["settle_job"] is not None:
                try:
                    win.after_cancel(state["settle_job"])
                except tk.TclError:
                    pass
            if state["animation_job"] is not None:
                try:
                    win.after_cancel(state["animation_job"])
                except tk.TclError:
                    pass
            try:
                original_img.close()
            except Exception:
                pass
            win.destroy()

        win.protocol("WM_DELETE_WINDOW", on_close)

    def _preview_pdf(
        self, win: ctk.CTkToplevel, data: bytes,
        source_spinner: Optional[ButtonSpinner] = None,
    ) -> None:
        loading = ctk.CTkLabel(
            win, text="◐  Rendering PDF securely in memory...",
            **Styled.label_muted_kwargs(),
        )
        loading.pack(expand=True)
        loading_state = {"index": 0, "job": None}

        def window_exists() -> bool:
            try:
                return bool(win.winfo_exists())
            except tk.TclError:
                return False

        def tick() -> None:
            if not window_exists():
                return
            frame = ButtonSpinner._FRAMES[loading_state["index"]]
            loading.configure(text=f"{frame}  Rendering PDF securely in memory...")
            loading_state["index"] = (loading_state["index"] + 1) % len(ButtonSpinner._FRAMES)
            loading_state["job"] = win.after(140, tick)

        def finish_loading() -> None:
            if loading_state["job"] is not None:
                try:
                    win.after_cancel(loading_state["job"])
                except tk.TclError:
                    pass
            if window_exists():
                loading.destroy()

        def stop_source_spinner() -> None:
            if source_spinner is not None:
                source_spinner.stop()

        def show_error(message: str) -> None:
            if not window_exists():
                stop_source_spinner()
                return
            finish_loading()
            ctk.CTkLabel(
                win, text=f"Could not display PDF:\n{message}", text_color=TEMPLE_AMBER,
            ).pack(expand=True, padx=20)
            stop_source_spinner()

        def show_pages(pages: List[RenderedPage]) -> None:
            if not window_exists():
                stop_source_spinner()
                return
            finish_loading()
            toolbar = ctk.CTkFrame(win, fg_color=TEMPLE_CARD_ELEVATED, corner_radius=8)
            toolbar.pack(fill="x", padx=10, pady=(10, 0))

            search_var = tk.StringVar()
            search_entry = ctk.CTkEntry(
                toolbar, textvariable=search_var, placeholder_text="Search text in PDF...",
                **Styled.entry_kwargs(),
            )
            search_entry.pack(side="left", fill="x", expand=True, padx=(10, 6), pady=8)

            match_label = ctk.CTkLabel(
                toolbar, text=f"Page 1 / {max(1, len(pages))}",
                font=FONT_MONO_SMALL, text_color=TEMPLE_GOLD_BRONZE,
            )
            match_label.pack(side="right", padx=(6, 10))

            scroll = ctk.CTkScrollableFrame(win, fg_color=TEMPLE_BG)
            scroll.pack(expand=True, fill="both", padx=10, pady=10)

            photo_refs: dict[int, object] = {}
            win.pdf_photo_refs = photo_refs
            page_frames: dict[int, ctk.CTkFrame] = {}
            page_image_labels: dict[int, tk.Label] = {}
            zoom_state = {"value": 1.0}
            search_state = {"matches": [], "index": 0}
            page_base_images: dict[int, Image.Image] = {}

            def refresh_page_image(index: int, fast: bool = False) -> None:
                page = pages[index]
                image_label = page_image_labels.get(index)
                if image_label is None:
                    return
                base_img = page_base_images.get(index)
                if base_img is None:
                    base_img = Image.open(io.BytesIO(page.png_bytes))
                    base_img.load()
                    page_base_images[index] = base_img
                base_w, base_h = base_img.size
                box_w = round(760 * zoom_state["value"])
                box_h = round(1000 * zoom_state["value"])
                scale = min(box_w / base_w, box_h / base_h) if base_w and base_h else 1.0
                new_w = max(1, round(base_w * scale))
                new_h = max(1, round(base_h * scale))
                resample = Image.BILINEAR if fast else Image.LANCZOS
                if (new_w, new_h) == (base_w, base_h):
                    resized = base_img
                else:
                    resized = base_img.resize((new_w, new_h), resample)
                photo = ImageTk.PhotoImage(resized)
                photo_refs[index] = photo
                image_label.configure(image=photo)
                image_label.image = photo

            def show_page(page_index: int) -> None:
                page_frame = page_frames.get(page_index)
                if page_frame is None:
                    return
                page_frame.update_idletasks()
                canvas = getattr(scroll, "_parent_canvas", None)
                if canvas is not None:
                    try:
                        bbox = canvas.bbox("all")
                        if bbox and bbox[3] > 0:
                            canvas.yview_moveto(page_frame.winfo_y() / bbox[3])
                    except tk.TclError:
                        pass
                query = search_var.get().strip()
                if search_state["matches"]:
                    match_label.configure(
                        text=(
                            f"Match {search_state['index'] + 1} / {len(search_state['matches'])}"
                            f" • page {page_index + 1}"
                        )
                    )
                else:
                    match_label.configure(text=f"Page {page_index + 1} / {max(1, len(pages))}")

            def find_text(direction: int = 0) -> None:
                query = search_var.get().strip().casefold()
                if not query:
                    search_state["matches"] = []
                    search_state["index"] = 0
                    match_label.configure(text=f"Page 1 / {max(1, len(pages))}")
                    return
                matches = [page.index for page in pages if query in page.text.casefold()]
                if matches != search_state["matches"]:
                    search_state["matches"] = matches
                    search_state["index"] = 0
                elif matches:
                    search_state["index"] = (search_state["index"] + direction) % len(matches)
                if not matches:
                    match_label.configure(text="No matches")
                    return
                show_page(matches[search_state["index"]])

            zoom_jobs = {"settle": None, "trickle": None}
            page_zoom_rendered = {}

            def _visible_page_indices() -> list:
                canvas_ = getattr(scroll, "_parent_canvas", None)
                if canvas_ is None:
                    return list(page_frames.keys())[:1]
                try:
                    top_frac, bottom_frac = canvas_.yview()
                    bbox = canvas_.bbox("all")
                    if not bbox or bbox[3] <= 0:
                        return list(page_frames.keys())[:1]
                    top_y = top_frac * bbox[3]
                    bottom_y = bottom_frac * bbox[3]
                    visible = []
                    for idx, frame in page_frames.items():
                        frame_top = frame.winfo_y()
                        frame_bottom = frame_top + max(frame.winfo_height(), 1)
                        if frame_bottom >= top_y and frame_top <= bottom_y:
                            visible.append(idx)
                    return visible or list(page_frames.keys())[:1]
                except tk.TclError:
                    return list(page_frames.keys())[:1]

            def _trickle_refresh(indices: list, fast: bool, zoom_value: float) -> None:
                if not indices:
                    zoom_jobs["trickle"] = None
                    return
                if zoom_state["value"] != zoom_value:
                    zoom_jobs["trickle"] = None
                    return
                idx = indices.pop(0)
                if idx in page_image_labels and page_zoom_rendered.get(idx) != zoom_value:
                    refresh_page_image(idx, fast=fast)
                    page_zoom_rendered[idx] = zoom_value
                zoom_jobs["trickle"] = win.after(
                    30, lambda: _trickle_refresh(indices, fast, zoom_value)
                )

            def change_zoom(factor: float) -> None:
                zoom_state["value"] = max(0.5, min(2.0, zoom_state["value"] * factor))
                zoom_value = zoom_state["value"]
                match_label.configure(text=f"Zoom {round(zoom_value * 100)}%")
                if zoom_jobs["trickle"] is not None:
                    try:
                        win.after_cancel(zoom_jobs["trickle"])
                    except tk.TclError:
                        pass
                    zoom_jobs["trickle"] = None
                if zoom_jobs["settle"] is not None:
                    try:
                        win.after_cancel(zoom_jobs["settle"])
                    except tk.TclError:
                        pass
                    zoom_jobs["settle"] = None
                visible = _visible_page_indices()
                for idx in visible:
                    if idx in page_image_labels:
                        refresh_page_image(idx, fast=True)
                        page_zoom_rendered[idx] = zoom_value
                remaining = [i for i in page_image_labels if i not in visible]
                if remaining:
                    zoom_jobs["trickle"] = win.after(
                        30, lambda: _trickle_refresh(remaining, True, zoom_value)
                    )

                def settle() -> None:
                    zoom_jobs["settle"] = None
                    if zoom_state["value"] != zoom_value:
                        return
                    for idx in visible:
                        if idx in page_image_labels:
                            refresh_page_image(idx, fast=False)
                            page_zoom_rendered[idx] = zoom_value
                zoom_jobs["settle"] = win.after(150, settle)

            ctk.CTkButton(
                toolbar, text="Find", width=58, command=find_text,
                **Styled.secondary_button_kwargs(),
            ).pack(side="left", padx=3, pady=8)
            ctk.CTkButton(
                toolbar, text="‹", width=34, command=lambda: find_text(-1),
                **Styled.secondary_button_kwargs(),
            ).pack(side="left", padx=3, pady=8)
            ctk.CTkButton(
                toolbar, text="›", width=34, command=lambda: find_text(1),
                **Styled.secondary_button_kwargs(),
            ).pack(side="left", padx=3, pady=8)
            ctk.CTkButton(
                toolbar, text="−", width=34, command=lambda: change_zoom(1 / 1.2),
                **Styled.secondary_button_kwargs(),
            ).pack(side="right", padx=3, pady=8)
            ctk.CTkButton(
                toolbar, text="+", width=34, command=lambda: change_zoom(1.2),
                **Styled.secondary_button_kwargs(),
            ).pack(side="right", padx=3, pady=8)
            search_entry.bind("<Return>", lambda _event: find_text(1))

            def add_page(index: int = 0) -> None:
                if not window_exists():
                    stop_source_spinner()
                    return
                if index >= len(pages):
                    stop_source_spinner()
                    return
                try:
                    page = pages[index]
                    page_frame = ctk.CTkFrame(scroll, fg_color="transparent")
                    page_frame.pack(pady=8)
                    page_frames[page.index] = page_frame
                    image_label = tk.Label(page_frame, bg=TEMPLE_BG)
                    image_label.pack()
                    page_image_labels[page.index] = image_label
                    refresh_page_image(page.index)
                    ctk.CTkLabel(
                        page_frame, text=f"Page {page.index + 1}", text_color=TEMPLE_GOLD_BRONZE,
                        font=FONT_MONO_SMALL,
                    ).pack()
                except Exception as exc:
                    show_error(str(exc))
                    return
                win.after(1, lambda: add_page(index + 1))
            add_page()

        def worker() -> None:
            try:
                pages = render_pdf_pages_in_memory(data, dpi=100, max_pages=30)
            except Exception as exc:
                self.after(0, lambda: show_error(str(exc)))
                return
            self.after(0, lambda: show_pages(pages))

        tick()
        threading.Thread(target=worker, daemon=True).start()

    def _preview_text(self, win: ctk.CTkToplevel, data: bytes) -> None:
        text = decode_text_in_memory(data)
        box = ctk.CTkTextbox(win, fg_color=TEMPLE_BG, text_color=TEMPLE_TEXT_BODY,
                             font=FONT_MONO_SMALL, wrap="word")
        box.pack(expand=True, fill="both", padx=10, pady=10)
        box.insert("1.0", text)
        box.configure(state="disabled")

    def _preview_audio(self, win: ctk.CTkToplevel, data: bytes, name: str) -> None:
        ctk.CTkLabel(win, text="🎵", font=scaled_font(64), text_color=TEMPLE_GOLD_SUN).pack(pady=(60, 10))
        ctk.CTkLabel(win, text=name, **Styled.label_header_kwargs()).pack(pady=(0, 20))
        status_label = ctk.CTkLabel(win, text="Playing from RAM...", **Styled.label_muted_kwargs())
        status_label.pack(pady=(0, 10))

        duration = get_audio_duration_seconds(data)
        time_label = ctk.CTkLabel(win, text="0:00 / 0:00", font=FONT_MONO_SMALL,
                                  text_color=TEMPLE_TEXT_BODY)
        time_label.pack(pady=(0, 4))

        state = {
            "seeking": False, "poll_job": None, "started": False,
            "seek_offset": 0.0, "session": -1, "stopped": False, "volume": 0.8,
        }

        def fmt(seconds: float) -> str:
            seconds = max(0, int(seconds))
            return f"{seconds // 60}:{seconds % 60:02d}"

        slider = ctk.CTkSlider(
            win, from_=0, to=(duration if duration else 1), number_of_steps=1000,
            progress_color=TEMPLE_GOLD_SUN, button_color=TEMPLE_GOLD_SUN,
            button_hover_color=TEMPLE_AMBER, fg_color=TEMPLE_BG,
        )
        slider.set(0)
        slider.pack(fill="x", padx=60, pady=(0, 10))
        if not duration:
            slider.configure(state="disabled")

        volume_row = ctk.CTkFrame(win, fg_color="transparent")
        volume_row.pack(fill="x", padx=60, pady=(0, 10))
        ctk.CTkLabel(volume_row, text="🔊 Volume", font=FONT_MONO_SMALL,
                     text_color=TEMPLE_TEXT_BODY).pack(side="left", padx=(0, 10))
        volume_slider = ctk.CTkSlider(
            volume_row, from_=0, to=1, number_of_steps=100,
            progress_color=TEMPLE_GOLD_SUN, button_color=TEMPLE_GOLD_SUN,
            button_hover_color=TEMPLE_AMBER, fg_color=TEMPLE_BG,
        )
        volume_slider.set(state["volume"])
        volume_slider.pack(side="left", fill="x", expand=True)

        def on_volume_change(value: float) -> None:
            state["volume"] = float(value)
            set_audio_volume(state["volume"])
        volume_slider.configure(command=on_volume_change)

        def on_slider_press(_event=None):
            state["seeking"] = True

        def on_slider_release(_event=None):
            state["seeking"] = False
            if duration:
                target = slider.get()
                try:
                    state["session"] = play_audio_in_memory(data, start_seconds=target)
                    state["seek_offset"] = target
                    state["started"] = True
                    state["stopped"] = False
                    set_audio_volume(state["volume"])
                    if pause_btn is not None:
                        pause_btn.configure(text="⏸ Pause")
                except Exception:
                    pass

        slider.bind("<Button-1>", on_slider_press)
        slider.bind("<ButtonRelease-1>", on_slider_release)

        try:
            state["session"] = play_audio_in_memory(data)
            state["started"] = True
            set_audio_volume(state["volume"])
        except Exception as exc:
            error_message = str(exc)
            status_label.configure(text=f"Playback error: {error_message}", text_color=TEMPLE_AMBER)
            state["started"] = False

        if not duration:
            status_label.configure(
                text=status_label.cget("text") + "\n(duration unavailable for this format — seek disabled)"
            )

        btn_row = ctk.CTkFrame(win, fg_color="transparent")
        pause_btn = None
        if state["started"]:
            btn_row.pack(pady=10)

            def toggle_pause():
                if state["stopped"] or state["session"] != current_audio_session():
                    try:
                        state["session"] = play_audio_in_memory(data, start_seconds=state["seek_offset"])
                        set_audio_volume(state["volume"])
                        state["stopped"] = False
                        pause_btn.configure(text="⏸ Pause")
                        status_label.configure(text="Playing from RAM...", text_color=TEMPLE_GOLD_BRONZE)
                    except Exception:
                        pass
                    return
                if is_audio_playing():
                    pause_audio()
                    pause_btn.configure(text="▶ Play")
                else:
                    unpause_audio()
                    pause_btn.configure(text="⏸ Pause")

            pause_btn = ctk.CTkButton(
                btn_row, text="⏸ Pause", command=toggle_pause,
                **Styled.secondary_button_kwargs(),
            )
            pause_btn.pack(side="left", padx=6)

            def do_stop():
                stop_audio()
                state["stopped"] = True
                slider.set(0)
                state["seek_offset"] = 0.0
                time_label.configure(text=f"0:00 / {fmt(duration) if duration else '—:—'}")
                pause_btn.configure(text="▶ Play")
                status_label.configure(text="Stopped", text_color=TEMPLE_GOLD_BRONZE)

            ctk.CTkButton(
                btn_row, text="⏹ Stop", command=do_stop,
                **Styled.secondary_button_kwargs(),
            ).pack(side="left", padx=6)

        def poll():
            if state["session"] != current_audio_session():
                if state["session"] != -1:
                    status_label.configure(
                        text="⏸ Playback taken over by another audio window.",
                        text_color=TEMPLE_GOLD_BRONZE,
                    )
                    if pause_btn is not None:
                        pause_btn.configure(text="▶ Play")
                state["poll_job"] = win.after(300, poll)
                return
            if not state["seeking"] and is_audio_playing():
                pos = state["seek_offset"] + get_audio_position_seconds()
                if duration:
                    pos = min(pos, duration)
                    slider.set(pos)
                    time_label.configure(text=f"{fmt(pos)} / {fmt(duration)}")
                else:
                    time_label.configure(text=f"{fmt(pos)} / —:—")
            state["poll_job"] = win.after(300, poll)

        if state["started"]:
            poll()

        def on_close():
            if state["poll_job"] is not None:
                try:
                    win.after_cancel(state["poll_job"])
                except Exception:
                    pass
            try:
                stop_audio()
            except Exception:
                pass
            win.destroy()

        win.protocol("WM_DELETE_WINDOW", on_close)

    def _preview_video(self, win: ctk.CTkToplevel, data: bytes, name: str) -> None:
        ctk.CTkLabel(win, text="🎬", font=scaled_font(40), text_color=TEMPLE_GOLD_SUN).pack(pady=(14, 4))
        ctk.CTkLabel(win, text=name, **Styled.label_header_kwargs()).pack(pady=(0, 6))
        status_label = ctk.CTkLabel(win, text="Reading video info...", **Styled.label_muted_kwargs())
        status_label.pack(pady=(0, 6))
        win.update()

        try:
            info = probe_video_in_memory(data)
        except Exception as exc:
            error_message = str(exc)
            status_label.configure(
                text=f"Could not read video: {error_message}\nFalling back to system player.",
                text_color="#ff9a5a",
            )
            self._preview_video_external_fallback(win, data, name, status_label)
            return

        video_area = tk.Frame(win, bg=TEMPLE_BG)
        video_area.pack(side="top", expand=True, fill="both", padx=10, pady=(0, 6))
        video_area.pack_propagate(False)
        video_label = tk.Label(video_area, bg=TEMPLE_BG)
        video_label.pack(expand=True, fill="both")

        controls = ctk.CTkFrame(win, fg_color="transparent")
        controls.pack(side="bottom", fill="x", padx=20, pady=(0, 4))

        slider = ctk.CTkSlider(
            controls, from_=0, to=max(info.duration, 1), number_of_steps=1000,
            progress_color=TEMPLE_GOLD_SUN, button_color=TEMPLE_GOLD_SUN,
            button_hover_color=TEMPLE_AMBER, fg_color=TEMPLE_BG,
        )
        slider.set(0)
        slider.pack(fill="x", pady=(0, 8))
        if info.duration <= 0:
            slider.configure(state="disabled")

        volume_row = ctk.CTkFrame(controls, fg_color="transparent")
        volume_row.pack(fill="x", pady=(0, 2))
        ctk.CTkLabel(volume_row, text="🔊 Volume", font=FONT_MONO_SMALL,
                     text_color=TEMPLE_TEXT_BODY).pack(side="left", padx=(0, 10))
        volume_slider = ctk.CTkSlider(
            volume_row, from_=0, to=1, number_of_steps=100,
            progress_color=TEMPLE_GOLD_SUN, button_color=TEMPLE_GOLD_SUN,
            button_hover_color=TEMPLE_AMBER, fg_color=TEMPLE_BG,
        )
        volume_slider.pack(side="left", fill="x", expand=True)

        btn_row = ctk.CTkFrame(win, fg_color="transparent")
        btn_row.pack(side="bottom", pady=(0, 12))
        play_pause_btn = ctk.CTkButton(btn_row, text="⏸ Pause",
                                       **Styled.secondary_button_kwargs())
        play_pause_btn.pack(side="left", padx=6)
        stop_btn = ctk.CTkButton(btn_row, text="⏹ Stop",
                                 **Styled.secondary_button_kwargs())
        stop_btn.pack(side="left", padx=6)
        time_label = ctk.CTkLabel(btn_row, text="0:00 / 0:00",
                                  font=FONT_MONO_SMALL, text_color=TEMPLE_TEXT_BODY)
        time_label.pack(side="left", padx=12)

        def fmt(seconds: float) -> str:
            seconds = max(0, int(seconds))
            return f"{seconds // 60}:{seconds % 60:02d}"

        time_label.configure(text=f"0:00 / {fmt(info.duration)}")

        state = {
            "playing": True,
            "seeking": False,
            "stopped": False,
            "job": None,
            "audio_session": -1,
            "frame_queue": queue.Queue(maxsize=8),
            "decoder_thread": None,
            "decoder_generation": 0,
            "current_frame_time": 0.0,
            "eof": False,
            "active_processes": [],
            "audio_stopped": False,
            "volume": 0.8,
            "decode_size": (info.width, info.height),
        }

        win.update_idletasks()
        area_w = max(video_label.winfo_width(), 320)
        area_h = max(video_label.winfo_height(), 240)
        state["decode_size"] = _fit_decode_size(
            info.width, info.height, area_w * 2, area_h * 2
        )

        volume_slider.set(state["volume"])
        photo_refs: list = []
        wav_audio = None
        if info.has_audio:
            try:
                wav_audio = extract_video_audio_as_wav(data)
            except Exception:
                wav_audio = None

        def on_volume_change(value: float) -> None:
            state["volume"] = float(value)
            if state["audio_session"] != -1:
                set_audio_volume(state["volume"])
        volume_slider.configure(command=on_volume_change)

        if wav_audio is None:
            volume_slider.configure(state="disabled")

        def decoder_worker(generation: int, start_seconds: float) -> None:
            try:
                frame_interval = 1.0 / info.fps if info.fps > 0 else 0.04
                t = start_seconds
                proc_holder: list = []
                state["active_processes"].append(proc_holder)
                decode_w, decode_h = state["decode_size"]
                decode_start_wall = time.monotonic()
                for raw_rgb in stream_video_frames_in_memory(
                    data, info, start_seconds=start_seconds, process_holder=proc_holder,
                    decode_size=(decode_w, decode_h),
                ):
                    if state["decoder_generation"] != generation or state["stopped"]:
                        return
                    target_wall = decode_start_wall + (t - start_seconds)
                    sleep_for = target_wall - time.monotonic()
                    if sleep_for > 0:
                        time.sleep(min(sleep_for, frame_interval * 2))
                    try:
                        state["frame_queue"].put((t, decode_w, decode_h, raw_rgb), timeout=2)
                    except queue.Full:
                        return
                    t += frame_interval
                if state["decoder_generation"] == generation:
                    state["eof"] = True
            except Exception:
                if state["decoder_generation"] == generation:
                    state["eof"] = True

        def kill_active_processes() -> None:
            procs_to_wait = []
            for proc_holder in state["active_processes"]:
                if proc_holder:
                    try:
                        proc_holder[0].kill()
                        procs_to_wait.append(proc_holder[0])
                    except Exception:
                        pass
            state["active_processes"].clear()
            if procs_to_wait:
                def reap():
                    for p in procs_to_wait:
                        try:
                            p.wait(timeout=3)
                        except Exception:
                            pass
                threading.Thread(target=reap, daemon=True).start()

        def start_decoder(start_seconds: float = 0.0) -> None:
            state["decoder_generation"] += 1
            generation = state["decoder_generation"]
            state["eof"] = False
            kill_active_processes()
            while not state["frame_queue"].empty():
                try:
                    state["frame_queue"].get_nowait()
                except queue.Empty:
                    break
            thread = threading.Thread(
                target=decoder_worker, args=(generation, start_seconds), daemon=True
            )
            state["decoder_thread"] = thread
            thread.start()

        def render_frame(raw_rgb: bytes, frame_w: int, frame_h: int) -> None:
            img = Image.frombytes("RGB", (frame_w, frame_h), raw_rgb)
            max_w = max(video_label.winfo_width(), 320)
            max_h = max(video_label.winfo_height(), 240)
            if frame_w > max_w or frame_h > max_h:
                img.thumbnail((max_w, max_h), Image.BILINEAR)
            photo = ImageTk.PhotoImage(img)
            photo_refs.clear()
            photo_refs.append(photo)
            video_label.configure(image=photo)

        if wav_audio:
            try:
                state["audio_session"] = play_audio_in_memory(wav_audio)
                set_audio_volume(state["volume"])
            except Exception:
                state["audio_session"] = -1

        start_decoder(0.0)
        status_label.pack_forget()

        def pump() -> None:
            if state["stopped"]:
                return
            if state["playing"] and not state["seeking"]:
                try:
                    frame_time, frame_w, frame_h, raw_rgb = state["frame_queue"].get_nowait()
                    while True:
                        try:
                            newer = state["frame_queue"].get_nowait()
                        except queue.Empty:
                            break
                        frame_time, frame_w, frame_h, raw_rgb = newer
                    render_frame(raw_rgb, frame_w, frame_h)
                    state["current_frame_time"] = frame_time
                    if not state["seeking"]:
                        slider.set(min(frame_time, info.duration) if info.duration else 0)
                    time_label.configure(text=f"{fmt(frame_time)} / {fmt(info.duration)}")
                except queue.Empty:
                    if state["eof"] and state["frame_queue"].empty():
                        state["playing"] = False
                        play_pause_btn.configure(text="▶ Replay")
            state["job"] = win.after(8, pump)

        def toggle_play() -> None:
            if not state["playing"] and (
                play_pause_btn.cget("text") == "▶ Replay" or state["audio_stopped"]
            ):
                start_decoder(0.0)
                if wav_audio:
                    try:
                        state["audio_session"] = play_audio_in_memory(wav_audio)
                        set_audio_volume(state["volume"])
                    except Exception:
                        state["audio_session"] = -1
                state["audio_stopped"] = False
                state["playing"] = True
                play_pause_btn.configure(text="⏸ Pause")
                return
            state["playing"] = not state["playing"]
            if state["playing"]:
                resume_at = state["current_frame_time"]
                start_decoder(resume_at)
                if state["audio_session"] != -1:
                    try:
                        state["audio_session"] = play_audio_in_memory(wav_audio, start_seconds=resume_at)
                        set_audio_volume(state["volume"])
                    except Exception:
                        state["audio_session"] = -1
                play_pause_btn.configure(text="⏸ Pause")
            else:
                if state["audio_session"] != -1:
                    pause_audio()
                play_pause_btn.configure(text="▶ Play")

        def do_stop() -> None:
            state["decoder_generation"] += 1
            state["playing"] = False
            play_pause_btn.configure(text="▶ Play")
            slider.set(0)
            time_label.configure(text=f"0:00 / {fmt(info.duration)}")
            try:
                if state["audio_session"] != -1:
                    stop_audio()
            except Exception:
                pass
            state["audio_stopped"] = True
            kill_active_processes()
            state["playing"] = False

        def on_slider_press(_event=None) -> None:
            state["seeking"] = True

        def on_slider_release(_event=None) -> None:
            target = slider.get()
            start_decoder(target)
            if wav_audio:
                try:
                    state["audio_session"] = play_audio_in_memory(wav_audio, start_seconds=target)
                    set_audio_volume(state["volume"])
                    state["audio_stopped"] = False
                    if not state["playing"]:
                        pause_audio()
                except Exception:
                    state["audio_session"] = -1
            state["seeking"] = False

        slider.bind("<Button-1>", on_slider_press)
        slider.bind("<ButtonRelease-1>", on_slider_release)
        play_pause_btn.configure(command=toggle_play)
        stop_btn.configure(command=do_stop)

        win.after(50, pump)

        def on_close() -> None:
            state["stopped"] = True
            state["decoder_generation"] += 1
            kill_active_processes()
            if state["job"] is not None:
                try:
                    win.after_cancel(state["job"])
                except Exception:
                    pass
            try:
                if state["audio_session"] != -1 and state["audio_session"] == current_audio_session():
                    stop_audio()
            except Exception:
                pass
            win.destroy()

        win.protocol("WM_DELETE_WINDOW", on_close)

    def _preview_video_external_fallback(
        self, win: ctk.CTkToplevel, data: bytes, name: str, status_label
    ) -> None:
        import tempfile
        ram_disk = "/dev/shm" if os.path.isdir("/dev/shm") and os.access("/dev/shm", os.W_OK) else None
        tmp_path = None
        try:
            suffix = "." + name.rsplit(".", 1)[-1].lower() if "." in name else ".mp4"
            fd, tmp_path = tempfile.mkstemp(suffix=suffix, dir=ram_disk)
            with os.fdopen(fd, "wb") as f:
                f.write(data)
            self._active_video_tmp_paths.append(tmp_path)
            if sys.platform.startswith("win"):
                os.startfile(tmp_path)
            elif sys.platform == "darwin":
                subprocess.Popen(["open", tmp_path])
            else:
                subprocess.Popen(["xdg-open", tmp_path])
        except Exception as exc:
            error_message = str(exc)
            status_label.configure(text=f"Could not open system player: {error_message}", text_color=TEMPLE_AMBER)

        def on_close() -> None:
            if tmp_path:
                _secure_shred_file(tmp_path)
                if tmp_path in self._active_video_tmp_paths:
                    self._active_video_tmp_paths.remove(tmp_path)
            win.destroy()

        win.protocol("WM_DELETE_WINDOW", on_close)

    def _export_entry(
        self, entry: VaultDecryptedEntry, source_spinner: Optional[ButtonSpinner] = None
    ) -> None:
        path = filedialog.asksaveasfilename(
            title=f"Export {entry.name} as...", initialfile=entry.name
        )
        if not path:
            return
        data = bytes(entry.data)
        if source_spinner is not None:
            source_spinner.start("Exporting...")

        def worker() -> None:
            try:
                with open(path, "wb") as f:
                    f.write(data)
            except OSError as exc:
                self.after(0, lambda: on_error(str(exc)))
                return
            self.after(0, on_success)

        def on_success() -> None:
            if source_spinner is not None:
                source_spinner.stop()
            messagebox.showinfo("Vault", f"File exported to:\n{path}")

        def on_error(message: str) -> None:
            if source_spinner is not None:
                source_spinner.stop()
            messagebox.showerror("Error", f"Export failed: {message}")

        threading.Thread(target=worker, daemon=True).start()

    def _close_vault(self) -> None:
        for entry in self._open_entries:
            wipe_bytearray(entry.data)
        self._open_entries = []
        for child in self.entries_frame.winfo_children():
            child.destroy()
        self.entries_frame.pack_forget()
        self.close_vault_btn.pack_forget()
        self.open_status.configure(text="Vault closed · Data wiped from RAM.", text_color=TEMPLE_GOLD_BRONZE)
        self._bca_path = None
        self.open_dz_label.configure(text="📁  Select a .bca archive")
        self.open_dz_sub.configure(text="Will be opened only in memory: no data written to disk")

    def wipe_all_on_exit(self) -> None:
        for entry in self._open_entries:
            wipe_bytearray(entry.data)
        for entry in self._pending_create_entries:
            wipe_bytearray(entry.data)
        try:
            self.create_pw_var.set("")
            self.create_pw_confirm_var.set("")
            self.open_pw_var.set("")
        except Exception:
            pass
        try:
            stop_audio()
        except Exception:
            pass
        for tmp_path in self._active_video_tmp_paths:
            _secure_shred_file(tmp_path)
        self._active_video_tmp_paths.clear()

class BastetCipherApp(ctk.CTk):
    def __init__(self) -> None:
        super().__init__()
        self.title("BastetCipher — Sacred Chamber")
        apply_app_icon(self)
        screen_w = self.winfo_screenwidth()
        screen_h = self.winfo_screenheight()
        ui_scale = compute_ui_scale(screen_w, screen_h)
        apply_ui_scale(ui_scale)

        target_w = min(int(screen_w * 0.75), 1800)
        target_h = min(int(screen_h * 0.82), 1300)
        target_w = max(target_w, 900)
        target_h = max(target_h, 650)
        pos_x = max(0, (screen_w - target_w) // 2)
        pos_y = max(0, (screen_h - target_h) // 3)
        self.geometry(f"{target_w}x{target_h}+{pos_x}+{pos_y}")
        min_w = min(max(int(720 * ui_scale), 720), screen_w)
        min_h = min(max(int(560 * ui_scale), 560), screen_h)
        self.minsize(min_w, min_h)
        self.configure(fg_color=TEMPLE_BG)

        self._build_layout()
        self.update_idletasks()
        apply_screen_capture_protection(self)
        self.protocol("WM_DELETE_WINDOW", self._on_close)

    def _build_layout(self) -> None:
        self.hub_frame = ctk.CTkFrame(self, fg_color=TEMPLE_BG, corner_radius=0)
        self.hub_frame.pack(fill="both", expand=True)

        # Single full-bleed canvas: background image + circular portals with
        # true RGBA transparency. Transparent pixels show the temple scene
        # (no black rectangular borders). Hieroglyphs are drawn with Tk
        # create_text so system fonts render the Unicode correctly.
        self._hub_canvas = tk.Canvas(
            self.hub_frame, bg=TEMPLE_BG, highlightthickness=0, bd=0
        )
        self._hub_canvas.place(x=0, y=0, relwidth=1, relheight=1)
        self._node_photo_cache: dict = {}
        self._hub_photo_refs: list = []
        self._hub_node_hitboxes: list = []
        self._hub_text_ids: dict = {}
        self._hub_hover_key: str | None = None
        self._hub_resize_job = None
        self._hub_cache_size = None
        self._hub_bg_source = _decode_background_b64(
            SECTION_BACKGROUNDS_B64.get("hub", ""), "hub"
        )
        self._hub_scrim = SECTION_BACKGROUND_SCRIM.get("hub", 0.55)

        self._hub_canvas.bind("<Configure>", self._on_hub_configure)
        self._hub_canvas.bind("<Motion>", self._on_hub_motion)
        self._hub_canvas.bind("<Leave>", self._on_hub_leave)
        self._hub_canvas.bind("<Button-1>", self._on_hub_click)

        # Header floats above the canvas
        header_frame = ctk.CTkFrame(self.hub_frame, fg_color="transparent")
        header_frame.place(relx=0.5, rely=0.0, anchor="n", y=36)

        ctk.CTkLabel(
            header_frame,
            text="𓆄  BASTET CIPHER — SACRED CHAMBER  𓆃",
            font=scaled_font(38, "Georgia", "bold"),
            text_color=TEMPLE_GOLD_SUN
        ).pack()

        divider_row = ctk.CTkFrame(header_frame, fg_color="transparent")
        divider_row.pack(pady=(10, 0))
        ctk.CTkFrame(divider_row, fg_color=TEMPLE_GOLD_BRONZE, height=1, width=90).pack(side="left", pady=8)
        ctk.CTkLabel(
            divider_row, text="  ☥  𓂀  𓋹  𓃠  ☥  ",
            font=scaled_font(15), text_color=TEMPLE_GOLD_ANTIQUE
        ).pack(side="left", padx=10)
        ctk.CTkFrame(divider_row, fg_color=TEMPLE_GOLD_BRONZE, height=1, width=90).pack(side="left", pady=8)

        ctk.CTkLabel(
            header_frame,
            text="Choose thy path through the temple",
            font=scaled_font(15, "Georgia", "italic"),
            text_color=TEMPLE_TEXT_MUTED
        ).pack(pady=(10, 0))

        # Bottom security badge
        lock_status = "🔒  Anti-swap active" if memory_lock_available() else "⚠  Anti-swap not guaranteed"
        badge = ctk.CTkFrame(
            self.hub_frame, fg_color=TEMPLE_CARD_ELEVATED, corner_radius=22,
            border_width=1, border_color=TEMPLE_GOLD_BRONZE
        )
        badge.place(relx=0.5, rely=1.0, anchor="s", y=-28)
        ctk.CTkLabel(
            badge, text=lock_status, font=scaled_font(15),
            text_color=TEMPLE_EMERALD if memory_lock_available() else TEMPLE_AMBER
        ).pack(padx=24, pady=9)

        self.after(80, self._render_hub_canvas)

        # --- Content area for views ---
        self.content = ctk.CTkScrollableFrame(self, fg_color="transparent", corner_radius=0)
        nav_bar = ctk.CTkFrame(self.content, fg_color="transparent")
        self._nav_bar = nav_bar
        self.back_btn = ctk.CTkButton(
            nav_bar, text="◀ RETURN TO TEMPLE PORTAL",
            font=scaled_font(16, "Georgia", "bold"),
            fg_color=TEMPLE_CARD_ELEVATED,
            hover_color=TEMPLE_CARD_HOVER,
            text_color=TEMPLE_GOLD_SUN,
            corner_radius=12,
            border_width=1,
            border_color=TEMPLE_GOLD_ANTIQUE,
            height=42,
            command=self._show_hub
        )
        self.back_btn.pack(side="left")
        self.nav_title = ctk.CTkLabel(
            nav_bar, text="", font=scaled_font(20, "Georgia", "bold"), text_color=TEMPLE_GOLD_ANTIQUE
        )
        self.nav_title.pack(side="left", padx=(18, 0))

        self.views: dict[str, ctk.CTkFrame] = {}
        self.generator_view = GeneratorView(self.content)
        self.vault_view = VaultView(self.content)
        self.views["generator"] = self.generator_view
        self.views["vault"] = self.vault_view
        self._view_titles = {"generator": "Cipher Generator", "vault": "Sacred Vault"}

    def _render_node_photo(self, size: int, hover: bool) -> "ImageTk.PhotoImage":
        """RGBA medallion with fully transparent exterior (rings + glow only).
        Text/icons are drawn separately via canvas.create_text so Unicode
        hieroglyphs render through the system font engine."""
        scale = 3
        pad_frac = 0.28
        pad = int(size * pad_frac)
        canvas_px = (size + pad * 2) * scale
        img = Image.new("RGBA", (canvas_px, canvas_px), (0, 0, 0, 0))
        c = canvas_px / 2

        glow_color = TEMPLE_AMBER if hover else TEMPLE_GOLD_BRONZE
        ring_color = TEMPLE_GOLD_PALE if hover else TEMPLE_GOLD_ANTIQUE
        ring_bg = TEMPLE_LAPIS_BRIGHT if hover else TEMPLE_LAPIS

        glow_r = (size / 2) * (1.45 if hover else 1.25)
        halo = make_radial_glow(int(glow_r * 2), glow_color, max_alpha=210 if hover else 140)
        halo = halo.resize((int(glow_r * 2 * scale), int(glow_r * 2 * scale)), Image.Resampling.LANCZOS)
        img.alpha_composite(halo, (int(c - halo.width / 2), int(c - halo.height / 2)))

        draw = ImageDraw.Draw(img)
        r1 = (size / 2 - 10) * scale
        draw.ellipse(
            [c - r1, c - r1, c + r1, c + r1], fill=ring_bg, outline=glow_color,
            width=int((5 if hover else 3.5) * scale)
        )
        r2 = (size / 2 - 18) * scale
        draw.ellipse([c - r2, c - r2, c + r2, c + r2], outline=ring_color, width=int(2.5 * scale))
        r3 = (size / 2 - 24) * scale
        draw.ellipse([c - r3, c - r3, c + r3, c + r3], outline=TEMPLE_BORDER, width=int(1 * scale))
        if hover:
            r4 = (size / 2 - 30) * scale
            draw.ellipse([c - r4, c - r4, c + r4, c + r4], outline=TEMPLE_AMBER_HOT, width=int(1.5 * scale))

        import math
        for i in range(12):
            a = math.radians(i * 30)
            r_out = r1 + 3 * scale
            r_in = r1 - 4 * scale
            x1, y1 = c + math.cos(a) * r_in, c + math.sin(a) * r_in
            x2, y2 = c + math.cos(a) * r_out, c + math.sin(a) * r_out
            draw.line([x1, y1, x2, y2], fill=ring_color, width=max(1, int(1 * scale)))

        final = img.resize((size + pad * 2, size + pad * 2), Image.Resampling.LANCZOS)
        return ImageTk.PhotoImage(final)

    def _render_emblem_photo(self, size: int) -> "ImageTk.PhotoImage":
        """Sacred Bastet emblem disc + rays as RGBA with transparent exterior."""
        scale = 3
        pad = int(size * 0.40)
        canvas_px = (size + pad * 2) * scale
        img = Image.new("RGBA", (canvas_px, canvas_px), (0, 0, 0, 0))
        c = canvas_px / 2
        disc_r = (size / 2) * scale

        halo = make_radial_glow(int(disc_r * 2.8), TEMPLE_GOLD_SUN, max_alpha=110)
        halo = halo.resize((int(disc_r * 2.8), int(disc_r * 2.8)), Image.Resampling.LANCZOS)
        img.alpha_composite(halo, (int(c - halo.width / 2), int(c - halo.height / 2)))

        draw = ImageDraw.Draw(img)
        import math
        for i in range(20):
            a = math.radians(i * (360 / 20))
            r_in = disc_r * 1.05
            r_out = disc_r * (1.55 if i % 2 == 0 else 1.35)
            x1, y1 = c + math.cos(a) * r_in, c + math.sin(a) * r_in
            x2, y2 = c + math.cos(a) * r_out, c + math.sin(a) * r_out
            draw.line([x1, y1, x2, y2], fill=TEMPLE_GOLD_BRONZE, width=max(1, int(1 * scale)))

        draw.ellipse(
            [c - disc_r, c - disc_r, c + disc_r, c + disc_r],
            fill=TEMPLE_CARD_ELEVATED, outline=TEMPLE_GOLD_SUN, width=int(3 * scale)
        )
        r2 = disc_r * 0.88
        draw.ellipse([c - r2, c - r2, c + r2, c + r2], outline=TEMPLE_GOLD_ANTIQUE, width=max(1, int(1 * scale)))
        r3 = disc_r * 0.74
        draw.ellipse([c - r3, c - r3, c + r3, c + r3], outline=TEMPLE_GOLD_BRONZE, width=max(1, int(1 * scale)))

        final = img.resize((size + pad * 2, size + pad * 2), Image.Resampling.LANCZOS)
        return ImageTk.PhotoImage(final)

    def _on_hub_configure(self, event=None) -> None:
        if self._hub_resize_job is not None:
            try:
                self.after_cancel(self._hub_resize_job)
            except Exception:
                pass
        self._hub_resize_job = self.after(50, self._render_hub_canvas)

    def _render_hub_canvas(self) -> None:
        """Paint background + transparent portal nodes + Unicode text on one canvas."""
        self._hub_resize_job = None
        canvas = self._hub_canvas
        try:
            w = max(1, canvas.winfo_width())
            h = max(1, canvas.winfo_height())
        except Exception:
            return
        if w <= 10 or h <= 10:
            self.after(60, self._render_hub_canvas)
            return

        canvas.delete("all")
        self._hub_photo_refs.clear()
        self._hub_node_hitboxes.clear()
        self._hub_text_ids.clear()

        # 1) Background (cover-fit + scrim)
        if self._hub_bg_source is not None:
            src_img = self._hub_bg_source
            sw, sh = src_img.size
            scale = max(w / sw, h / sh)
            nw, nh = max(1, round(sw * scale)), max(1, round(sh * scale))
            resized = src_img.resize((nw, nh), Image.Resampling.LANCZOS)
            left = (nw - w) // 2
            top = (nh - h) // 2
            cropped = resized.crop((left, top, left + w, top + h)).convert("RGBA")
            if self._hub_scrim > 0:
                scrim = Image.new("RGBA", (w, h), (*_hex_to_rgb(TEMPLE_BG), int(255 * self._hub_scrim)))
                cropped = Image.alpha_composite(cropped, scrim)
            bg_photo = ImageTk.PhotoImage(cropped.convert("RGB"))
            self._hub_photo_refs.append(bg_photo)
            canvas.create_image(0, 0, image=bg_photo, anchor="nw")
        else:
            canvas.configure(bg=TEMPLE_BG)

        # 2) Layout
        node_size = max(200, min(280, round(min(w, h) * 0.28)))
        emblem_size = max(140, round(node_size * 0.78))
        gap = max(30, round(node_size * 0.22))

        cache_key = (node_size, emblem_size)
        if self._hub_cache_size != cache_key:
            self._node_photo_cache.clear()
            self._hub_cache_size = cache_key

        for key, hover in (("gen", False), ("gen", True), ("vault", False), ("vault", True)):
            if (key, hover) not in self._node_photo_cache:
                self._node_photo_cache[(key, hover)] = self._render_node_photo(node_size, hover)
        if ("emblem", False) not in self._node_photo_cache:
            self._node_photo_cache[("emblem", False)] = self._render_emblem_photo(emblem_size)

        cy = h * 0.52
        total_w = node_size * 2 + emblem_size + gap * 2
        start_x = (w - total_w) / 2

        icon_size = max(28, round(node_size * 0.16))
        label_size = max(12, round(node_size * 0.075))
        emb_icon_size = max(28, int(emblem_size * 0.42))
        emb_label_size = max(11, int(emblem_size * 0.10))

        def place_node(key, action, label, icon, cx):
            hover = self._hub_hover_key == key
            photo = self._node_photo_cache[(key, hover)]
            self._hub_photo_refs.append(photo)
            canvas.create_image(cx, cy, image=photo, anchor="center")
            color = TEMPLE_GOLD_PALE if hover else TEMPLE_GOLD_SUN
            # Icon (Unicode hieroglyph via Tk font engine)
            canvas.create_text(
                cx, cy - node_size * 0.12, text=icon,
                font=("Segoe UI Symbol", icon_size), fill=color, tags=f"txt_{key}"
            )
            # Label
            canvas.create_text(
                cx, cy + node_size * 0.16, text=label.replace(" ", "\n"),
                font=("Georgia", label_size, "bold"), fill=color,
                justify="center", tags=f"txt_{key}"
            )
            self._hub_node_hitboxes.append((cx, cy, node_size * 0.48, key, action))

        # Generator
        gen_cx = start_x + node_size / 2
        place_node("gen", "generator", "CIPHER GENERATOR", "𓏠", gen_cx)

        # Emblem (center)
        emb_cx = start_x + node_size + gap + emblem_size / 2
        emb_photo = self._node_photo_cache[("emblem", False)]
        self._hub_photo_refs.append(emb_photo)
        canvas.create_image(emb_cx, cy, image=emb_photo, anchor="center")
        canvas.create_text(
            emb_cx, cy - emblem_size * 0.06, text="𓃠", #0.66
            font=("Segoe UI Symbol", emb_icon_size), fill=TEMPLE_GOLD_SUN
        )
        canvas.create_text(
            emb_cx, cy + emblem_size * 0.32, text="\n",
            font=("Georgia", emb_label_size, "bold"), fill=TEMPLE_GOLD_BRONZE,
            justify="center"
        )

        # Vault
        vault_cx = start_x + node_size + gap + emblem_size + gap + node_size / 2
        place_node("vault", "vault", "SACRED VAULT", "𓊽", vault_cx)

    def _hit_test_hub(self, x: float, y: float):
        for cx, cy, radius, key, action in self._hub_node_hitboxes:
            if (x - cx) ** 2 + (y - cy) ** 2 <= radius ** 2:
                return key, action
        return None, None

    def _on_hub_motion(self, event) -> None:
        key, _ = self._hit_test_hub(event.x, event.y)
        if key != self._hub_hover_key:
            self._hub_hover_key = key
            self._render_hub_canvas()
            self._hub_canvas.configure(cursor="hand2" if key else "")

    def _on_hub_leave(self, event=None) -> None:
        if self._hub_hover_key is not None:
            self._hub_hover_key = None
            self._render_hub_canvas()
            self._hub_canvas.configure(cursor="")

    def _on_hub_click(self, event) -> None:
        key, action = self._hit_test_hub(event.x, event.y)
        if action:
            self._show_view(action)

    def _show_hub(self) -> None:
        self.content.pack_forget()
        for k, view in self.views.items():
            view.pack_forget()
        self._nav_bar.pack_forget()
        self.hub_frame.pack(fill="both", expand=True)

    def _show_view(self, key: str) -> None:
        self.hub_frame.pack_forget()
        for k, view in self.views.items():
            view.pack_forget()

        self.content.pack(fill="both", expand=True)
        self._nav_bar.pack(anchor="nw", fill="x", padx=24, pady=(24, 10))
        self.nav_title.configure(text=self._view_titles.get(key, ""))
        self.views[key].pack(fill="both", expand=True, pady=(0, 25))

    def _open_cipher_in_vault(self, cipher: str) -> None:
        if not cipher:
            return
        self._show_view("vault")
        self.vault_view.tabs.set("Open Archive")
        self.vault_view._on_tab_changed()
        self.vault_view.open_pw_var.set(cipher)
        self.update_idletasks()
        self.vault_view.open_pw_entry.focus_set()

    def _on_close(self) -> None:
        try:
            self.vault_view.wipe_all_on_exit()
        except Exception:
            pass
        self.destroy()

def main() -> int:
    harden_process()
    apply_base_appearance()
    app = BastetCipherApp()
    app.mainloop()
    return 0

if __name__ == "__main__":
    sys.exit(main())