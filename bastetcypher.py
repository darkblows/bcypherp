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
import contextlib
import re
from dataclasses import dataclass
from enum import Enum, auto
from typing import Callable, List, Optional

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from PIL import Image, ImageDraw

from PySide6.QtCore import Qt, QThread, Signal, Slot, QTimer, QEasingCurve, QPropertyAnimation, QRectF, QPoint, QPointF, QSize
from PySide6.QtGui import QPixmap, QImage, QIcon, QPainter, QPainterPath, QColor, QFont, QLinearGradient, QRadialGradient, QPen, QBrush, QAction
from PySide6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QFrame, QLabel, QPushButton, QLineEdit, QTextEdit, QPlainTextEdit,
    QVBoxLayout, QHBoxLayout, QGridLayout, QStackedWidget, QTabWidget, QScrollArea, QFileDialog, QMessageBox,
    QProgressBar, QSlider, QDialog, QSizePolicy, QComboBox, QGraphicsDropShadowEffect, QGraphicsOpacityEffect,
    QToolButton, QSplitter, QAbstractItemView, QListWidget, QListWidgetItem, QDialogButtonBox, QCheckBox
)

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

def apply_app_icon(root) -> QIcon:
    try:
        encoded = _APP_ICON_DATA.split(",", 1)[1]
        raw_png = base64.b64decode(encoded, validate=True)
        pix = QPixmap()
        pix.loadFromData(raw_png, "PNG")
    except Exception:
        pix = QPixmap(32, 32)
        pix.fill(QColor(TEMPLE_BG if "TEMPLE_BG" in globals() else "#0a0806"))
        raw_png = None
    icon = QIcon(pix)
    root.setWindowIcon(icon)
    root._app_icon = icon
    if sys.platform.startswith("win"):
        try:
            ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID("BastetCipher.SacredChamber")
        except Exception:
            pass
    return icon

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
    try:
        hwnd_value = int(root.winId())
    except Exception:
        root._capture_protection = "unavailable"
        return False
    if system == "Windows":
        try:
            user32 = ctypes.windll.user32
            hwnd = ctypes.c_void_p(hwnd_value)
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
        target = hwnd_value
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
        root._capture_protection = f"linux-{session or "unknown"}-fallback"
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
    # Extract as MP3 so pygame.mixer.music can seek with start= (WAV does not support seeking in pygame).
    ffmpeg = _get_ffmpeg_exe()
    with _video_input_source(data) as video_path:
        cmd = [
            ffmpeg, "-hide_banner", "-i", video_path, "-vn",
            "-f", "mp3", "-c:a", "libmp3lame", "-q:a", "4",
            "pipe:1",
        ]
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, _ = proc.communicate()
    if not stdout:
        return None
    return stdout

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

# --- Sacred Temple Color Palette (museum-grade dark mythological) ---
TEMPLE_BG = "#060504"
TEMPLE_CARD = "#14100b"
TEMPLE_CARD_ELEVATED = "#1e1810"
TEMPLE_CARD_HOVER = "#2a2216"
TEMPLE_LAPIS = "#081424"
TEMPLE_LAPIS_BRIGHT = "#0f2a4a"
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
TEMPLE_OBSIDIAN = "#0a0806"
TEMPLE_DEEP_LAPIS = "#061018"
CURRENT_UI_SCALE = 1.0
RUNES = "𓃠 𓂀 𓊹 𓆣 𓇯 𓋹"

# Set this to a raw base64 data URI or plain base64 string (PNG, WEBP, JPG)
# Example: "data:image/webp;base64,..." or None for procedural temple gradient
CUSTOM_BACKGROUND_BASE64: Optional[str] = "data:image/webp;base64,UklGRrJJAQBXRUJQVlA4IKZJAQDwqgadASqIBq0DPtFiq1AoObsxJXG6o2AaCWduaMQqg78H9/iTbkhvoxVHGY1/43hiqz7x12/+5uX+z/8znc+Gfl+Nj6zr75be4W80H9D/73UD/8PLB+37zFxX0RtX5D//f+/2L+Pfr3///N6OK//XJ778wf/+9s38H3vraH/+T5xvmf9h4G/nX3r5+PZ1z19wmqz4d/8vvd+cH+f4i/R7Ug83eo/Fn7T/rehT8Y5O/7fpJ+v/8v2HfOXym/63pV+jb/x///1d6oX7YkmQyGutDwnjo5JXV3wjLT9YUrP0PNppEXK1G7kW6AT/B/lmO8EJLobOp80AI/MtA2N3zQAj8y0DY3fNACPzLQNjEkSpg+dCuTDJURysFaqFj3ZkjJMt+kA1T9huO89P4oyGsWelDQlvPwMkboNb8K/HWHDE67s252rm7JIvl+j8otlwaT87JdwEOOgVcL0bEimgL2da6tROZizB4weiWuG4qXIdVjmDJMpwDQAxfVajJSIC/vlPevTslfsHEBobQ6UB17i8++CBdM6ITFQrzNO1DniiVpDEvr/p6YwcNboyoNMCjIlvDLBySKgaAml5jp/IAmp7EfcvRXhGXzrjGY/w1jJxey7p+pzNC1YeC3Q2cuTfwDOQD1ZlP36nJnezF6jjzSHvkBXUbzajJMu9SuwTLgRXTvJOgRFN8SkQG9w58wGaQPt/FxSKNDZ57rxDQpEppaUIRzvJfPVMeqmnBrF8qoXhMcxqd/HYeSX9ubr4juSMO2X6QXVgzdZKQlbSho2fBPkc/KvY1rUm7w6gEtdWXxT9iHqGnRL1KVL9ZUbG7+LnvxbO0QUQOYxj+iy/hc6DrG6jc+G5O/Fhc62CbRiAJZZXJKazLi+s3epPatn7dlIM+603j/Q/TYPJVsZpHlL73sMzCVGdA75Rqa0w5bAtbHI9hRIGiUop/HleORMGzyBnSyNtvrFzv9s9i8dpdEA7WXDTL6nY3xq5FIfiW0mMcf53BFfVRFGP387VuWPRUUizr+pwBGoGkmd0TgbLOl5hJYB15s4VACPzXp3P2oQilB3+vpZSr1OZXqz83/UjadKn29OnSDRAuuWtJ4SrUwpeG/NNJEAXhaZIYnoMsUJRZ2BCWDwVUW5rtIijy70NqL1mDG0B7a1kK+FWMiWOOr/mNjR71h8qN9ZXEx/LHbupL5g/aBl0F05At+A0jmz1mtofByrPGdvdZ18yMl71blt4DHUTqKtNAmkuISKktYyNtezPWrQA27psgl6UAyCgEmU97NXtRqZ9sGSaYk5inqLSt/ZSR3dFRZempovtXoMpYRBSwgf3MHPIpyJxOea10W1GkuWbABPivy7XjqBrrVf5actqRJA7fzQe/qbF9CFzcjG4RCwN3LH3rikGHPFZ4a4rxjjDHK7Hl7nYSNLGj5rhv2aYZwDsRtopNfOUwKhNRJD0A3ksYj2HOZKtkNpI3bPzXp+EBkmXxJkrQAyNU41MYwhhH0yo9WjzFdJH2eDcoOPEspmRXhkNWXOw1Eda/tB1zcEU2WVfsb9QEMLcxrFfHs5qm9a24akP0FEZUChpW0Y0XlQEX3FZd/ZJlvKuvnD5A4AbaVf5pM+AYF27GUkrGe7kp74LilRw3ejjNQEfJjDy4Y0UKos72Me+dsdIgGUFA0OGXKfC8Dt8uINGWwtmkJixFzT2n7kfCCZForFWDm8CAE6Uxu+aAGBTLSTiSR9tIbnBFj7YJ1I+vRQH7XZnOqoISQM0/x6ule8MTCbDZLbspswZq60zMZHvA9WqPiYSlJE6N9E76XK1i6TQBYMC0Ybix6xHK8e1EZxTMzwiHIiVyqdmH5HHfUT2Mq/ewWJ54XCwtKLe6G1yg7asyzMCMlgXk3RLGCwWoei3RRwvosWugogYcNiDRKsuHB3wAvz0AMynC3wmz9wXa2MIJzJoU0HqJFyVDX4cFe6i9lbBJhCuhdlCI4DgQjtkz3AFNKWYKk69Nx3Tyc4EE6kSX6LinujLyEzl49w3I/8XF1gfHn/5YQi4fnuKAMnTuz7fiPZJyMHGvUoIouCUbEOcyNvW3WxXdxqQ0Py2hbIOmK0Y4MQ7RI9Fmwlc5D6FkvSglVwHxerTf0dnmOZjWxw44/VN1N8X7Ik7NSCVw68GFoKQaAEfmXz2CZd6wq+yUMpJoJemvXsoR9pAjE6lrNGv10x1nDZld1Esz9brgnMxk5O3m255pMeO1z4CvzQkxdF/R7nNFQZrLSICCvyyAQErwGzNPgpGEjERLGn+T5tznrQlV1UiE5JL9ULW16xjVka4RRGv5mGde0dIv2Un6iHZDPBgpRnSbz2E5xi0d8IcyytQLCxL/mIxfQsspWGH3OqQga+4cmVwYC42lDKwkvRmMifAzFwI/MviQH2KgbtMGlHhmv/AMYn9HDwteLrrDtWRCdnraV0hyVjbQ2SGfZn98xG49pGR0UqZtEu8btf94wVvetLwu14e0oBCIPtMP0NEcZNh4Smubt1kR1wErTRE1aC+mL8/LzGQxpITHvS8CUTmSNG8wQR06yIB5P1wsjrAT/o4oCtDODM3oTxuj7pecxxd3hZ5Hqls9L68wCfs42nC0anDmAha3DWLD9MQJOahBU2xhQZy/R0AECUklB96rIgbG75siWBg07J9xtIRNtz9Tfl2R4pYOgTWwarDE+rNsZFWyvhYnWoVcYLCvgQgfpcWQjmcgBzz6qrrYPsVxaFPnyT5IZM9R0qOVKuo57KHR+nXU6w19Q7rbsy8/Hc8imKt00EBLzk0Qr+xGa258YjFzv+AwL5MG4q18LbmFrQmUgDnwrl1eULC4JsqgwolXyMMIZ20a/HZQvnfR3aRktZq6aXKdlxvbFCGLa+htuZu8O9jfoj2GPX64Rjr/7OUjH7On2SBnB8WbaKxLQyA04AR8XlGfzUA1HDp9isYYHgREqpgE21F5L/uvS8im4AG/sHGgta0poM/CxNCl/DckcNblymLr/h4bIlKQP59UU2v0h24BpzGrVj8yfeU4QPKlwLwRzALdWJDfOQDJ+ymkEu2n3q3iI6HTzwMeeHFtatKE4j5F1Yq5ous5MBu2YTkfUSlOi1v6AdERaGuRfyxelo+ySxqjVQ9uHnAvc2rEK67IObSn0jRBDOQiiDJOveA57suSpUZfl/ca9vA1IbK2CFMfGDZ6u5W1JGsuXzIVaClcO77gXpDwifLKCetT1gAFnQJe/FsOYru9OkUmwNszoEeP170XgFcxYyCbQ5tFAXTSQuUbVyYqEwhd5tWEW4O8rvAx6O948NcQWPhEedUhjhaXv5jLvgJnw/BOk1IuBj9CBSvz3tQf/jtv+NYDmlK4XSvi5mFpDwiA+RjFDGGd1SSCW4wwFg7Tm9hxAzagWkSw2++it0NXKX1EC5rV1Y838kg0AI/mP1eUoCORFZqkITUCE3rEkXK6baZPV05HvLo8RfI+5/k91myBdDq55ymKVjse08zmin0arSaIeRHBZNnUzTFvMy+63ge19QxR8WVJS9O4pUriLOgxF/RSI8fOMEuYxvRdnQmw9l68VBccr99CPy5vrKyCMWLnFW2RHr/Kujp60KM0Zz1Ulq/vhvcG7uSKjkFTGFmLLBDB6RqfiBJ8eTgRd61IKVERGSsdMc2meGNPnKJqhPHR4u/NWnlvohMnqECUxl+kOGhwAiEIttYNelPywTghY+QSL6kLMirogpkqwSfIMQcoCeLopLoM4INJSPUvZ9ECGZ3O4UWig+N274gxCv7vGWp3w+OqGqOf6CCNOHwP14s9Cx3fAiPfoU29YqGA66K6CYQoIQWaJRAV+qjgCrkNxq1nfibOh0o03LSQLsKQcAI5n/vazQzHeta11Tc9TYZxg3d8EdpNk7uwBtItd+SpFRW7Mwy8UgncuL/DE1cxIQLbl3smmiwG8YNtcT+d3DT/Fnwvt5YZF+es9WGSLMRVBRfysnLSJAVmznURlf5GSixgrvlhXguuj2pevIVom/AoiSuOjLLvZuuXiCbB0Xe0o79PWf9vV7stfyBjbJ3UwxABKwVngFMy/l+EoWfNcPxTPNJKHfoSojgIZHKCtyJLGL3aj0l7rkaLXlV2RvXj3QAQdQAYWY7cHPlcqJmgXzus5b9Z1M6DSA/mn2YayufSgs/8H4wky+0uhgX1ETxr5qQg8eTTWuGiQ1/nztE2RAt2gD37LYnaZiM+GgRELr1kP2aJEkkrMCavKnaHecZB6CHvXJY0OXqWi9tJ4bDWFI0fDo7/zzRLGS31MORlM3v0kRdUzGkE18yC89bOq7xKw7WnqfEVusMhFFdKlHpaSUd0B2w64IgzYv117yzXIUnQNeNi5bKmeHOceZuBJMmpWbfypF4o8VwZIULllqgv4gApe9Ourv67bI3LQ7RgwfEihKQgP1OspKIjHMWlyUEDy1aY4wrn13F0bMv6hiwwVBUGgOuHOzdavzKwT0S3DYNmXJ2eiXYnJurUZcaKD6XB1rA78H3QxYt290owu0hK1UvWQyQL8XXy2ZgzaJyhn9IHafOeh6seMqxhJh/IPaldx5J5uiIY4y4LTVt2GxD5a+pIsKncGDi4RTCY43TxMyUJ1ehGt2bdepKrBpuVZaLRtYzgpUZxzp6E25xOXTsRd2tBUGVDMhICgl8+m+nrEeLPaovsxDPSUZ9odNj3wMpchkd3BCLSXAngPtEIFjq5DtNcK9gaD6Gjl9pbhFP86u+2Vff4HNq22jVRgkG5FUB79cqsnriDMIMjF0W6dryXUYIIpcYGrkoeyXUw41Ic8J4eYOF3SGh4XGwvU0gwASze3xqBt5hh6oCKbfrADU4EWLgq5u6njd7kISZ7e44pwNxZHHkAN4S7s+jUf2q6LY53wAnAC1UiOyRXL6AMgZwUvzCclRAbBZaKtXxYUcCBgiL4NF18nFUZVwZYL4cD8VqZ/jUF+1qhrfW2hFDBCDQAoBuiEMQqXIlYAYW3uXwyWcUUt1W7nOgNErLL3+lVTr3Dhi57DH9dR8uf/CZBTB+wftfC6A5pT8tnKC8RbloBsvr3eYJmiI99scKp8Ug3G3aam6bFIhTiTtEfRpVBGEFlQlimiIn30B2Ol12u54zVS1QAMDGUvG2t1xmH/wsi59enzmMMUwKdOWpISwuaOLx/Xsi+Iwvu+snVTBtaqukI4ubOhOSGpiC25/QwO+gbLGQC1b2RqQxzO44n8p5lZf8kt9Eoj/YduPlR7sFkDOktYthtsGX/JTNveAsjXjgBkHPYiq2v7+jCZPhLmKcL5GkOGC4bawgWXWo8UkFYyJLM9l7s9J/GJK7Hx5029NA1T6/NfQD7SRtw4HwSj8BcL91DQfYqeuMX9DnSNK/KJorBJXCRI41B6KCRhVw0m7JVt3ONEio8uO2uXFbihzXzUGSVY+QBaJD/2imU5sluurZ5k34kL7UhDQKBXlEa+zuChdzvNPKnKF3/TLP0j9agM3N+7jlgLAfns22bfxk9Vqxlof2vlrI2d5iVC75jIJOBRBelwk+Deq/pkVl+sajtNejUH4Q8uyQ5oj7teA7T7BGGcVyFLuATls7E4eBO8FiD6w4Dh7RltT0apjUfvV0IP2lBQuheZsi7d82Clb11y3ta56s4UEUVd0r+jgevTEJh5lV5dVu3xoZiakh9eEHlX17cKiebtkhRjjBZ4DscKZ17p8N/5BDEOLf3zSn/EFv+GrXbaFyhfxNRdDn3ZwYMOsLWDRq3xf059C/Yu0Ny/YAGgXRYoJ90NWY3wJ7AbiBPGQSymYBTGjmAxQH5r02g+4qyNE6L0NCAU7fNUkSY1vMzKRrRu8Q9LUjysff+3ZYqvcVaYGpYbXlf6uwPZDAo5Q5wUu5fIV4FmelfF1bGRDj7D1bBWY3tdLXK+1aVxhEYph9BhFeFL9gRJ3xUW+u1V660yjPjX0VwXG9wpRAJI8F9szBUI/E9aWqx7kitc7tXebZJm1zktqz/A/zrpPvoGZd6S9+B3Ze6NciofTnT7gBbOvqyLiruPTlWF24dfcJZpM+qvSbjF1PR1597Wc2m28VRwWVx+7lfrh5BGIlSWjHGpNsPUnnkXXNu3TE2gMYSRMV5VpgVnMr5g+ODw1ItfTdNAuCMEa9CWtWDMvNFxIsKts4k3IDJaQ2BGW+oz/JtdCTXf+bnjWO4BffhOdnEaH2zF2i0IPmzTO1Q7+gHWrJ4K6vvn3doZlDBOXTv/PVzxFNuYU8NiIGoBILM6DYA6Ae5wtbI2BWVYcRTODXUfAGwhzDLSBk2z6oIKYVnt2uFU2AEPRZ/MD7lgolksEu3KIJhpXFPJlsezRTjhEawDUiT4Y6w5+RrVk1gUhwiROFPoRpypetvurGzn1VKSW993kk9CBpdNvl2vHAn9+yIugajaA3mUiBA3A3KhZXDADwQsdFOhvBDAFGRQY830ayXLFsjUj8YlnEXeIgbfVFhG2Ig/LqbqiH3Bu2B5it875mEu97Umz4R3AGcyYtjZecO2e9b6WfohqGMvljTOGXHf40gIYXpx7shRiCGSt5FKRS5q/wxOIjb9TfXA2R58ZOCWebBLOgAWKehyK1tnSa6Oj9nwISNHVCTnxZuhTbu2Y226eCililiJtedEDv1cg+PyiOKKa8hYFvcDUBXAw1vMZgsZWKBaYd/Mfv2QxWKc8FRNverO6x0fduAqCE1N9FBKSB2ksa1KzSMuwdgLp7RoKtxAnBGAqic/aLPVUXh1z3pIZjyumU1nhFWUevM8oazIrZkdPfddFsVITrmOatGA+XQk5tr9hijCjn4BvC1Soxt1nYU8Uh3RNOEhRIObKJovYp3i1OcyVPRknqcDQC0kXHxoySV0rGeliqBLW224vVFdxbzyVkb91A6UlKXk7P6QuiJDcsLX64+MgTsYblMfdxdOCURtbm826oxvrm9DlgMF0thnYtSPNara2r5B+8JU+2HoXSq7QT+5S6rd5nTFEXtLLYU1FNsngIG2nZ0QucupkFGaJ+L8o1GBtwN7Wx9uoDKs8Y9vu+eVIgfzYCPDS8/a1JIohlf69aF4nkrPoqMvGCXMOvlvTFV1nYnK4oMeGHK08eAr/C4EXjTRFlDpbyFmOXpyfAyo+rMlMlAZhETqVzQDozUAwgLpJ/rfWeVOq03hNp98TfFRcmmQh6R/0L8Th5zFXhT9EFxVcNKImDVkCq8gXjFUDvErgfna736s9Va93Ni1KIAzfdkr1E5QBJ4kdt6fupIa0WdduPoIWarbMBwpq95oMIB4AUjqWsAh4U8r93kLYRSFP/LKK0tuTbisjfCUMF6MfC4yMOIsGK+iMe/sVqLqq0t5YMxyWLIsrNMb26KR6rYx+9Ax/TbysnqJ9Ron1A8FH7eVUP5GlfqazZF0eoGtZcAXkL/0mwatdtXeCT4oWBNNetu0gtcG8HdwLKo/KHErHCF5hbi9wWJvQnNuZu82cM4aWioXowFzBGkzzCejjyg2gULLc0tz+IUjPO2iLaagbZmTfCw77GRoULP85AztKpkrN3hOHRL5QfRPNgRLAgRSN+ISoE7PR4uxWXs5gX8B/mEguo5GMQsof3VrNuy+q5RGmbmJiT47egn/U/o9GfxwSUOXt0j9vzo2Ch1TTpQPCxWsExRZ7cGqlUdVYCwsBEmu7HjoSYlnO3UpvTJvZJmyH6vLcnT161eFe/SvCTrBHsJTACGgaWj2yGDmisTs4Z3LICTdlH4nwuUzxwdEKQ4C+rvz2e/jYCKowBwcdTSFpnzgxVlun9Gd/24dYsWvTdoRcRv/73G8HLIA+W8yfhLu5w7JRAgVHX4Inq92jxgOVfFExv+xxff6vCW5TDHM1xO25VPEdacwqCEp9YxrvBhxQSM0oyyM2j+KSW3+FoAJtCf9JXodV1M+9VnhtFIZXLDw/JN24EtGI24qn8PNMv5Rxe0gg8tbvCoHGAJ5BvRun9HZ0kcneEspGlsgHWxFZ+TBDG7EITn4WiOME2CR/5xBzY5GB3HI2q/8b5vfMJ4FZTKjndf8S5NTXQWjP6mcfjICSXM+YOtoxSjBwfhT4WPNafw44TOD5Dh5JRcXf2foTEvVFGHL7wLmEx0FYUL6BMggY873tmUwq5Fuv1x+SKs22bwsb3NzVvyob8SHhhP0QlqOv40rJNFX4fszcxQmN7WQNl4pmUhjYcLnIKSAfO3623d9HOLIFl5adhg3J3zJ/NkU/50c5VJcmy8SAn01XfwLtyCDXWOzvIh8uWyOwWyhPvL6gyXSNSsgA4g8K6Mp3L4NGn672huyqFm2cFhxKBv65La7/G0ZaR7Es53J8WU0LkekLriHz1C3UbMGa0Vv+lM9rblKppMfRnKtAWFUXvx8p8/9b0oGfCFHfRK7VjXRgXgPL3XmJ6a1ri4kIivU3CmYooabQxhoV78RVDQnS6JXFQUHJvEgE2eSecFDAK3vZ5DlUlACUhISbayPUEwR0G/Y8GyCJA6JMrZvfM7ZB4EbXHWiNjMsNWxnoSGIM6QigArWOlQdENzFsj/TC20RsDF70ptGH6y4HVtRUN9SgB1K3EDLNhDtLpQa96afXYdCFx6kaCil+x8QgFwNcEkw8Inofo22E8+xB8xpe5oSceegwDCVKYQ/eMTLgy4Gf7W6y+1vJ+TMKsIEhcDxCWS+OzsISRBsNrA4hqbpH85QSDYhM2VrVUR6xqjZdTEqyMlCGaGVBWC68yvMwVBvwg4maRezi4fvD6jyfPuVSQnleSbiS2RPmERxQZoHDuLKIdxjc30Dq+BewExgLuZJA/9uXbKDuzXEflPVqSdCHcOHj2Hg2XAAdfGlexkqzPIqbcrMP1UtSvJGuTs50LOxO6oVYUers/gDFOmyh2INwy4van+x/ZND1PNVyy6RZOJKVW3turJGCibs4WJN+OSnFlpIPTqbttscCPPORQSYdxB8IP64whwle096/2eZGqafMRs5wi9/vD6c8njBEhhTcLkgR9ItCHDaSzdj9hXbSYWC7wguxb48YZIIs9q9t+92A/Z9V12/3aC6sQDNiW2yglFEQ5kIlLCp4/3FE0nHWB0ZTczo1Amv1d7ulUdE7G9S0vNQuIsLk3e1qprhcG2DS/OLe0kk9gCNZeyCVlhdCpfVWoGs+AW//iPsLkJRUFlflGbTCgJ2pkw+VV9vZQE7Up2NfZVwWRT0SYULM5lGCCfUEBqg+XCC3I8Sk3FXhfi2sp3n2xAQpQyyIJA+U7A7Lm69eW3NmJmwBC9PNG1Ktd4KBlrO4cisiiHcUwGEZC/HomXO47Y4bgxPPoDKppxomLq8WBjLw7dSs7UTJdAxTknCSZzWHsw2MciLLfzFHV57hRDPvAHttIHKdHAvoH0dbVE79HvIc617bRl1mNUTCmaJ6DHfxQHDjkMyW3cM/+Jmdenok2RB44SSYtYpe2Lq7VzxlI16ovPHioi8oCKlFUwho4pehaHKJGV7Bu2a4nha1/PiLA15ZOLGyHCyyjTy2vxagZJIKmPTF7BPkwEdRCLPwS/MRZYAvamfYLJtslq0sMF1kHmABIn6Kcy5Yoa4MDqBlKqtXPZxOw6hS6ZjkDTQUE7NioUsHC3wdWS8uFAYiwSDaz7FsZnW6C01ROy78kJeUmH0Gti6Pq2aDy0fIu25GOXOIoot8VU76sbch+/fuqfo3kF8Eax7ixwjRwX2NGIozXpH0Spyq1yljEIgnB7Ko7dtHtFziGGDH/qf3PqxIpbYRQTdUturA1xGD32FAHp3mFDB2lOu8ZXOWI7YUdSIO0HuLI9TI86z1i99OD7dGM5Ldw4Gikxg7Z5oYom3cwMBuEO8pLtLVjQ+nNkyfQnLu30+1aajROgcYbnLzvKpfBzwgjX8J4IclHhJDDCGPd4mZJvf7cNSczWqQEhz7hFCj+6XRcSt3ZFNTv+O3RDkcH2bo2JsDx6RtXrpATWukO54zQvk7cESWjSYAUQ9ZohPPXOf9rfWgr1OnRFP/7nfN3L6lQydOCq/eduZdSeaM2BTvU/OewzhV5h8/zPmJsJ7t3ViGKVzDkiP1cCo6/sJUwjfK2cylthAaRZkQzA7BhflOvFKxk9Sh/aBxCa++xCoIsrFDHqa8tYIDSonKldpCt6eJkoHGHOLF+X4V1c38SFrT192uTcw5vVtKRyax+dhduMO69myLZvcFwGZuGkH2eYkRAv5ETCITDI3TYADCflvlPYjwZAfIfPkQKO4fyJ0ZAfSxP+GRqDnthNdBN142u2Coo2dudry5wuyXC3VNKmD4mDecLBeEHtCaAm5E4JVvZe/HaxglDn3HZKB2CLwc2R5IXjFNvi9QXeNI41wJGh8RUQKbEWenmiyMrMeL6HiFEzC15DC0lAipiD10AKg3PVb0HVi+4HPc6PpIQm3noI+vi5JG5JqtUWXt3dFfhoods5eXfFfbn7qttkz6beK/2SPpNkPwtlk6mt/DKJRjiwfYy/8s15Odl2i2OtzlhloMbbhF73m5l/Yt0qQflaCRXAeN2Ngytq2FYbB8qSz7ZUCcHmlYCcO07qX9hRnqy0hujI1lLa5DmEVegFXH4AaB8slooeOYwS2BtlvUkeBarGeMp3RybsOqCaltUR7U7bK/Jm07QLUNdW14WmC8CIMd0lmBQ7wmcvllHYuYcFht69TMwIh6tFW1la+PcbFMUZvKTy3OusF0vy7wzBpBAgq1PTMRkgjIxThAUEP6wwFuTgvUQ5J6dEG0Tlcpp515+8OqT2pSbeWxSMmlERdXI1sXKDOCc6OF3cWv1O3lpYmUgUevAnRQLz9ymsodLLzsLNKGWAhtQh9Xk0vrkulrM631+CRIdUlRY0IgITsYlKVB5X70Ns3B8GdGICCdKiKrcz24g6QShDd3nW1LfgC0c1KRKQeps/HXjqZ2uKlRskZFQLSzynMQcTfMziKLDiGykis6x/qqs5M2v6ZlgpDnuunchBJ3WnP824GTqcMcHWOlYnVaEZLl0dT6jl9QtYyVdwPyQ/WPgZ+K7w3Y+7+SkzmXF+XNCtbtBP7rnI2IkV1RlHhcRMRMKMqCoyMcDHWDa42aYyAZIjJNdcFUaOP3B7DNnwAV0CaNyserv/iEcuSejV4ZivCRk/VSDQC19WrmtjpSY8KUTFWLectKF0jl1NVf6PvtHJQ+2JMAwI5+6riIXfvlC3ksu/tiiKxXv599ekWKBlQVJa81pnmFQkx40JBWaJNgj4qAFya+1KhNynK7yTtLCyVVhDCZ8pTlw3Z/6TvoqGoY/cX/ztJPuTaG334UxLFrYosHKjUnmHq0lmpHaNsVwVROqc6EyI2v6qJ2nGqqkzzmUcqjQ8qrDNEjKaM7t1Bod1QZbTf6YSjL3Btid/ZkpIPyqyhWIYo1Vpz+kEOsd/mEe8L2ZdEp7CFfnZdBIaCcJMU0auTZflbmDo4al8QdShoTHh8vrXpiRcvPuw+z7r2SR/jAEIFuN0Fw5ZuhNti6TowTwmrgQpZxvtggl/LmDrkfw92X45ujCmPgfwVvWnsm8/vK9tZHS6ImQiahhABC4gLZD4/34i7x5GnqirvEyAJ0kTNqzEQYAdqmEaxD5qGo1p9EI+gP1sh3G4doqI69AcyybrBsXUVnh0G+eujHXDlV0HpIjMqnPG/GnOQr0FsGpZI9ydPlrJf8Orewz97X1vgunhyifenc4wNdpr+r+CcQ/eOPVvZU6u37VBRJqI273FEQOjICvTciCCDpSsiyY20O7wghq6W1Ymhym3m2UK5JNQ80oA616ciOLl6cPfHy2SmqU9YrYSSnC/+fZOufDWrK8a5WRS9X4EGjioAy90YFBKiBQcoK+5kSn6fjiIuXL0Qnk+T0+SbrXh4QqoMq584GnOyawIhL5GQl2kBDlkdQiTZSUUGoJsSBjeUxJKkhMiOEi6w5SxR9rypdTMZFmmPFIESBc27Bkv7n6YVpvtM31lYcNkqnTmohYlIh3SG5mzgsbmHmoKtRwlBRCyQwPcOyLWZxKz2xBOSIwCdaqsFZY96HRb2S2Pgy2TQ9HsvzFLYpLucK7JJs9ugNc6SCaIzjgIigR8HUqXrrWRq5aRDpZaEvvKl9mTN8+Ml1PVUsWdPhJUR9ekdgF0XjQwyoTniW01BJ2mc6USN3NA+zqkaYuErIDOKnYhRc0TKLaK/WSI023EICHisf29WQesJ6J8WeY5YRr1NoWZVegAavYVXrEADPBRjMtHnrOWNg/w/vQoFx4o4LFEr2aL7mwI3a24Mi3C2+reFVjmfWDwuAkmYe1lx6y4xWaucf2Au6IrX/l76/2BoKamglrcMhHMAjFdUpuZfXQc9SrgK3FIECYMfpdQ80ht4PXb/7JRDO6GBx/jqGue5Sq+ITi8CzZzmrUbHgsubaGekpnzCjrGD0QMlnTfRnMtXcMVBRxtjRYL7NfTpfbBho6V6x/b0PBJpsbDAAzO5DKSwObbSRuqzRmuSYD246wYisUJ0GVEsVeJL/WOlycuF72tqTLl44D7sPD85aZX3MxcgqGrNsImHSO3PL+rGvMJmVRj5DUZggICn3MEBxyJJd3uSThNQqV7dyY74VUw6npf1P2TOq0LxDJRDF68eminu4rRaB9pqdT0lyBSqaX5lxvZiNPIeErToxNMZHSNdgGo3hUm3xDnDOudHYtSSFZ6+9N+D2hr9MKQGD3YmcFCDwFSuF8HddoEDhO8hhYt8iPS6hoXXqO+K7zEiqEBTWpLy8MgRIUFdt1jNdXBJqDkPLtniSeP3SV3TdEi4NmcAcCu9DTNZaPFQ/nc0XVXEIR/mLHtsPyw/TfKpvQUu2Ch6AIPr3Mype+3FbEOKkA2NyWCmtqI2dZk0yvRORcFbENw6Ofjo66B/930VAkN8PTB91larpsEwuiHq7zOM1g9i/Knmm3jltXDT1zd33MFRLVR0JlmcJCcJy8gl55OFlH+AsIm8U3SAh0AHRhKPAwW2P1gYTfLGt4FpCxW+GeLHM95aQY1qs+yWCrBx8LFBJm1eZQx62bbjPlWAo1T9mkwPAnp1zpK0PCLpBXYNaGIYQpj3DeYjkMeV40r8o+XBQdOJ8vfRTmb4kFqrKDwrfIeeSroCFJfqYNbhfiCEFttY24ewrq48u7UtvZbe3kddnMCUli4GeFQw8/yE3rDuNQI7MxbqA620hibHmlVuLz4/tVUecMgNg0d7FHTeNJPmPdBE0B1lJzBtrQLnwD8clQdXwdmneRiqUBlrKZVd0acxP7FVe6Bfk60egzhYre8zAtOFfERyInRzcf0K/qKQIFTNS7AJ+zHClZibh/0TEWl03KwG55F9uxVaoeCSY6XATDgXjynv1itV4hwhqe+jFKtB85tWwOSu42I2pX+O3hVK2pDLYHeYgiwtZsnvQHB5/emIWBxIBxvJ2zNxUPIs+FZCOb/EptiMBfDRFYeLmKc18N1I8wxcfnyxdsV/1Bd2LRf4Frcak6i9IU2jmuZjdAjdVLlM9hYDnhW/HSb8pUCRzQq4gDoyOYlJOCzzr6J1ILa8aqIgrgXnH+qj74KngNViANgEuwr5ZNpkGXHR7Fcna4l0FCa5TL0Bin/2hm1bZRC2+HPO8UHeFRMrkJrtyAbd3i3SuM5bWmZKqQAweH5l3QxNeHdjYsqiVCqyX4vXWV5t/HUHUrogfer/OinmLYX/EHviJlqlOGliwkRg0bgSP942255RCq6NGhRPpGLDPEo05C3FrW7pEywnqzssefbIbG1UYFCE3aVqwhIiuxGqrssIOJMfZgflBnxd7b45LAMJ+TCVu4cmhvcxGsJf8Wk79rryx8NtXnNq8h37aNho9GZ254JVKV06R0Iv3mbmL3Wh1kFUksLhtQaIVbpWh4lKzb9VchNl211ISwI7+TpsCf98X8B2djX3IUTOrc9ILxu/VQ7+4Uay+aeaZzMu1/kxs1jstgy67JH/1Iz5P2fbrRH0aWIi7HBFn3FYtMFRlm9RzIGvPLn5ogfLS9+6M3GfwcKE1wa9AXrKNPn5DhpFtnbmVdF2XVIyiAQnbqHuTfEPvpH28QOGo7SjkUwxVu9l7PL7w3//kh2MfdVlIuKYeMznrHFMq+EsLVu+CdFcgR74n8dniDKf6ARxVSBKa9x793HiPqnEMwnbwcDMFl6bbaU/tMU81whzamCri7Yl0AqkuhOoPri+sqRB9YAxT/0L75qbPJRWmJHEYGSTPd+94E08AJPAl8BhCZS+YPhL8eHNM0XeYhvfyExwPVhYsncf5bx8h5yVqfIabQExsFY06+ZmGhz71tQyeqidOJUxeBRn+yR58JLgNRlxhnQC4fOBg3IBqYCwuCgHZ4jYba+ZPW2b/ADqBR4IVA5liwubE5fEkOtVXWxWnshlADPdh2VFfgsESNb6hInGSXsWhoAouj8htPpS6FlE1/GUVS/INFCZU3C9yx+fw37n5y+iHFTRgTPvIDxZTILOoADXr4gWB1qFqO5EAi/V0ZRAcnDcOIhrFL/uzMXvENp+DTVrGeU0/kcFoBxi7+aLaKWtZbe96PWZBpB64q0zObvLCeYaRBylcfwdWvjUausZHJOYGAlQQh8BZ6kqKYnkHXgbtYAy2yNybN6ber6jRXE9fRicz/z/Sg/wKl/wkhPqd/Y7Nx1jJBJJ1MJ2sJky708fSpHoztWQ/o2LjAlQofjU4TdANH2LGbN8f8ioeOuCo3hjk9LxDGOKZuv7jUc67QBMGAsJOEOTxkwmN/PPV71xF7ndP7Fv+dQXJGx+mb5U6eT+3Th2zpHrym6T9df4xhtkvrI0EcCeDIYSJvYN03b1FvTuifo6K7d1bsqQoFfHxHAOrz/ZymCmHYfCy+/I8g0BlRa1wtazz0dgFaPx53g/FI82+/lgMIbgsoRCiP+BpQGCB1GzznGGaF43zBQwqAXh4y4xCybKneNdHVycYJAO+zOetkHFYUj2SkPCOzFuX2rjDA7BY6pBUHz6oIscQSrzlAB2XKhaBOQz1+HllLzlgzmLqQwIeJ6FYcAxA1Rg6kcctqRkpClBXRIskwrHzQ4pSGHwsacT1CIJCgvEBzyPuD721+MwT5nVlYMzzxj4EZuOJUBPsCv/DjXZJ3urCJ4TFeXAf0zCxioREBblL1pifnm1ZCuXM85p5Rtzcv0kMxgon1QDoBqyacYSCmRkEh+ZEIvn0OPWkMqEk3MkYotr9YPyvdmWBwgQLQ7icftfZdt/j3tfMNY3pHR1SDuadmhutwY1DE26GGHrw/ExiJz9cyKD5ldE9WsxpGMvcukYBH0IAKlJ/pf7O5+i/nQhbylRT69Dtm/R05SipxqG6qHMpC/6gIJZn0ijVj/1yxoK13MF/Lv0L62ydu1jkmCRZGsFFfBOXwseP9S5IX4Ctv1f7N15zTGXMTxzeGQH0lOBWCNIYk5cNlcttOWrpAQwM7zhFSBjJQcLSBdEB2/+GNYLfPstweoRhHrK8ciHWrTy+3OcWw3JtFysJLFSRUt8Q0FpSM9UrpcmKjRJAp4LcIQdkXP96gT4jBGjtTVx3ThXEpnRXoj3ac5c1ywdIkmGE28hc4Ld1qKW/pIw+fdHHAz5Hjz8RYzki9SAUc0QSFwUYCdauH7rusqpiSBzgpwfJjgCUU8ByK7Ib6Aqza/rEgRZTC+dqZ5VC8lm37J3NER1GNFFkm6hOgaFqjJXSfCYscPrNjW29bqHRVKoFLA539Z6jUUGbZPT6HJxU/4T4N5cnejoZ5IXukd/oYBTIHpTkRwkpVKTzqgGqDMLbDnBEsK6BVgEV3NNT3B6fGteTMCgrZIkyovIqdcc5MAGWufFksC+sefIIuxLYZFNWtbdEvthYePxtR7Bs4W2ScmsPzDeBgyCMpHUi2KLSzBVLTH05FuNbj7DdZNWwYtfoB26JaRuKAEwXYZMIcbR87rAci7pOWSmkaVnqAQYdbjairmoyuRdBOU1VpwirU6f7A7+vVpJaHyedtZ/xKCmUF5lYByuzc5tyM0GPlpkYF+iUyhlOiEMlG5/7PirUgArnceujEar9CD8Ft7qN0YO7bg2Xe3LPHcWDjdIf9JCCQuMfqL3PU5Z9npF+pKdsqO2WgW07vG4aYdI7Ci4DwOc/0BBsiNaFGtFvF2P+OSYE0gLcHysVZsl8pP9Ia9ZuOLF5V1+GztZ4n2QBzczbff/QiB5vhQeA5HxiuGCOlGdqP/dD+G9dVItn5ons3yjZvem+mJ7c3+secmZ8qsTh8OOibfdEepLhx+njOp/s4gD3L+z63UVUcQxXMzWxyzZTr++KkvRkM8Z3YM66nzLwEsygUqXlyyCJVvgWEMNnStVcgtJNiwQRIOX7deln/owjuA/xgnwXkxC5JkCAk9HcNFn9aiqhT4yI6lyBVatRLYEfSDX4J312WgnHx95703FLt2IDd0RZ8RR65QY7W9k4LPQ+mYoZZijRiz9gflpmy9cu/lcyl3hqHPwjxJhTpdgEbmJGDIXX95J6CtrX09cTt83D2mf2daz/+gXrvfhMWfC8t78yzE2f/WZRoLBU5aexqGb3VXpr4BprxZUqEnQ4HdM2SKR4f+e9121bYnx3cNdXvFfjv0MyKNadsW1bTdn33V41/JWpu+b6y/FQDVu09uc50xSSAdgO1irsjP4Iobikebi/ovKnvKFRZh2uYqs+pXsFfPJBhcVndq7FucK3h+SBbx0zN1GHdwXtxY/SDaegztDF740zMETkbkoUyJlXEBIMbbMMUL7ZeOgvcM1GgFHjYH1UZAddEZBRarW9iKckC7rPsfCGd69T24o8VaA9UnUd97J5a5cp8TuOfy6nHxWHbxNgR0AhNGDDtA926TKKgNJvp6+XsVl6RwAmsq2/fSXOQJh00buyXquL/bu4bVvILiWFgVDorXESqKS0BWmLfzhDJbHiED/Mz6K/663DKItOhn3ChnGqrm6v4v0dh6GFLN/W+K09kcd16bZXzReYFkABzsKhmW4btyvQjpS4nrxc3MwRp5WElrNuPMUMqkLUdFmJdeNnX0XBBjt7lHejPGZVPrFaw0IqoJV9W2/INeu2r+jc/bDwPGkc67/QjjNH4f7MP0V2pkhy6+Wcz+BPNTWgtVUpfiiq8MKN58l6AbdMrJ+svWIizuohRlnUa5ReaV1D0Dt9NvUmbjT9Yax8pre9tj09FY1SlP08hbWiEIXRCa2ra1GcXn5riIexKlur9skbx/rc7Bj5DVW+IYZGw45CgpwJwYEkqw0RGqq+6q52te7MfBx1NPaHYJAZjjtSjosr75nOOrE3TUfv+7bIGw/6VpRxNyRN02V9PNbQnrNsrerMwvmZaHibbzPrEv0LS6v4eWILdITUAnde0Tc2xn5asjoiqMcHh1/KgyFFl9/ZFVxNNPz15qOtiFXv0gOMXNVOfNzrzCql89w/WaTOYiEYzQBzavX2+YrAD9BqN6mG3kcqwGvUoZHAD2iCWYnUcShjlXpxINHic3xTw+xg4APpGc3Dn/cuu9hKWjMXdrQfy5APXmQZ8iGb2qq7b221lJot5w9X9wYAWDxHXmkwySPwTh5DPMYJhuLFXqb0aaY6nIwolQauVRvJwytiCKqzhEA/NtsUNPoyHa41oicd5luaSqau2vXs8Snki4MoAy+Cj6+FAHEiVosSdQreG2c7BDefyMy6/P+xalL3JgITUJwHl2X+VGPU+Wnq7XztC/brCDHNfDKaLJe2QLR8TeF/G9ecCa9m72EdDleEVg0ecs7c+mNL11JcSNiMKKGZVAfmWgbGZhX3VjwC/8Hse9tCy3sJpEZ5N8Ep3//+1UoKpILb5JEuJoCASfyIyVHWCw1KpmBjVb6iEGUekIPSIARs4yDN8b6o6+KlNEUwXoH4tuoMW58F0/zx+TkBe4RLSGVbotCHE5qOpT/8mQM7Yb0bqtmYRd3K/EmObmhqlfg3FocR35j2nZF+oh+Crq5Sgsc85Av9u9OB9mQz0IY0fFfW+UeqMT85hSjKvMZwJn+TFVxknnFh2tK5ME0PQSjxdrSzpv+bhVZZK+O00tjdixBIt9llSuIPsXclzOz6eLP1Q9Y/mQ1eXmuD1YkmWPzGT1LlXpGk6I/2L9HQAy+umFsEwMez4QoCkJrePsIhBVR0MnTDUozkcgnUuoKH3ZIWE8yuCRXEOuA2jM/ErzrPjo9l8pYGivb2KmLpeKIBznyp1yyxfGcrf6z53cyCnzmNc0tSjtbceevPaJsyocDZa0sGeDg69SRBqSbGhWEsQTF4PHvuhyK5q+kAd8DhoxW2dL7YLkcJv5Vr8ek2CFxIfejKLSc2RPCoKXpL6OgBcAAD+09pwx7VV8aPhQdt8wpTFXMgEryQbGN7sFHH1Hy2t0Y4la8CyIL28A1w3O+vLteSLnLXdn7w66+cmMnTPcZg724j/IPaAhy/byWZII2Et3VT2kMtP+3ZdlzxG24BpxDHPZ8qgduaNqECh/qNCBxo89DZs/y3mZXofSB3ay+jZbGxhgS8TFoQOS4mKYeEkEnJozswoth5YkwnU6nyxqhnwbhDDbZj5ukTC37orr14K3YDaDaso+R10swW/2VC5O+U0C9X1VB18dwccqQMVEXfT0+34kkdztH4arfaw8fMIkbe/t9QS8wibgTOpQMrnl6P5vmEhC7hiKx9OxykdjskP9WMUbu+21DoBlPF09gUHFBxKx4J0iPBZ0acH/Y3rVpS/L3GV8WVLCchv5dFxFAlmmOITvAotuKufxm1roaIzo5PznCf31FWfnw8W+P9v499lBjeoHV4TOHlmXjtZhSqkQxjx64mislu0JLT20WXGE8e+ytKc69mLd/JOyEKlIS3Vc1yFhtKufCBfSztoYpmHm7B3dlh0tshamk+tQ3b0aHDun1OSpSEmFeQaKsyxf3jb6jZpSmV4rOAUCf+cmiZZon6qSpNhfK3mZzQ9yLN0o4y34GjI2+FmL0AdlXemInmwax6kHOcOmEmuy+DQL8fNI9e8YlQQ0uA6b2CngZuFrN45J517XPjD3e+GVSupP1M80+bokhviJiOsj8PGjSQ04hRhlpdSa9VnXsZro4t0eiFX+IzTxFLzTx4pL9eVtQ3OWNJsVi24YXiZpL1aGSKyF5M4coeov++ftOKPrQMU4hdbc8rYjHFby8i5D4ajSCUQonRxgK5gHwJcn8UXQ0UpNu7tJYSQizLrHYSbLxCt+uSH7ULl2F9sq1M1njVyGrCo84iECLlLHEWCgWF0XEczIlCf8hgAW39bDf+1bVPdTQCg1yQJj+TWRJKRBqpXS0v8p6naEGEEAv2+8i1vJlG9CLIwq2bbza3qzrtRr0J1tABbGTXTQyKNURwGr/EkyMSqVq9rHilYnAkGXkW9mFmjUtlALu/w/AAAAAAAAAB3ZPgN9SA+GwCXwA9KVAg+4djDnwAnrx6PCAxGgsAAF3RH4WLgAAFK3mefJZcI2wgvtnhfVw/7TYwhKwaKsHPEWI9BG0HCJQ7YPy78e86IMa3IQhBDD/dNaZIDP8TVq2hW/zRHI2JNMDpYm0AJlQjeEL2H/QwzvE5cEWZ/MWBFH33KEE/ZLV2cpKH7sf/GUYXW9BKBKKQQEWw51SQm7oRs8HY7FnWQT3xSN2meTSf24Yhkuz0KAYsryhewg3Y2DhZZchCZQvw+U1mVAGd64SRlAMQlNxk8yy+AYraCpg+ZswCWdFFHFnPllRoojxbwx3mE4kgSnmxotaOAPphyKkSSV/8N9tFNag4RM6dHIAuxYlHkruecroQUffIgCNG24QvUi0XJeDPhhHYe4hJLJZMHoywGBbVGo8KyV3nCGEBN2qFk8gtNiMrMb0MK0Kd0XcJ4GEp4SbwCKVM2h1e9AEZU4rW4WcHV/VWPD82OiYQ2MlAYsGsmKmxIwTYDEUwmKPWgeyGKY39zogCQFGDV/YJqfzNxcq2RLv+JYA1VRr2Vo53+0NahoQB/blTWS8wkj0Vvebug/dsc4qK0D+dhhD3T+g4xZ0ElJ0m48O8SahfTdVkqyJ+Bl9hVBFFoEEW9bVnAAHUoXYQAA5I8b5Rh3TEpiAMIIPAAAAxzoCR4R+HgsuhC9P3IfTa4f3dSRo1H8HP4WmDChf9gBQgnQoSvY0a2J13hnhS1NrLSdmPNoaOSLZCep97kVj+Pr078rTxvoK1Wd8C0D8//QRC1UgWbzGCb5/yw3+MCheI2egkE0KkpZZvRiFACmW2ra1hsLvrumeRp/HqY/hIdgR0bnTLEG3vZ2FY5aQrs6TyqC35gb37kHxQqWuNdLOus3Kx4j16Ib5cLxjg5eTTFFvAAHSR1pYjbkLfRWCTvSwgqqZPxXy4XYoheR5uA8Stgb9I/8Ay6otOclgcUo1IByK1Nt+D9ANS3FBnYPrOECD7x1aLoJezHtXNdKPkViKtcF9XI+kDbZ4NNJqEyszR3AnzL0+8wap9ClpGn9mPqWCFb199gmZckyFz/OimyXis8GgVdMSZ9RJTqd/B/qNnxEUXboXFtKWQ8HkeneUXvhoG74yiFCCadRhxx09Zkxdg0Yxq319mcrCUKErIP8o0Dhl/AVhLcxy007XNd1rURYarYSxSc/PBmTOAOLTluP3QPbiftq3XORjZA7n7hsivqWkHjcWOlgBYohxP03Wv/5AhrjMGv8bv9bg3kJl5I5C+dJ9pA47egCaKobX5RouQgPQ4YeAjs8mnXcIDPiBppC+6bsNMAAAAB9EWgwLgAUig6ADcgOV9bIYUHVcwJaiB5RxZgAAy2mVdnwf24H4wKOosbPGgL89YKlFIVQ7vxa+I+VhWdbOrlOrC6IIATlVNofgpBlCEUoKs0aSUXhAnCGD6aAsXEHfS14/qLqlc4VyNIQYUci4G4DLrPIB+FGfzXrSs3KaKQjcVseltJ5sK6oLSQL97qf3TFxPvgZTUvT8BvwEqCIqY7bbgDgpT2/DHemEyHieKrqQGgf4wv4M8nZ158zbxNduupd9aAGMBJVMabrCNCmPRXrVjC/TvF5ItnAROg2hfYgoyEjkHmX//X5Yvf7ZHvmApYcAAIFQKzN+/63MYRnQ+G4ROFWPQnfH3Zr3eevw3G7yrC0o7acMwIxBv74G/RyEkPQrEVCyWUlbdPgI1aagkO+8lVIpm0/FlixWwTGdqtTscq4gZlXf8UiTzvWSxAUASBHonT70V5pSEGIzLfg+Qn4e7bwvc5tufCV/g7U1OZRGifavjaMCGSK4rCaK1ncMQsc3/WKCCWJ6+sU3XyUZzGwNj/pV0jUiGeiLP89rvm9HH8ceAKV6HcrOFkr1qeZyRlCFqlefl4qnTk3dWiBBm2UPRauPDSfkgdxjzwjULwczWue+rbi/a63Qb1zP9rBbyuA/FqVMstNfOeZSH+ICACvJono/7vb+H+uoug2j9ZxBNjk00ef+B0ncoQAQU1cfq5m4wo/AvpE/bBC9ORFD7Jn0HFOoLiXA6+rC1/dUpqVaINKSum/RABF0BzAASm64D0vrN7r2rZiGncHYmHgDpsKDbwcBHb8iuR3OKzeukIfqRT6gN0E/gcNTGDWOsYilt5Z9k6rHpuQqK0Wa+Bj8/467cAe7ZnMgtOwgWJ3UB2z2xJnZOC/Gs4CoVMvA4Hogg0RDzHIMI+VW5nH759zy36Sh0V3KtHZb4eOZmEMre4zLdhj71E1cdAXQEisTaY3ULvZN2T1n8SchA4DfVby5plwctLSWHUVr1U8PwPc+3VokFpK09wgi5gb0qvvJuRTj1LDhN4FSaqGUm/wbJZaKlVwTIgm7mq1sSJDY18HYamIUa0jX8Cmc2tUmVI6/tTebH6qXM4pKpM0RX1OMWnh7Abmb5timP28BQASb0rJ5g/+rap5mjAjvKG+JIAD9FIy12tIhm4zK53KF5h9MCVkAtfD9BTZvXPx89PpMDnElvL1ZkR1vNN7BcXQkhdKHoOGf2YomN2ssVtI24y3sW2H46lNqUVzSk7xmE1VSquS0SpqQUYmWsvmy9xBquHnyU9wToO5mc46C5ZXBbZgSAKhiEJLlxWynk0V9NoH8SstD5p1aw8bbIEf2c0R4tCbN1Kkj3HpOwVonxas2EG28qlb3KXkWEU5Pj78gajXmQDfMxu93qf/1Ern9ZIov1KMYVMJcML+/4/l6AvN1SPNRYL/teeQrakkppRdXJQ2WbCqkQUz1eCxZ63OpfcS9bsqRK6Qgcn2GG5m6Mv1hYgABCTr/G4sR19R+BY4Uc/njBo9k7PL/5R754Vt6ki5FDoUmWphkzxzt9X43zDPg4Gu8kdpHZE1TwyG6QU0j8B7zIMnhir+QveWPhYsbDKlkfREXkjjzTC4+fL9AAAIk6wAAA4gRfAAF6AkEtBwKrQEdjhAABPohaNT6tjsUDMvFvcSmkbf1MHvS4I3TWYUJbghPr79uZ+/GhGmN4ME2YM0orU34yQG4ewxDkiPf5ogdRzJUVxxFqfCOgdT1aMocI49KPhKwYLXztfTBGfdOwA0uGJn6TUyMS+ZieMGcHoze7kMRBRWdly8CHbq6oIfJ0+lxEQbBak0fvObz8SAfq/3Ym5CecQlMJJKuVC7AGDxotU5tyTQGnEwT7+SQqTZPTO/cyH+6BdiVfYzMC2aeD1RU3eumHdt5fu8F5qNnJ2c9XsHbmYAcOKYy+UcO4EogKo16jJgbxjgxWYupgKD9Ex7g4hj9NpW2rpBiNemrb8wySOHGL8dmW9FWkM/NeDYNJQYardSSv3mtrhV+bm4QaCV5DYmTHDi+MMGFQBr3kfMlzAg5tq55iQfqOgMEW0IJFW3ui6p2byYMXmFBdva9arOWDeOfeNDx4Z7ZQ2U4tXIseINWoLA4Sv4z1WsVLO9nGR30hSPc2ApUjbqJrwFGY7s6Sr3mGM9g9CqFI9KezIbCpOV/u6Y/fh3BNR3PeMR4Wk+467EmOvNkUXao+X3SB48W3W3F8fjTkOPWwoPWtQqjXvydsG/EJolgSdfD+Lo757rW2JgNeTAMc7A3rBQRf9QsMDkvrJxxxAmmf+Yk07gEQAy/an+qUFcm7m1PejYu3i3Iga62W6nLv2blMNUuTq25o9zmUaGpe47Max17EXSx6qySpAAXchoy1OkaJp8WFLITTHGSsvb2Uh/V+y40nqiWIKtB741qFVraDDM1+3Z5VfDLP4l8hKQITOy06ZOXY5rdsm2R8TqAbpWZV5Ouy+1zCGVrkHD00eNHtTzfZZLhlWoth0hpeQm1uTerrjsDewSzgAAABdHgJTGCMAANzhYAFUA80ucIfKH7XcdQTKD2CYonJbpN0yR6RDgR7CwuyxlKLDR3f0FxRS078FhBIg+Zr5wODFTJ8jMIeHli+88PO8AFg2FteihAhwLLCBaMSg9vekoMacI3+qH2lELyngZ3CDFq6WdsWYC0D7NRRHu/kI2Da9lSSR44p0F80fLdeRCBayMM1oLOuLK8vY7Bn0pjIfrEvGwLOrX1eUzLhK86CksLNPB3ECnygrlTJzGb2xxLkvmLjvTPY7HE8mkAfQPgYCcZ+3CZaA2Q1U8+I/9W0m8xt8syJlGoI/XBf0466F2BaXhL3D8N2lliurU+RHXlGCwRNX8jOfPtXi1ThoQHV7ahw4TWldCn4RT/jiIOtLk18vOjzH2XlbrPaUD/caBJxUBOkjP1GKdTKPsq5EpvBVJnZZfIAUW/Nc0KZonfk2Sv3AC9v2Rd6lifZcrp33LYGmun6dvJx0oo0kTu6VkROw+d2C4QqLYVBadc+Gqh7ahP5vMxSrhmP4EQewYfsn+BsBdaObQj2LwYd7mNRCZv3FVgcoqGVq13GMqgPWDwTDZNMkQQYLe7irataj1Y+T+SmC8zjh1AzVDN8n8gbFdP2HOYvKitzJbjZHgNumLDT313BI0CLYokkyaOKI0iiW6kb0o7lCIaAkZODZqzvqedt2Drhws/I4xddCuv3WNIpff+XRkDPsYvgZSL+gIKnwRRfdq18FrXZp2Y39Y8HlU8GTh24BMFouh8du1Eig0FxgQlDYWYAMLnmA2o+8d3aTV68NBpFAptb+msrG2kvR2DdC54UT1yay0lt6qG9g1gWS6xnEbxolzo8wh1pK3IDhV0MC9mjFcg7G3JEQGMaxByyCOByowK4CtzTUi6005lArd9zjRePzcPffqpMI8+wFxzRvghwfiju1ViIG5wvbdM+3WpTgTv8nCLqKoe6IqFIcaJ+7IVPNJw6BPpSPlHgA0M1aHPV2YnMtzWFWa1TB4xEw3BtC9lfDhPMnJ73PiHznunn2Azi1Cj4y1uYyySs2b3wcxJ6excyWYOZvEBtK1AAG1zzbtowwAAAAABfha9A4ZPtwj251ZcAt9LhoA5mO3bAoTQbLAutJgA4gl6wZrxZRePP0hoFIx1Ae7WoaMfwDnDAyx8KJj7n+qdqluaqblb33lNn7tlWeoCRW+pvuQ6ZdoyuV6/UtzrpAhu0heuaMD+o3xwMN/hMqdLWpsJHz/inxZjDCbqPn8tHUP4RAA37JmbXLwvgyPBmcXiVFx9qb8+36DcX5Rd1bQOwZqS9E8OaIGD2Je92hX+tch13unD8rBuvvo+BH2+SYy2kQQSPfYivJry1dWcjm/95VM70dMVphQr647gBGAlO0pKw7b5mmQxO0jPr6++/nady6FDeaoBRV8x1bh2fIdqCE1YkOkYtoGPe1nxQczsa4zyGNdOlWGwmIrzp4LmyB77+YEGhS6UmsA7VslenAoH4l7p9AKPqRLH6TDkVMukeP2DaaUmvab0tLNE8j+2mexKM8QCXivo/3KGtVqgYDpf3dp0huOwBJ3gCSLzcjsm0n9fWo6V6FezCphGhfWT9LjgMoOkERMWJ3eFx/G2E+vkFEHk6SNrh2G1MiKCz53SMzuBfFLSWMI/KwSpA3WHuJptPLlf4UJPkJkq+r/KqQ7B4w39Xwna1A+V/+vAJ8vmvvy9qCoGugENTFS4C2+IgrJYZoXYqHPzNgPAsjJYV5uPuQOd7912Qd1ojQKYH5nC9CxySYEl66yYPondGHwuGXbDQhjdI470i1xxqMj1YnFEHXdAJPmlZKM+VwetC5p6U0AmAndDLFdlTbvJEhWLUJx0vSHIkBMUTjTsB7mHILyAS0VcvaAEu5MWvqFGbORtVTNh49tMrhwNc/quJJhu8ika5Rhtr8KRMvK8bjhvgeFw5dZRFl4GDv8+ak12kqfKtijyhLj9VIUnOlnxY7oLfVMmFjql7TWTY0HYmSmyx04sx0Aq+iDnw4GTplHD+zRrZGIlzv/lewVsylgh7ey3IhSnFuoL7Kj/Ndmj2KyVfDCDbLoJkwqSm2G+HEyOl2ZeZDIgM7T8HoNgxh8j9F3u58YyaGwNcaCKGfjHB9NAAOkAAAAAB29pJgAAAAAANEvIylKN5YkRriXO2DwE2/DwBP2jLDyQJijjDEO2nCZ8HPdgcG8YVsTvPrCFgKTYLoWP+YDd7xbqVxEG+qQicuCa5BWDbnZvub2O5RSxSLzg3LUPgbeQC8TJulfBnozHx1Rg8SPnwgkLfvXlwvzK0t+u/NW++vIz9Nb5ADqEUqQ6pB4onS8ujTkLBpXFMbolEVZeiO3n7AR/ile9epaxtpFnS4S8cRHmnzJBA30rejqyPMQDW2k8oO7rLtkiJ/KbIRinujuQLdf3wE0liRxq5eJgMEOmuOmGBE7Fn/hSGDZZ7ijPRfoZoNrByHbWusc3OEciuI4hx29i5K3c1KdF2NQN8r4YNu+WzM38lYZKXgngQNK2phkffMmoglWZp0dCjo6M/Nnhs3Yu8/rolq9VpY3jZ6tOIIjLslf3Uns52p2bnoT9LdZyVTezxzeTBEimhnWFVowHYGLAutmmqj92byd3pXtz7d94nIWtG6M9z670ZpxqutQTcetQ269aOtLQvrsTNTVOPXQiBP+FplF6ePSi+xMcRICz6gIxE1QxBki01E3j7xOWoF3qF4p8aJpwRoy0AEhIwQlu569jeH80HsrpXBlqDIEUbSmH0HKdKECiIYIKtuH4d96OTn0m3ffMK7KHsgiUjWRIXye9BxT2UWExM41rpKks0TtFdO2oPQbY45FZ1w5MbuWlkJAeHguhi7W2+6OWKVwCpcuqjQvm4bYDqo/LZr5OT7t932r8PbImnO5MuLEx+wSTXcjkFj1YVW07mtnYHjZZTrESNYbflM3paxh/QVoiOvrtGNFKvNUJTOCKo5QFnJvpxCiKLHKfezsXbs+MD+GsIr+qinOEeM3LwHSOqfCwT7eR+yhoqcvZNBDzpYa1dxoQBAZdppMEuxes1oZPs2Ee5O8MyRo8YMwPwDxWch4PWkcqtyBgQjPALtK7Gf6sZhv41mdBP7zs35Ewq9VJCn4FBia9M6Q83rxoEimppA+k+YBnzlCx0zGzypsCMdWBvyDsomZQKoS4PoG28MSIoYAsWfgCO1HTPwTUGJEaePa0HhSq7YoAAAtE1qACkYABfjlmQrwBU2k6AHbuXuEgK3GzmI7spp7uXyR7kWaO7CSRkNYd49KdLqifOsIu18TRKHvmWJIq+6FfCydo6K405jPmWHo7NzR/6ewq/ZpxnSLi7g4RExBJz/sF3rp5fu9rauv1kqNYoFQ53xjdy0oLOyBTRuUE7sXJo5GEnYzdPndXAWynnEIBS/Zm1WEWPOm++dz3c5lH4uNnN6sZLHObqy2ZUTZQqOhVdAH3E4Q1oVJM1KSWNAsjErjJBYt2qwWGT6hfaajJyTylX+Fr6gc6LtK4Mi3d2jhEd98r+0eDqNQljpLRO1t5ZqEkX275jB5uCMLWym6RB3afeDbUH8PPldbIhX9swFjqzoIREdn6C4xLm0hnNgsJ4xX28JV18pINRlRbQKIzsKrNxVX4B/MVingB6iRc18Car3+CJvBNGCgnBmkwob0GnlvKd2jIxoO/VVF3ooXrgexIeXmbOUoKKO5Wo+en+RFTWIQ4n5fRT9Wpkiv09XEIhujF0WRILS4y5CNfnsPIlG4Jx7O+zpK7zghdcO3/EJfAt3ubyRZERBYIaBolOz4+A16QRktQGEjLBecxA4Q+qJPdDVwTaQo5i3H8Hj0z+ymtPPebJ/d1f9EpthMiXVywce4lvCXOANrppH4hoYKqaTP5Ks+zvqMJbNE2h00GAE0HmxXcBT4NUi9HZv/P44J2YD2IgwXDfOLqwwgE2Azb4XCy+CLjlsIJ/7pfTIL5UeRBKgxIGATC6Z5lUR5+SdBSfgcZjAUcOuwOLJpOVelfepzpKrCDIYULlrnowiKB/7zXWzDs2EwW+qQnEAsDGzhZEse3/gwGESS3LRpPgKuCMiHDtU3HC87/SgHygs+ooecquC1fAZFspJt1i1bzVlyElykEuICxJPJmXlTFTcnGEnAPLfVH9FDbpfJdsrMNphlpT8GS7WBipTCVfJ2XvDkihyeREFbUFcfZMnfR3svyM7A+WOlEP5REbyxE25NTS1CLRK6l2ExrqkgAfa/hJrXN+V+vvMoKx7lGB2RjPuyYe2xZ1CBOSna7qguFgA0YqyJQL2djygUFuvfA7nIm6wRytFErYVxNgVtCU39blKch3OnK2ZjGzeEc/vQ0GxUwCjI7dW8uuxhFXMAWdCfrYzLykmX0Tuo6C1XAicJTWAImNRE3BFo619nSAADRQcRYRfPDHkh/+qvmGaXZVxWIM4agNg+SyJANNdprIj3AlIg+FIQyc+YsufYgEhM2V5D17oBYqcD1Pzu+NzD8qkxbZ0GY462gpyEs4LFBPyJh7Pl27AE93umd/CQu5CjjxyIsKjex/4E3mqNEdv9WCxYBfOqgjrJ9AuV2JGDjFHSubPfelHZ0kB75qUswgPJidgCrNxBW7MEXpv2zzgfYMQlr2lBNI8h56YEI3TKxHpAFdbKGeidh17bKmg5mb0bBByXZp2zQ1lCfEWbeOimWOD04jJCuAR2bN8EPBr6nrkgVIVqycREJV5TXJdJ7ckI38xYiSoRztBpeMbeUVIhsoAoP9gF5kJngMBY8tj2GdrkpN12/8h0TKtqx2avhqvSr7UItIIgb8LQvfzUPG2XzyU8Yzw5HK9p01WonDR/iliorDoHi170sJb7d2+zGlMAHjk8hpU4MD55+NaVdat6zp677iwj9NxqbX7/VIIfv1yEgdzJuvnYqkBxcYWAAtIWGXMvAOCLYpKnlE6KkyEpDJGHkqx6Cm9x2SRWqmRQu5NsreXp4hqTAmVlaV3582M70Bae57JJ7rqjxbuD7joxzP2UgPSjRYK9mAf9W1U3VYKDVYVYJxHy2pNBG96IUM4YeBPvL4Qi2ZiISM9m8A64HPM7AnXsQ5EU1nGLtEht5/TvHLg0CZvC9qhVfJ31nuemGQXHWjYUrhBmFmHQD/8HzQgtmS+coKbg/8yoa80/iHW6uaZkIqA9pdPmqBKfe03KvQLQosxtew10OjhLdvejzSGABibUeuzJdTp7rlt2iNNAw3kyGNyfzXuaPFtl0KYysEkx11KoNtoRto2wwDU+jF7RBZTflSgSE4FsHUdfdoC2zRK7PjL/d1fU+hQbc1lhguZ5Cs87ikK2HGAmIle/3Cl10/ni7oRElNxWyNdaUeNCA44oCBIN7KpabmWer91lowFzjEbVjHmgDC/jGcZxRne3Ck/edrRR0ZW2J3oGZOFocFbCmkPBMFjlnmrtd8ln4vKaWgk5bqrOqTxIEvPbqY4LuYyFngACEQQ9Qv60eKFiepj7JrhD+6efLHJkjizoKDSLcydg2l/LDjidPNwCgkMADDTMyuV6k4ceD6GinhIheR3t8fNp4Y2sm1PLpJr1Xlv668qdtRlwAu7QVLMA2oVN/qQYaQgOEqpa2aW3NPPQNHa9rHvdl5Zy8/Y/dACqajN4JEzLrWlcBT4aIjFnup5G0QAnSBRVXOk2vEJyVCYmvSoYp60ArUkL6XcsQ2DVTMg0Ipobh/bh5v+OgF6rDRT/ALbXzJo80wsB31bQdELIMKjKhv364WEjDriE1JpxyNiS65/9Y/bgBpUOqUcCCvzzPCkoDyheWGOhRQwrV7MFvX1l2Z6TiaLeRTY6eQGlFZs05U9gQZHm25k46Aymn1/XwFPeFs5HdplUzYYPbdfis2mX77vQZLz7k8CCeQ2/SDzNcgV2tShMRpU44YRXrBbwL9HzgFztn3/zv+el8KkVC0vEGmgaLct+so/qbK4Rz1aeQwE+sA8+xwYiQtsHdGgteDnvS8r6WbRKun8z+nwVtM0ouQqWmDOWpO37S1HmbXfOOqA0MvYinjvrGfXT6oM2/5V7MJrsv4xUuh37EAL9AaA9doUt3bZFLqF9y9rLpGKUMsM/VjvEceS6o52jUZ6GYo6jOGWD+8ANo5fSq+iyqn3dd4WMAmMzw0cimLXJ1n0F4FG8jhFIQiwgiILBYlbakPVfbKbLZgS/0J/OEhzkTmr3iId8O9fHuRdcp7I79DZNIXHYyWg4vVkis/jL4XxSXJG5CzsbBo2sYfML88chiTouRPJY3Ytf8LCen5E0Sf3VSnVgU0og4Mppg3XTJeVvyhiMUi7le2myHGQ+1+13a1LtUlA3uK6Q3LrcP0OcxoZgT8N12rHqXXRxw6u7vz18beTZtDY3kf92JCetrr4cyn44bj4lIVC+K4AKlw/bJaYuzswFGzqeQvqHD2JSOdpcet6LRfODbiaASBCL2FFHMcbdrvsWWIEwezf6cTFZ8WBvCKarKeytXS4qFvIeBZvGMqRtHL+tU5pLBDNy8ClGAOgvIi4g9x/DHBby7I4oesnRPXrmBjzwULpYa65nnqEFHToNviBPbmEXXqzif7bldVMQ4cdKaYBgW9TyNgh8ZjUXkWO+qjbVzn1bPb4f3LfPcHFMPhFy9qlZoj6TU5561NNFUjsswL5kuiePkon5lZcmS11HbBazxJ1nRsdM+Bj1mBwfrdogAn9oDMUBpMi8vYtav3mnhNbPMViuWj7TVhqfppmkKUV6g9TV0bJFBWTjtgAioXxgaFg4LUXUF57iAAACPzdBipT62vcmiGt/BA/Nj+iXEb8EtmBR8qV+biCsZhCiRdPKhslZHCUITpQBCJ4bDCmeOqx1BqIcmGRKqyuq+7BiVnQDo9UyMvyHvjWfat9pP4pTf6KMKjYgq3Roz4ijjv3UtwzdrRxgm0TNSiMbI6Kv/kS1CObA1p5pNaxee/sp1ijgSPY2wKnMl41V3tj3JWTi7if2iC3abiyfc6wY7W8qQ8MdscNTrkx2mjAAcNDf9uPr77EYQzteur8qO8g4gU+h2W4E6yPa0vgkzO3Y9W8f0HVKnVPpPAqFkNvrx80+ebYliUd1w8Q1gK/ttkBgy8ldSx5mzVCprxhFlH7qTc/FlurgvmqH1vv7PG6y6bIZhANqv2QDfQo69LDbhmhsW45KlTjYT3rCmgcRqQef4v11BB3VirofG9ThoKs+NfWmQjvZOYrbCuPb4NuYn7Ox4OKKRJLMzB/YJIGI06VC+QdiRs4d4S8Sl9Ckbmov6dgq4ud+ZwXYiTMk3vzH5gU2Y7zg8QpES0hVHNZYx8gILdVLKk6vyuRjcDsSEuCxWDiZp8K9moZPcZf3FkOx/jNNU52xKlBKCO1yJfR/GsfwkPCaUJF8MJPZwkqTVMKI27cJUnpG9ZiKBluebyBwHnQmz2Y53HNaO+gV1R70yC308r/nJ7JTrOaKTeOKwR5lCpVZjW1UiYgXXWY5wxJJuQ/Gg2Uzj5wxiKoET4BrWcjc0Dl/Wudg7hfIgUABkT9XVQ7lFQpp4/mqntMpu6N3FlaSBBh6I3919VlCD8tETKPX0qLT9N3MT3qidlIz9JnSG49JV2ibR2Yr1JpKf3aZ+zGtpXfH04FHA5xU7LgYnHRZIcXnwkqmHWCC7iuoej4s7nrGfpc5toyx0rQeniLmwDCaEzoIjOBTzLp9muGGenNpqidI9K4X3nStDQZSrKLAgVICpMm+JcBknOBETk9rDDbnoES8DeoT1NUNUChiozDSh23Nw//S5VIV6DeiOYHbuBxafIp2H3A04ACl7m6RmcwqEi1YSkJsPofZHPkuJBEQ7duJEZZogHEklhN4RZuLQ7M6KfdDBc9uLmGwJTT/QAXtTqht3eluj8Nh4LTLblxlQxFrZ1U+G5ENGV6Z2ZsA/hl7vFYV2/aNbE4D/S2u2mbqsyt/GtwIuTwrW2ECSh750ALGyV4GMkg2YnMaW45sGB7XAVy4GihUMQIQ6GY7YlTCBmNKsl45bkWkQACkUAWOR2rCIOKrrQ1qVyVBbRoEoCgckJbWS5Eoy3AeExrKVA3wzGBMfIKHfIujAgc8nJMfjGduC4/xAaIluEAIrtyKWr/m05ruaawlk4zWbyopQV/QI6JZFi4IUEGD0YGH9JOq9s9ipuecIwIEPF9rqLWQm4dSoKtcwU/bWYJzZT7gZYyXe75g+jVa/Lx+xeJ8wlOY+eiJAvE/YbjsIr+MzxTnD6Ziu/CO2z/egIk8EVeoSg9dEy8WByeNkjFEiZVuuSK8FLrmDLwOtY5wEPHnru/EjO16QWADpRP4D8euLkpzIAD3R0JOOmLA2eWO13y8s5ZaZ3C1kkLNTGF4OqYGUvF5Y4FIHMm0f8ipuQ6tJcMi9MqMo/p1txfBtCg2q6xG14XkSkJ1pvAdfJehV/DcS9xIrMPP+mc+Qu/bcH3GPx4VdtNxRSGhjfh7KDARfJKJMfb+gjN62c7KvL+zMHGR+1vwmFjJh523N1o1GblSvDDnBzI3sgDlw188GNrUodohl2kZ/fAcWsam1UlMgyYxSL1iE86wZnKPzt7d2nTlOwfhPhDXlxMkmrtxTb1CsDhcJpfcR6EaVqXvf8dKKgOevjJ23kEo8sPWZPT2JJZeHTHCHUVV295YdMts1GUxiTFBQXA083y75SYZzUIR35SR/qL8zFb+iI1RGi72kaidhKHr9fdRxonMj3iIHHZwNvSuMxFuuMmw1AwjXxv7bNwnk/SEz8UH50MpGfhzmLmZy01/fHSYHF2Z8XoUabCU1DnB208aJwF4N9DndSHPmpFaljEAdKFd+fcWx++fD20+siWOeq4bW6zVKCpKD7LooGb+w4XYO/Xb60VwKVJQoNmITjhyfp0gPANGNFVFo8DOsHUzm3BW7Ke0wJ4lUmfJ3qeqRJ7CnYhCIYXBConppJ+FoLrMdwXkPJlTvgy9zjuLtAFM2fqn46ReTsCee1UpeIMCwHNeK/MRBC9oLHCSe262cnQcKU+lUA8aRwS6AzLLf6aT8eazNK5tS0VzVgSyu11mP65+h4OPnLIxhUJY/udSRgVlREtF4VdLQaS7htJe8uQkeox4KC6YcV80eoK8AxXScHOCSfyyQHoNo1heEO5wisIncn13nsEdFAWj8Rxr5Yt0GNXIfPY6AYOq9U2iVChW9y+1ZYfzYN08EZYWtXO25HE51t+WlQgi5tDzAqICobDMS9hkmgJV0YddAAArW+IAB3MAXImZUKydkyxUFMRSFMJA1fDheAlVxwKA2nlfwAHC4GcD4sE9FDzrVpfXu9u1ktag9JICQMYmgjckr1BBjd7ARDlimKyfBkK+hexNMrnP//xTr4ysSVKUkSA6NANNkhCGHE4VMyYcRqnyQbmwOSEgG2ZAXdVs6+p0e9VXhJhIolk4IGlJ6DE7U+D6g8tMX0bjgt0JaQyF1R+JOvs8iGKYSI3Jz/6+GjP99nqC4mnz6HlW1FI78Bk355Q48iqQ4jzBWYxmwNPScJhXh4hvxdiyASSSRVeZrXIsSBZ9FZldJ4RNfVUykcGNDCOY0J6PnK1VlkinH/i1i2N6Cqp1p2y3x/0qbpbj/2SQ2c/9wvV39/oHfJ0TzV/V4TG6oR211rvwPt+WWp6rFx1YsxNdk8LlirbySlZ1sz94TcyOk/DmF3VdJCD+ycH/pk/ZDSQE1Qul49X9XSFOHJmdtIJngSkVJkoWWSloxi+j/h2Wn4CRKATXXVyvya73CR2WelM32KHbs1QIa+TDbKHCeAQeWnXXBuNexr8EBbBwJp57zVwnIyIYusWjqw59wdv+wpFr1kGK8seg690UvVZP2NJ6mMPydp5o04FtlXINYX4fjhezrGf0xJdZTM+5pJQ+kfFINlrikD5+DJ0CtFOQc06MUDv/az7vXbBDh6HVfBL+TEAL0wd/6aAGJLRKPM8xJJR5ntRcT7bh0pzlzb2pzOYiPFYusKXUO9ZlIqOSHOjb0rTS8zcnlC3ejTVfziEmsvrw4/ukgWk25PJjlZnhPVieN0xrD67m23RPnPTiuDNQKDiqWlfgCLi3H+rkYAl5/NdGnQ306RiPisXaL4gj6ylAgbe+Y0f77YBHiKJ5n8RSCdm+ePEIxQiP4Zl7NHAC7Yu1mM7bhPq7AM7hlUMMV2mfhCDGIPBEHzWw9geD6bD1bQjt/yzqbwJ/u+W3O9JKLMP/VXaJHbrie7s9qqnpEPlAeUeeAkRxcjT35P+LU/9eHfaMHBYM+6Dc1tFboMLLZLkHySu90TK8UPebsr3wqxViD/AxwuiwEIlhQ7NROmFAr92BqwKzovay6jEla30XWD1a8/m6AVgxy1D/AiQQqFHBSPeAAA+LpGESZg/LUer1RcOpwYKzyIKDX0fKfvRSJWl8s6YELg0eqnvxvAcz8NAkBrR8UoFsf2n2/uoEJse5fIEL6RG+C1f9fGG+U6SHLBxHnB0irdNKPeUSWD6puPIDNkQJJMQXMLsRCOUS/ZErcbUqM8IHmCbK1XjK6HUZm6C99/vT+cO21bG0ETvRmuSEefrO5sJuxVvly1UBRfS8OpLW28nCVdAAZ2u2E9ZjKqcRlLF5svqEkwMLwjc1BdBuiQs/uguhvwMkpfTA+08fcL3ZBnFN0OD1aZHGJflTLPZJhWPN4uY9mNckTU8inwto457Ndjl6eM2iZdES8MBpuhOvjEaPob/MWZ0uYHNQwGt3qha+cz6meSmTrX0p517Rd0ruW8lp22OcXpxgZXLFa1h7EgqxyvLBUkqiGp7h2P1P/nCY7M27POyx496/G5qT6Bu4/VIN/zkuziHHumptKA2lPGIzkw2zctJ940yADyjyQ7tEI5g7uAGrFyC4lFhxjqbRMfjWzK6nsfUoAfxqB1DIFaMKVaGl2jLhhvK9pYb7o0BkYk2fG5j+yQairCl618te2Jcb6Py/zltePP9ufzncJwFAdjt7vaI33VvTToaP8PxyZa6hDCgvT1SVCTw/JixpT1RjcC4kO0jDq8Jny2weFjBsKVmAF5E2cd5wLm3ELSLbHlEafqoS6DzDsQ53LnIK63Fc76QvUKZwqmJycYUYrDDqSDyhbCYDU5FRkvMH0yc6EKpCRVu+D2yk1EW1grpA5lfLZaiSMuwq7j4oEr3nZrLi8P+Fzf2c9RNsocP71lPEPG1u9UewFUWxgdZUOCNzB+s+l8e3sCCiG4WV+oGOxjkotTa3g1gLNv6ED25eaeReTmJbbN1gl4j6oT0W3Cc8cHgGVPrBH9mT3rlAtrAeZymHOKajQwZW9mwjqW8CgdEV36MbqHbqZmU2p94imoM9qchxrZ7M98wCdA4HpXhHyFrAB3IRnL/9sep3lGaPFgd6Wcy7wXSTRO3/wiZiO0/FEzUCxgX9vgAAU1AjRz9NsUBRQf0RA2oF22SGgBgCEy+67R1Z5Wxc/Lq/wqxk4LGfyigaYQ3RbouEQh+DWH58jGL2hH2pGxvzJgAABYWYTH9n1S/utNx1L7KoF3WbWODp95ulKWONVcTxtm28PbnFw7IOCBwkiyXUSh/zkhXFrrcWnwQDOWRpc5F4zCpjnw1gj+cu/6AWld6JLnz+LJojGG92AlguTU0whdCyyEXgFQA6w2S7bj6K+OGAJlraiTQEwXj/Fhbo8TtVAUI6WVPpRa/NFQYKa22WIPEsFsBj3bAMDG4tCsKfaigs8ZIwdPNhnpy7hQhEMm2rtbcjDDcLxNBk+gdcLkEfZ0CGsfFIgjX1dOOrR+sQ20+/OKekYw9zebOQQU0aLuROMOW1XNKksUVAPLgE0bTk26/1pWHpbHSI+QMcQ4689fU1L0zBzvxzmKORRputhz0HNf43Eb7C66RUaOL55jXBTqgTTb8nFonLS9ThxjeBwbtbAzS0JJ5bIu/xn3cSj7cTdgY58JdEMiSE0+dQC52QD+0MzbHAbxIU67w0Y7dorUPPr9rbPqjf7SHuIJnhf22sEujP41FWB+YWKwqc+fB1XPNsKBaafnKfB0HvapKmDZYxKmjkUkrfqAZ+bmsBik5jHqKXOHv+X6xbyMRUPw13j4hr7RsQ+FPwroR8coAkSq9HvR0MUNrXhVdpIeZvDKdU8pAwYYL27cKLPKKJ2j5u/gvxYscBShzJGqw9LPyROPve1Sh44y5rKID8MVGOIQhWs9tbaVi/IPrMPnSHJj7olI3Vh1atqqbexBjk0xyYkB7LozVhwovELmdHO0bOuVSfPQ37xVylQxRkcbJVij3N7+nMUKw1BD1RgylVsGqllRXd81/192e1Muq0JnCsWz3ki3/UyxRr3TeAjDDJNWrPec9iSgwsOJzTrGJRJm9LTHE9fyTEEc5Y3ZeFHh0V1vqr2KgWItMxfdWWGhZkpncMPcZTFXyooZaAZwBPxyGko8+XdjU7OYxfxgtXh9/4Gv9BnuARR8Bc11h3ptHH2vDSbwJvTj4qTLAOky0AAFyT6llftYAS0Yi03tR6/KxQYv1kDVVhI1pXE/u2Gje288UvgQuI9PX55gA5eFYwcGKzqvrxq+VZZGwwvYzw7CiJOdWlOnEMHUR+UQJWEMK7AGaFPzBceOq/vLUuR4QcagyJl9+RylkyoqnhqgWDX33dEYnTawt3A6JWwmlmeIy0KOGOdDz5bYxP56IyNNEXhAqYXmLts5Lz/oaBC/UExV065YrJ7VwvhQ+nQ7c5DWH+Kv1XAcrFxDwHywjfBAB4mr7DWQqgUnQfKuHdoFJhKwCzG7gQU6STxqVSXccKTWejHZsh1mPwQ4xmyVd3Sv1GM7UVIqjal+DM63Eu0CInuZBm/Nk9vQ9OPKJYv3urHx3p/H9Ppw1WWixvt6c3rqoRx3TzOq3OSS/AxSmopdmU9MoviZPIK7gHq0pwy3JAAzaPCnJ3YgEzgI3TgiFKgBIMkA9aQAAcEK1wY3qoRLo4RqRpWsmefQD52MjsyBupIIBdhoaKzii+Zneqba28sU7/T3tCUqAb0joHVyH3ag1Md2gVdAOuk2MdprIQ9bySsc4QMuRxMEcfZps9KSx7zFbVuPcnV5rnGKwr+i65JCMM7rgt0rOqhDELbAQyTrm0nooUv6pkIjMXS3wxJp+p6sIvfRAVQ8dsaOABfBlAt6dstE/cc/UMjIOYdZ9ixKCZLDVORYyzgN7AN07C5ewPOEABSrhVVttO3QMXK7e6u/l68Xkt5J6Y/m/NWJiW2arWvGA4EZ4bsRojN1/XKYafU01/Ft4AwqEYeAp92xcDUIOdLECFlD3CEI02ftWY8D0f7cit4d4ao4IGrONCbANV8zqqO6lQAxpdArsM89znl5dpsYwfXthMVfnI+fCbb+XRsipXpKEiukSUj5rMsfzpSTakgzLGWQmgMMiJaVkOYsirq2YO89RAAzNJyr8JCC2uCqywQYfUr1Gykgk4lLZ65r2p77l+76KHZZGTusHGON+cDaH2zCTKWBxYKh9l4SS83kBqAlTrGpDFLub1BJM8n3whU9L5HJMLYlKg07HfrVjSglK9KfolCunDb4W4l0gU1zGySTu9BYiSQjt9Vg+uCqpfAXug7JiNqOA4c3hA/xx/CtUZO8dc9lKyAqnvXLAb9iPvg/gDw2qdJjQmqOj2Za51LBsjVIvkF34X+ExpASGHIyABu5rPYLq+RM6pqOHr+FcRAvEZTiCPax3lvetWzhVdhJ2MrQKLf2tfcwCnmuDS4E6Q0RNNCFCLD5kssigBJo3MEkeybyM3lnxZx/UYPmG1iEAQzL7qcAxkbTzGUUU2CVAVgAAUB9ovUh45Wl2GWpyoytIzR7jP3klHZJqQoI/aJqjAlqqixCYLS3uZT3xKtnJiwWHeRrgAwEA/aGho3aWmSiXh+Wj/ihNOIO4YYRrwUkLpOj6nIY3YxSn5H+f/6FLF3B3TyItBRFxfNeen3sah5ZSfOrG2IX1k/bXBFOyUx3xqic/rYSN/2+ddrwobiS9GMGq7u4v70cwahlVB/o8ZIBeM3C9bVCmoAcP48tgMf48ljQsnfmdS72/NcsyKDCCTpL7uYBIECpQf0m+g6B3eIJsEZpQlGYPNprlVP15eTzhJxEauVyxFcrO+XPQAh+/bDahFp5Cyv1j4qHqUFL7VIDUtkUhM3/XHQFskJ/Yzi4DGOArM4jX8W0rLH53ucU/zDQUVKlnKihltnd+TARmgVLp/ZFbTAM8wp+0+qOvPMFmjbRJIH07MiHw2P4q2Tt2QAfrexoWigxatBEnl7qN2964z0Qn3dO7MtzksxpXxkLjRd9qGbYMHpA94wmRmOMslK3LpHRl7IyZCwikWa0IAEuxxc+N9uhZQgrw6uC7uu4rsn0qL2JdBLwhrOiQGpzz+QDNgxw4daodjVgMwpUDoyGk8+4FdIq40CaPz8oxis6/BCN2e17BlU19V7Omc7m/+f7ExYdOIn+OSM5Z09yLMLl1B1CMs+rmCFQEM7OqAaw3rSj8KyxntfrxZidP5W6i18VEKUlImSfDxxNlnpmlFgnT6/Bu34F9pUi+eiiPA6Y5AacsGpaQlUekoOxYQ7Rsiqaj/wkGfHyM4pGW+iyEyvWz0qL1U43Cd7csErgm86d5mkWcmqhOaB9SstkncdT6+UT5Rqsf11Srtj20AMf7oAcmh7xLWXc1TU4Ayyal4898vXktZO9IslT6q3sktyinrjhbcPiGMizi8ieHFVWA3fAyJ7b7T8m+lIOrwLzsmBAuX6Zq0ryNtBWQ4AIlYUatB2S0UlEp7tcO7Fjad8fUkVZ9xE4GKjCJrxyd+IkClyhcWhdSBJz+QpEl9g6x0q4pjoLQ9p7SosVOlFT/EL2V9W2aADNC3O/ByzWtA4VQEtyBkSkdarviQEl2+fZgwi8iSc9X00IF38NRXggCY7p0ziW5nsp2/i24OwYEmfW/3q8z4zuZL3NEANhwGY5KQ76K4TKgQ5fsR2PvtVfPVz/eY0Fxq5pmLHx6pQFvE21tkZQUyN73XeR63ZwKw+4HxBIvcvBAdKMr6XlL1U1YfreB4jLWkNT8Fvsh7psPX8lHOzKUY7PNoYeP7BCq/TEFQo54cqAdXY1xEm/j5u79TzvMOAnzv1DeDg1SDCTtQnhuyZrRHj5Cn7fUu09bPrgk7BtJ2Wmls1v3jYsy7nUBqhwQgqjjD5at8g2vW4ZjEfidvLYrR7I/8FAahx8Lv8XUr47J7mMEHxTPUKNsqH7rHVoK7WCUUh346j8HKFIT6iCUcAplUA34hC4I4brjHaePEbDfHUGOpd/sIzi3+6punw9Ij1fdhwqmR0B4DybPL3QBWqX/awgMIvD0Yxzf9jhTYv0KdFrMya1ae7ibLSw6/9oCoZaPWTCA2/lWoHONV/TJXUdydSgXjF1bNrn0/Shmm4JDvWiLNdEoXY/WMFLCQDRihR/Bocyi0RUPzmeqcRoPvVeXdVsdJiNNQOMvzDsapcExXIKIbXvZdypt8obgAf6HMZ5Pjotz5cccjh6/Hg8zwW9A2kuEWFTwdkWtRESf6NBeq0Sz7+skiGIxTVZcefrGvQtwBoaGCbxS37Mb/W9iObp5Og4O41U5y/otdIHWTPb8cR+sPJd5RXzc9AKJeHhIZxNLN7LYInyU49w/kI0GYTYJOeIl5o1dtg+4pICwexkqIsiEs53SEjJciBVye3Furx7FewMZMZ8kQTvsRcS1Ib9gUnPyPq7psskXXILisuttyKqEkQUyA4Vla/S6NwYSDhcFoDUmygO2V9b5LJq+oluB8YdeBF5ehCfzaXJW6TVzxtEBLVTCKiIm5WabfCiG269k3cBfaopGu4NPawLbBUgYB9BUV7E5Hnq3xwEV2UuSg/lp2VxNAU/G+Go7PSDq+9xSiXPqw0JEx0ayO7BFokRFOWzr+EU5DxCPZKosGEz49e1+dnfN+ydbMxCbYXOVtZ0/5iinkwXnQOyDjXqxqqLglSBr6c8L1VkzsQu4s50sabZLGrT/zvXZXCWrOWqg7SiLvT0CKIjuCDfK91mlbA+IRSlCZoXkaQFLfP/8tZqlhGVl103N3Y5u815Ktk9PvQxZv7wuosDGezxpdtdlCklWG0tj9q6DA4LlH/nbPMOcA/3DbqSh8/sSwuph51mAvMW8ARIqbH4zH9plA134hWYDCRg8lKWy4vG9cPf2Lr0vsuEukgTS2X8vgcIwYKLnZN8sTGzlpT5i0xoPkF/I97A1kVxgj+UlrvXbSw+xJciiXKCeRoQbr23ZHvfUZ9wFkF3NF+0FD/NcfA9P3FPXHVfvHE8MwliIioXE1Mpoe/Kzi2yd6oyZOWHOMAcr4Wp7EaRtH47LgBUE/Yx8SmworZBoWgwE683WZPuTRidH4SdwgSOIXchvMjM8gCxtl+uIRJHFG8VU0zdGbQ4hZrRT7ECmMxOnvag7MiHM62jKsZZyeP7wAAV4PUBIb0B4ei4tas7DGaMSULUOJSHlcI4DPQqZInbUiIPlX6pFAca2EtsJYVpnoiBXYAHZ3p3CIk/GQXFDEN+LR5K9sKIaSg6P6CSx1mULpDyoqqq8sV2/TBUiQ7iaQw/mEF1t82XDG7jCBp6a3jN5d11GYWGl4WPhKuEQnAZc9cla6VDI2BRemJpQ6usWLXnmO9nWDPa2+q6ibVuWarLRFBu4qiL1YQbpD5R6sf2T64uKfEhNPn+FQTXi3h1lV9ttoUvmyVCK2uKxtUwrw4HMBdxUVkm7EvKzDPsqC51vXEGdGG1+dUiBGSd1TKWYqDjzw8qMOXxz6+MO/SJeeJdLTm9oltZzMrBZuxp7p3dTe/GOvaJV6BXY5kH6smUnHIUipbTNTLs86Yd8+gpAMYrW4G+UjfZamCuDix/X64HmN0dAUtmPZg7zKjzaSQDthj8I8mxZ39IkkLP+BBCrDuL71q8zZJazDkRi8cdjsJ0okCfQKygHG9//sEeWo6SRYTZ3irC89EJ7f1ecrY7J87mBBjpHReUxsivtxvHIegNNt+89Ssd0rYsmcpxn1oGxmkS0YxvsFQ5kPD/xtw33/X1mc5cSODu/YdIR9N2CRWEH2r6BKSAHvAmAAF3Vcbtl1HNR/BsKGcObvtha30PN360weeoMEkDC2eXtuxJTBSzeoommb6aug8zn7Vj9cOe94c2or0AukwVOm0DY8d7gnoRHPr+DFXPXT1G5VN1rZcoYTz4E5bKT17UZDPSDuo1mPgCPqdfNOMtpMDdFoTHlB2j5HabHICUUQXSsHKfnC1lleDEFRhTR9GW8ZIxATAETSnRfs1zZSqB7yrqIr9i21padB5UVqzSHPzTXVa0VXH0u+b8sP6TPyk5CoBQk34fHWDBbKDWn9DSEO7KVqK1iD4o+7lH8OG1c1MvZv0rvT2ojx5LGu1lEv1o6vz1kIRIlmCj3ARrovXmF2/GW1S1cSO3TPlIPpsoBK4KtTs0K1CL0PSbnFnFoHiNk5llkLYb5iLb526iijouzm8KCdrfk8p5gabW5e9woeTNpnsaSWZX5o+2cOt4Fnx5KW3vUgrQFW6tgjYSQugao24+PSOLcvRasVpgHBb6i+/3ZNRlg3LhIT10361G9gBUlc7pCHJbgVqEK0CGWBVv++3aFEfZkGLXr6bCIuZ5kJc+6zoG8QHgxI8tZAAP+SFsYvvn47hb4V+jidZ35tXLyfYh+XeQ/ZQwP65QbI/M0seFfYj4DiNv7eDshE3Y2YG0DAuNNLjHSCBGo3ZZUTm+zmms1q9iFgpxU14EDfpylaSjm5CdAOAmSeIE67G5a7sgZRbVFknZf+9sjXBkcO29DdzhUI6gH6JtqQLGgTsc3Ypxh0qr5y8mwiDc/TzvErFc7o3xB6LpAGVLuSiF4QBOeR8lLe0nzAQedBnur/XvYU5lZSjdKtUUoili8ccVqks+q4xBUBee/45SPCXGbOAS+heNY2dtqAwg0bXOkaD+IJR7w3FNz8hNqiN2sQ1MwAQ2H7/0eQPnu6Ep4e731NlR1YM5TLHGQ5nEIW2nYfOgCdBpFtH1ynKr595rjPWO3/0fJ8Y84iiB2En4J0v+bNusB+01MS6YkOrZxukaiqEh7VI5WzgGE0PgRWZsGpQL+ac2BUQfELT9+bK4rD6UYWtdGrR2wavbLzyK6a0g/10tf3ns+PjQv7DJPRM2BGy4JA9pEfoooo7lQ3YueYJObZQX0M67r94jGTa1F+1lHS4JE0/3GutrDbumvoMm42zInY0Fed88v7RbE2fRSqLlQD2QElb+eNk1ZxH0t4cye1tRfdZ+v4JvdbsPmyVXvOJStpqCJaRHpl/2ui3Jr2WL1joWeCQavYZNyTSXTLvfQ9OnXbpdkXgn6GMZSqyPblCXmkTvkCE4pbha4EpjFDNXSkLwyEeM2jcc4/NCNPUYiO0t2DPaGAspFObSC/RLZppoONOm+j0c6uEscsaktGsLHPdWj7dxT1kVMX5+9e0cSigSsu3CoRf8CF+dDz/ukYiHmF1NTHC/JHCsiQYyungtX7IsgXaIDPRHNQX1LdADZbSXGBd8/aP1xJAamYUo6cVPw/Zc4qcbfOXSiXmDSO56zv0/za3NhRwyca1042752da/z5iWDuctZ7SOU2wTz4a5P27uS6o7yX2J/IVzkr+rN8D1hAESF1VQKgWD4HXb8vGBU2G7AJM3Ali4xNfIye8acLe0Bt10QSGaSSqy2prbcwzZFhJNc2mU1FwHXntMl5RY+CDS12yxVU0JEDh3Rvq0G+dIKF/3oy8auQqTK9JcNSwiNeTdR2YK5gnHgoBkoDSU74c/Y1MunP5p/miydK57eDTWNB2EpvH+MEUjnW1HBvAKXfIgIzK20uaewcko8FEXLCgXvwNY04IVq96p9bB2o51dm/T0fFyFLSxDkau7cKjEaHNatZ087mueIQrinNHIxL2QOSNY9tScITGm+i4gFLEy9cyIhoJTSxXcPEWi6yFYbowms3EIro7X9X9k+Nx6o7dZEIu8fLJ+zVZyGVn3FjliMTVkEPz2QAUH9WYyutdemuDkoCEUgMCRDBZBwrrxIsqikt1Xt8IbqXInU92y4MGBqfJPSJmvewCa3ZQpdOIVl8Xzlk75cZwZ52M0x6HkWNO9T0q85y6w2JOwALQtS0291e77q0yNezCHiiMxch0K7EiBZCvB0IJ8fwXV5oxI22ASXfq5n1bkoyxqKVIp0+3rKGMBX8ZgXhnkiQvHZuhobuGFEx2HywxVIo+BNjwuJJ5YjsVkyWA8b/g4Z619Z1yddJPMliU1y9Qmug98rukPwFyDJLeg8LyNItMFzxsuwVHoVN/zZ654+71711bBXPz7QO8NmQ7uPAmkg2RptHuFtUjokBmE3gB4g7gUx6xEdPiHZJ7d2dBZWg+f3SR4p12HBC/PNuoG6fuFUJ7hC2XhFWKVDXCJ/gzOxo3c+Iek91L4pgS6gnpUkbRdLoky3lcIrvvmc8owBduVZPCQvRoG8LNu0pLKz2q+qr0tiLsPWBbyREoNmvExBApts38FVhG03a/WIZ3BRVdtDw0IlsF8DV+XeF4pS/3kMxRUcxOghPKAb1orABd1sJIIvL/8XFiAUx6qCRAZwUZlsO9tV+wzt6pHT50nNQscQqA+1jdOxe0kgmkim9rIiJaFhteGxNG9gWU0k3Ji3IehMQSW8YVBBjT7WbWwTbqKyYwmR9vy7wsRc0ONhhx8nKsr2y5qCc20L8JWOz99FtkRn6Sj1uH+UtczFsJfNF6yyCjr5SAgHK7gRP2fwtXeMef/kkx4oBCwqXOTQS9iNXeL3VEnHc5hyVJKF9zubAzcYt2uQHN+KTKz5qvG1BVsxsM1rWuOb2+WxJ3L8DtaN43+pFdTVO6RHufJrrA3b/0Z6wY9HJ36aHU4qtPfi/FKqkRFahwhVeTfSAUBfgl9yfeZYIlTVuYZ3OiJIAQkdhMMMic8yoHcoobRlODdda4UsAZHzK1OBrUGifwNWDxEmPTVxxmQopRNYiu4BhPkryfileKT455MLtsZc2voBY6Q1oIci4zDg+4hfWAw953u1p9NjbDkuhZcEiRsPaUebSZQIwjgLcJ+pJVLTZwxgC9reSECcmvLZWB/QsaSptIoyuP49FxQQ4fcz24LDkdaxSFaJ5gVs/5OxyCaSqKzCTRI/xU3xFkrCN9v6766VnKbNU4/NNW6oGoh7OlLjLTfsjnJdPXfR0v4RBmkkjab8uZpV27aPol426zrn4xaaDsKEi5l0L2W8bXaU8Zy0h7HB9HWgKcrGEtXF7bDVBLW7U0F6NCAr+qaCN4OA7TreJF/RqZJoQv8v4VId2JYGOeb63Cwc4gFIHgTdRewrdUNz27+JMeMYLhbtLfdSJvvSAliRVFYgHls75mfVmdD9c3IifdeYbe+aNXld20u3GvyoyoDC6gd+SiYGNSSJqWBAPqAc86AJVcyp7EDu0JqFTrdbVf9k7nzNAfwSwa6PU+gSJfssyNUcb7Wtfrq8qzzffeXsjip4Pj/LxlQm5O4G4q3pIFdUcZASoOaT9eGsQNi032MrNGHSJkB5SIRK5WuszpGszDUWN/p+daoN9p7IfRZq5XgrrzPGUiY4ynrLrE7ttJcY6G9zhvlsh4BrE3XDR13IFNsI7FvJ9OvR20rJMzFclrQx3dVUNAif13dQ3QpIuL+AQglZfCTmP+8GCKkHtwVA5oJNle7GIVpcOzGAA0ShJIOof3n2iy97ElftT4pqhI1aojKrtPbhnGhBJI/NsUWsyKD6gDC6vWPaTL1CDlna+pe1L6Qs4VG6EqAMjSgJKH3GBEiHtu88vpmGt6m1zSirrekY/MCCQNqpDevCID9WJ6dId/hDxsjZR7mBiIWh7QjNZ4YATw6Min7Goyd/x+xPO7tXZ+kHBFqRpTAnm2LBCRiqdlVxbGCakN7PiPshv+tJuy3/W7hPqjw6dJglWi/MrIcKqLwWUKC7HhQuWg2RuitpiRrRSJ6iueqYZM6PuPv1kZzOl+s33TuXNXUMdjjsdF5Jbw5jBARwfKpNa415wx0gt1YObYv8FgCmNEN2ARLBjW4lPn8T8If1aEc67I5Au5gsxHv3PT5dO6YhCTrYrf5xrusIMHx726niibAkx3CeGrPiU8oQPtw4UEEu4+g0JXaRDE29ru/jKN1qD+TUdvAJ5YvUyyRDrubU9q7ztCS5EaXfi5ZRwAxO6EkkfSKHaAj/2BvsezAMqwN4YlneoGghUwblISuZOLStXJzaWqRsDdPc9V/3syaPbEOwTG45A+Kg6Wny5/6ucN6/zhmYidj8SbAa1DG3ZlvliSvejqiOsv4iVgbXcriTSDjYpQ1YwRuWhaxf66ov0Y/T2Gqn6WfGH61AIcK+atWDnDWe5beiD2p8uyzxdW4ZVSVoAdPBosfzd00V64NqLruutjZ0R7dubwcnJ/MFtN9cxw1B6/lTJkrhaVvlUOld6Sob8xT0M6quwnLVD/ljtHLtCDzivfoEGf0ps4WoSy0bdeHhbYZ3bGCvCL2axetfucmn08yzSdas9V883XSFY68iWyMIAlqN/bRIOSi4/1Pq3Mv3WexyjujB8764cnBCE4SJMrJgWDPmUNsieAAmcmUFKpGxkXuAEaM6yv2IGkDsnk0JY5Xvag3S3t+O2RtZa9verTSlCD6ypMnLILuTNJEamQrPynwIgN/qXehnoKbCNkz+gdTOz/a7y1n2Um/T6ftZGOF0eyl8FifjPxrrseDlhEoyPYMWLGbdTbfEcpTTGGjXtovzIBGTU1s14cZkvLII07Sloi4RZ7QIuYOFZK0JNfqvLVdWEDAA0XNRXjTmHCeJ0neQjFd1X1X2uVy2lwWrUhwMM8BCSQkubE/SIRgKp8IUHPfn4OVjAKm8J+Adn21OW6bv71j7QQwcY9Nb0lwXnWGdYcwqcO69jUzlfFQBLonyLnblZhwdnlFerf0CtcVq32ys4lMt0NvNTv93FXRAkKn/SirV0hQgX8egHD/F9yeXNtXMa0WqcLZJeasPNX6iB/NwjdXjsp59SjegX2QmpgpanLvi9DGzwZi16wWUMgBtMwskCeOt9tsWs+lCcQoGCr6Cp1A9OAi1d+Vndq5oGkbKqERzNM1PPM8uTxUJM/l+lOVBSmr7Zq7CJ0JRFUCLqJhSDNzhg+78n4mTY9EDoDlS5hR+CyFzDmX8GCjwcM++KBE30J21K+0QjRBOTWOonowXsPuLq6rMY8NW/+pkp2aPE6Yk2NOjoJnYX0P9L93MvKDorqDQUvmDvGeCylvkoUB+PiHveyyKt6TMgvPXAN4YKUBRSqznbHr6YRJDHGpQ1eSPA2095w4/sBJA4VOrHRv+BU5qV1Bn35llA+kwaOdSnVbz/DjCQufyjjcvaX6Sj1Tgr6PBw1FxDgBLcUuyYoDUp7s2hvranMV+VtmpkdB8s+0qoXvkcLFt3ABp00G8WNCh2aFATFrEUVPYFiCPWwExghJyFcVwz0zyscIg/cPfrZvwZeAjeV8poMM0oFBj6X2QkSukkyYt1N5lnHwbwpv89iBvtYAMVN28h+fHK8KcY5LY39KvtID4XmzL95Eqd3SdHeD6bPHNL52yw7iIEv0HX/nVzGyCaise7VUo25lhP0iiCOUcvFVWELMrDIl8YDnFWU1zCn2LWtreGA5wywl+nZ6HMU8/gwMAFudqYPA2VE+9StiODyT6+vGrFvcYnW2qIb6qlO74T/luDsh9hsLSknGF9h6nUclQR3Pl7yTKzFKoihoJ8koSoBQ229EPaD8ojR/gEj1C2xm1TC/5HoPjjOgvP911qzKOsH59dWg0slPamH8IVbbsYeeY+6Bp7rLIYIOe5TS5q7N//uO5BQdyV2DrS1ogROPdDVk/hklQ6jGyqF2SeDV0XFR65xp4E8qmMbu3cWD/XnxNcqM//VCgCcnlTifuX7d6eac0m1misO0H4kulCDC4kfa9iSiQyLYYKwFb236zB5+iQlBPG3k2aLmusla+5w56W6a+V8jCg5yJloXF6jPyaVB/LTNwZqczxRwiBmsWc1ZRZRP6LjA4VM0SInfb8PgdkAG7uCxx4y0+3fnUBWcSsScuodNHAR5sNO9G/0AFsBzO4czmeUGclvAXC5PzMPLASxrE1CEMhzvVMMaIeRci4wcQnZu3AhdIRi65g7uKkbLz0MsRx9u8zeKyPMiTvwbaDNDXGkTYS5DwUSdVF5LHsiba/k9HLmtUnbZi1SdhNNmU0TUJN6wrQkurQhO85NMfbtNa8e2IeoIRoh5MmPOa4/Hq/fq3+kpH1eYIpDtw11OscHAGrUL3xsNiJmtB8Bwsksa8z3wXu2ig/fNIbKrLFMaPT1uCR/k+5RxdXCtmtBKRoyD4CwLUWxu5Q7vPdgjscmm89jeAF3Rvhu3qj7EtsyAxIhwP9SIdY5omDWn+7doHg+ESYbPjlNePs5dtq9RRnKSO0TjghOT6dJRdgRyXVi0c1h4hscJ9IJ/xaKZ+7h/sZUtCqFaqKaDyWPAlavQwkDOtJSxHLxEx6m/YafWpTB5NVQULMuVTgz+THSsYckJtKU0ghagZVXdZ5gVfu1TzkxJmkTjdryvIz7UPgMSwE4KXh3CP7rFBBXmGo3M58YQ4oH4yvlsLE9bi1mTQ89u2nNVxWG9XoJiBaxIeITIsbRgms58wGoshb+6K/HzGC036+fE62kgbi+Sm/ctf1FXzbh1DAe6wGEZbKpUn+tQUcG8w/SiBAiCpqP9YBf0iFVDyBE8w6/dvJLsIztaf1KfKnQ0FyikxSMUxti5fCGuZpl3L0iHoGR2kyUecMZ5IpmWkR6IMpml6fKaRLCQkEQ6u13f0Wz97NiRa4rPevKGImXwV9U1Te9gEjX2uLtdHXHC+03EUUNe1cbkYQhVMbQyjkBnOQFWqzmoJydG8dc640n8w+yE/sOxxs4QtjgDKfczidAIDEBayv6Ks62HH9yEdgDeoy6nkGL5JhNFDvsuvQ90j5s8Fsm1FwU4GS3m5M+jveewGiocSuEh/IXiA4Hk68+C/XlPnNb847bBrucu2BGMwHZgvMmYeDqrDR/PEp0bLd57W+xYzr2lVBRyqRIKPx4lpF87HKH5nLsv8IxQMWLRNtzAvIZAAnoYa2cT4ViVT/6NOTZJB2/3HhM9oE0hrWiLKOi98D+SAJZE3Q5IRy9R0BQe7zdXqq4S6vsbxIAsDJHHQ1BTliqTyis7Etbx3M1FeziHb9UtbvwmhMZTZNSsyboEfOzm3aAZFgd2ugDcRJscaUHkqJgGpMgH2pFKs9uWHSLWX8CNBoOn3JeKpZvJ87niPdgcGUFX5A2wYr5OZmlPE9/+lBslpEr+lcyt7TWHDglg+MTxswgmKlaK5L3MqOI7KsFNPtGeeY2zlOt/oGaINwogKVQpCfXoB8Y7oAJF02vhZU/YEEOJ5kx0aAjVZDYjlk3p1oAa+bnRnrgwcd63TCsbutuD/vmp1yzlxrw0aaOmqrXIdptuQTr9IdlfYYxBrpdYeijE0UHP21KuoEwKtduCheya+rT0rQvlGQrkxQm9hSFqiLNr0fTDQxIHMvwjO1DqvFAuxdZp495FZaGYPVLp0jXVod257aV0J/zz6KeVqwDDOsF+8lKLjn7Z06+cUhc2mqeq23kjJX1FfwGjpTepGz/X0SyzqPhiCN8xyKOlwRdkAl84+Ukv2qzsU3e2qoB+qdQnp4PPw7vv0XJTfLTFvTVynycoZPPsXD5n/xAFUbZOss2sGYWMSLxY//vQ5pnMPLDZqTgIfppFYtpDB6GWALUPshZNukSy+kzjE2wqat814RA4BUslGNn4h2Cy/QzEkh9kSyj70Gmv++ZnYu1PvRHTG4U7w57H3aTDC8rB4iTG3m4igCYW78BkS7fUwf0iTvuC2fWuPGAMzaTlwHmZqmwbIKw+Kj9A3pq+9/1A6+tM8qJNevohaPIGIYhsMsH+QR2GZodYVUsA/9aRKXgxnuD7+pwsPUTsY7T/mMs6NtSUcE3HleqlCwGUdEX9gLzLQUy6xwJwf5jDPMVkYLTWrByvTVTucfSnNA4Tf4zsMXQQZaXN6rwQ6vwAaR2f5ZkeYbmcYbO7cci4Fpx0jWL4V9MxV7FO9bPJxsjO4cOaQT/hsGfXASawXgghpMnnwhOlz0p70uGLGUiZPNYcWuNd6dyBdk+Tp0CvohgWRR1y/MyVgs8qa3y3SW2M8CVfTjVkRLXowYGKw+1MZ5wKrsu6ZR+9HFtvNQJXMGPMAhSNZjm7617zjX4fsfZbSivOKeTOLnu7zleXwVYv2jpzJVLXoEUBYzoCWZr3sxnB3mZyE1di5nqpqdp1yAZlwVwfdIrKH2rNl14HeBRwEASE5sJ9KiL7PiIPnfcsS56veY+OnRw+tcHzazCxwTNWsfoabtpyNAk+wTHT0OTJYsXUmDT5H6ccgegSkicYZVkBF5ysbkDuoBmcaPiTWH+5fq6LGX4Bg1uMKi35IYYge3hBYe6rduZr2sZwQqL4dEz7Bv/7Ui78O5pxWRDgsnTTY+vq7FGEK9XvKCEaM9njKqehmm1w5dpr54uU2KnIuWUn5lk3lbVg/D9+hsMIZjkyNkaHFx/BJMI4EF6N+zQBeyno0+csqps4MATeMcnCc6CS6Y5nhwT4xFTqu7wNZZQVXvdH9qGMtSmFur4YQl6+FXWHnpJOJQosA1r3YgbX4bjiPqFpTSzEk7mZ4zHUK+mE9ePLVeLhpzikXIA9n9uN5uP0usacxdvIZbeGwM/ORqCS6ni/7bD2cvyynNnGWZuIBrN4Rs1sMuTz30f0SXD7jqxgXF2nbcRhuFF5gIDaSBsrr72inNY57c3+GtNhQFqECrGnUOascWnqiwhFvBitcFdgYUTW+qrpXNANqy03rcEYWYBP4pUetCVKGCIwltUJc7nJqPODdFPuegONt4Zy011S5ODhcehAbnPnnBa/HlqdBFn6mNaC9mqJ6bJ3mRFdxleILXg7p6rkEfVJQgCI0pb3dza84uBz6/LpD7nZ0kjNwtmZII4NXfb52F07SN8sFokeVwYMjn8MJEQW4+DMpAP9Dyr8v19M6E9ytN4IyXtkvebxZNHf5xcvEgyMqpHvnr9tMDs9dVtq/RzXykpmq9Zxg6Y+NMPiM5ofXtKjIC6yDAd11F7lYGBRl8eTeZMaSJlNOqnZ6p7On2rqONQV7jXUvCffE6DeAL5K+oY/MNNSzqrUYtvp7naj661JrKssseFpF9Eb6/KSQScL9riWczq7Aq1R1Nznw2tOMr0mjuuuvaMiCa27ea2V56WU28ijIKaApADT19UYgR4h4DtlSDyo1uOLj2cvr6BzhnjiMIkJoC9Ct8bWHH4tAiyG6IHg3vF3WGtgsPhrQSnI+Dn1M4Tz4v1f35hOz1hW6M2XSkIUHROSwP1xkhSg8pE3LhQyhVnFuDyx/tDT359ghCp1e4+UoJJj1j8ahmb+jIt3SjI2vtbkzDJIl39iCqsQnLpRF1IQBwoQM4S088w4hG4wt8gK7j6ut3aEbpu6Pu/j4UH1CMrd63qyVH842Jg/K3Bc7B3xswj8QkVlU9QQ7PtK/M/G4nE31wPwTnxe6747uIClHnG42cVrpBV1sVDQ5bdzNIVEoU7Bzmey5J7rdjCblqkyMddtnsn54UBtuwkehZ0pTjIQLgMJN9wL5VdLmDUzKkGD5MPO4+C9bE9hxOSzHwz11ge95rS/Zud2LCBmkuUXG+/54M4h5vw81qsWESyujEYsQtcV5YvnY03inHQuaP0gI3K8njrU1QiR0EAemMwaO1/Ab1o1CavOL0lvQIsIDoVIknmnhSp5+C3cSsUANtqF4ASx1VbZ4cz0FKanfJQrHK8YDsw709ieWQXDav6gyebAET7IVTxF0mh8AjE9zmSZ/fMetfUOGfpaVXcs0HeKAzEwY7QIqNBTH1lQdyEj+avHX7mwhFBoF6twGZ6sla5RHl2b8HFkHx5BjCh1Da3WWcW5ijxvfa9uGWMgFmVEcZWKkbyRJRED65woLoam7j6l+rN4j70q9Benx2BmMBx9JiNr8V7+m7Iz+Q2Ar726QshwveaGugu1VzkKOmPIphK//j74vGIOE+CPB8ZPJrfE6oG/eMUT2ieIQVhLVFhlQLw0zl7UUGMQ7NK/nOriVspps9hQck3WMpraClFNgUvqIa73Ax0+R598E/GIX0exqjTk3o//UXltU2mzmTiKmiMW9gAiWR19+9Dcco673Zf7O7vnsWko7iNq59s1XacSyH9yDqvndqieyIyYybxbL5ymHjHySWHZ/k1JS4L2GyEqwWKVXxzAwztOhRMjW4R60nxzipbmuiRY44TagdXquXLAksv2vTdi0cFR0eipXBxYpcI5xSgxCSxsg5Ofx3GPWV0cJLzKEUnsZCLYNbAUWGJyNeQDxL1aufHk4i2ozG3NifIxQDSRNtfgZJGZZRSGUxuMcUl5Twr6NTFK3SfAFoXUVncl2L24Y26/pywik7COz7rdJakNl9BLG1qe5WaQfa8GnAwQ/130QQcK/d6VQtyt+xlA/7A0Zm0hO1jtt1DB0+kyIFMU0ASS8gZbVUFREoDPPksR7/8dbtyZyqtrySND0rbedmTn6EjGykafKfwPae74KaLrZGAZOPRinjB6PMNIr76vRHwBsmouA6+rnev56jv/t/sxbbCy01LYUKRbpFB+Fbpx7xEYpWRtr6gEGvETE8zhgVFinAUloqOn4FVNf/j0pBRO4zP6j73aItDHaiObVNYs0fDuBdKyM4XlihQ5SNOU33Kw8Gx09HaHMaoIxZbZJzrq+9CMoo4Lvk36qFxVgjhkQK5IFZ0ynhKitn0Xcji3uNujOUqMKWqEQZhzYKUJONwnXua66MP5YCm0USNO3ndzFi8ODHpLXd3rVH1EElR9MLXS9m0a9FEN1z+G7Lhjgx0KMo4VwSr6afkRyLvg15mWnTzvrJsA1/zc28wGXvIgktzQFQmY5kTUe/YvCqvEk3KWUWoM1GP+POfJhkiqJphzih9bhgjLKdUh5YJY/Uu8MHC4HRz8AFJVY+BrMflWbVqt1Vf1wumOMiiUdWxrdO95QpjIxlFQM4VDQXigskQQ19kcf1HyyrnAxof+lMLW1ZeYGl3BEpmG8HBjPcZ0lV8vUzxdJdR0EUZRq9M7q5XFsst8h/oO+2A7KVGe8Xpm/rATwMxT7z0LF8TZqdpNOkj81WA9qF4fzX4ARvl96VmmDSeuGZ23vxZbokKpcW72D4lroP5/7UJmqOlBSUzh8E1mi1qb+SiI27AwUDKYIEKyXQRyvU0EXim9vdu9/NFwNatkimR89o1y9C0YeLAQhsR4OaAAIPBgIx1YYB5cO+Aj//hzLuiMHJkij1hCwio5wr3UHwlAPeaJ6eB1SmoMbELYu2mCIvNOhpx39bHZ1OFDhHeUYbqL4WzDhgWMMOUZZTVsY2XBCH+depnWCBn0Er8nq0tdHWuqn1iqhPhwyZpR0QPh6Y1ezFZj4rftJKl4K4BkquzKyXbYcLW3eCyWGgFwDsbjcZizdVXocryfRryqgsYcbajPWjIQrHeMZWN88S3d4+viPenoYTcRLMIp7zAXANs3NIRbszi/WmaLVEnyIjOEEx3Nq6cOxnU3yFgIiJNwFpRlgOk6S3oqyjd0L4BVlupsXb8EiG4MMdDu+1zjB39l/4szv65saNcibikEj1VAXIjvhktg6/mX/V/6UvAgynT4hwJ6QJky+r58lCyMSGcbDIoBCu/di/j3Mlv+r7zbNEl0GIaP/KDiwKtLD92QNXHYQiWQ/NPd3Eq2U1Sok2/maqHUzT8Idk6i2ReDN0K9UoONIHb9B0RtDSkA3euSGlRPxyaVDJ8eFYP9qRYIRSoft/51mnB+LuPcpw8LkAg1ykvgYdM7F3sEAizkRWRpy87gMquxoEZsvmbT6inAKAeeqEuBv1u/CicM5a+ZpIo7Nq8ua2HilnWIVovnP4KBKBfXy7qswgfj8JOf63ThhhLD7fzYHpJ3XyYIjVLj5MutJHKMld0RUk58fLSMebFMMND2+0C/JVVZZ3yQ2av96vNmaeSSPpcDxmvU4Ktj4CYS67Wt8HRNt2J9cX6ARe1ln0mAeEQJgmd5mnVelKnekBw499Xd+ULSynczhap5Af8mLeQ9/uhqDuYqx+SwrkX5djg72DOphVqBlBqCVVXm3Ui/x7F7SjDAerRadTpzmVFJ0tzrKgr5K3CUiFtPBiq/5ZNPW4z9lKYlsQXwyWbI2f6UsZ6GOnRrEWUxfw5TVBLFek2alnqnB3DXTdOiU5PFw0Wyd5k6bnjBpmgkGe7Zm+f9ILcjNpUrfLD9zyiINriLvwLVSL1gMp2FOfpe9EQmhyO2xogg37lhdxGV2zqsDK1hZXHCGWXVZn9xBFxOHkmDS7yJYSGayWG3+5Vqa7JA1p0J+DgPH9aHqtyTD0g344VtD7sCcMIMiSR9jTMCwhTbiCrTRzdWww7fUMKaMFM6boEutwIE4e4mdvB03kABUi7SCSXdFun8C+NCW6dsmw9iKDeTF1lYDhuzoaXYmn2156iclys4G6HOZPLfB1xgUZaDbozOQy9lU3MrtMxLLQMO71ihN3QZYA6nReb4KCVI+Iw1lEWuLWiG+cUtQddil+PLN/rFoBEWTUOzkXC52acyoFqB+BDjUcLmoNEo0mxbefBntBpDD+1iY3vbBki9mRCYAtg1y15fmvNzUPoWJ1zh+cBOlMXVnhqGwf3SIJRk+RJ7N4riZPkLucVP8XzvBQIPKzyALBUx/gK1JgxaMjfujHnXJxRsuqk0kkRe/lnzRLs3C2S+xdnN6EtyZfZcLlIEV/2uDqXG4YXYtQlWFelobEnHc36ip6leWPCf103kyb23LEH54Ogo4sTHUdtffdl/bXejQVn9dHiEHlWSSM/mmmt5A7IhCHIBvKigq9rj9LsrIcM3DR7zbscN08V/N1VaR4w+EDeX09wJschIap4ghiDz5RF0fgK4lfChC5MmYE0eiJBHfyV4NVv7DHwSEtfrJhgdq7JIByFlFfg9JXeoh1iYh+ximwvEPWsI7XhIehh24IBrSk60TGY6K2fa5LrJKQpnoQgjaduspguO00mQmApuaSNGYPgOrYcr9UdcCiT4L6i50XaOYYbGVMfzlFvnWCGWnO6vFHGo9z5U7lzhmoSw5BOAORLy3b0hLUwUrXqD2eowfoypnQJJgcPy8nO/vIcol3mZaK2CyNDaa/hIEOLqxYRy2TtFiRlj/pAG0Cq4R5P0RtO32rQ38eBH4J+9VF3AHKNwWVJLDzHz+0kSjO+J1ShXezdQnKhdrBS9g5uE/5ZOYTFOLWCN64xaQPggQduFevUhkbC/ijvruni/ItS7oeSxuLoeEnpNJsbUANyTaJ/QzThaRwEOB1+JEtKcm9x080YWCgpgTFC3ZdGYrtymGINhdIKdSiV1I0pW90eFJDVRmcIZoVC3bKoUNAh7BZRz0xpgH0lYPD3Hj7zHU12HlzfoSU2OFmb9eysvyO0Mig4X4W9w8XIufYvppyWZHMEHKJTERpooM8vcuQRWEc4TZ1XThKoc0cSJsQtKLKxARufYvRSNebkENPK/3bghtk0YMoURdQP1ebpp9qzpnGwSS7j7EoheV5EmgDgUsI5MoIeFC9Fu4vBHCrnZzBhE0ArvHhk9f1t9Gta6VDYn2os4NC+9FLvLI6iVpRL4M5bgPnl+sgLDdAjtRM7hyBd1b4wVdJ7dEpq3WrvvO0t0lEbXs9W14Q0Ktm6kH5OMT8omS1u86YonnUThifTmATtUJKt0O19yec5dDb2BdmpNWnppurMqCEeYzdXjKZJUzwnTB9ePqhybZvy2D5dqdK7v3DP1VXs1qj/EaR3mkaA4j1A++r8S6LZbktnCBCiUPEmuE+iiq4L88rCx+sp/MKunxBXgn0jhmTMO2KdzWPnwo/yzo+8HDse3pH+P0MSG6PMYn3TLknyd9QfucuXPnqNxdPC6ND35bOBYpQ1Wd56XukWRExUZCi7bUYmZB+NAeX0ZuqsqrnjgjziXqxGjts394ayj/iB2JVoocg8TVnt4NlDRVfeZ7iviPeQAy9I8POsVGDb8mJKVHVu7qLNQZVqcTffIEnQTO0avQfi1MODI2fHmP3qvm9NBjzeQHP7aFXskYkE+8/8DZzNXgHo7JezWQZYyEdhCUB8XAYh7wtQqxlZ+i5GYpB/Mb3hgnxgPud1JbbPr0Fx4g5KgytJOC8csyUNbKau+xxrUc2LAaqbsQicA0SNaZzCD+LUTo92Dzh6ET2/mjk4bDxes2U24JRSWUL4/qETqn2ksejPZ524N14BU8CIOlnX2zzxNr/1X6iMo4wLxvgFc1/T8PIlocC/frY9zyRmMpYQHNGXtUQBeJ5cxtwLGzrsmcoxJKcooNsZhYnQlUHRZ6xR5Kj9JM26IPr3gnJtHtDoYXlGi0V4LoMrvQaQ7flvEOHAyih6aW5a2adfqs3sIiq9IHVNX373LnoNheu1G3yWyjftVL1Oka5UV9K8Nd/vdiJcKsLWbw5Q4CMYb6AAVxtLumWMBJ2D9rQhF2LuebfTjvMu96++LhMYNeu4ML2gvvwPxSpi6C3VoW+aHedIx+ql2wgiGa6ypX6Ijz+hisZyMeAz8eBzm5/1MZWcMRxUAsnv3IzCa9sViT6HJzfE2LYtNN4eodYVj8NkBSLpbeKhow5Z2r0V8g8opPDA7TyyKZ44krIFRewgj8v7KbZ6VKRkUcPV8uXghCQSGK/Q/8HBvqwSXlxJlWNHRR+yi1ALN+awtLQPX8ZTgAhfS3Dju6fQH5wlBPSbtMjEI097f50BjhBGCVAUgUfHtiL72X653fWqcMy48ZDSAf+JVpVmodsUL8Jwq+rpCj+vCZLSM2hYCrtRAyqoECLGiBUb+Dj1L/VdUPSN+EZtW+Uo1H8i/nZdc/mshN1blKmZJNYcBt+vyrgIxghwjT3NiBtsmZK6EeiwByhlWx5NvqyAGJfVwDvjGpxon1AxQuZfjZSTbNndaOF9cybfCGnRBH7/UvkSx9X24xXTNX4yJ0u9sjSSYp+UEZdqveEYMaOO1Q2FRl5OGTRyEdRtxR4b+1WFeEwQ0eEveuMXqlG8JJ7RBjaFSLJIkGX1PdJxJZxNVbvWvrrzUQrxmpSnAMTzq4PUcp+SUt4uOD6s4qHcfcEAsUFEkbxyemLANSy0BNUFO+0Cgo+5KILzf0nxz/mU1+qsW8IT3AlMb4mplgt3NWY9BgxSaBQZCl/rfMnLdyT7EpsIxxFCiButaGff6Nl/J4o08cmyxYph9oSdKhGm7sVONdsyH6HpDWLqz/dtMixOg4BPwdCut6SJTDx2Jx19/MQ9UCB5M5azDV++4THRefV2g7Uvy8jvZB7Dr4oBdIV/0DsuNObGRV1+XDKfZz7cd9uXrF1AnuSRJTh98ySE6qw6FYGIkFZ4qa45b5SP6dQ7ZR+N0x6EtXEZPlSmUXrUuZEUdL7LbX+dsqKIdirtr+PA5kbR30CfvKZoAzTuTRbSNtgl7l1wbJ3GMe+0eytitAAD8f4vniJzyyIjnOEZx2vjLUzN3mfkLeWxI9XLEVP9htR8TFkGzwhzO64zBz1cGEd5htSX+vEctXgrVlQrw5ob5xTaAnThu0sOjLV4znG9un1GX8xbiPe0FBWOyU2h8i/hL9iuKderWBXlX1nsOkLPgFRjnvnXaiVHqrUZ6l6MIBOipWQ4Auq3LtpxXDgOcIPfyhHYiLgwlKvyhjZtk8fQ3x+v//0CBHKUx1R6QTjh65YUGO5UzUgVcUgm2ko2GK8CdFViW9H42BXbHPmfBKpT2CfjKNuKXHq95Grpi3cmQbe3lfdvCnOhw7LKRnuJEXXvT0lWn9OBbeHQq1mOqcMDsobTbLL8LUjfuuoaFznU7kI3j6UoEPP3kjNcPK7AZ3qPP76MQ5GoiBjJwdZHU5tUUcKhrgM1EX2UPtR62FQds57S7bpCvEgW5Z7y2KQViosmTueyZY8nnLRWBNpQ1xyujTm/ZtKsz5Nuj5qQwBmEl4Ub0rlnflrUkMb6zpE8DNvevgaIrxX4aav6RnzKgbLAFbC38w4q3zv2FOKltOrd6ZUnYnHENKzSj1AakCFLgo5nBze0FosYfsnNOmeRxMQ6QDRD7qr6EdfXn5DUEwA9Ve6ROVumtRkLjcsnwSFwLXJFk+iTDVqrCOPlrfwndmio/D7byyFWH7Uj5yKoVlM1foPkZzyDPACx3uUzoFlsyGcKX/sJz8uEJ4hw7s60dPM5J1xA6nU/5FaIWExG8RAb3HeCKFRn98QGZ94bluPB2G26uuLU1/qAP+AAw2GbizUGYqNeEKxlsHCNJ1/PCp1ZVqSxGCjPjGhC/P+uxivKQCfaqd2okgjealMQOVkqbTWPkSwYfI8uQJWtZoG5+tNYNIWgZ0azXtQkPNuxS74I43KZZwLTP6zFyHvSIzg8EGFj51TgfhoyQ6sA7xkGDnXx0fJjMmslq8WcP2r8yywUOaZSuID1QPuSMiKSDm1ngmmi6xALR8SgMw+LC4AWpVsPe3y5VXVFx1sea7cktiz0EiQ4VaNKNuZLTDzB1PG15IKqDqbtTyAgDW4XYh13Mz9e/1zUPqCfWl6GpmAw00JVnhAUZLomWrtuRhVdRQ58CqOffJCRraAnFdDl8uq5RzHB322ebkIIu6oPZuvtxZ+Ndabpf3wOTr8j0pmwp42h34cHHPNZr/mHBcqDOUoYDsjrVshG4yKBWonayX/UccsIgNGembvb5i/LGpZ/K8miAX+bCmfFewsBeJWTulaW4CuBeybvHioI5Wrv/f8kxFSU5P/In+DyzJykuAElFgmS3XH/tujcaGG36gfcVbI3PENsRV0n7uqx3P6EtpkkjgL2X6gS7OhyZ+03FMCDANjaxl0NA/BF/VL1ceFiT6Qpgl6jRZCChqm37+WvmSPPl49+y7XSHakL+Qf2FdDL9xf9EEAXI44XW/h4YlJ1lBEtUI6vP7XxemTfue/ViSrO5ah0xzmryiWTxX50BYASLvfMwNuJYnT67Igon367TEi2RLyQ6Alv9oKto6jYJTA/DaoknBIgAIFRU2RynaV4fTd6WnZXarVRpNgfjRw5dJWMTau96TPiVIpDSVC9lg4WMDxIL5piDI/6MIm4YWXEOgwu0xBCJ2ce95qPYtVrKw6sPox7ZIVTC+t+dyuZuwMJqoBcrDIhHxVQDiEouZUdp3199UGVdifz3gZPP2BZULefVKgMoaYgH1AX+qu2cHIuVJ569k1yhJ1kT9lg9lZRwPSkS0/NhdetqXmV1zSuDBuT7FBLsRvfmx8nbXZRWRFAVtFlFt/MdwI6zRoTQFtBPiMKB9DgOqgOi3VOf/+eI6ZSetVWo5MKMwKz8erQXbsVwcukt7kYwM9+kloi3MlRw8P3XO7IZ+bYFkoZV5z+hsMfMtilGa6mUQFNY6pVgq+b00tg76eIorZuxevAUFTLrBJOK+naMo1xspGvCX3pJ0nn8l4AQ3yqTwp4zoidKobv6GMyBse6umyRJfK47kTRrjZHYN8S/As07ar3jYuy3PMJNXvAnhP/JJqE+IpE0A+QMWu8ek3W7e+y4HkT7k0wh+jMdO9zuS0EcqB4u/fqrS4T9r1cnaT/7NsXn9BwUclJrakn0gMlCuYuGHOMtXlBE+G9D640UCXFUpkBcR+TkIwHELXOLTyq+IO6mjtR3skWCuSW6Q1aiVI2PxC05sxJW45xCQQIVYtZHrzkfyZ5Wthw7yOiXbYNOAdNm/HWGf1/Zrjdzek6wO54lT75OyBf+IZ6LVjmeLdSxme3EJeydzvo/jMmFh/Ne5tXqXdTsBt21wLx830+QSQndEmUwYe56TsgCk0qy99dKzQ0o2yU8Bb8bShjI/9FbPE9dl3rB4INKPa1+jTd6pkXZIy3Vnhbet63NBjV40VBg3nYl5EyvzGYeE0Bb6GeXD1U1+bPWt+89vbjrz1rR/T0cr6iaFBrAx7CCOCveUUV9m53BUSdumJCFOKHrQE8FTubgGBUfpLJX3uB+XwBbDi9G5YGQY8U8rGtF/aSkUSZhT6nhGt9K7RFa1CiVzzHxuoBPS5HXWHZP01pnyoEpU3LKLbXCzibSDtLzPaGyjhCAfe4q/M2EGGtqo43kXmqz2/aA9N02zE8lKOBdz6xzR/aDjEEDZlnhSDed/mLxENiG+e0abmYwveLqvtBzf/barLtAg6pc8R7oZtSyEuDImCLohCeYc59kqeFPQQUbU7Wt3ElDuQ2gxdp/TdoYhEKTotTkRDuwwL6vbBscgC3FMqA9M3T9Xmsd96B4Ms08L5d7xjn8uFQGep34PsuRCO4bjWiIIXcGIgTK0gn4tbGt1Me7p6uQYilzF+Vqn8ll5QSo7v/S6nyCzswN8MtmdpipU6A9EoBfY+KqJ8dWI+iv4W0cuy6YomzF9WDI7x5EZeTk01BAZCTxEiVy9MA0xPRGaX2xxDFhhkEGIYK6HPp5iC0uy3ecVtEJGHU/0EoXNKce0eoaWxhHq8Kg3TDy5OpjJlBiW4wWQQr32QxkLpTQQSSrO/yYfse0/9FeKbG6GaP0yiwNJ9P7eTDdNfPxVQ+CvkbQHw7jY+HbETQlFZF6ZaXdm58dy4vx7yDDqhJ7wA6/G3+Im/F2IOYiM8aEYFSWBxxabMjwqHDkM2+R1MMU1nMO+jXxQbBANXZ0733DRu0iADJ2gwW2rz1QBPqiuSi1RuMu17eUVJ6V9qfOW8sVAR2xJN+s5zMnNFATZNEBMuWKOfC/0WrvnlGMpNjMqOnnC2xWybDnmV2tTZwc843Q6lIHpoIYC8SgaPV4OJ01HRnYYJznv7koh7C6JpTMojWsQrHx02X9JsuKOygXJGMkOwdtpqdLTz5saYT4ESaxZ0fWb9vfZM8Tc+DY1EeCJtRnBjMfJtFDGNm/RvOKE6rwNrhgiNZGJJGUIohjv+Bmr6ojiAMdqXfJdShWWnhIXnJonk9ss/uL1JtjJVboi7JrZfgzrNaPgmEugYSJ7wpW5sWn1/PkC8FFrsF8/tE3TeZDE5jSxs8/d9Oiz8faaZTuFxDh4uYc/z5apob9fXT03hEJqd10Rd/kkxhAberkieJPEnjOksdMTph9ccnBQ1WX8qZrO1wW2zBmKcy+ZufObarxMgbjG2Su7Y0pKHbt+fwRsRKPQ6NdE9qOYsBuLR6DsocYXYglfOgtcBynsU6q3HOFpKlqgnnTcN8Fc4m4EFSABvp5PsC1bNDDcKKFGuXoXhW1xJH0aC3jjXn5xs2tMclOP3gjQvUzqotMrpPvW91gbtFNnQf9rudgx9F1ZTrQxs3kIE471i4LF/HYsCSew0R/EhxZSSlLTNfem2nsiKlC22XirUW2Ux41RIbkf5yPI6/3dv9l4aSZ5w17ueu3LhpiJqPKhX8inUlOWpN0jp3VnfLCaNHmWUKmT7S03AREFmsl7W7ZB9/HP9AWbyAuPs9qzrYKh6PJbHqifxNEzBMnI9HAXV932jYlocixYT4s+ZwiGWFrY3GwAbnRFLIzzlFD9tsoUFpPJzxoeWxoXJvduvqqy+bsw6iBATTkNWnjFzidDA9NaocCmn3ToTHG8ZYBK7C0Ly8wDlzdsrLs9oJO4+vppvSnbhF858D+xudhUB75kDdThQb4j1/qYQV+Gqv3EYvifjDDAWJ6zXn6G4Fez61ngwkMEApeAUMzDko+NSZWKZ3Qcvts7czCg2gQdqiRyAEDQhGur1rQFW/ZPWWBRqQCRJ7AXoTLi0gHWo45S1EqvfVpXR8clNDarBii086zhcf4XgBVjZ4X0dPRlI0MLXWkAD5UFOZcOQ55kxY5kdiH4tU5dYxrSkbtl+6EP9hDqPxTVVoIRbOxpJmxtJvEHJxmN+N5IaRuYGM45DUsU1y3ytDSv6esjQwL5Vi9GJ1WwL335/NNaE6Ba1lUTGFAVdI+iamW2jXs637SFQ0FiIawcBaTTtMYhPIebncJa2LmT/MxRoh4Z1s4nEjwJoXC7yOty+yXBZhaRjJlMK1M4/yrs/vl/H1eprsKIbM8BX5d0Z2zMGf+mQbdpx7/QO3BZt8mKhU0eBnM74rimntG9vYlW/R+Cld2kYWn5KlLQX48GHjgHlogDEWlSnaJcJ5e6EkKsRanYfke39VJW+vmUlzxGD0GNqnLRdKFsiCkQOMCtSZC687ZVsKYuahjQAGUOpCXbBl7KywR4/22dgT27dNXXAOu/4EaPx6rG9EpJPhS99ANMHoUitjVY6oFwg4s9s/mizZFaY6TtpQzlhy1BWA2i7HtufTHYHX70/il2Vxppa/rzEQseeoqeDvh+FVQYqZxY2J7wa58YyjHSDgtHWN+XE84Jn0JWOYiB8Yo59VU4Xrxf5/eGzyM6xIJg/u5miu5hf7t6PlCrLJjmRb9XNU2ljFjHdoOno0Tb456Oyq8uiYENz9670LhYBYysIhFXW+jgpFtFmepEMiJLtynWEgXT0pprcJ5fTNBpvf8Cp9Jx8Kj4vmMCyVU9Oip/G1t778iiGTBB3O+VhwIJ8KScZnIiJ8s7qkItq9kEUiw6zxfWl2hNPYHW3zIdkk4ayD/e8wNG/CK8mdRYEj2nFmPqbmhJdivgueHRf78zx2UObwdZo9iUOkCmkJ+1Mz6vhEN2gbGzojZ38URIQ2GOZqGg4AfQpvMCreOnYuLtyuxc8MrG5qILefhFbvQzOWisZF4GfOoHS6tZkNEVwR46XpuTJ/nf+jJse13s8MOsR/UeU7xRFXXOrnlgSsTGIcEhzD8y0Wd4kU/MqNLsjX+PigOG3aB3XSFQH7bac/fzh8kzXLqqY/ojyLNEihG7AfY7rrdUthMADNaWo/sIX4kYKpyYjLHE2kflGbqUAne9sp5zUti/hNnb2T3zuVsDOgsf47QgY0DzNqzI8cQIw5ncf9mDxjJdY+cKl3a2A1fh05cDrlRwgH4Gi0zBCCJXdIWXTSrQiUjQ20LegRav21tnxUffjofoPcrYowPmozrWZi8KlFMQTNIkM/CJNgRmjfevYgvp1AQa7jJ4Nxhf5XeT52FKaNQbGYl7E/BYcgDDiRftPGlqilFHP3wF3OuOTiovviDqT+GT+Uu6LEjrMPsJ1hIG4s282JEF1u6MEcW32iO4oEYqgIDv3LyxWl9jYtUfbwkZOSsV2KS9OiJEg9Ai0JPaF1qkPItdkfkzbmLNcmPgUzvHZHuyVzAn5DSqj0ugrfcNSo5VbdDI5WCcCRmcNt6QAYrBWowiI9KBPF7gwm+QiNkiBWtAozHxlePfXgLMvMCaA/MnIeKhEEnoHW90OxyjzGTHaaYRWgPI2O2YDtiyCEQbkaUz5Hl8dIRnm6cJO6L535fuCqok8/M+Dcrq+JbsjjWoxnQTzR+ejNvPQGu5CbSD4P5+JjWXn2laLtDZGV+P8c0PieNBMrN90FLaz1NShYE2TUO15Ahri8bOkwHaHWYOt8ylfethxLasuCK05yoygVCZq2rYuOm5EiUHKB+apJ8Kao2GeTuKGURuQJ+LFvQqXIwv+mVQFZi/XdtzI2cLORP/th3Wdqm5AQrlDqsy8H2ug7HvCd1+EmstPhTYNwSobM20tXZtUku/Rkp+TgIWNLgCWS3JrVp9Qikei9/Pm2H+8IJo6jIZXHKlLNER1xa1niQQ/nwfPNGezKekBpgdxkNGgNUF8NjThBt8ewB4lB1mTx+91uuJR0LhjOI8GDRn182H9ODtIzvG1NiSqgVCNvUJzpEKBySpwz2gP4j0jOVEBSB4AmhVlva9PgD7IbrKpxlMtIfUNxizdF93ui2oKQWHsNJhSrxPCNewXiaYKrermZRbby21kKxElKAWQd4SwWRxltXaE0Fd/itqHMcPt34k9Wr7R1N5RaFQa5/W1RY4qiP2jAAjHhnXs8JrktcLYh2MumnxegwNH1es7vf0r3qZFE80BHf2cpV+sdR98U0FFRdTeebHboRaK9zJeTT9fuQ6nOsDqMeWvfcplJ6TgVt53iN+UfQkmcYqU33VPljtCzZBg758YqAIt5nbWlJXcceOoWWJWjQxp/UKaLgwCj97husXSze7rnvFiC6PdITEsCJRRhkTSDj6ut5HIeM7SW9AZtXt56cV1TT+yKq+Xtqk86+/ewGfLop7joY+LepLkqGueHF4MMUx0MqZBXhT1zJxqwGxRoWpurYjqE8+61SnGeZFWeEzvKvjZrlbVsqagE1fOr/J2tEyn0F/EJFTzSK4BNfF/Bum4xyQGDV3hKD3ZC3MhAIzBgU79v/EVxC9IwuMZbJ+eZnz0CA6HrTO4FmCnQxiBxeFuLhOtEtYdPmwQnfFm3K/RyqGH2FC6RkhJSKZ17uO0/b/sAYPMVJSwgK+pI9bL5aKVjkZCBh+YOjeAJYNBpcUx4cjFuBHf+6VRCF/dy6z14j2xzM71PSS7JHNBakTkwwulnziBYV3gXdqZsYnH7gT6ZRhAIRsvbyI+5M6cYQ0c5icbUNx6PQk9q+/Je0lCXEUYyWiirjdkFmWVj4Fp7T83NVvaE3v76uwiHMFHnuvSbOpPgO6ygFU41lrBlaSl7YBO6HZcu1FeJeRJLW+0JBivMwlaez+yZCCGI7tdg1AoXCEItatD3aiftjdnSbjidYJ/L+MMC2ygNKDUEvafcYwmUmx55XXGRlxlWdNKnHWKsDjqkv2dkQ8OyCuvnqiDgAGrCsZwQfgoOlUspMEtwGNidXCFb4ZCc5ozoyEI7dR3iksKfv/fwDo8zZnr3xO/3NSlJAq8CxCyCqM/UmYPgizJ9D+ah8O3fGydscm86Z3bOfCtH7eENpo0fMMAVvKhyriu360bXk2ytMoVSURfmWcyqzt7XoPuABw9HpavaWnzdTxtLS301+OOlQeogqeKToJmUnTKNZHaCtqcnDOeWd6M6548xwo/6BbCgZ0xWU43unCyYeGOc7nFRh4Y2wkhI1mhbZfj+s7v0N1pAA99TkSGkDKTR+osiPJN38+VmtwpwAFd7xYW33PEki5Nf22wRbxGjNDY42l+MefXBQT3dmm6sxcT1BA2edwN/7L5KzM7N7lIQJ1M9DuZg8fYO/xJNaNCjjmovnEdqpU2giArVLLiOkQl8S+9NiBpIDptTGaa1Fs+QJ+gqCKarmD6hRfW3kgQpij1KU36kpzabo8QfOqFpIkBlHIOVAZmcG4V3yaze6uqyLHTIEry76JZbQHDhhjEpyY0Aq6WT60QYHrof09jCwbCCP8v3GGcZWJ/xKCOCAw+ANSKiQgzeCOR/CAQtk6Hod7RlNA75Pz2BNjQTJOdIBQOHdlfWOaasqv6cA8zP0CT5f3LlDAN8ZZQ2A+27iu+9iYN8CxZZooH8ByDbpeeazTZ5ugCZDptHcjWGkSZhtRIsgx5O+OSxCIXyC/T9Lekr5v+SD2WUxKQkN7raXQ10+N2h6CWzV+G+8OnqOThMirNYiDGQp/WLc/w0aLsBMha9sq+efhK2nHE77yeIuaiHy9oiVFM2I/GX9tESNsrFVp7/fw+qSL5yu9rv00xZDRtgJdjRixbVQfWMENrRqIb+3vHxMBMMf/CkVVbWJ2+hNAAMCP0MjrerJpEVfr2gypQzE4aKd8TZqvNyvK53FWXK6Vvt1PpO/CgH3Diepjf5ATXGEhHeVnT97XUsXTocYE50pRAW8ADQBNKyKbHqTTlcEUcRdrAyERpZK4+RHNTxiZPI1tTYjrRQfJJcKQMFKcEJr6vCHogQWlv8Y/Zu+uqGUOQqB2ahR7KEt+BN3fIZdMKJ3Pr5scRJ/nt+NGldSSuFRqvzhmBSH6ZaEy8ZVu9FAeuj80UyHB1hHdJIjPS9pBqFDYs6hx8EysMFFKyxp9QoO/eVR98iKzoBd0qlawzph9IqIejbdBuvCAmc520iCkAbGe09hMwqf2vCMEN2j6MLQvy+wc2rvTYGuMyI+nb9ZmK/KUQ8vXDynlXuDp5ZwDS3plrtf5oEGCLm9DYylX5b2KPbI8f5bJxcQIeTkdQNtyhVkXcO1ZO2MfHiytt4EkBSvLzZyz7bp8wOa/gOxJFJglNjLL0bxsFY/PfBB2Ft+6O1RXUYIgNE7d7hQmLuR+m+JLDux5UbGqXUdBjMi448pUrxcYZvJZtOlH8bhplm6eoacAg+SjGxth2IxoSg6hmo/rLb1/WvCf9GYNDTYroFa+FCAlKM6E0z0oykpJoALK4URZY+ejXIbg+Vmyqqx/NSmIgJweVZMgHezuFGbrI77vABao1YnpuacWJV9k6CZfNq5wSfb1deqsDoQ47h5FlQDrNn05gkOisqPIEyL4sXbpae4aA4iPWknVtq2slThizFybK3DAl5f7bAvY3075CHquRgI+q8P7wGiuc3iGdKt4tlUkVqO0otQxX3NWSRsYWrE1t/UgJNgVhjPttTVdfmZmWh+KLB5LLOAK/om8tPU5Sv9Kp1HXnQV5xihW+20G+ySdZn5UXrCFitsg8Tt3PC8YBsajtSvsqnP2V59SVXkNDMjAlzcBptmjCmgG2Q6jVg4gF3NSBREHPcGbaI4mFJSpO67sxz7x0GYP3tEiGrEWVj8vUQWruNXocGNpS7Fn+RHtlqXg1wjuy5D5GM7zYVvyxShAbtLMjRKP0pXD6zdVoLjg2565Z62V6uDWOJBNoY2K8vHZ3oUVlyGwcqZP8NNuF5a54sUlRzgPI+5kj/JjVqVDMmpG9CM+848+kQsVOFhzkeQoE7Jftoz+OdkFcOhWMF7sAWxYO4XwIrIEIsgzKYFBAKIsNZh9DBVZAouY6HNBAjBWgARDerMGRYp8PBPk1STDqHCjBiNb6KOXaErcUYJ7ee7ohGai6hp+YVQyWc1bleBk0KBZL6Ybh9qll1ykbkt5QTuYkdCqGgmTz70y/shbGmJLYXqIqFOIXGS2etOiyx0QOWCeKbC/SERSeKWwzTyIgmS8WcEeMJTNO6tCB5qZgp9m+TWZdKCJHM4l7VSHLvw/Gjrfw5/dMAkk1vGbAwdehcacOt761SWSGE2ntn5SAHJWVet8ePlnPhNmqOjEz9+bZ0in16xel1z3stjU3Yb5d9LLPF2lKcoC5Kknrepk7GSSYSsXBxNfXxKrFsNmZqKNh9tG+R5bOgiJOghgVqqlYmBEZKq9/HCVJKaTj9ybltEL6LcdiOYY6de8jVPwt+nsC9+JsslPqVINqBioJ6IfRhGbYb3qtSNuUkhgrWQFGWGS9kGaOEa/U1AUO4uDdsKryPLYtZEplBdqrPVvWR+TmQrhClwXM9+V44bj/DurP6v0r2JNN+Eu47L5uPe2gBr1naD3GmFSfT1yLFHZd5BWSWTnnuhvYhRDEvAq068BOw1f9lCivnIBSES9wdiD+CtNdNL87QxhuRWZ6j6BM4XwTh40q62nhhdPDimXRJGzX6WMp4iZuyPsDa+Tc+q2As+ZAGBED5vaxHOstlvDWstFRNndDyveSyPrxWEivBy+fc4p/tPy9QCK9MSVJTZbFX2Y3Q8XVodQWHF5BKCzVOF1wBvtqeSBXQmSRNO96qj8KRxlSMa979OMDMxkNda7P8obe87lMSZInTnqqJ2Ls2VRG+puCdhkNSOPjrepwxPUv1wiK9VVwybNBUrdahUADtax8Ajrdc1VidnykmiyR/wMuRtt/eclH+4tQ7MvfN4xQZq1J6rJpEmaL2KeMfpDLvc80yln7+Vwbjgz4lhy3ZdMOWszbB0sU38eWXJ2PvaYuu8bL26q5PIm2CLblhl02Qk3IG4P3W/VQwboYJ+m+loqSlUpAe+ipe9nWBfexwLVM9t/KcvWGiGGaKlOqyxzOsercY/XDEbtfyIIsX5/Sbk0PPL44zS1UuLk3wD4oDZL0slHyJUlgcLpMVYhU0YW8HzDMd9/FCtX4Ed3U+vGlzXeTewF88GNBB6cpopR/XILiqYKV9TgpHRGuGZip5dx6mcv/rqs5KbPQCvpxLspnQmxhVQOoWRlpE6b/KvdwP6vJaQ4SyHzVepqkGQdVhpmmto5qJMSocvHuKQMn2LEkCuY/jYiZnGJWiZ+EeLopnn/hdxrGfMFEwTRA8a2n12jteSjquW/j6h+VQqTFEBvMnHQbAIZFkqxEG8XGmt0j/rmTxxaVUo9axGYvPI9zh+w6KsqMIdmiU7UoLYeBpNA8o1TPjYXERGx15x65tMA9nl6ShUMqr5Rgw/B1OOvkN3Ms3Qaov5Dom118Jp0pAc8LuR44j2kGYz/iQ4quy97CJPkoFHqLCAn0TO42xwpIO9SH1V5K65zIZiY86VLqPqynst3xbczr3Dx0gSglvtqBgaOSrzx0qG4yaFLaoFVI6K6wUM6LiZ+3f5GRomp2Sl7kAWdQ66srqmlxW7lIGQWiY1XrOLkFwRwDsrWZ5Fa7KjZlo15y1QtHnr+ey/DS2yaUqqjVbFNiPlH8Ahe3IHY+3A1JlAKwTgQk1L+rtkcopPb1eUnxcrebGsPBZnzCoRCSj+EzJBGpd6gl3cdTkg3Mf7sBV/5IeH9PSt+hBHyp7qXg2UJRF9mdHyPy2X+nfo/FCbEAi2bpJ6BxllVzwP58QQBx9IOHkWxrr5kjShqvchRVcMTrHNE6lVz7uoiPqF/WvIxOgySIri5zzJzed/YMDV61wiwka4vNU9obtB2CNPNM8/ehFKA8bclYg2CTa4A/29YB2iif0bqQVPWwJZcvTEEhzVSbAImLHq5mOIv29HF/OaJlxRsYyKG3ooegWI0IuPwpT24f3ZluVIzoc+TFHxZvtXb71dVuq9CSgQfEnNI2xKO2RIJz6TjqlS7YdLzgN6z9Zt47T3TP2SLsnDtLW1Lf+RG4nhjwLEQRqnBBx0ygeT27V8wCXn+0a7lpH1FaxRIbDtJc0Qtekd2jWyBrZa15obUNT8jiip/NtAcHOlTGOwh419MpVAv+KL98B4ZArPKeSDy9BFjOqf+DYP8PSb31GlE6LceusiUvTNix/wwqdqGYLP70E6F2O/IQt3pMhoZ4ESzTg8N9LlJmoAQVuOaNg2M90Wm791wGh8wAgQLAYsaHe0XZ7VO83P2PPzp6uXL4dOsfONUAh/FhVqLQsHnnREXIfFIB8BcUd7Yv1wpxNQoUHh+6QJGT/paHI6zG2mMzZe75OsUFQCAQcz2ZvFAyZnnOpPYs+cXS8LT796K28VDm1KlzDqerfWOjDqaCQIztarO2nthOgWiMHnuJICjE9XsKjR+m04NzM5xbtdZXU3IM/GbXjUh9QtMxdvAwylgxp+MdtRHe4JIdceHWk8+cGhIhhBC5EI9pHHoQGFcWU1kKJy0ZmOzz4MNpddkDrpz1+GaWwdqvn8/Mgi4XvZlRuUxmb1SpxzIcSEKnOUFQp0x48rfhk1OXeXt6F+afRcnb+yJDEeLAnFe0GK4MardvUYlJ3rnfrMOQX6bWXUQdY8nOsdTOJyP0f+pykbrtJXPwrPKq/E6sGfBIvlsccO88d2qOe9lhnlJskpK38ELxLvAqjuF4fP8QSZcZTkt9yezhP7oA5U5DmZyomU4bA+CIsv7p4JDpetDT35kWnayIEDUduPWcAvC8oeCrjHMKnW0w7TyvTv/1nAn+KGVwdNvEUXq7cd7gJvX68kPhXB4mrxXpzmvnveYApQloCkkwYBRHiOxW7yye+MQZKrtdC05D6aNFKiDumvG75siACFSbC+tbeYa7hVNtINmA+WHuKMWmccl7ZTkGv8PFY8vZi4Zj7p1dSY9YM4R4c3fWfD+8zQ1CMDIPva2Ci1mufg1BF3Wq0EzJbztgEYWyPeffRc47EHtsRm5IBFfxReypg7xlMTi83FEO6chac7ahBURzULuCKN5QskS1YNNOeVhQr1F0bZEBUw/6uhOCsd3AhYxEX71Xu44b4Gj2XbpklEZqq0L0iRWmNrrgV4DBGAW4ONLmTaGW27VrQ22yEUA9+0XVr6xGCPSfzgygWFwAvZs7HX8DkyUKoHk/+NOhiXjRw0v0lWYJtzMmxq+IVNL9en02H/6a1NiCx/i5mNC9/pLsv9TMIpwWzQWe/HwNOQZaQqJ1gjFoOEUgitB09h9JYHRBR/nlHcClQzJyfgwsHC1Tz4FI+jIMvkOc8ssMImp+EkYqekDhzAWbJRrHD+WfIY9N7WO5Zx5SOd33VO0IjiMZpc2R2zI5+z3cLI6T7vC7A0Bda3PTVWeph+kMhwoi8h8yfuzi2JSo2k2W91AT4gTI5CYj3AmY3oV9xKaYlL0cEd22A7EYCJ+pHY9nDNWgWzF4VM5RJXdxoZnju7aejkMK6BCI0ZKVlDWTlA+V3Rl84M52ZNIWjuuWIVO7yV/+p3q6UAl7oJQSxF05xB4cYv5XvdeGGChVxrFtkCXlYjPZj5eEWNEePpAx/Ou79qYoIfUP6ISqpJ5U4pQa2J+3HEPWz4q5kBGKpgpX1GOHUs84A/GkxXRTLPcFtXdqkq5PY6I3LrVfjVv//FiLzjte5rnSuoYjf2xsJ9FdZ30eV05m6hrpsdFbO9odbaGCPoffwFVsOVuYQhFY5diL75H364zuAON1SVq8h6qtMQkMI9E9ARVloI0AxHVIUdl3+ST7bfai+wrQxC15KnjO5wIH9QBXKcwYYPItv0cQ9vFsJyy7VOjZqAd9gcv9/cNEzNNKAeFnV2o7BYn0DGXgUSmg4s12YebzbMtow/C9bQG7tebNfl/beWHB4SxRw5sQPkF9MQYheKpla6URZeSJgcMV/m3Uf72gnauJ8jKt1ILOiVyczwtga8wnDZKP6NMEUPUXCqGu/38fBcvRLSyw4D5o0QyQygOtvSnB7UHvxchqeJ3wJBfzS1nvcfLv62KqgiFk9KQo3mIFi8K+taWu57Jo/gJw4CFPW2shlbcZkDvotIL3pUCbq/qHngzdloDF3LFo97sOhjmUhY6MxE4ForexqJkkQHtL/xIL96l+1r0GYkcTExNgL9/GDm7pc74veHQdPmyIfx5jnFJ13n59gvl2PqOg/fUeBFNN5Qso6nxt+tpjXJQcme/iio359PhtZlI/EHKR/oosnzhcTuuxM9tfJ3kgpxZi260E/FSeBcwhdWWmxMRtqLahO4gwCAgIwWvKSR6aIxSElXCTJ32MbYUzB134n3yQoPZq+3kKrpbQhFqURTjhJQEEJVwA/NYiDEsvlDozgQjhoByxkRNvZcDpLUdlpDl0C1FT7mdzveq3wme2m2/NlJJTSVsiqbUbZvX2gw42LJ8gBidMvd5+TldBou0SQOPhbcp+J30Go5CON+Vqb6yEDnh77GwHyFE/xhhFwcb0Rdm1WBXBB9I5iIctaMVI5EeBF8i1cRj0Q2BSv9nFUsObvoGdEJQ4FIbw32BjRWLlzyq07dUVOba608ecdZ/Ffu4Sq7OVzsB8OlLo6wUMZmGoewSgLWkRfpTDPpB8Qt1hr0exCFVtHaV2gGnZtMQBWyrUKSu1PmPmMyCto2s5xBSBKMOM0nbRzjzidQNN+Z1tTysY6PiG2ZVasoTj2CsbqmIpxE9Yj9igbVUHHLc2ZHStuCga8S4jFY+r4vKx8XRYcaO65PkzXBkebLNm0Sm3u/WDuKZV4LVqaDiKsdB34w/ampNXWwGAGg/M0FQouc0Y3HMbt3X2aA+UdU5rfyYtrp/urGH/rVmXtKv29BP6W4sTWSJzMk8oETpuzGAmBWxQyZnH2X7/2dX//Svn3Wkal8f0RUXjt8XqfZKd38vj94Cu1oKj9WEedD0nK9DQH6dAYjup3B43B1Y7H6J+ybVILvQjOphdtZ0tQQgF4W8iZsBTR/J0reGwfCG+6CyvpjGmcwENhADHuJ6xzYBbv09W7x+W7EJYbZ/XqD7diglOB7jLAADRSfLrEUS/UbXysdqw6DazCBVghZ+y83rt4HXfwAzMdFLTJ+B6pmjKVRg9R7KqPqG64+g0w1byRlbFUrdlAh+qCjbo2ic8QMdxlQ0ecR7/eU2xKYnT3dgbl0MYvQVVaN1KYf3FyKSaiGPs9icNXTeVWYKNssvplpbkCvdUasUp7KTfrweVR+4cQBzQMQpFcCNXU/Pkm2W8SPYxoOcg6hhhFVR0WR2LXUdmJgFOYaNCkpkpkv5WELkgOXNgU6UYYVMEN0zsl9FEVYRyc3nq6YmCdMpmLTTd2fZFvvdSD0oy58HleUl2sb1Iv31A9j5vzFYO5e18InsVBSMT2Vtcrfn9US5JCq9x04KzAGVoVdW6opeM3KrBrBFODQ9inB6cc+eGVtjFMhoTjbkXY58WpDFc5ugQ73g5xEPkqrlqpN32kToXGsYPn7Jj3RADcwCCbt3S3YxJepbU6huYMbdXHIcbUKtaZmNS0/jkVopyr/XFXrbNGTLwFdaXnwQ6GU0qUgbIeD+LhwALtENuteuYxYcM877Y6QiVwu4KStVL+aPKLXTpDDosCNe68/8PEGbrZhoukRI+DYW/Q62sQlbEwlyC/2q0VfOqveWc0Qp86NVNdhc4Yxj76gvvuVUeUi9aatjKlGqc/X/189NBx3I6CrJCh+96CwTGGL4CcasANtBlCmc7l/ZJvuz3ZZv++PMgmI+HjOuYY8zkbqEffTEGjPiJJfxdoxQ7oPcZ3+T4e7n+u87z6uNfaILTi84KyMy2S6AhWSLBhfk+by6hCkhl4KjbrPHx/za8izp9x9TRK9gO2PV5x7/dN73cB36J7Wy4CAV+yJf2dYMiX2qPHrT6wNaH+5RFjYdZvcGnnsEInLBnmDqNWifML6DTedswh266yGeZLeq8nTSGhW6dtY6z1Wbj+Xhf5GiVK0OjHF5zazxINQR/jTFl9/03Uil7gE6PclTvZfraHT2f1fm8ClRMcUyykE+gfMGsTrHgurJfLQA+doJNuxQEPMyf2NrPuiOhwvNk9ZkaO+8i9CipJ8xdZPlNM5LXy26xRy8L6ZBvrl3H2yKQpbMBQ6XQXYnV8xnfSvpCeKkuwr0sZdtqrEWV2tjY0rYdZzFSkDF6DAswUpIeKbXsWtX9Bc8hSPf6WdFeKb2eHYhXvKOdReJvodT/abdhrlZeP8xfqV2NI7UCJcFJtOS4Klk5nG83FgR4rBZDWtMLF7DFwZm+t9+J2r1uA5NWwkMlmnzHDke8kXzicLwC71LQz0G5k9Ozxyk8VvDFUpSV6wGdvz08rwopT77ygCjwZij7WmA9gJYxKrWGfrPziyhDthGUdtjmYpjLuFeMH3VCRwc4GkSXV6Bzef1nkA3RAFJ3E0rtmBCE9GFKPWQhCpD87HL+xOQsMZWpZ97XyuMfFYGUQSTrFrTwV9yNFU19QpiS7EC845jnx03e3XK+vkIoVU//kVIJRCULTJp7KdBw8NQZIGGGDrXMqsE/TPSFV2k29qJ3BrAoOR1mJIA+u+zHnJyLO4y6bb2Y4W6fhikbbL/84uIt0IugxqsPvsfDST9/vZNrkiqV7ck+AopqH3HKc2GSkFIMBEGVOEkjNx6X8kFfC8fmLFst5SWVM5xynjnsVcxFxcpywVazVFvCh2Q2qF8r3Al4IqHftnZ2vQB0Se3QXmGLlus3MM3GYlqCyWKwxrZI93bG/nso0CSPKVVBU1PsQ/438X1F3+NHpuqVQh9GZBSSp+XBHcqTevNfVYgXo2UI6SwubShArhGELzySV4+oiWtobGhUOrk385VM5w1R6YpGtcDNPtuvaKTJGXXYBF8oaCd4LJaJOP7czYhKw+hjesZXxTsIpsSnB1oyVncV0ax5MYEdML7OPQO+lRZ6uBN4gRoHiLyRmmvBmcPbbSrMXdAa0zR55uuiq4y4gI43Tb1VrIj2P7uqKKrqpGI5T9BYlcyNK6+1SX6dlZUqfAF6dqX/RMGDdz39eFGa8T+AvKv3fqeJgQFoY/vKFZBJ0MXRXSKUBpFVv/s/2KLMxDhwnJxQhjeat3ikWjm1vEHD4bVH/nGt0IsZnoW/mMFjfejhmueLU9X5OjXBvxEgPyJs2pU43PmaxnxsOvq6caZwNZwgI1dX2OqExqYaOH5IVUnmro+ZmSKdgVTQOORajTtKZgIxw42q+VzTp3lDjFP3RoUOhK06wndjXRafb0Trl0enmbc7FFmJKDJjgGpQIRqIhqI+LVKxt5OCHRDh4u6nn/iud9lX9vfuZqUBQvm7T3CrkgMrDKbFotsYV+mgDdOReIXNc30CmbKmFwObXF1r27h73Mk0Av0LzlWNFdYobUDAAZXe5JFrpYZo19Iybz/RqVxJfqAII0bMK+yYZH/vwwK6Nm4FChiaPwyJzciJK1F0lfL7Y/Rp2bIni7HkUeCRaSXCOr0qwkwY6WN4AtCvYLclWRowHAhZy9xFVcCM3l269O0dWqx+KR3yqEmPMttlI7Tf7I2rjDqtLmvGhPsZ35zH7z3oInbJRpNXPZw6dfkokeDw815WqjmFiP4HWW8Wbb3lh7tbLG6MMjMqLCtE0j8l+rrS2s1+S85RDTqd5JUYgS8xl61cuHGpDJV+pHnSbfuV/3vVLZKEhQol+FKFYM5waMpVnRAMWFcq9bvDKCBBrF9PCFzKu9TwxXIypUSp7af51MP5a6MaG7OPlYeFYsB8/z4oKbeYadCxCxaGACXQOXAsjQ3+fOF51EfN6kKSNOv88LYVjJGh1K+oQMmdgbtR2UoBcnt6btxD2AqayAM7Pv0L+WH5jxUoIL0IbbOBDvsUes05PePSD9m5sDoLxUGAVKCBsx3Fqup7QXGflMc2p0P5EeFEBO/8AeByZchC+AF6KYSMI8H7kgCbgxWIJC7aAchUN3V5Kf+taF68rcZtk3Zjge8M26CugScOuyRXew33QVqwUDgFuOC7kZPXQDn1kVQcmMUysNa7jFZl4btZ50NTza+mLNeFQeLMejHUsNQiScYT6GJ8aYmAKXrcZ+dLRSVuZ0HmS+FuUzRnNCx7Xt597rfPSbMs7SusostqsBcznwVOl/i5GuEBjlMWEwKI+GgAiWzLlf+MykKcGcRRY+0/4Xj+8hFXn/UsoxYFLvMpqVRK0mJVWasOe3UxkWlTBrqUHvNvDSfuDHZsETfWmFFdku1sinGVyQ9QRZ5sb5Y8evG9pVdml7M1n2MErtUYDqPKaeeNj3GyVEV/FINaDM3AjafbPeiGeenGbyZZvyFV0Iw0rLd5FXec/SID13+0MKDi3SOoImmRXx+rRPnYYquNJoLgRs9rc9Q4u89qox8vuf5SiU7YPqj4Nju79op0a+WD3Z77Pq/RMn5CaZbAlz2h7hUg/JUs/JWaiuutK0LrPam4X1GWMHz3x7z7JyAhuX3+bTCi9r0StjsIA+rQ4Z1O9yejG8W3oIfsQB8QfmKNGZ9WpCBDyK7m1tIXivjACWwGb9i8Cye9A47+KSxbGMW2iyD5nHDTQ1ZDwuJDxDEi1Y2yEcZIVd0rWnT/3eP6gBID9LR80pvUWDVr2VEUPjpaGoHFLz6h1qJSHX0Um8SSjzZHJj2qH36A2TSz7XdL610U/bhor3KPCH6O5MDQwoZ7Z+b3yN7SGAd9TQKEz+KOfAAT+hK3gf1Q3aOYcxdVzYg4llM4jtfhwB379sHGrnqO9t6jtjhdC30BaLMoCAHRvtTQwoza6w7UwrB19UokjbYXEpMJgcFUTN7e/NmGewDc03/3nVHRUYaQLNXPiDYN0QAcTA150bVRO61N0CO8dLZlgxHazxSm/vZJejho80X+gTBNnlQjH0rbu+DH5vgxtbjJRMbx/6IvthG3i9Z1jUYsHZ9PiqZoQhCKC264Ywi9UD5J1vvyWGww8qqq5ncyv6vgY5GH9Ognm9NQTioDs3aBC8MdGSduiXlwgagKHzd6v3N8vAiNpihenMYS6tCIwtovWVyJ0wCgZoKXful0kD/GYhLyldhODFy0uxbDusZa8K75C3llzmBOpCHFYnOS/cYp7rXN4Tu0PfboUeQQUeu90q7OS3eq/s/p+6QHAzYZOQUkASWtE2gQ3xptYzPKefU3HehtfVnYUiNB4emL6n5O818RC8aGAqAYfNaME1RvRXRNPxKBt3RJaOr9V5AIxOr97vdc039kCDlrsOhT8NdZysP5cpUNSE8xjDfqorqThpAADXjno+UUMGzeFxztJIuuJreeC6jQXFzts4pcMwPa4SeWwuE02OyUw8/iyOlnlkz6i0VyTJSP3EtlNGFS8/L10ozoAACjxeNJjIfE4TNPMLRYLdyTLL1r9Iw3JY2x7gMUZ2hhcor5NBeGcueNPW3ATvOFCHSOvIE43oqc6e8JnAkOf9Yi6hMGE29tPP+34KrT5sr/yxoyfNf93GT72wHzlKi5hqaoZJGC0i3kMTdadcamvfSfhpk9DNKLUFQLOgIib3OzmjhDIt1OD9meTwoH4VYaR9ZJh5NBkunj3igf7K70GCsE0VpRGZRLiJSDvd39rBWdCLuSSNiXY39ilx3xj6qluiJiCv8FNzRvzk8JGI3So8OhfqmRfy2uGJSWFibJv5ZM3s4o7HM4/whuRO+xTDCpXQVOMdhKBgO9zcNsLGVtfg4JfWs5rt60z1S6koGFJvFWvs6J28Vqrpncy8ocJ1ZymEkNe+jKYm9o4NQ6uoSOCvWaK/rFh57Ck//V3AxmaOgXzj5VZrwGcCco/2HDOYAvcYklWN1Nca0RLV60NJGUn8c1aXim/K4csjoBSQ02Z9c3eVKXRCUyPSZecdTb7WsWH2+YKtKzR0A9IV/aAuG4LbziGHKYNE0N6e0vacQXxccTM93Gx/H4XzZwd4C+zFtz/csQmF78VzBcE7G2WcWD4Wd/i93bwEyNxwcopWhFgkWFszSvVqBjQkNjjfNk+Gyw6S+kxp7ljSw73K3xFb+vYWMAyjNCLsqtoiE5cxNKhQnWt9ZrnCRUCZmVC5+uDOmNGbytMsvrCU9HuRUwI7n80eQ9z33DWIpI3gTspDyybELDYD6SRt5yWJkzBIW57FXsHrokeE0nfZ1L+NVHYPkOe3GvqwM7jFd+FsWq8rYhfqDTTw1HNAZJ7XtNX/akGl3sDof9xVGKddoX6XiFJvNdu9Jx59lr+8RJAOE+xZ9HMrpCluHmTfKNYNRgSIrp3YTqfGOKp3zrwGqJTR0S/nYK0Es9n3rxoNPB/W89tAq0R+RVmWJKh6Oat4r+dYgdBtHxm8dCF+TuSEtBHl/QUHhqgUKJLZRK3qKKuP5LapLXsKk0CUMd5qt+dHmHwkav06ZMfhuHbdNPd2q5hkjF6vc214ZTh8SlQ8gIO1qxV3RVZ0WsGZpI8w84ajG/Oa9O/cxhcpkyowBCov3FT36ClvCA4G52x6gvtBT/xsqFPbiR+9lzWVP9gH35dJw5hVfQ2qMRqnoVgPcVpzpF2rt6Q8bX3UmFnBhK8vRUs5X1rGFWk0on2OTmMuo4c0MqUzK7yrQ/UA5ALiKNxkfTAXm+hLOZYV6tjZeBVv0JWNUsFLQLpLtpjp2A1BLh4Eg7tqDLEK3a4x0lVAn1n0ZZR328mTv93pOE7IDyhmZE6H3QVpfXeK2JL8/v1rIJMyod9aE4xHXhW2wf/dt3QGlUlVUJZ4gHEnxm+VCVyr3XrRYm0UPjXXgfxDa2WhqXyoB3X1pv1U17RLEpsOBolBU4hv376cZzvjtTSSPoVcCe7QBmTdPYaMjUpgFgg9CEcFS/NJbCwb8ibNhWtv0TjaXyUVuP4NS5+7XTOXD2yUaCfqnVquKGWiQjta0eugleWDLunIIgFftcnjqjFUzTkyHERP3Co606ln6K5fEizh0sBwnq/wwPPm/PqBTpzvAdPiWP78d0j2J8ArIIBAYArjnJ9dCZLiXZlyJDf1UIu7DLyfZs7fikIW+hxbe1kKVYpl7Cw+8rAohJzdqCEox/oDVZyHqwaumD7fGju8mW3VjeFGKI+HpwIXBId/Tm0P7QrRw/3ewRLIdI7V0WjZcF0Mz6R/86SXPt/lg5HSF9C5Lajuy0DQSvvWxGAs/BcL/OAE8mybMsp+3BBERA8KFJ94RjaSrCdE3yI45FpNDqhSpycpRXq1LrnR0auNH8CHUjnLR9di06Y4uFN6BzT9n+P0trfjuuW9s1PwcpTZiTKxSqd+VyJrCoo9rUa1TKdAOFsdVUR6dKJcf+TI9eQl24aCGorwMt0h5jb8WECzxyF75TvsQK77DM7vw1JSXvbYK8zyXXvQCHWdST4LkXZCqL0FyHsyHEABOwyYfonSD6i6ua7mR2DIGeWGPxsY6Ec47lMlDQPUTOAK0m9bHhtY50WvCaujF6iiPnQN1ta9F3y6mNvMI8BHjZK1PxuFtWrTnFUCcsGEumnFZgShnIYRJqiK9V/izMNKRJg+NiiQE8CvfO5yxhNk1XTMf6AWGzRe3V2i1LpPQSDaTItQFTZBDagAxPCJCjDQOdQRGiv3fmLk9h4WeGgp8aTLci7Ni9ZgEczwydUNJGjvBmrxIdYwWWpdY3hbNOmmJuPZBohVhkuu1fSwoEBnQp6ApRnxdSbMuOQrI7zNP6+jnazlx9mscJWU3vRqCkfLjW4p40/B1HQF/dGTbdoW+T4kyRXW48UiRqYBRhdIsFwJHkzs5T4audyzZ04S4mtbgLpupt862JiHaGS+g/amQAd6rlWDNnyAKgSkRExbNdgE7DlGTnIQzeE3bKy0pE4JB2TwbAgAFqa1hA63M98WoMRA3kne/RZ4NiNC9tLuYeSS8H69DbwtIZ8tsuwPHRu/87ipuTYvz1p/naET8qoYaElpHQ4n6v/XUFXHdl6lQ99mx3zW8tqVqhLUuzW4JrIZreeHMGqJDpD+r7XVI7Xbnqa7z7GLOiv3GSQoTj5WHDTbpFDCxjrzzDEGTqGAdthPZmRoheWfu7Y7j/FiRTNOg9ORSX0CR4XsbFnyNHa1Rw0rP5rBINpW+jKvx9zkBIaYR+8C74NdUoXGwbB3H/fj9NnAzY/VwJyo8SAdZE3zbcA+ddh6UVdbLuquxv3utfPLNlQ/igKi1EH4JXnlqR1QohLYmH+dwpjUl58UgNzjtnVJlyJthl1y1xfEISfButtxzCUvIIFVqWf+sxzvY5c9I0dStLiX9WYCuJNsNdF30QGCgUvx7knj/KbwnTMwR7CSm0stqs2H+WXgxxSdp9uZwdmjDrSHnA/lnuF9Yo681GvetwZOYEjb8qmT1oDJasKIYwdSv1PjkS/OF1PRCpL56/pELrz7nONVsLpL3wy7CURIuuNsfml3qAioeVLKzm7tAXv5g+Kc1fwX0l36rTUXdnJtHXGMCKtDXGL5Uth3ETArX5ajQzsFYrOk4oIQIc9x9m88Bf2bXAfLqhIMYpwma0eGzZYxd3OTMvN5/qMEjMhfuYfXILzL9SH6Qi6Sl0cyImqKeij47yWA3Bio47qv2jojtcuVpfuUudvWFNGr3zOUu3ZHKRo1SXBjJTAyGUsh9quw/wIQ+6MIw85ng9/ZLxrZa0CNGTdUwiFqDMahrdwpjqMoy3oeVzNYtD5MyGe0AI5C6iIWGH9icAoqe53IEKl6GvOXWar6Ypc5cqQ3tLufnSfW/+hacESEgd4oBkckU32s+FZuH0ZFotctaE94YLSEncaruCBLkYIPHIPFUZdjS63HKAXCEhh9dHE5O1Z73UiAcwRmxqiqciAryM7FNyFk6Vg9d9ZFwH7iu0LwccrhXjHFE5p86JcyYkcXYDvqmc+PBTYSjjlRENRDEjfSZRgeu4sSLXJUvy6F2ivsLx8zZcGFVnhyO2SsTUMnS4mIe0cFYicxmoQMWH1IzqoXGe6t0YxQidzC1dxXb1ZkvF0TCYS4lDLdohvNBHUA9q5DtS6lDytKjMIVNVeCdRySpYhAhODbuveuyWnP2NlXVltLk7akC8umQKDsKzY2FshhimR3bIfEo74c/O5Ubx+tsxoTL0rBnho5xr+M6QSeetezT98/KVztvgySjtrCwAh6M/fWBB1o13DIY2PZEgNTOX8P27B7qrXrwNdsmmV/1HM0njCweHzpkeukEAhcb0JTPXptmEKvS/2YxakDfGfOnvMOWZNK5RFdS+hG4g9GIFOMEahAj1J9gc3i11a+woNXXjv449KpYmEAOf4J3KhKNNqBRupdlX5Q90pD/tVivUfrscRd2Sq9ieoGogY/QnrvVJ9M8G87YYzxi5WsheetWxY5yzI1/IJCCZhGCL3+0MT0w1VHr+4Q4ihwLHR/CLKEk80YinM2huYmZajds2BHitN5itPE3GD/v/0rK88D+br8b/mzNXS0MHQ5xnih9HLUpXIJZGULgsA3z7fo/f42Z6g1KYw8FNASOfS7VQJRwJr72SwKWdNs0mNEgla5WwqC8Bgwxs8SQtznDdRyjLfq0ymOwVGAluDAyot2NNkaY17wU7F91CVNIzNYeONH5DtN4aP6oZcip9TggrxD8Zn42R3Oe9YWutVJvxYuMj5qKiRex39pDToszchJ19tZfDNBEGXa/y03U7X83AMU+t+Xv8mE27ovO6viq1DnEVEJuOUPa084jXzos2JtTpmCueT8ss+OrlQ9eHxtqv3OJhTNjocU2hp+XsAJwR0rE4srbvkX25Nn7//Ifdzq32hFEu0u6p4NICbtCRfR+8BhWbIFddYdcCaVh72abBhEmduEo8PEnssT9majOOAJxW6DN4uIHNlw/h7FGdWcRoEddxZGwYWzHRQD6ZdBlEG3OR5429X3+0Fkc1wfKOqiW9G6CTF4p6Uhwbjx580NyDoEfQilMjwKIwEbyW4B1UKU6M497J+nSViHQ8hej/v42NW/5xjef8MUPuUutJjBNPUKMwhTkT0OTR3idTEFcjVwV8xgOi4MK10vSpN6Mzy/Sr5tgFfQbsLG54LrLVoM4z8JoQ+eEwPfizg7W5D6dZv+dcVDAM8UbS84nr5fcT3Hu240kbzTDU7oTQlzQuQFeCXP4rAlxCpdrafIqrp4Cz+/HkqUfdImNJqnyNdkaeOqpeu1vSbcSVI0Zz3DbxNRdyiq371oS0aqFS3k7YJjFuBhngtvinVtjMJdazxxnJWbiVQL0WyFnba47TaNGwLg8KPvpiXG0jNEwfWuLSbKyLudF/GMnjIf8eHZeF0McWANaC59HYcUk6w+cfjkZI8uEHoXHcvf5A6B8nuvJ4ZWvHdZTYCIusWSvm8J6ZIWWta27BD7VSbdVle4mgJ5KAF2a6O58fDb34Nulgu/sl88IpuMSW2j3h7dmZWUHOlMjqk9TcemsA866zuORPUM5yt+r27roYh4iddiQzJ5yA6ASnWtEj3XNWHnCQy2B9OMB0A2rVWuakKerN8q40bAsHq9keyBfq8f7K/ZGpx3HgQn+vT7iGGWe40CpFwiWIqTPDoY/oIu7Nbi3ZoY43ORCG7JdmiorJUos8qBTd6vqeEplOIbduraz2NK63hYT8EuAmz5vrJRI6ILhAsvh6ZK1uSE+79sJZRfMqCSoccm9hjh0DKN//ne/12CMzfTotSX4W7CQlipDrM4gpN9EQC/q86e1npbBjjzFgDbyNoLWp+Y3PmMlRNCVyJNySupA/kuj8cWgbNzciYZz8byDeBcaKb0ZHl5RhXoH+20/p+8nGaLIkomCuYCpSTPq/ba+VZAOxIGpvVg3UVpxCphGybkJ9Ws4m8DorzyB6m7Vc9rVZ7WM0KaoK8hQ7LyUXjaevVq7AbWfmpH8FYsCXD/EMECbbqg08m0UAEnztguicJDjcH9rrkBZ9slkWLZyScY9WRLuut5yeYwP4UObYzCIhFTz6+A9B4h8sHwWtLMJuEnx0n0m+EpbgI+VCP/saIizbSOvGbAJuz8RyQAhYq1tgcLmVUZ+ukp0r6fF5/W07FM0drAydzLFw9SOxT+RIpXuiFrwPvBkfmn3l4ezYjudBqjXUIbamj+25BUsnf5Trhk5V6gsr7VEYvQtpwUsaU3h0SKVZYnID79rU4hJmAEh/4f8on8qhXlaX5q/rNPByM74W6rCW3bp/yJMzG3OWTCf6++cPeXZKb7dxqo4l2u3pifulUUVJy7X8Z8v+rvgrsFT3NPO3oUkr49A4sdS1pElfhAfdEqmOwZmnxjf962CexWkKaElkvm3HoxtmRdqTArJ9i4ZjkP38jLGN6WdnM3rT0koCJrRfPpJXI9z9qIHsQJFV+j9Tk8QPXTlGJphyjtbS6lPBHF2ri89we77ObNaX7KjV1ZLLDRHHZC/wd4zJgD5o9NUIFkcQox8ZUmzTl8PYOERolXTtk0GFDfBS5fw12qNs/93yEbi3ni78etBB/UUUfAU20xNtIbrO8wn1tyhGj9uOea1mX1dM8MrA/zLkJ4zLGRBSRpRvUWwdGvu+ahjw28du94y8ZC7YjD4Ts2G3gLvLOcfOMWgk62BYrB5VbUkJxUp473yPidrkf5Em504b5mRoMsuwqBjVV+6oR9m90ff6aFRLlqENVqzWUvEGNcVWHFho+rAPxJh/Z1obB2Rq0utZi9qucG6AGqZpofaoPIBsP302bGBxJyqwm8hRqOLaqmX3PA2zhHWUjrD3ng07M+LlGvUOLh6sbYhauwlPJ9qPi8U8u3Aq0jSdaAjX23VO3v8ctJUngZ5qGeelJzf1L11jCs+VUsKA9X7jCP4F9MRRqQERpZsrIf0pYdoH36cLJOsVHojdQFiWfdvR02ROlJbafUdfj6Ux2iShD92Tt3vliTXHfJh/9MtFRuJzuG+/GTpoC1n1XQJ8gqvifNYgh2X2D2uaS2b1VufS29nDdujLmETDmaCq/9AnqU9/PuVkaT1ebXfBTEmXGA9BA/IJFPwY/vsccI37PuFjgBX/orAtAQmFqnIOpcx0YTvpy7PeXn3ksRyVTI2y4h8qn0bYByFlIyF9nYSRYupi2sppf5yUqhemtQOsNoqcUOC19J1iwDurn4JS2C+mFRMHOuSwQeo3BJOhay+Y+QMoaeHm5UsTQWfCbLW1AwExzNwXD+VZns5tguRflMmdnWy0vBmAsmczt5S3GWpam7Myohr39zFpB+P5YqmrFi4+RJ4O4kVhG0//1YnS0TOzUFuBsMr843kunbOs7+aiOYVJdJ8Iu5nP/HK7s6ui7NI880bvv1XCS2oEKTkDVSTaEHZLr4tiJotLbQuiRKYfjj/yPdd7T+O1oszkwp12IW8DV/DdzM1MoWPhHFSdXlIkhulq7bEee/EJVwJobbR5kqrQeVPIIl5yE8c7h/1T7CjBERf5qZ08ZcaLg3/vclAZ5xC5trfuw610q2k1SQ7qgvZ7y3S0BWgQ8YfhuYbULYwil3oNrF3Y294wYXPQocH0LWxR+fXFdCnPyE0eKj9EsJDknDZ55NPsp+z7Ayu18N9J1nejrCekGCMiHPtZ6I+O7z+sXg9Kn+NNoOXgebQFcNRvzteoleUnFLaEYswoYUdTUwYuwfAL06eIUq6OpORkiL/0hitxXWkE5e13uRNddAAFJp/bmnkTIBf9Qg3QxVaLE4+HDgvyWtyxPOKdtsACBOciK76TEFI5V5idh0Aw9MImZ3hylTFtslNhemk+SZb/4NufEuaX+WRUo2DJo8PLCJ1IioYS6uW6d4aSiVsC6E//W1zVR59SEhp5vawjeFhxhXWxO4O1E8jR2CEz2ugT/pOt7sHgW95ty3/CmCn3YUhd7lFyn0UQxkkPwizqtawZ2TUeOr0voKhO6dkGsP5YF8gbftCEPiKXb6rHAAMOW4AjEWxu8PAkIlyTXubFtkvQeaUrU/HoFRg6a4CqCD6WnyzK2UAcIrDb/Jlc101Hrh4EGlxjn3jjwp8wc8vF0T0Av9KOWJ/n8LJtJrXQD7XtOL1cuMRBz/WjhvCJTSbCNPLyHB7jBs2flVmn/37DLxwWLAFjcz9UvkHCsZfZJHqhhoo1NOKdJ8ZzT5rcdFDPCpzEZJce93XqYTnmBRQrUUGG5OclpGk4sz/kuxMXd6K2BhnvQMtDRa4fXucEpGVUiKcq3bfAkpjyvQ3o/IUmLEWGkdmcIdwfCR4Ca9HXIURHc+i2USx6fEQiooquHocEpOECWLZG0CshwlAy8R2caheXxH/wPGZeByIeVnelEaSQA+9L65qPdLqZbzWjEza5GQVftJRTYrgkd0mdULeW8qd5j2LoZkvG3d+UkiKkgwawhL2TTYNoDXabsO6AKokemT6LLpVO4ZdElNDar6QrA7x44uGtFOJq2aWixtzJWaryZUUzJORdO+rE3HQ5Dw0MNaJprwu5Wuid3ZwQONI3Lagu3kVxJF/OFitbb67krdGzojCCsJ57sVJhSde6XmcJXaNSS4wmlx8lLW60PbgJ3+vqmLoRlreys6vtVqMDNpfZtTMyCpxW9DK0qJyWaFLrHfSU88xWtuqCP1kPlU8Pm7JHmy6Dk0rwdP5XKAWQvfik0Ol+GQOLCsDbs1rl/zXY8yckDBOtMPVDhJPNP85Ets+aqPAzcnBkRJqItL2IdERqpZKo6JLz/NsdVKoucxz63cO/3qWOMDfxNd2HzclsckJCH4lSgBIbVUZgP/X/eD9QHb/xINy59xxCxRiTKDdSqZi0JlGFMMQhgp78/1OjP+xCPmlvee5rbQMGhZSRbfwf2GmCfPG7p/xZyIavLbUfQv+hXbMSueahg9ttnzh3P7A5Io8oczEWquR0+gIhGXWYMvxI//yTMApOD3j4D5LVJU/D2Cp2YFetRbkXqKsUjvjzIQdvq6o2d7Ikx0yMzGONgyNGPkOXeEqCRzs5ycVlt9P5ghG6JlFCJu2ovNZF+C78r0oCS1xpV0ES+peENTJzZVnd6uXDGnoRmvOx7uJsjKBx0EQL4xkMdz4Kmsw0PJOaDJJfa5qx9MWpoqIpqIyrBc4d2gJgUiBJIpuPs6bzxr8x00Nuwa5wc7hvC2NJcr7Brbnw1ZlQ8vo2/7UBHGUyGsDDcPLU+Fd0y65w7PJcewYw2VSo+HCAWtw2sLgppV0FLNuqhyGeKjZowK4ZwJGDNOTXueKhyKMAD2rS7/1WoWV5PVzPUPq0ewIdEz9px4BlOCORbTbJx9p6NvtWxHalRdQg7bjzIQplOWZSnzrvc97EapEVQXx3C0WbKYE9TKqR+oE0NlTzTxOxjKqegIvd9PpZXSRsedx/dshJrAEacPL8NJUeUXGuIT4UhxL0nBnOPCnUC48kstqGTA1/vSOJtAOk8Qy3ZTXMteMIIz/FUMhXjZ/E18WExtGKlLIS2EE+Oks492ReeZZVjIwirJetJH00/QdnyfiYd61S7DTDsB0c4TVqntRlxm8Rv690l4CevOXgd9yMloJEDAIm0pb4zm2LCct/9Us96YIrcjBXh6RQHb+9sEILx0hz72tNTAo9+DL1iH6Ka4awQ/wau6SOZqOs99AFs/BKH8rSh5Qjav+IqoMdS8BTKFmzOqs1FTsNqz138HN/MWAlwT3BImlBBYDhIYawj3U9/4uM3ec2djuWTB/3mCnh8/UouH7sb8z9Yt6HQe8BqQ1DT5TFNjWOQKO6G7sdNRoPVTtEijiNOr+8rTN4E+JQPbtY5liNfKH0vRIJ4O7kPJr8a1qj7J8wf7iEykGYgp8OZWYO6BoYW2CO2X89pd1FQzUl62Wj7Ty4LsyhCcOa3ssSeImPBKScVIwFc/APgzOcnlXlsXNCCu8UO4QLkAe9CUMbR6Zb9rrWXpZFmB3ycNk22UpSwpLFqoINoM89JYz14mfjmH+Z9b9kl0IGn7bVl3aKtUpNiMFm+2UrhCMrPJmB8fqD2/1yuDY58vZfZLIBDMaI33Egb7hFKQsAfY50w2hJHIJ/hkCI7HLAM6IJSzhyt+i48oRx7U+C8vnI6EJsN7f1ez/f6O3zwacpoUZjXWOV3+BTkZ2Bnv1BXIJvrihv61XaYj0wFAyQEZYWrqsta9HHJ0VCeJJz9br3CaxJ19bDv/nfGAxvgJz10tleOM5gnZRc3cpbhYBZNPYm724fgVxwmDDQZ5yLdB2hx7HeyRITG3sbzYxMcq3Hj3NLScDiVohFO2gJmMYZu0x+P6BgG4lU/1eQxv290Y34gMjRCY66JRvYDau1rJIHw/7EjTvY4QvgXEa/NSQqUl35Zr1/3inV1Ig/zbrwuUvvDyfktaAgwlFZ2Pn11Oo8fSl1si7ZA9c+aJHOmnfFRvwoHmdmUI7DejMgxg8YRZSBmFuUsKNGlXSf8YydNnoFqS44Ix6FJipkPouoT0mNIk26oO83K6gw2dck0UnMBZfxO8JaL28CVaC6Vkpiwb2Iro1OmOVUyi8oLNrYpT1owY7lFBIBGQaAX/LKjWMInAyvoc7UazromzdEOsJvXmObZQkH8fCAKM4uwb0ohFt4qq1BzO+jCG03A9TlF6Dgm0udX5A0OcoDIYmqymdingdh61dKoMjdnjFkz+jL4jMxLqAKAo2Sj02RR7b2sRPwQ3Xhvnqz0gcsGvE7t+EWdJKssyitKPbc7e1pFOTj2guF/vWOwDWvXqYKACUTGOOEIO2fPmbh7AzbPZrgWehcbVS33c6M+NrgGrWFL23Wjh6Auz7U36w7jhaZI/RM2RDEtMB1YhZ+4swwhTMpPys9QZSwdGgdtokqS7O978z7rsDerkJObL2vvga0IgHzHN6TFhAfrxYpsUsqukzyDpYF88mj6vPc1IhKpw7dkTSg2fHZmRxfWm5yAQ5BcPafLmleZY6KlcFe4pDEW/zWlDANBxi+Di/hOkf8h0+yQoW/xsdUfFnnZPmPpe3u2Wm4ZFH9nKt6jKZORVDk5ZAYwP45/WrppFGbW3S76fFYGeuTL8PG6MDssGFoYEbWUjW6nbLfepMoQ94PAqi1fFsVLnTvjAyINosHgF7YIX8BBbSvGlGB0WJW5+LkJYWKTU0H7tSp+LvnHIzJuYtkWrrKEKMBcv2iqr4+vr1fz0dBD1KgdUQAyNwwy1O5qSlDqA09lpekuqGKZ5faklbmA96KM1d5Rm7yDr364VUcO5xA4Z4pGMPKrKEAe2DDXQ/df19ExfZnbGTnRWB5mVQ39cXrKAvPz9LcMSVMN/NA9mGxMA9/uQ75DB2IM9n0gwSWVNfxE2t2gCdcQCRwtOhyvLV5P8yV7pU6Xtck93oTWmqrxbxrTVCdnnAJQBpXwsJPjOMqIDwNj8gyqfJPDCj4rRGpcVZrQZcQ1JKIrzLboiO6gY719wNAWvw9FhzRwC0Bwb4VTshQzMQMeUqdrOEoogLIZ9KerVYvCwjQ9RgE3waf4ICltWClhfzgv84z0LP/ZGJTQsGEmL92SPu4tteAKBM6C2oHNd+zCAuwy47eIVhucR6mNMpL3eyLsaC2C5/QGFaezQEjqsOVFzWGd0Cb74mlx94ORveR68or7xSc9LaH6vj0UQIMwsFlXM9/Y9MXbN/IPo4WydBIRTbHw+OwBcXr0mRcQ7lI7sw39JXwracFPC/nDffAc0RLIQwoA8RSfn0I94+Wo1vuSyQq+m7hAZ77I0m6oY33gidJLnHPFv1X5AaskBAeZhdor7VhXJnhAAskKiMVhjXN452E8U9FcGoZgryeUu66bKaj4R9L9WARoPvRLxrWFESLWI4xOY1qUiH8kdDW0qua3gj7qx/Y4pUYiUmSug2BeDxqaPY9rEbJavXDQ04oobAGni6v7NHNF6ZBc2UAKmtu0Kpk9yDqQERmYZM2wHRNeh8FS01J6WOeQkIOwKdm8M+t9ifJbnR2Vk+QSE1zhqzk+t7c/mPzzYm/1fdBV75KE+EohVPCxmMdX7+Liz9srzY1gZIsQljNwyFRzbAqo+9DDx+ZN/fdwV1YU7al3Frn2OaPbLUR3svvUo6EM8TU6/zCWit0HJkWK+BruzMBbJbi7I6eUD6I/afFJtD8UiKsnyIwBlwJG0QJH8RbiI64TAtW7IcSbGj8O6irand4SmlZg7Kmb/gxMsR1gwuCE2DLsW0ILZBTcc235/9f8LJ4Fu68b0PoJFZQjatS0QJQfgFSNEbdrKEIVP6u/JVMIA+rF34geLhqzsBFzeWXR5jbv/hjOJ41Trm925Fb0a1Ckinxa/arc7EuUh9MvaRFF8WfKFX8bsc8XZM0sUgoDqWxFiNcTcoU/k9KD5Fs46jsoa1xb2hRShdWysoPI8XN+5S6yP2WbjvmFwDhv6w+d9ihEKKWzYC0u6cScWGast05dPMIxRL8bfbKwY/nbnskgQ6hAGZSRy/y+/wNxsVpvtR4/xrKU306CzZ11kmsm2PjpWA1UqaU/CuIyx9ex2AY0yCIYfwRUQclg3hoVakGgGv4dt1dHszVX+A9VDsDXUCCqomd/wWCdDunCFTqkdPBACFY0JgGKCZmVw56uewwgIAgRUyDVOZUEWi1EWoonx2qnDIerx0yaZR+9/+AG0Mol+pq8Xxy7RILY/GBFb5Mkug0oR4feVEOIgAlTiueXLejNtrXQcvWqrVBSbrE3q8RSpKCYjAvWYmT148oSeFXmmF8Yc22rHGP1ULRV/x25NyT+35qAjNlsE9RiqGf+1+8QT9/p/DNN0G5xk4Vrle9JpFFTnNIMjNzs53oEfqA9Qv3Yni7sF9cEuYJ8TRrukn8NTAfgpxaoii76TAE71Y8oXPtaEtTM+4A7x1VHZ/G7g266qUWZ8VjgOsai4dFjvQd1qkxQzuPDx/ebgJGgqQ3PdI/1uAp+4kEZUCgOsdkyTfdRCUUbVeLevg0XN6AMZ1Zifbe4zhoiymB8tXDwNgOfV/B3CyRLZI6kWYGhpQNG5Vl8WlqvhX84LSD74v9gS7Ox3oIbGJFMMdUB5ZkBx7lKdkcPlQuQXZE3jKt5xRYrUQJJ/HYHeZHgx3neNsQLt9fJPvWKR4P0DWKrX11hPMlXXpY18UBdlAMItofvoel2OAG+XwdWxMv9pCku+jH3TA7EMWiHiG/PGYM6RC1OqZIUrHwKTpY8NsbDtJSG9FdEex4mG6YpkRSwV2ymnVXK8v2k1pdF/L/PCjFu0yKf7Ss8Gfr8FmH6ajeOmGrM/fAB6n6gUkXjtQvUb4NcYN4W7UFHV1x0VxvO9XnNWQS/5QyNTU/cgXlVVPIVZjZcI3CV6Q+v+a99Lhz90UuvoPOteQBFZ6WOTa+T4Xi77Y3MDphzNdQlYv5FYAulArlskazQdAY7WjxUCk5mZfrkUK6TxoL+cC/9tmyC5tos0LTzm+ELSbJ9OviPhJ5SFYaSVlc7eQ4+kQa8qwwl2l/Mp26CA7ZmwlckUoVd7yg6wVXfCXVqyO8+dPCe4VFT8/JgyDmxm/GGgLrW0ncpfN35bu5soZ86UzxeKvAVjaTuo/dIxjC3KCWSavO1vK8tABoJXgvn0/5s72QhhIdQeoE70xAO8mRhkC+JNyIjtHrFRreqw9D8VS6Mr7G6j5eFVrvl05rcxdTXp4TtDhudlKzm9YG7TrITX0FNobkm3KLWrx8H1ZIsYUxu3k4fs0AfuNFzmhklu3tKXi/CPyNmcdbiUvY3+yTudfHEh3l545XRfWYRP7alQ3gEakyRNeWmFZitl1JxIK9+yjZLzrZxOxz/WpZNBXTDZKs+LmTUaJjJ+JhCRTlBshUYj7RO7nNEHibsRo/apJ2VtgNM/kmEbdHsmLS38+pxiaV0Czuld6VBeFVxeO2XaZf47ZgEHewrYZNn9QJAFGuQ2ewokyQs0OADyaPKSJZgj/VJMTxae7hJzreY8dwLPdkvLCghAwBR/6fuj0LzCeOp+WSTRbaHeTv9LUvPzj+kZ5HDLezYY8UfEmYsDYbIdjR4C3+GuRRQGXWkRGYRkGQmuMNRKbWbUsIkTV6wjr38x2mlgbcmcH5TzX2guv8yMYT8psEQxGw/iWg8CuK+wXVn9pFGTHRakKzffj3BlqvL7VZJbkzGWljW/aFlsPtXyA4eQWu9eF82Uh6iE9WR3GIf+75EW4u+bOup4HaO/eyCC9q9kukVEbexsIRwEnIWcveuLc0aDA5Y4Axq1FM7duxYYtODJH1JuHL9T3NBtV+ywA0gSEQlX4A+q+gRKrB9UHOiJvTG+DVPENmQEkNpbldVoJAggenkB7uH5ppoaH+KLHz72ReisikcBzYJRUfjDqVylRqbW6RO5fdzYAjngIt3I2eBT9BhNV2Omr0vyLig+N1Lek7nVcZbxxzoTWDRe+tF7C027jGJtOhLnRECt0gOXYYtkrINjzS9/ZBsQ8HG3y14bdyBwoiS0PinkMvcyh+3jhI5G/acag4/yd/XEvs/vw9BIHshdSV41n4Q82K3WQK9w1NWVYF314Ve9+P8vsyY/M1l0R5xgw9fYM8WzToDhsynx+3mm5VWLj9bhK8AWNY+zEgK17R5tcLo+6mLtraaghixpYPzqG7rJ/SlwosrOT4lFT7X4y0Itm4osJGso5V+afRDvAKy7gCzEGsakfK64M3vnkFmp3j2akOpJ6Uvxyuqsf2fq5SbfV0+YY5OkM9N+Dh95oOAfSdZ9qo6Cbjel/nQ6wjpcUh9PmEl3bSUpYyJqMY0r67lXRouMTPOHDNZ5gjtexiDKwOhWEcZhyHNss0X0B14p1NSQrcP1wDiCJWLD2v5PGkUq88YeHRoREsZzWLcpiw1mGmfvGx7paIgDtwcZGPNcMhIOHn8X8w8mtLif01ahD8hGgsB7mE6QsrDMCgZs3/IwUxk3+xamwrdhQcwEXrVhAveiWu/VMRNw4sM5oH/KAaluOuAdp2uipg9G/CWKKhPlVwJ+YVqxdNMTZsfurtpNm3FuZPB+vi0pujpgjepCQuO4CueYhD4Frp9sJPWD0IkiRMDuB9/1/VgwhOUJ3jr9wFKrtYIVEo3QVMxqjBgHHTQmmQu8O/O2bVSGj3ce7vf0K4y/zXqo3cLJwKBgnnPmSlJDA3NxqDTZuwEI1MZM+Uhe559XBwdfJnShQMaYj5onsm0LMtju6cYKq3e+CdnD/8Ecc/m4czmIunXnif2c6r2QZyT1k13UU+12RCAqQgKZo25FRnOapf4gJzmT5Cgc5e+0Zz7RhuAWFFmgEOlgrtBcMv9k8zy+1SYB0oPXHE7Ufu6rd4KpRf2aI4E9RP6RF6KS0QkwJork9vMP7unujYbmFpN53QJJcxQQUssyoQF5Yjwfz6t6rnfAjpkV3XA3RjckDiolKlIehaonkk4JHZc80+oRniLbUrlysPrRMgOdCfGg430AzSPw0Q6lSWAHIojfuKd/Dq5u/mNuSiE+8eqSX0ff8CuGptJk2VlbsqQX1gTI0/fFv6gA0GR9aqzmzyHkLaT4jFxS9l3LDNRQKzoEwE9EbcPbexM0OvoJeGITmWWJODYGCm50/qQ05F7kELH+ZfMq2qoYsjps9SM8ayxviCGlWbpXCwv7yvjMxJq0YpcwdbqCTM74ZaEkGDviVYtxQjevBa+oJ0gqCxKHVuyqZ8+HMoiwOKpWjpQ6TFaEoPtX2p9RujqS8fl10zVoTNZyAeQG36IUChcYlpkdtmaXN+lfAVpmNXWYMcZLmwL3Qpz5YoNFQC2R4FVbar/nma1sBqKec0hlXtcmRtNQaNfVQZz2ewHRZQxFqLmRC5bKYkFf3eJpdWjfzslGOH8Wk0avt7eeVlTFnOrL7t3CVIB0TYXh5u31KMoXt07OSmj4wDgccYOo5mfDgQ4nAQWqalp2GXPNhE05htHt9+xdNTg0NadCgz8kW2fGQCiKTzmUGmgbxpRQFd2yw8FVq8RXa7WWpPakCGLOTmT51HLyBlwqTMBLPTUzP5WIH/kLtUC5M2Y5a08hWzKBvfOo12/H2eNUBUiwiVwzuTG7EhENrLFGQ1bYoQeBcVEdQhmXbdHIb4i17LIeyXpSFNtVIyDE6ZCwWmrQ+GPD/l4nvctsEOiCjUM8OJC+yoTAQ/pNyYrtygiMo4s63fgQ/Lr4tmKs7aPnViQSSqNeUqtm+6hMkp17xWBNcuE6YrJw+A613ubqOtoDAmKm1+wcaMcGizHPc5L2UUfokmcdGZIPknduJrGhv4eoreHzeMONhwUqKQyexEIK5PjWWvu2h8yal5sCakEM6UWy5u0Qdubf2WP3XqBiquKcgwrlySMsQFp8IbyVTkClS0UN96zYKYHR0zl9PBAHaN52fwaODeoVPkX7xGHYwM6eeAy4bHGKuQHhuG/l9MZnHwd5pcYqGQKVRRRtYYt63D4r58K7M3RuCke40PHToCQqx/nVL53C82q/76Ncat2W2OizyiKF8rHfGuK5mIwc6n88l0mnXI4efYKQ/O8BPE3z1uVXHxVKezy/sKQSNKE51whKr2jbpF64WgYfTcBrCOrXxDVnbDT0TAKrjvKEvhqBcL4o25s9Ui78v6pfS/ShpsAKP1ASwtEW8JPxWngPH4S66VoCHco2gj37ecwKDZPhCl8HEvrXWvv9sZ9clog4dPvzzjjBVrIOwGxczyyh4oi739/pmOKaoSSdbU/a4V4iAnxC9gaoFdEZfCBMbIOkuCFl1ZDszoysB8cXXhkYVrxEA0q8FCMh6o655zfVFY/I+WSCj2ATKUDgbPWGPHd/bDUrXK8UarOR3O+0MUE5rhBaJB6bGF1x7S6P4ppQNYACNpWAnztEgKl2fabs7Nk22IwgTzlFRnCyYtxv3se75iGvr/7Mya+MQ76YTGw9N4UTic6Kp7cwrG/VG9DKsbA7VeAzhpYRdFXKt0S7k3BwY8Bf+oKOBETXm33CFDS0JmJG7fHMg8OV1+UXkz2FIgY5qJSum5sVV6pxT4qVYTuXgdNmSgu3vOuJHoH2rV89D1ujPU7VWw/ijNPOWt/yFamwePCFfpjbK52vR0ozgVJcgoDVBYZ3hw2WOxg+Q0rhy5t+uu/YB+SyxSIXW37CND26iJiAJ0300qpZF7FXGm/7ujx2IDCVKF0/v9yELd/v1F51ATvG4SjwxIufJ/0nSwpgDmnMBfkKZtBruBW1P3dbna5LPbsTi7dbyvqt5ieyUggumD/Vp9+gP3jaPL1v7O5sJjnph9fHlhFxbLkg0kIb8bJag3uvRe5lSW9v+tmfSQDPUQkHPqxZIJME0D1NPUg5qjG+NyOEJKgcyqcQ2L7XGICdyPP4+axZ66tn91/Rf5Y/P58h5D/q0ZZqKDMagIW56Vdj6Ie/2qMEAC3Q4z7oZ9wSPWBqjKPWhiM58mCnBYj+L5VJMYCRgIN2QsLLIm6/kFcLbj5eKATo6toISsTZVrxdNAIeC8Pz/I6RIrV2TJyOyNu7+7Nx+XU1icRy6q9N8OO8b3drMOYRya3ftvvFvaDR9VP0VYKPy50cFu5YA4Y33JZofq9+syDhV2YjylD8j30/79yXTCMTL9f8YcYEewdde1BWS4Zu4n12Ai6ir7vDJQzwYoWhuq4BMFtjf/LOKCUmdBUL8YEU++l/Ns6EXWXd+bDpUldNRSgGxA61Q/n9eWqij+BV7KHVxifTJBF54DVDRXNMeBfU8CHXu03BfwRBB+eOeY4zMUIWu9YKygDq3UzSbuOn9ptgwTVzPNCX0kEdUN7rPS3VkuWT5KV7uA7+7BPHdu5ELfzvwoKMnbeXcEVxkyZnhbgFYX6Hw+T3gz7yuBWsAkUYCo1hZe3RPjFpmebjKesXpTNifjXMn7szZS6t4jSYcAF4Uv6LBDR2vxkaNbrxZ3jK0sOoYE3fArHriA+8FFCtz6pKlTE7cBQdOmZOa69L4f6PfBKMsnMJ/wNu1Or8lpFqwYZvOJi3NaOGddL+9b3tU+flvGmWwLKW5hGB4uG8WPqvRooanCu/PLCmqXuTi5gT9GMdYPeQsvvAc/bfvoUSMobiqQ/HQVbAWYe4xLixOJ4a/Kj6GMgL7HCssQzJRxeedrtxq+D3NPiLw7EIn+OJG0NivMAQOxp5egYX0cE4gIVpGl6M+BnzozSiu56+ptbNhQDkADPz2oNeqnRRJaEueZMP6RsWg96TtjdnRL76Gr/9LUdh4Xx9l6TmK64RA6EGorr9Dxf64C9FGgoaieF9Pmfp05Fz1I42XEi0P06G/+OkOr0kM99KxQ0+ch5BkcPVyXd7Mjn+swcdPOdwdO0vODOkyEauTrDa6BKXFxZjB4dUSfPriGtXGw9DF9VKL5Dvj9WHTc1zmQm/J2nXaEjmGFGVy1Ul4+PbqP/U79bSi9XoyD4FC3CCjDbFEXX5GRToCUBH65mBxqHCMyKkNP6gDDQf/pZZ7F8iipwZCag106x8MJCvTmlukOkFsW9zK4D97JIXuOkpm9r07qHOkAU02jYDgcteQscqOYzQDoH5Ix50gGgEluneL+s08xdiecCJMR1ZqOZ8+6IogpEPSwIbxJWto0XIEkvBtnowEy33ZvQEAOQQj2ErxeEczUQpR24r+7z+NhSjVgjEGaWQTZFFH66wRhvQlZKYOjdUXP1csW1hK63Qoaj6BaOs18z6i2k86dz7Ysd8ZCwT7RmaaUh3+YoQy7cXHQaUQRunuudeiGyyOcMgLSbejTa8d0U7BwiN6UDFb6obNL2uMk46GAHgIqB+gsHarqyBk/0OE9Uefn/MfGjeG47z1fj/e+kX5WhdNfk4EIRVGoowQGcA38JP5e5AiPY0lFmXY1/8C/2lzaK7zhOSV7QyEfunhWmDcdEJq1zZGPi3ssLfA7Xo20xmm1YO264MQN9lGPGKYHeygqCcBqURDoZ3+YyE8KFOyh/Mp6YxXg2l7UPT6Xfich3APljvx5WKOpNWDkBtbh7qjT2Z6oFjQ/G3rDwm2CACZj68eBUy1EsFxfQ5lIkbeMG91ASCogNQT7iHqzpgzUI3ZJf/O2E5AKi8RlyqXMqWIGzcMupbOcCnpUVNpoWAYN1no6A3kBvkvE3Rv9te7XbqShKoZdjZCj92X/+Mtt3V1yjuGP9afHMGmDc31EKAhEfn3twT5I/fqJyE3h66VxSFVcqQ8Ba8vdfg2qA4VbrDA9jxydHqsvTCXBmeuyNr89HIXqoA1yLpNa6jnjkrZFSn/Q4hXhiWOn8mJSvdr2NUZVqkwkd8O4ekembRo5kuePuADicb2/nsh8sZAwc+PmkWImy8zHBqJY7Z5TArmNcGNmidWG9+J8Ibg8bUgOp/ekcfOf+MpiZTv9isUKLegeCTDHe3L8pIJmz7gZnr05Qv3bHVim0lYyuiJc4qhoqH864IiCEXmyacwp909VX0NxHIsi9wT0TD+Jor8oDhCVKcnJyl07Og85+n1+EkVH8sRk2hPh2y5RQHz1YEEV79tUuWde9yd1cPDo7uKPswoJUM6G3HkgeypI/T8KsR+h13zHFqGI9TB3TrutrpPrgs817i3kWS16INZlS/5cMN+xaTtWydLIbVkR5GqoAuKJ0nCl1oQ9zQyXGZeqo2ZKhAGNf3/QogGuZiDi2zoJkmP8PDZh5g//pbOHk23G88Z9heL8LAHs6jKajzzmqc3zDKyQh3K/0b0fj8B/i7kx2o88soT9NExWY1z5Ddgzp7Rrwj1xHbOWwMsxW98C0LeBBVx0GE3rVHXyMSRZ+WlM9P8yPVU6BkQbe1sdtgCX/sQVgYm+Zajw4VCO0Sb6rlSBkINbBKABD5sgiJrsvk9mc9mnhtPx7kaXjFtyRLeFep+HuCwnZCB4EY4xYFDPQOISfGQ8W5JU5DqtTHehBooQzExvFoqfPGsmX+wwjNvkeRbEpU4vL/FuRbcaZZLkRKKgazTbjr6jcyC9Um8KF5qMGx/LoMrEfCLQ8DcICbLACR8XG7R/2TgGsbZir2bKx6wb+wi89I4dKkKlfbyZB1rxFt1ZC9E65dadlt1vR4SW78yojWxHVNBNPY0MJL1+FPe77wnhfux0Kewg2I/zBpzwEf82Z4hdxjw7+vDyfnkwApRy9BsJts+WBpKkjw9oueP6ZaELAIk8Y7Us23ADROzLKrCGYIyhkxX+5b2VRZh/a3KEaKCGAgaK8gXpGHiN1Zx8yBqYrF9nzSq4xTH7U893+VFtTk9VZZoUHktDY6cnD10ruSaTFXT1W+d+Vgrnk2DWBHs4VoZ45op/zMWnQIFPH2kNt0ctDt9oyRHv8HIc7hfKhT6m1cSuSg+9Ai5LW/Yy5n2trrE8FowMXJFWUXp9yXmyexoAKuWiyspH+0nkh5ybuvvpmMGzcsxRpgu+RfT9WTIVqnH9rkEGUllKg3YgAgubjZvgJ1lbr1Dym5OuRin6gBHgmoOke3p6IS8eutUlMJO8DfHXDSZRj1rRvkP2cDHuRPc2kzKNSDXJ4Fgb6i6B8F7SPsPt5xMqdoze58qKucWqh0FGvEY6aCleSwU4ZmSAtChlTOsm9TZ+Aei0RBBdrkrmRnkY4/Btsr9KIGjEWKYBiF7ZEOy12r5Ma/y1xOacbWMHPp/7SFYP9wl71Ct8fJHqPfAfT1QCmgW5tePazT8fkaDThz6LgEcDi24L9O+shH9VUk00gnp/FxSqVdpEJrGXqWKlqG7mcyInNtroKVkUGuDa49WAMWGQU+1Bi669VcOSGlfXk/WEBwKy3652sv9IvEBmI3+4XJTNGsagXUwXY36UEgnKuKsgqgp+uBkQaXGHYhtfTm+UJYDFa1uXaxT5TXLawB1n8yC/zVUIqNEJEPjuWUfX7XvxSbqHdozecONT8tR9T+m6MobRFvpFtk0Y/pV+a5LKbI0XWd5wnDInix2kifv3pAo6nzKOszXAq9U5izjkpXa8NOQvouiKE6XrGDunQFRJM1DoHB/wHXcsU9i8NNpx6YUwCT8JH6KWLJBwWdKhoKTrhsfoOxPy+qWkGTN2abviYuUxAuk24082UcxVqfvPDkQJLRCJ0usWbmmlHx355Yyg9ht/Ni+xLWhWjMvxRFa17MKxhJnbrh9tvEaQHULjKAiy3M9CZI/hyhgIpjcNCk2X5UMphHJVZglWv+8P3pHPnUji1t5jJoHlpTc8scDGOycxc9JPo+RNPbUTbYbYrzt2Iqy5i2VEc4F01VkN8vVGixz8wkhNwk9Cl37D57hQPIgx2QsdTOwm9L3gLYxpkn+VdSsNFfxBka2Fv6tm0KameEBKtCHmfXvpywYiTQORfIa94rv9tWuNR2RtEyUN9i0yO/j2oeghs8TWA8yMminx/JfTsXSLFo9eZeqeqOZD0HPREo9I76EAZW9p4yImPbJpe4NbV2T4kJVdTxGir1aanNmpQjD/+BwoScxBQ9Haew17Hth0e4XG5tvDQ7qbOv4NLFogewujQxWnb8Z8bxS+Kltz3ClvFVrlAGkMM3xXWWP4258lnBKi6FGOHwBcPlWbIFptT0G6c+fJIAkJDSZw7+4uDSK0tF/MYGmz3fHLTsYTQ9rp/6ICBbICjq7OpqPM++8CB8b5rUG4GonrixO9OwQUgvTwo6h2F6KKBOmIXPJZsvzrLfKPEiDC4oYvzzthOZ9BTsRhxVvbDw2KmVZg0FmfYNpZ0ow0FaSC/TvuVZeELRYtShS5UBBPJhhmJreNXbmXnbBg8eoUVTz8WWJVoIRtjXQxhZBtIIO7zWuSxO2ctt1uCohfDwaDLF/Xun7ue4NXXmw+Ak6JDdYFxjmShen63ZCjfJbx88gsCPHtmkIC88Yv4QCeQRyuLL+0Gsd+vBfbZP49/LjvdYW3L2U3jjqRP6LRMXsb6klKb2sVgExMfcMyeuAJ11J3ensYi4xc1pkiRCoJ+D+YfMBMfDmXVW7TKB+rZLfmocrAElhZkQBoLlu2W0LlnZP12zBiFMpxYt2BavYKpmHsD5jHZDyKZ8Goki1GNQ+2zRFZGSxJprBdCkQNmqAwxM/gCChN37yQ01NiWKJu4UisQk6TGgXZwrQWeQHOeGXKtw2tR5Gjd/vpI2R0k7HogrxYOcmYDBUQDTNO2G2x0L4ZLZZlP3jLRTzzRp9U/eS5iztQyv6axMtqmWgL6JQ6OzViPqOADrEBI8wsR0zRY/l5Q6vjWq0w4UcOQ/6gtksS3YucufZVyiUbfJdAir0QVzUBEG5BMZdRWsr2Gj2Pv1sXGrUw4fBeZYvVHzE1Ta3rQbFTuj5nTExhn8KlToSZMHzQLII2UsSE/mUd6Rsmoa+NGmpUZM25RxPUwt/mL4iKKZ3ytrW9uLUHuTzQtTxNWo08WRRoqNKufW5zEWA5VTmi5Ree+e7bNG0gouGrUoNsTk6fhMeAkT+sFTrKKTQRKSZbR0JxYkG4khi2HTNUZ3p/9mGrhyLFhP2b9eueyf4l9sYh4ee3a58LrsJJHix66xhbp6JU8Ka82BYHjb1zWm7Nai7lSU/Jnf6wqcAFxFSaxbWxArmt6Yg5rsmWSRqAO7pf1JxFt9ww2Uw1QBuIZflJ8xXyMsYaUIOmjzsR453vL87QDiUZXQ9z4Ly3G3zWXzcI3Am6rhAcLItDVVHxaui115OuDz1FxlFA9kSGyE84KAPAza9x3Ijvd5LOkFbXPtZReDciuak5H/8aAbzfeWJ60R+76kUOp/AhsnmHluos0wIi/5HCXHyE3r85mE8eQo6/1Y5v4i6tGYDET1WvcMwG+47G7S+ESFXPyZTz3q0uc5yHusIuStpaCnt3vspjt5fLPI+StR84d7tjBOG44OCSJh/2suLoKZzp4F2H0pOApcVGKHoEUtE8SNWOeFGTdqs9md6wKGSwUTnCYKnaEYAoXQVPIUq1uPbLcxpjBwRCN0osL2t4KPu1HByq7ukkgAB+C0M/wBq8vgOJj9FkM4I9Pklf+6CHJO0cxA+H+5jvAErLR44VqWzEFAUH+oy+ElRF6/t4fPUZOB2IQYCFfFN+rSmi7o6b0tnzKxt7UuvZ7TQuPIIBT6Zje8axZHfzQqyEPikFFBkak/6YSwlHZBcz+C1blAeUF1Js3egOqhNjMXH4Oe71dW6BFNHCnbh24vA2IToul26z2cTxXSwmO6bf+VAr527p7FfuOT8QDYfXkIuXaioXQuRImB3o4o9RB/4lg791Xlt9rbh9f0aJuWbBErqWcc+TjALrHoDJIO0+PrzPP+uCLMjoVyMsqrYaTJRpH7zu6lyOpyc33IjWrLqQTnHRW6P1/kdi/iXe/BM7kSuzy9PiDS31FM3IqdO16S5T2NEAINBy18izsnbJNRNFDMVFO+MmbMaWZsywMBADlEIttdUiAKytN8tycaiL2uU4VZD34pjaxN25wHPNYszioEwf03qHa0MZmMuHRVxVBaTysXSLaKh/UVdmt0MmZkXnQKNJgAAFig+xwpK2T8jl3uEbueAUdFkmeyIAxs1C519wIoXu7W++i/5eD0O81CLzcYNxoCBWxzWaCsTSLSJ3Ijaqy8g7yX5fNHVn21eXDilg4UxwyNz+MS8dxGSVUaOYd+yTwbPjfarvn84s828J0FeXN5IMBl0lmEJBzPbmisgkwlCkcW27vbGBU5f/+K1BOROqD5j7VZ5MJrXNPOvsrowEiLW6KvZwRLld2DqgJ5h21MCMsuppNZOlMzXq3GVTLj4/JV4YsVaw4wW6nZSN8XaEZKAzz8Iii+KWb14zd1OpInBiEDdPrjuPz8KpPIsTcMU+0yH39OW9qya4pcDpTEoHsMvoaUnvfCsrJI+29qIz0Ka95gMUUSISOg7d7DSne+EdzGebW8leTfhoaH2awcXMRu5lnwUGLCj0BcFOUTaDhnNAUUtmiAfGGWqP9SLKsi5RSWVzMvE7oLkEh7EWFUX1Pe6kK6z82T0tHdw16olD6ctgVsgyVU82rcILkdK2fe6zXL2KX681YZNqCQiaghPJH+gGIiZ+L/Y+cYZ96LxdXfAwGSytI/BKaRTRfhM22qAQijgtaDLDcPyDECR8+jRG4vARl/7JvPbjh93uXcmh2NDAVk23tw0UsjHrSD8S6+GgNYJ2U0QcY6pp4GFUeD/10HGQWDU29a8XpCgpOUEf1Sabm2p9TRYef57Tdmi4tBo4KX/jZylqfXBfSvHA7Sq4iMhSiKUM4Jf9ARqoCMXn9Wj2CTKYi/NvuTGfcPwS3XqV9GQKqDWRNpIbAsFUZMyWoN18N/QQtLD4t+V9CqJrxvyIim9z9JtKhecnyT/mT9Q/9ApzssDY2vw+7GCOFG4QSM444h8Uc8O1+YLPb6nT5z1Nvfa3E9vFnx9aPxpKZFQ18a0AsfFxb/ixz1tEsFnfY7VTTfYH4O8OLSOCrsN5AFBq+WnyI08CRZv8YyAqzCkzBTT8G22U0JYe4Jbpv2uyQauePzWlUR7B96+aqDP0QmGPBMcTjY9f38qRuKHb2RbVg0yXjwew42qaUTBEdWtO372PnyObvJK9ZmL1M9x0Rb+iIpL3+Udpxt/vCDwcgjUrUKRX8RnJexxX6jmojrSiK42YbrK4O6KRtXj2uMOX4uIaTYlGxn2blOMCwcApzacDqUze9c+/lonvcU8Uh4z7uY/WfvX9SavFPlvumSE2g4PK4xOF5shdmpMCXjJMOlyPyU048IeWYhwmvZ3tAwecshUrQ9Th60azJZbAz2HkVMHQEVEe2L+TFnIF6TReYiVrFJUvKQmiqOKXn9393KHTUakF7PGHd+gpEFSkNnppx2YA1XYsbdSCQx6Sa6llDnMeoyRJj6dwGNDpYYqNeCZoVxu/+pEbjv29R3uDJYv9e4kE1oLb6sYMNJBHbvE4EtWYN7Z40LWiBiQOhs0lE9WN7FZvDyoYRvfIQ9ws8db+qpyqLQOpfAEgAQwgzKTm/HCyUJLiXW4mvt8nVtcdXH8w8iSgI1W99ofnYdifoOXmyf4TfM2GfukPwXTy9pNSgVwALcx8pbYfMLZSual73Oac10E3WPhkPq1zZkI3shbX1Ep25rrkMfpQ9oqqx3W114bmw+98TFaMhPfHxPSx1dE5E3l73WuNx0vXRfLtahO6l/DjQCaqNIP2UxsNuO/wWfCRC+k/2D2FBO+3PmjVxXHOphaIaEym/C6cDXS7hdEjk5Tz4dOxDwzq8LLvNk6Wkb6suRvKRT7a6xMjIKnYVB8gLjNMN5zWnUE0by2du9lmcxJImj+jAiAzMlYwUhzfDawe4cf7/vSO5255I2BYUKuqCaioToCsQsRykJUJLnhGjlaQvc9HVVZUX7cti84etr5xn9GuYP+pVzxglGY6XZeyu6IaK8D7okkMQE4PvUvjNgCWuIkCAQBba42XD1VymIgETjE5D1Qg4FIHN0qTdsqa7JRE/i5cLJ1cr+EeJ4xhdQYfiw00AuvnS7KAYLCnqXLoPzoUwv5YrWRwCZKc8wgxkgDWUyY+SJBbV4QnPYqk0IkxbZuh0um2nWG678FWLbAI64GMd7yG4PnWeQEmVmjTzleyZaRHS6EIeAHR1kHqd/lylrnSTNdWweVJVbwDSdIfnNzByi1cRCY9XqrfRj1j3AzTbmWcu4AOHPOi+DHPzPS8HbaaqQkMkE6ljs2fexbL9eWSG6PYWdFYEDpkQzyxQHTnH0h2dA5rCIAUYEyJj0endLAkcf+Zpw+e1Y5fZ79XuPMhqoxLkPsP/WS3yaZrS28rHE1NFNxjCspZkC9ST63mUgoJUOlL5rWDffobVptkBlzamCVYlW4HuvhFGoEVfN2MeDSIUc2egvTvFI+1GjA32vmSIZ+ZP5iMAfdo7Z0aQ7pdImxo35EWTXXOzQ6kwcDDg+Yd/zE82BjRiklQOs22PPsgiWiw1yooSbJ3Jv+dOlQG4C1PLGa+a/2u6PMFM4+bEgb9iMGLZ/VlPiOYYOCMdkn8zZ0UA1VSlWuTnENYoz5/8bRbYJ0Y1YjNhdssMuWd3uowTiCjQuBnfh1vG4zjWV7RgqdgmrcScobdXBtW3KG1B+MJW5EsullGe49CU6pxjrPVTr+mwG8g+q2LymaKGp6897IIFFVw3ZkbYfNDkdeBcCkFocCoqrYFPLzX5wiZsiiIpzd+NdZRcyueCYo0/m8EP4RLIn8FaBsShwBCyEo7SLAykW6XbEyw77cOkPIDqEHuIwjFqlbpq6CK9zLbeFk0HxU4wlMM7uXtwBer9+NwLCpFAqhEg8pce5BAD6KBdY3oiKCF6BsThQDyhtnJN5ClcHE9uZrMIE3IYzZDHSw/zbXVXnA+59innLoRM/U1w98OTg7UNRpdWXaomDgt2xoilSfWoNncyPJ3+UjT0axMr+F0CemtC69YxLgT9XwUqf1fdzzlYBajGvmbD/SQHoVa+wilge7FjSOOkJ80z6btVBpBcWAQJiv9ikNW5S8VJt4Ez24v8h3SoTcaHp8A9cUrkA5QWGKqVbgJ7RHP21PV6vajKuiFQx3q49nfYQH2IwtD4KfXoYfTpRTgxsdYz8CA+KrhBPqf7AIihcgKNkhr1O41JDPHWY12Ldd2vCPjxRCZbTmWrMUWZ2L0nMPZNLEr0YlpQ+P8qAiGA9qm9TTmy2wHUIOOScI+vtD2KMby+d24RHA55dqGXIY2N1kqfCwVMhCZnbodiFLVb0cqsayB3Lp8815lhl81q9b0cckhOaEtm8XdT0Gg9vCqxBpjB4KD8T+34KTgIvY8pBkNyQcYBHkabApKG6qrHNP7/Qrz5xPjGTx56bcPEB0EafUZYYefSE7v4Le7h/7xIFqx1Cb9FShwsuQEn8mH72pEFuTRxgxOeOkp+oJ6p6WoSh8+CPYvKrzCUdis5T3eZis+6155Y5V6ByA/6vfjkcRONlY0Lie1ZqPjCZKLHhP2f5VCe4aToDmRRtkyHJGb5gJujbRONICN4V4Oep7ySmLnuiTtNi7sRaLCKz5cg+ywtKGbwKh8J++gAMZdj2TP2u/hYU/bEwe39tWxzoVu8fnIvMGSndWMDbUbfmYfrI2RAvSG7K3Rr+fkZLc1yxsOXV9qx3cAnD93jlZO/rf0E2BNbmp98gWuNBkKYGuD6vaMFYtULpD6dw1mczAnD86YR+fvcZhd5+Gyey43lRVYgBFTO9S/mT93uAke6Zh1TMZxUvUCCHuIWN0m/3DzZXGVMJ4MaoIpUdXu9Mv7Pb9eLLJ+HIZt2jlDNBKECVZqdeTPP6hjd5KAkxl17dXiz9bsKiDnja2CWubRAKjyu3lGVNK3jzl49KSM7gK+wpvXdm2aNUnutwvzuPWAU+7Xk/XUQAEnH810DAW8kwUJ2PnlSTk2eUSJji7EExPRIWfMbytFenHlz7iwIomqRBdZgKNYuQPVnSsMLHoiHFZGGynYJR/cSqFGOLFDG8MmJxFSqyGu+nX5MzO8ZZ4d/cb7n4CWhWxYSkkAqiKTSWOrMr0rzWuzKVEBXq/s4JftgJUO6KlaU5n0VilpjWzL3EBRUUcTMmyWbhIlzk3RKi319mddJIPfTScrGqWhGTvkynM2Rtq1qE5+6/oe5pWsx+IgmkADTtDkfsBjS02xLkAOAPoksbLC6i/Zs5ec90/I2TAof3zUIPd+q71IeIx+mIhSgIh/1Kq3DgkGxOMuLqKyzsKOnYQ9m22Zwh7JqytU8XTdKtgnM/jN/m+IkhsonjYhCqctk+GRlXidJxf73Ch46OuQ6sXRh9d4Y1V6njgKpwA+J3tPDy2gdvSKHvrWGGefK0z4qiVkQtVlG3Lu7E8HruvznJufiZ3NqfaT+USa4Zl3zS2crfnaKrEuZVPk/W5s9ay1/SztDl5uuYWt/KmM3TzhMyy6LpgBil6Y4sN9zJ8qyG0gDYQNaSIQVX/hAraQB1Xsdfx5X+zkr1nqsUzpMgcZSYw26BLWyjFc6yBWCR0wsXt26Vm11Mq/DfcxNDBUUws0X7N4+wn+nylJPjvxHfNqcqKbshw3+eVoK80som4Ah5fIY8pVkl2Az94EGdhypI39YB3kxQc2Lrd7SIYf077JiQtm1oyEFeYqDwE1f1HMVJiiz23XZN5xStMUl3902oc9eS87XyXD12DjrQEMHIfg7ftoZ1k7jBAO2J4IA/ZfzX0GZIsuxQz6k0goapFO2/wBipFAxCG3m+VxY6iXjMBAU8CLR81MmAyc7EaFKQGhSFUeEzPzhxjFPNz4+1dCnb4cUiMjXvKB5CbMHsDag6nE/yIvxlLHTcgULwg4F/km/7bmZL0paFxCvUqiKDTHu7RuRMSQPyzoIUq/gR6zJi2ljc1tg4OySeMBBvR/4TrXMaVczTgBm6tUH1o9CblLD4UcaDptoDUVlKw3I7JAbPlJtl5q462vT5pMuGPujfKuVYz3GeXO5+z/qeLcekrGnYrKF1h9m2lvZwUGfoWmyifeqx4UOhJLozxCI7d2ACpezOtHKBlt30EvDPmQuojPT07ZLO5vhnvqHdHALEwzrVN2Dm6d9u8kXma4UG9JMrtEmADCNJk4FEiTSlu95gvRprBak04v7EahYUcCXEwrKC7fa+kF0GGv0N9cJZJQVWem9yarsUIHZb4D3icr4hYSVkpK0LkGydUptQyPcEFkyE7quIqLft9ip/AJbd+hYdJz7rHJugn5KWdBU5FbTJZJGBaFtTIuWKbu9z02BKSbwSvVfbOIzO6S3ogVDUReJ2b/B4IeIqUXK5VkZo1jn3kF4OSVn/33xlPlbT6sBYmOa/Y3+OgHguniCH5S0ZNlZQJ1trrViCgfqrDmqEzTpTVSXepiNwicZyE8KHP6N9UNk6fYWQhryfTW34OJkbeVL9nnDjwxqORIcl9MJ2LVx0UanxJXHpNAZUZX2uSOd7q5RiRuGBm6SiwWFCOa1xCzm/5M/cuVgNnnfDtsuKD/u0e8KOaXH+Ao6FRA/n7qs6G9h09nxChzunSNPh5rKxKT5tzaDc1Mcyhx2gYdLMSD5ybAspAaSxUDqJ0GkUEMBYri6j/YL53ewNW5uOjGwYzu0DCC4QvJZiyTz9VWzmA51XiTJ/JMBcI+HepnEeNkeYmiQ2psh9Cj7mgkwIVj/UjlLWryCvx2YLvQ1U5uGN4xmSBHqM/uctZb5MTMy48TcfW68qR9BGkxFGb6FV1NIxZjDw11yfCbWXYzftUtMJ+N5384NmxktkWE7lTU62Jh0xIxyN8Wrku8FahrSUt2OMI6rkaoizFjVZgAip4UvsYEpLK6YqKZ4wiM5ySJGNi/AHXGsn/u3vA1doqZi8p9eHePLIy2YifOHjGGKLfYLLK5M3J1/Ni/l6sCRaUyU8VBOR+9VgOvp2zzR/zExtKv65VJhr9BydqUEgKJjOPuzJSCAABBBgmsImeRBC+GCzkm1whBlqce8J4WipxBD16uVBn56BJ7yo46pxebjP6WG2eQ52v/M26W3D2HrODnXcxsx1cQG3w+YfieqeHrncDCKQh/YqPKfG+pzvhExJpGiYH9QV1rtN/ZjzvzAAE81MylqheIFGUwANzLJA20yRvTG99nNTT5Clb+O5CQB1QXwLlYzliCWGltsQGMpyWgcqoJAsVFoKqdkCyPZmfOau0xtI18wqZ4tA0jVQNoUA95rxaCMQAVnIdadSIfDlvjhLXGFOvS+RI1vtDbmU8POqswW5qBGvEHM7a+yRfbciUHV2G2YmiGe2Ij2eG4YJ+x1a4pf3P6PGZ3ARvdMRPpXSfpSDGtOeq1ZS+xOOZwS+oX2O597OdyWQtOTzY8F4K45lbPHWyNy6tHHwOWceHf77Uzc08ASW0Zpzk30ZNvp6WNFc6ei2491x3hOsmzS3hi55PQ6GQ2n9QmKQgsphC90cvzBivIB7en4LrNXnAzT4XIeDUOI2B+rLzXFMmJI9wC90khLzgtQ9h2ZlG+NBFSxmXFh/mU+GDF07kIidpRcJOQiyLEWKfZo5Y8h1lfRNFDiSgsvMn/vMsq5r8fIcYfyCh45Qjc5Gf+oSnQr36s/1WH66wlJCe8ajIFDMiYpdDpp0Dz/7mOiyXcmga/w8oZzysnGmuirVO3JnkjZTBZXmzfLzTZ+yYxr0XcNEvP+MgPSRz8SS5iB69+V2WiDA8G7Lp4bpdGrpP74IllrBMbnOGOC5/AeFFMAJSr5qd9HSft0eJT68mQg5c1m1ySz4hhjidafqbXbGw4amBRTvNqodHqx16qukWk5zGberqgCx0CIro4/IcpUuL/lxt66iAPJDvNjST0dQUdECIpFHniQvz5g+dSly1NyuT9xRhXH5VEV0W4bRAV8IOpFMWENWzW5WafQtXIZCFm277B11CZeAY8Sr01zfep4Szi7DmZEPzg50gipe67kYex4NA94lWwChZPqCeepsqNzcaHLcTFeWvvcswCZY3Ms4/xOtohaWFdzmxHLyjn5CA5Gmq1qiW8dk2POKXKuugGeuF2FiZ+Gi1ng7a2g36HF0hcRr3sY/c51hzGV0HAVBIzt47tIb6TPS3VQK5MIgESPvtYM2u3iHRQk4M6t1/mRX25wPJeTsVV3omrmDBxea4whkZaYECh4bA572Vvylhd78Xf2l2IXMfzG/Hhlrx+nlI95Y3mC7vn0G/sDoUO472UkO8H9KGLZwhDZQ+c4Qcy0d7d4Dx+F3ed26adQlVrqzg9RIFpuIvo0WwnQOT7f0q36/kH9qSue7IEbZVS+QGqfvS8V5y4vhEZfT2Ybk+ooNCv57KzUK0bek3bF209ha8vioukVBtOlsuz2G36DxwwbFaPX477kemDD2bZPc6QR5wVurUIykJVNtHm4VlQVo7kf9UfMDRHjnPJDdnVE9jk/8KZb+dp4XUhS7cIuPFz6SOZ+n8mUSPDdSMPa+de3FvRCIIDU9/Sld5J1PLdARctCvpAtPb4ScH4hD9Tg4tIPcdOd3eX/7c3M/52Q9Sc3CiWFrIZdlJtVm+HZTMXVmfSbfBl1L1/gU9B16RrsGRN9r2JcbZfUPZqiDR5KsewovmuBo+oS1sgnAjSJXJAVG4c70f97tMSeW3n9L9seVDXNCmzlaxM58hnd6/Sy8rqmHaFRTilcR/vIL9MkmN6YQtQXRYoJ0mCo1Ng7hYy61CqkDrvCzCyg7hiO4GzFWJ4BoyWIAWBBQmunuItJ4c+iLn4oKVPnHke+1BY9e6UiI1VFLGlyJ41yPKfBcly03F5hwO0N49DHiJ2EUsE6UcAHbB/X4P6ncIAh40JijWVXSWRpoXJoI+Ty4bbq+yuVBuSThaNQtLOF5TkENnJKB0pRI3EVzAGB36yY811TA9HQ/zIa+6TApvFsQzkENiTb+u4ttsG5NC1jZ60eaI+1U2rpLGleW6PTLQX9TTMjAQy9wgumHEpIdymkRT17io1wWb0xt9Y0CRny8orEAPk5zWUeW7peWGApAMdoW4zTzGNl7SyfkvYdWdD3vjzdnWvBVWNx96r/CGq8Ls/Upx5T8PF39f2AbGCkHgEs1zzB8lIny75Lv6u/qXcxkS9IoWdHRT0Bx8m/+1ByOvRqk4sq09Yo+syH6VWwgYJD4AZtVyrlNrg3tBfkm9JMU3w6/T88OLvpu0kL60AgV8k93Oqn8qpmcTteZ9fRxGl1lJwb6GpF2C11M17WFm95/gBva3IcBXtxw0IBcL+fthkiwh20tFk3Nn64xQDKWKuCgM2WLeJ1TrAeOudLVeVy2e7Q3Nx/glznlgg9ea9iyZ1WcWIzZDYvGkbWTgb53DZpCs+yuxwPHK2df7brxWLfYQCFbjTcVuZD+nTWcV9bZF+SgDwWHsnDfwnH75U+KqpyFToyPg/vKA/voGMKipxgV/teKoLOiA8PoRskaTKtV0+AKUrdZ3FmYWJe/6AZjcl/7hx59oOBUzyzFaSfOdtzR58IWL7WDTTedRxOtODK5Z5itnu9gyM+1KFQDLOyDrVfHOXxOjvXts78iFu8sxkvT9m62uVbixFq7RC+C6ccmVGKviNC6/djoMrKpkyLZJiEXsnkWdOhiNNSxw/Y6x1j54A7EIB0Q/kjMgLLiUZFDb3AxgIzovoHt25Mk72f2JfwE4Ni7mpL1RKnEgsd3krS9GwDc9xy1jsqe67oQRglmA6hjBvZMKAx8YO8aNrzAao2oIgSKFswJiGMm7yWnqPcNC355/nf9HAHzD38TV8LgI0Xd/+CvG/S3malL8cK+rIUHj7xwh1JqgH3ioMmJR5bdibFMApRX1kTRKIhskGjOCi91VrDLjwrQAr/2NA07F5Hyb3DiLBKq1RSN0/xE1XvVtQdgA7/nAs125HNtmGy5wSloSnvbotAMGwypynIGPoKEpK7BLiXN2SxiFe1Q+Utt0qfoUVp6P0/iKedArsInSHGSWdmeiCA7/p+TNKbTALD6k1Mpf/wPWBFr2PmtcVpMAXch2KrrCTOGA13Vy6e4+zHKIDyq5Y97mD6f15qwsclXxGdU7+fdRxEXZLO7C+wcqdpGByGgLJHHuc95FcvoCbkSXk1hMOSbh0t9pP/wS3Hmbkx163mabOc77o1PM/1uXKkwowwXh+uGn83hfD//nLZQSepWtFEXgGT6X2etns7HDsjuia6ZY+GDhQ8wEMJl5BH62xP+H3+/sYjtXI2L99CCR8l1NmZv92UcSHwpRU0d45UOMOJ3WUcGBdHs0LLjYT21rNi6TQ3wsAXrIAA187PgxpqbJzC0YY/IyoXZazBsEHYhJQbyG2wVKYA06pKzQ2kKVo7hOt9n3enGpHo+CESq7uZ2lhz9ADAGytmaFqsc5Mb7D+cAOHAZjAsbv20mXSBC+XXKrItKN2bOqnCPqVp9l9I+hP4+mGKdN8pEpoA6/M7G3iEgxYnoZqAltO2gotqd4E835M2NwcAXqZUbSp10+VxnZwRKAuBtW9pof6eu1XUgTnIXcGI4LBY518YYVCByPuyAYfQqCTbfiFSfcowPBelEg8ib16ZbIlk1oXnlkh1n9vpbKq6Od1AdRN8FNByELfiN2MQGBwz1OkXKxXDp1kZti0g42I5o4H0fJnLyUf0+5KTIcnaKfyu/yMv2Dsw81C1x7hGI7sj4akzz7sXtl0XgO13X61M3Rq0Ingw77ZI6D/WJC4iDpH/KpIBHjRNKlvgN/p29i8umcqbC/mH1oJ0p3E/WEF291Gw0/2WvSxrdL5TQy6uTvJp8VsRwyK7pI3kAOUY06eddqvY9SS1sfy8kZSH0MQwIWbvKll5PMbnbIZJVPv1U/B7T/B/bG2T4dE/L854WM1KggLGSP3EXdHwyT4A+o6oALsFS8XQ8rpparc4jiHpB/RBV7OsD0X3jGR5p83FDRkHKf9gcuyT1LYJNZlKezDmC+zIZNtY0ugG2er8wYt9dFTGuwXrzDBfLYnA/E715M23M/jSqzlQFSwRppL7Ui9DcxU7L9d8b3esgsFG/Cv3tONpLEGXoGXTGIFoDuN3wMHpVdTnieXYk6iCKoEriLGcVH11FGZ9/PqX6Ams9WqSgqhWt90vA+Sj73jyMLaEmXCFPvaUiZ5xe2FqAntEviP9ewC9GgLjLAN4goY3CikV4hV2Upw5Xto9RhBVWcHc/0DLkLgRjYGjP2zFkfNLln7qHHRaxdrYzFXEJGneMgvWWAP+qS3+7zBbT6nYkqPoTtaZVGtueS0f0Ng2+NCYxxe92StdIzdCjlYvQES7rwct71OrSbBu5lbWZhXIZNFIohhLXQR58Qyp3eCr0EDK9kRIsNkpTgLw5Z4P22g+YZkRTQGl9oiUtLOxWWWsaFbMVtvZCvNjDR4SKbChqj7s0WiBwc5CktvU6iXrzVgJirMhkqxoj0ubTQtBcR+RVWOMr3TFDmqU/JRVHPZWq8MLtRccrlxLVNltOFs1JvpGyCGPpe4z0dtmkEvlBRR6GTbCdXvH7PIaCZcggLXRQm3gxtqRHYR8jXqaca1PfXVmIWmXoQG564HWIC+wTnOSt+12ysnST2YugQ7VxJEzVlnZycJzknOaDGkxqzyCSoJun19TjGvTIiguSDBLW9mIZ2hbWAdxR0FPCfQff6PY52O17AynNMCOLWVsU5/VBHlxobrZNTwQhzHtQbPquKg9cKo6HAzHPN6BaC/c2JTldSLSZEna0WzwPgwvSKzApqpdL6dWJKhi37fABmS4tErcGm80aWMcWXZxCsyvlBIMtpjj5hv+Mm5gQ/NT6rBVlhEjf9nTIXAVuYCOonJaatgg4Vzi5bwhBTXTd+LxvRln2s8eFyrWnC37LPK9rbUh2c0D6SXmO40+cOj3GOwuYYgzbNhq2QsCBSWqDYveZ+EDE3u5b92f7DcQu4JT3PVjAGWNbgD6vSrw7teL3rbqb5TIOhO1UvTaSRFjXw+qbpvE5FiS9+L/wecQxFD2kvMGZCqDRIuQfBsw4Wf5wsVNb3N6HmbqJspgJqJgO8ldNfCfLEwGMnZeaG47bWmjxVaiWvVo38D65tjckKFv89ckBatoLhTXr+hOq8D84SGUlEyIPaVWHil/HRYt6IJwnko/YBmbePKZ3X5XmoB3NfGmMBM5ReNgQPcra/7N5NcImYbDz+rv4eazHCO2+qQ97cOI1HFGvuPtzNOd0Nk4CsTSCyovquGz+xiGBivQolo1RYfsepmLmhoyr9yDxEssWWd9ohHl7vc7T16PkDSlkYfoYfiWkHtYzsuH0t2tnSMdRBH2EXEjgLmGHOo7XfsnzgjAS+J09nEk/FaersCBdSvsdb3U8jjijo8dF1mXN+yzJAZLcDGK+0JtpvO9pmoRFr+ke5ZKDLo2AB3smp3Bd6anwh9EBbSq70zq5WJF0mmRZKFztZFO9Qba0KMQ5pC7XLnZaqi84fJh5+IQY9NlN6wJShH4LqM1Vz+iiHzRjZ0R6RIm8kd6ooKrC2fgFVIJwrmADbBATBfAF3Akt14aPfcsxLQdpZkvw7oBOk95QCAxo2zpieoP0u9upB4PMEEKqBzVyhvE2tCyT2gH5++/XiFvTxiO+GoEuakkEftEMEGyd1ekVteAEWLc6JSwzgKsY7aDV+lICbdA3A7MwcBbb8D7cqRPQeav/8PUPmravra0ocedQn08FVVMwahqQMyhWvLuhuAm9JkEG7PwwKnYrTxtquffnKp3prIYLwjoo08tcPhTKQQ6/PnEi5n1XbX+5e93s7BOyM4wgCtcpCqKiZZtNDN3PkXsqBm9QtHpwoXGjikxQEncqgG2RU6eYBSpZMpe/rrfRc92RCiXRSru3ALceXFxdjzx6CBW130l6fNcLsZS/nlvqm+6rjEkLMQs+X/cokt9uIN/5HXy5fdkYSK84KL0Kr5orpaJiqGURNy/S6y88Yc/qtABHf35xdlBSMzUp3PrvBLNkcwFt1gq12tRPdXfZ0r+soHokkfuQZOq95udegwfgH8zX7vuyay6umupgcniy0WTZBBdGq2g6VbsOCq2hyXpLDkVtbwr+m3RqjQFec/ee/sKJj5kdTQuC6i92wZnIhZSjTWOzExdYZX2EavOkST8kWweFwCSX8J1cdk5G8mQCJsLDocE67zu2LwBZhDsKBAq8ZlXdlDrodpkLlwk4WcaGUrNKFTT6twdu2BYQh1zYi+Ja7/olDP4k0DwOJs255UbbT5O1FgM5//dC3LRu4TkywaEpDJ5qbWDi1jpI4OPPztZLxFSOhqitMsoQGM6cD08ddAHFUPRAuAcn8q4wb6newnYRdhkpitWFKRfZc3VnC9hmPWZ+XfbiPXqAhuwhIIQtCe4dEyWL+1cEkjs7WC3teLJsZf+AWQfWwV29q7LLzze0XH1/ijMgCYfVwep+R0ClmgYnml8zYxJt69MgZfUKtTHPfuAVYT9A+E0NWj0fGXyUixun1OF6uQ0FOkLOj9xrjkLiJ5PYjK1pTKy5f/1WQUwnKcB1Vbezo++maM1Qy6fgamIzyvo0tpD+xdoa0rEv7mfLHv1nX3GMT3m+27hQeKyExQUct59G8nJSXTIxseL6Yophm+sATSJYZN+xYjp74R7gA1bJ+lHfOcBotpgTymE3OY1MRHjKnjC5qpF83yGZs+S2MjwZFj6qgg/xtktTZwNY0R2uFUegF/2b1vVwoVeYq4udgh/eHcfGP+tTxk6O22bCcXbng4yoSB0wZHpdylMfurwBUBuwX7CSsMBePnWYuWqCLk54JAs1lrgsuOPzI4ZEwfMBDt7cBuEv5KRuF8M1XeUf/73bMHc/Lm+RbFj+dKMh9Vcj0Cn2TgpKNfT0d6k+2qMH1VvF+AWfgw4DEx1TdPRyPMhBvnkQKdPvyjNR1GayifNyWJf78t/gH5gCdya+Ip08UKwDBpt4QJqIC0eRqBqzgbMek1GzBE0aiD3mdhRb47mx+rQAAADQzcDk4ySm4yjKJl6jiTMj3Y8KZD2wgC6YVzZuV46oM8VrIWR+I+gMmfj3k5V7HYzYMtLMgNfWe3TbqN3RqkF3ohG3kljTRwJR8mlbWZ+ENJSu+V1mubs0GtbkOJOeLnM3kAuY/pCWlgboZTKJRmLK2CRjDyxdyV5ZiIlaV9KFvJOmjJDzBpXxhlMX/9KddY60pSZEeHgnvC4nWoX9fM09cuXnemf0+oLZ8/fw9/boOcKN2bqHica24q8g/EtdJe4zqBmg1o5j7Y8iplLhjIfxx3wD4nKri2IbysV9jwmIN6r45JlTNxO1XHe8kmFiaGvorB0upAun0CxqrK5PvQive4juZd0keS5pi8aDp1zY5yXjMECuLtp7v845sLg0njit4Aaf5jFFcwIybSY01o24eODqeJoldwyWA9ir1XzKkue3GZE/AaxbA+drFLwt80RDSaY8ZXOYx0Vyyu7Xm8rhcbBJj08biR4riNJJQv9LKh+e7uUcroGmwA46uN1zvVJQJS5xeTs/M7TK7s8oZ8qjx1E/hLQOhWJhiYQrBf+gbNGyuobOftcg/KMb9Om2UjfGk48GJx8Omxik/fSEl30ddhk1v6aH9+JdJsBSvvs4N4dGLING8aOBZgjVxd4K6feskKH3+SfMvPLFVTPpl8PYkg/aPW4vkw3dW2Q6D2rU7XE2r+6GFHfQvp6FX6Pdwy/LSxp3539Qeyf0KboIJAfjj1SK8D4Ch7h4wOWInIt/Rb+2PghvmNDMAeCWXOYSduGtXpykg1E4opu1exRL0pCupDR7rbH56avWtvHfs5DdbbC5I7waLcW5MInM7b5QcdODWjnI7knrpV/dnL+myq8PKdVOqeJ5QnMoayU/eqpf3ROibBAPoJXPbt3GfAfscOzOWEQBA9MkE4ryvYoLFyVQVj69HDMPyAseJZZE6o4tlAiVZYRkr6BtMGAleF5db4C2Ht4GH4kVwuk/1nxEzBJWp3jY2BMnxYYe/A5u9Og2s7GbIn2hQZQDpJOwYamA59wtH5eUWa/dORNXUhD9vkAEZvIFGFmbtGzZq+gXoaNwHWTuosUSggLm6qI0DtGftXFJwxnlzQt7z6brzYd6Zelg1IT7WFU/FYxRNjV18BpAy/sNL0GD/e3CLY4i+Z9Pj+9BiHWb6b7WLi+hkgaiFACkgJtOsU8x602+T8tzMddAPILgL2J6Lybo4AZfAMmoDw95C+FubhL4eZMSmzKmVqSJ9Ek51vvqSiZgx2G0KV59xny8jYc7lv6DBsLpIdv0Ds265igp3Hc205dKvgsxj3VrVMdkbC7WKFQnHik3Ke0uYWZcq1OIK6fAOm3lxrT+SXSnmxvo55jWed0SZB2ITS+Hmw+ZyhB+SojKvacjE93aLCy2byNFE0zWl4ZlsOpodRDtXSkiI+y4O39pQJIMf+0nHpfURNCmehAUGnLKRUquO3Vltx8vp2/ThEihu9E1OWPUpgaGYzRJohK7MTXlWpdqSKuUo/QJf1qfDNGa+MphO10jYCE79SyQwbdBng60JBHk145vyP5vcdeeZrhQTxnPg+N8S0NE7InbLOsmD6of2r+MslALuBtPsTnzzrXi5ePvy76NPh+m49ZhHWI0AARmUjU3QN2kbTl5cvYAqX4A8ZLlYtcx7ywwviNYPpcR5ppML/PmbPBiK2+wl/XnpckVchCXaU+cOApJHsOF3rSbpv+pXYks5JDAAAE6GWXUmkw2QazlNd1hnkHvPoU5f/VHvRlwHd9wLyApDY1PgXvQxLGoHFQj861PYciFOPulgjBD6vcB8iE90LuJjfsZx9DnZHsXvq2DPstU+8a2CY1wMyZp2NkwLkMhYLj6vvYw0i8e6Lx4Ul8tCqdluZzK5SYQZQzUHV2o/diJVaBTQepBDmSLUuEiqc5MS8DF9WsbkBQtqP3l0EpRpmZpkzryC/hLFR8WZVQKpf3WkQAxkkLVevQZloFFulI190zS5vEMYRugxnC/wkhqm3cbmf/CIXEkYOmUg0VoGBCJpgC3KV25IlqnDwWiey8VRRC7WE6NzqRiTSCne6Q+y//Lh+46NIxd30/VP3IFcSMW1UGXj8KilRhfuYMl8o70KNPqcH5drCruIRHp/EL5KrxGI5MwjkIBUwg3DCI9KWUH3yWsssow3ey56aHGEFEKPqWYLnuY5ppXJyLcHyZI/7tOpI/S66s0gYUMSPubu2G2h5QkgH2sZeL70fBC8au/q6XDT6mEHU/p5ID3WJ8uWWo94B8TxuN9F1+8XMo6Y3eVMHtsAgVI8odjWmlDXOyWqSSHv7ugvU+nfS7EJ5GHJUFob42aqiZrKwQwyEh7sCvFvrNkMEJ5yuXJKIIrzjYZxw98ObzJ2fdGdhhlw2zX0lfTrre6kUHRqw/L6SldXS5mQI5JmnSlDp6KHtj5pOBead/jhBvQLPO9+TrPMXyEMIliAwfkB22W3+VTDmml6ErrsWgAxKYWE4JUwi1BA2UalxpeHE5xKWwhR3Uz3aZwd0ueI5p1pakMd7Hk1rfGiQWPcSV1DoQCIj54WhrusAsAYakiTcCSNq2G5/F1pQ8kc9o91465UxH+Jqi8f3jdhPMUKJ52/5aRXyj0vGi6qF7NIvk+SoZnMsAdT5xo8xybkl/LZs+OF7MNg3dfZFD1p+RvCYQrYz9b35Ykvwv3BKCF4B6pGdhWSZ+9aMOeFlUWEuUPJEUQRw4m6IS9Y8iVus8w/FuKpQRZxze1+4hCG4RBgQF204EIbn6FAF9ZB7oYTFGA9noynEcwnegKoPmCuMpMNBXksQcgcPgCD/nJW7LkV3+62tMyMfoTpry7bYAAAAAA="

def apply_base_appearance() -> None:
    return None

def compute_ui_scale(screen_width: int, screen_height: int) -> float:
    reference_w, reference_h = 1920, 1080
    scale_w = screen_width / reference_w
    scale_h = screen_height / reference_h
    scale = min(scale_w, scale_h)
    return max(0.65, min(scale, 1.35))

def apply_ui_scale(scale: float) -> None:
    global CURRENT_UI_SCALE
    CURRENT_UI_SCALE = scale

def scaled_font(base_size: int, family: str = "Georgia", *style: str) -> QFont:
    f = QFont(family, max(8, round(base_size * CURRENT_UI_SCALE)))
    if "bold" in style: f.setBold(True)
    if "italic" in style: f.setItalic(True)
    return f

def configure_style(root: QMainWindow) -> None:
    root.setStyleSheet(APP_QSS)

PIM_RE = re.compile(r"^\d{1,32}$")

# ============================================================================
# PySide6 GUI — rebuilt from scratch. Crypto / vault algorithms above remain
# the single source of truth for security-sensitive operations.
# ============================================================================

APP_QSS = f"""
* {{
    font-family: "Segoe UI";
    color: {TEMPLE_TEXT_BODY};
}}
QMainWindow, QWidget#root {{
    background: {TEMPLE_BG};
}}
QScrollArea {{
    border: none;
    background: transparent;
}}
QScrollBar:vertical {{
    width: 10px;
    margin: 2px 0 2px 0;
    background: transparent;
}}
QScrollBar::handle:vertical {{
    min-height: 40px;
    border-radius: 5px;
    background: {TEMPLE_GOLD_BRONZE};
}}
QScrollBar::handle:vertical:hover {{
    background: {TEMPLE_GOLD_ANTIQUE};
}}
QLineEdit, QPlainTextEdit, QTextEdit, QListWidget {{
    background: #0a0806;
    border: 1px solid {TEMPLE_GOLD_BRONZE};
    border-radius: 12px;
    padding: 10px 12px;
    selection-background-color: {TEMPLE_LAPIS_BRIGHT};
    selection-color: {TEMPLE_GOLD_PALE};
}}
QLineEdit:focus, QPlainTextEdit:focus, QTextEdit:focus {{
    border: 1px solid {TEMPLE_GOLD_SUN};
}}
QPushButton {{
    color: {TEMPLE_TEXT_BODY};
    background-color: {TEMPLE_CARD};
    border: 1px solid {TEMPLE_GOLD_BRONZE};
    border-radius: 11px;
    padding: 10px 16px;
    min-height: 36px;
}}
QToolButton {{
    color: {TEMPLE_GOLD_SUN};
    background-color: {TEMPLE_CARD};
    border: 1px solid {TEMPLE_GOLD_BRONZE};
    border-radius: 9px;
    padding: 6px 10px;
}}
QToolButton:hover {{
    color: {TEMPLE_GOLD_PALE};
    background-color: {TEMPLE_CARD_HOVER};
    border-color: {TEMPLE_GOLD_ANTIQUE};
}}
QPushButton:hover {{
    color: {TEMPLE_GOLD_PALE};
    background-color: {TEMPLE_CARD_HOVER};
    border-color: {TEMPLE_GOLD_ANTIQUE};
}}
QPushButton:pressed {{
    color: {TEMPLE_GOLD_PALE};
    background-color: {TEMPLE_CARD_ELEVATED};
}}
QPushButton:disabled {{
    color: #6f603f;
    background-color: #13100c;
    border-color: #3b2f1b;
}}
QPushButton#primaryButton {{
    color: {TEMPLE_BG};
    background: {TEMPLE_GOLD_SUN};
    border: 1px solid {TEMPLE_GOLD_PALE};
    font-weight: 700;
}}
QPushButton#primaryButton:hover {{
    background: {TEMPLE_AMBER};
}}
QPushButton#dangerButton {{
    color: #ffb3b3;
    background: {DANGER_DARK};
    border-color: {TEMPLE_GOLD_BRONZE};
}}
QPushButton#dangerButton:hover {{
    background: #6a1c1c;
}}
QPushButton#ghostButton {{
    background: transparent;
    border: 1px solid {TEMPLE_GOLD_BRONZE};
}}
QTabWidget::pane {{
    border: 1px solid {TEMPLE_GOLD_BRONZE};
    border-radius: 18px;
    background: {TEMPLE_CARD};
    top: -1px;
}}
QTabBar::tab {{
    background: {TEMPLE_CARD_ELEVATED};
    color: {TEMPLE_TEXT_BODY};
    padding: 11px 28px;
    margin-right: 4px;
    border-top-left-radius: 11px;
    border-top-right-radius: 11px;
    border: 1px solid transparent;
}}
QTabBar::tab:selected {{
    color: {TEMPLE_BG};
    background: {TEMPLE_GOLD_SUN};
    border-color: {TEMPLE_GOLD_PALE};
}}
QTabBar::tab:hover:!selected {{
    background: {TEMPLE_CARD_HOVER};
}}
QProgressBar {{
    background: #0f0c09;
    border: 1px solid {TEMPLE_GOLD_BRONZE};
    border-radius: 5px;
    min-height: 7px;
    max-height: 7px;
    text-align: center;
}}
QProgressBar::chunk {{
    background: {TEMPLE_GOLD_SUN};
    border-radius: 4px;
}}
QSlider::groove:horizontal {{
    height: 6px;
    background: #17130d;
    border-radius: 3px;
}}
QSlider::handle:horizontal {{
    width: 16px;
    margin: -5px 0;
    border-radius: 8px;
    background: {TEMPLE_GOLD_SUN};
}}
QSlider::sub-page:horizontal {{
    background: {TEMPLE_AMBER};
    border-radius: 3px;
}}
QListWidget {{
    outline: none;
}}
QListWidget::item {{
    padding: 10px;
}}
QListWidget::item:selected {{
    background: {TEMPLE_LAPIS};
    border: 1px solid {TEMPLE_GOLD_BRONZE};
    border-radius: 9px;
}}
"""

def _font(size: int, family: str = "Segoe UI", bold: bool = False, italic: bool = False) -> QFont:
    f = QFont(family, max(8, round(size * CURRENT_UI_SCALE)))
    f.setBold(bold)
    f.setItalic(italic)
    return f

def _rgba(hex_color: str, alpha: int) -> QColor:
    c = QColor(hex_color)
    c.setAlpha(alpha)
    return c

def _add_shadow(widget: QWidget, blur: int = 30, y: int = 10, alpha: int = 110) -> None:
    shadow = QGraphicsDropShadowEffect(widget)
    shadow.setBlurRadius(blur)
    shadow.setOffset(0, y)
    shadow.setColor(_rgba("#000000", alpha))
    widget.setGraphicsEffect(shadow)

class SacredBackdrop(QWidget):
    """
    Single unified ~30 FPS animation driver for the hub atmosphere.
    Emits frameTick(phase) so BastetEmblem / PortalButtons share one clock.
    Pause when leaving HubView to eliminate background CPU cost.
    Optional CUSTOM_BACKGROUND_BASE64 image (scaled once, cached).
    """
    frameTick = Signal(float)

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setAttribute(Qt.WA_TransparentForMouseEvents, True)
        self._phase = 0.0
        self._particles = []
        self._running = False
        self._bg_pixmap: Optional[QPixmap] = None
        self._bg_scaled: Optional[QPixmap] = None
        self._bg_size = (0, 0)
        self._cached_w = 0
        self._cached_h = 0
        self._grid_step = 48
        self._init_particles()
        self._load_custom_background()
        self._timer = QTimer(self)
        self._timer.setTimerType(Qt.CoarseTimer)
        self._timer.timeout.connect(self._tick)
        # Do not auto-start; BastetCipherApp starts when hub is shown

    def _load_custom_background(self) -> None:
        raw = CUSTOM_BACKGROUND_BASE64
        if not raw:
            return
        try:
            if raw.startswith("data:"):
                raw = raw.split(",", 1)[1]
            data = base64.b64decode(raw, validate=False)
            pix = QPixmap()
            if pix.loadFromData(data):
                self._bg_pixmap = pix
        except Exception:
            self._bg_pixmap = None

    def _init_particles(self) -> None:
        import random
        random.seed(42)
        self._particles = []
        for _ in range(32):
            self._particles.append({
                "x": random.random(),
                "y": random.random(),
                "speed": 0.0008 + random.random() * 0.0018,
                "amp": 0.004 + random.random() * 0.012,
                "phase": random.random() * 6.2832,
                "size": 1.2 + random.random() * 2.8,
                "alpha": 18 + int(random.random() * 55),
                "life": random.random(),
            })

    def start_animation(self) -> None:
        if not self._running:
            self._running = True
            self._timer.start(33)

    def stop_animation(self) -> None:
        if self._running:
            self._running = False
            self._timer.stop()

    def _tick(self) -> None:
        import math
        import random
        self._phase += 0.018
        if self._phase > 6.2832:
            self._phase -= 6.2832
        for p in self._particles:
            p["y"] -= p["speed"]
            p["x"] += 0.00035 * math.sin(self._phase * 1.7 + p["phase"])
            p["life"] += 0.004
            if p["y"] < -0.02 or p["life"] > 1.0:
                p["y"] = 1.02
                p["x"] = random.random()
                p["life"] = 0.0
                p["phase"] = random.random() * 6.2832
            if p["x"] < -0.05:
                p["x"] = 1.05
            elif p["x"] > 1.05:
                p["x"] = -0.05
        self.frameTick.emit(self._phase)
        self.update()

    def resizeEvent(self, event):
        super().resizeEvent(event)
        self._bg_scaled = None  # force re-scale on next paint

    def paintEvent(self, event):
        import math
        painter = QPainter()
        if not painter.begin(self):
            return
        try:
            w, h = self.width(), self.height()
            if w <= 0 or h <= 0:
                return
            painter.setRenderHint(QPainter.Antialiasing, True)
            rect = QRectF(0, 0, w, h)

            # Custom Base64 background (cached scale)
            if self._bg_pixmap is not None and not self._bg_pixmap.isNull():
                if self._bg_scaled is None or self._bg_size != (w, h):
                    self._bg_scaled = self._bg_pixmap.scaled(
                        w, h, Qt.KeepAspectRatioByExpanding, Qt.SmoothTransformation
                    )
                    self._bg_size = (w, h)
                scaled = self._bg_scaled
                ox = (scaled.width() - w) // 2
                oy = (scaled.height() - h) // 2
                painter.drawPixmap(0, 0, scaled, ox, oy, w, h)
                # Dark veil so UI stays readable
                painter.fillRect(rect, _rgba("#060504", 145))
            else:
                # Procedural deep obsidian base
                grad = QLinearGradient(0, 0, w, h)
                grad.setColorAt(0.0, QColor("#040302"))
                grad.setColorAt(0.40, QColor("#080605"))
                grad.setColorAt(1.0, QColor("#030201"))
                painter.fillRect(rect, grad)

            # Breathing radial aura
            breath = 0.5 + 0.5 * math.sin(self._phase * 0.55)
            center = QPointF(w * 0.5, h * 0.5)
            radius = max(w, h) * (0.48 + 0.07 * breath)
            radial = QRadialGradient(center, radius)
            radial.setColorAt(0.0, _rgba(TEMPLE_LAPIS_BRIGHT, int(55 + 40 * breath)))
            radial.setColorAt(0.28, _rgba(TEMPLE_LAPIS, int(32 + 22 * breath)))
            radial.setColorAt(0.55, _rgba("#0a1018", int(18 + 10 * breath)))
            radial.setColorAt(1.0, _rgba("#000000", 0))
            painter.fillRect(rect, radial)

            amber_breath = 0.5 + 0.5 * math.sin(self._phase * 0.42 + 1.2)
            amber = QRadialGradient(center, radius * 0.72)
            amber.setColorAt(0.0, _rgba(TEMPLE_AMBER, int(12 + 18 * amber_breath)))
            amber.setColorAt(0.45, _rgba(TEMPLE_GOLD_BRONZE, int(6 + 8 * amber_breath)))
            amber.setColorAt(1.0, _rgba("#000000", 0))
            painter.fillRect(rect, amber)

            # Geometric grid
            painter.setPen(QPen(_rgba(TEMPLE_GOLD_BRONZE, 14), 1))
            step = max(48, int(78 * CURRENT_UI_SCALE))
            for x in range(0, w + step, step):
                painter.drawLine(x, 0, x, h)
            for y in range(0, h + step, step):
                painter.drawLine(0, y, w, y)

            # Constellation points
            painter.setPen(Qt.NoPen)
            for i in range(18):
                cx = (0.07 + 0.86 * ((i * 0.37) % 1.0)) * w
                cy = (0.05 + 0.90 * ((i * 0.61) % 1.0)) * h
                a = 10 + int(12 * (0.5 + 0.5 * math.sin(self._phase + i)))
                painter.setBrush(_rgba(TEMPLE_GOLD_PALE, a))
                painter.drawEllipse(QPointF(cx, cy), 1.1, 1.1)

            # Hieroglyphs
            painter.setFont(_font(26, "Segoe UI Symbol"))
            glyphs = ["𓂀", "𓋹", "𓃠", "𓊹", "𓆣", "𓇯", "𓁟", "𓆙"]
            positions = (
                (0.07, 0.18), (0.93, 0.15), (0.12, 0.82),
                (0.88, 0.85), (0.48, 0.08), (0.52, 0.93),
                (0.22, 0.48), (0.78, 0.52),
            )
            for idx, (rx, ry) in enumerate(positions):
                alpha = 12 + int(10 * (0.5 + 0.5 * math.sin(self._phase * 0.7 + idx)))
                painter.setPen(_rgba(TEMPLE_GOLD_BRONZE, alpha))
                painter.drawText(int(w * rx), int(h * ry), glyphs[idx % len(glyphs)])

            # Particles — simple solid brushes only
            painter.setPen(Qt.NoPen)
            for p in self._particles:
                fade = 1.0
                if p["life"] < 0.15:
                    fade = p["life"] / 0.15
                elif p["life"] > 0.75:
                    fade = max(0.0, (1.0 - p["life"]) / 0.25)
                a = int(p["alpha"] * fade)
                if a < 2:
                    continue
                px = p["x"] * w + p["amp"] * w * math.sin(self._phase * 2.1 + p["phase"])
                py = p["y"] * h
                s = p["size"]
                painter.setBrush(_rgba(TEMPLE_GOLD_SUN, a))
                painter.drawEllipse(QPointF(px, py), s, s)
                painter.setBrush(_rgba(TEMPLE_GOLD_PALE, max(2, a // 3)))
                painter.drawEllipse(QPointF(px, py), s * 0.45, s * 0.45)
        finally:
            if painter.isActive():
                painter.end()


class GlowFrame(QFrame):
    """Ancient Egyptian cartouche / basalt-gold tablet frame — purely static (no timers)."""
    def __init__(self, parent=None, accent=TEMPLE_GOLD_BRONZE, radius=18, elevated=True):
        super().__init__(parent)
        self.setObjectName("card")
        self._accent = accent
        self._radius = radius
        self._elevated = elevated
        self.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Preferred)
        if elevated:
            _add_shadow(self, 34, 10, 120)

    def paintEvent(self, event):
        painter = QPainter()
        if not painter.begin(self):
            return
        try:
            painter.setRenderHint(QPainter.Antialiasing, True)
            r = QRectF(self.rect()).adjusted(1.5, 1.5, -1.5, -1.5)
            if r.width() <= 0 or r.height() <= 0:
                return
            # Solid dark basalt fill
            grad = QLinearGradient(r.topLeft(), r.bottomLeft())
            grad.setColorAt(0.0, QColor("#1c1610"))
            grad.setColorAt(0.5, QColor("#12100c"))
            grad.setColorAt(1.0, QColor("#0e0b08"))
            path = QPainterPath()
            path.addRoundedRect(r, self._radius, self._radius)
            painter.fillPath(path, grad)

            # Subtle vignette
            vignette = QRadialGradient(r.center(), max(r.width(), r.height()) * 0.72)
            vignette.setColorAt(0.0, _rgba("#000000", 0))
            vignette.setColorAt(0.7, _rgba("#000000", 18))
            vignette.setColorAt(1.0, _rgba("#000000", 55))
            painter.fillPath(path, vignette)

            # Dual-stroke border: outer burnished gold, inner pale gold
            painter.setPen(QPen(_rgba(self._accent, 155), 1.6))
            painter.drawPath(path)

            inner = r.adjusted(4.5, 4.5, -4.5, -4.5)
            inner_path = QPainterPath()
            inner_path.addRoundedRect(inner, max(8, self._radius - 5), max(8, self._radius - 5))
            painter.setPen(QPen(_rgba(TEMPLE_GOLD_PALE, 28), 1))
            painter.drawPath(inner_path)

            # Fine corner bevel marks (cartouche style)
            painter.setPen(QPen(_rgba(TEMPLE_GOLD_ANTIQUE, 55), 1))
            bezel = 9
            for cx, cy, dx, dy in (
                (r.left() + bezel, r.top() + bezel, 1, 1),
                (r.right() - bezel, r.top() + bezel, -1, 1),
                (r.left() + bezel, r.bottom() - bezel, 1, -1),
                (r.right() - bezel, r.bottom() - bezel, -1, -1),
            ):
                painter.drawLine(QPointF(cx, cy), QPointF(cx + dx * 7, cy))
                painter.drawLine(QPointF(cx, cy), QPointF(cx, cy + dy * 7))
        finally:
            if painter.isActive():
                painter.end()
class SectionHeader(QWidget):
    def __init__(self, title: str, subtitle: str, icon: str, parent=None):
        super().__init__(parent)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 12, 0, 8)
        layout.setSpacing(5)
        title_label = QLabel(f"{icon}  {title.upper()}  {icon}")
        title_label.setAlignment(Qt.AlignCenter)
        title_label.setFont(_font(30, "Georgia", True))
        title_label.setStyleSheet(f"color:{TEMPLE_GOLD_SUN};")
        subtitle_label = QLabel(subtitle)
        subtitle_label.setAlignment(Qt.AlignCenter)
        subtitle_label.setFont(_font(13, "Georgia", False, True))
        subtitle_label.setStyleSheet(f"color:{TEMPLE_GOLD_ANTIQUE};")
        layout.addWidget(title_label)
        layout.addWidget(subtitle_label)
class PortalButton(QPushButton):
    """Majestic circular portal with living hover / breathing arcane halo."""
    def __init__(self, icon: str, title: str, subtitle: str, parent=None):
        super().__init__(parent)
        self.setCursor(Qt.PointingHandCursor)
        self.setText("")
        self.icon_text = icon
        self.title_text = title
        self.subtitle_text = subtitle
        self.hovered = False
        self.pressed_state = False
        self._hover_alpha = 0.0
        self._phase = 0.0
        self.setAttribute(Qt.WA_Hover, True)
        self.setAttribute(Qt.WA_OpaquePaintEvent, True)
        self.setFocusPolicy(Qt.NoFocus)
        self.setStyleSheet("QPushButton { background: transparent; border: none; padding: 0; }")
        self.setSizePolicy(QSizePolicy.Fixed, QSizePolicy.Fixed)
        self.setFixedSize(340, 340)
        _add_shadow(self, 44, 16, 190)

    def sizeHint(self):
        return QSize(340, 340)

    def minimumSizeHint(self):
        return QSize(300, 300)

    def on_frame(self, phase: float) -> None:
        """Driven by SacredBackdrop.frameTick — no private timer."""
        self._phase = phase
        target = 1.0 if self.hovered else 0.0
        prev = self._hover_alpha
        self._hover_alpha += (target - self._hover_alpha) * 0.18
        if abs(self._hover_alpha - target) > 0.008 or self.hovered or abs(self._hover_alpha - prev) > 0.004:
            self.update()

    def enterEvent(self, event):
        self.hovered = True
        self.update()
        super().enterEvent(event)

    def leaveEvent(self, event):
        self.hovered = False
        self.pressed_state = False
        self.update()
        super().leaveEvent(event)

    def mousePressEvent(self, event):
        if event.button() == Qt.LeftButton:
            self.pressed_state = True
            self.update()
        super().mousePressEvent(event)

    def mouseReleaseEvent(self, event):
        self.pressed_state = False
        self.update()
        super().mouseReleaseEvent(event)

    def paintEvent(self, event):
        import math
        painter = QPainter()
        if not painter.begin(self):
            return
        try:
            painter.setRenderHint(QPainter.Antialiasing, True)
            painter.setRenderHint(QPainter.TextAntialiasing, True)
            side = min(self.width(), self.height()) - 8
            r = QRectF((self.width() - side) / 2, (self.height() - side) / 2, side, side)
            ha = self._hover_alpha

            # Deep obsidian / lapis pool base
            bg = QColor(TEMPLE_LAPIS)
            if self.pressed_state:
                bg = QColor("#1a3a5c")
            elif ha > 0.01:
                bg = QColor(
                    int(8 + (15 - 8) * ha),
                    int(20 + (42 - 20) * ha),
                    int(36 + (74 - 36) * ha),
                )
            path = QPainterPath()
            path.addEllipse(r)
            painter.fillPath(path, bg)

            # Liquid-gold inner reflection gradient
            aura = QRadialGradient(r.center().x(), r.top() + r.height() * 0.28, r.width() * 0.55)
            aura.setColorAt(0.0, _rgba(TEMPLE_AMBER if ha > 0.3 else TEMPLE_GOLD_BRONZE, int(90 + 70 * ha)))
            aura.setColorAt(0.35, _rgba(TEMPLE_GOLD_BRONZE, int(28 + 40 * ha)))
            aura.setColorAt(0.7, _rgba(TEMPLE_LAPIS, int(20 + 15 * ha)))
            aura.setColorAt(1.0, _rgba("#000000", 0))
            painter.fillPath(path, aura)

            # Outer golden ring
            painter.setBrush(Qt.NoBrush)
            painter.setPen(QPen(_rgba(TEMPLE_GOLD_SUN if ha > 0.4 else TEMPLE_GOLD_BRONZE, int(160 + 70 * ha)), 1.9))
            painter.drawEllipse(r)

            # Concentric shimmering ring on hover
            if ha > 0.05:
                pulse = 0.5 + 0.5 * math.sin(self._phase * 2.2)
                ring_r = r.adjusted(-4 - 3 * pulse * ha, -4 - 3 * pulse * ha, 4 + 3 * pulse * ha, 4 + 3 * pulse * ha)
                painter.setPen(QPen(_rgba(TEMPLE_GOLD_PALE, int(35 + 55 * ha * pulse)), 1.2))
                painter.drawEllipse(ring_r)

            # Inner fine ring
            inner = r.adjusted(7, 7, -7, -7)
            painter.setPen(QPen(_rgba(TEMPLE_GOLD_PALE, int(28 + 55 * ha)), 1))
            painter.drawEllipse(inner)

            # Arcane runic halo segments on strong hover
            if ha > 0.25:
                painter.setPen(QPen(_rgba(TEMPLE_GOLD_SUN, int(40 + 50 * ha)), 1.4))
                cx, cy = r.center().x(), r.center().y()
                rad = r.width() * 0.52
                for i in range(8):
                    a0 = self._phase * 0.6 + i * (math.pi / 4)
                    a1 = a0 + 0.35
                    painter.drawArc(
                        QRectF(cx - rad, cy - rad, rad * 2, rad * 2),
                        int(a0 * 180 / math.pi * 16),
                        int((a1 - a0) * 180 / math.pi * 16),
                    )

            # Glyph
            glyph_rect = QRectF(r.left(), r.top() + 28, r.width(), 78)
            painter.setPen(QColor(TEMPLE_GOLD_PALE if ha > 0.4 else TEMPLE_GOLD_SUN))
            painter.setFont(_font(54, "Segoe UI Symbol"))
            painter.drawText(glyph_rect, Qt.AlignHCenter | Qt.AlignVCenter, self.icon_text)

            # Title
            title_rect = QRectF(r.left() + 22, r.top() + 115, r.width() - 44, 36)
            painter.setPen(QColor(TEMPLE_GOLD_PALE if ha > 0.4 else TEMPLE_GOLD_SUN))
            painter.setFont(_font(19, "Georgia", True))
            painter.drawText(title_rect, Qt.AlignCenter, self.title_text)

            # Subtitle
            subtitle_rect = QRectF(r.left() + 42, r.top() + 158, r.width() - 84, 78)
            painter.setPen(QColor(TEMPLE_TEXT_BODY))
            painter.setFont(_font(12, "Segoe UI"))
            painter.drawText(subtitle_rect, Qt.AlignCenter | Qt.TextWordWrap, self.subtitle_text)

            # Base line + ankh marks
            painter.setPen(QPen(_rgba(TEMPLE_GOLD_ANTIQUE, int(100 + 40 * ha)), 1))
            cx = r.center().x()
            painter.drawLine(int(cx - 46), int(r.bottom() - 36), int(cx + 46), int(r.bottom() - 36))
            painter.setPen(QColor(TEMPLE_GOLD_ANTIQUE))
            painter.setFont(_font(12, "Segoe UI Symbol"))
            painter.drawText(QRectF(r.left(), r.bottom() - 56, r.width(), 24), Qt.AlignCenter, "☥   ⚷   ☥")
        finally:
            if painter.isActive():
                painter.end()
class SacredSpinner(QLabel):
    _frames = ["◐", "◓", "◑", "◒"]
    def __init__(self, parent=None):
        super().__init__(parent)
        self._index = 0
        self._timer = QTimer(self)
        self._timer.timeout.connect(self._tick)
        self.setAlignment(Qt.AlignCenter)
        self.setFont(_font(20, "Segoe UI Symbol", True))
        self.setStyleSheet(f"color:{TEMPLE_GOLD_SUN};")
        self.hide()
    def start(self):
        self._index = 0
        self.show()
        self._timer.start(100)
    def stop(self):
        self._timer.stop()
        self.hide()
    def _tick(self):
        self.setText(self._frames[self._index])
        self._index = (self._index + 1) % len(self._frames)

class MediaSlider(QSlider):
    """QSlider that jumps to the clicked position and supports isSliderDown checks for seek bars."""
    def mousePressEvent(self, event):
        if event.button() == Qt.LeftButton and self.orientation() == Qt.Horizontal:
            # Map click x to value range so a single click seeks immediately
            x = event.position().x() if hasattr(event, "position") else event.x()
            ratio = max(0.0, min(1.0, float(x) / max(1, self.width())))
            value = self.minimum() + int(ratio * (self.maximum() - self.minimum()))
            self.setValue(value)
            # Emit pressed so downstream logic treats it as interaction start
            self.sliderPressed.emit()
        super().mousePressEvent(event)

class TaskThread(QThread):
    progress = Signal(int, str)
    succeeded = Signal(object)
    failed = Signal(str)

    def __init__(self, fn, parent=None):
        super().__init__(parent)
        self._fn = fn

    def run(self):
        try:
            result = self._fn(self.progress.emit)
            self.succeeded.emit(result)
        except Exception as exc:
            self.failed.emit(str(exc))

class VideoDecodeThread(QThread):
    frameReady = Signal(float, int, int, bytes)
    finishedDecoding = Signal()
    failed = Signal(str)

    def __init__(self, data: bytes, info: VideoInfo, start_seconds: float, decode_size: tuple[int, int], parent=None):
        super().__init__(parent)
        self.data = data
        self.info = info
        self.start_seconds = start_seconds
        self.decode_size = decode_size
        self._process_holder = []

    def request_stop(self):
        self.requestInterruption()
        try:
            if self._process_holder:
                self._process_holder[0].kill()
        except Exception:
            pass

    def run(self):
        try:
            interval = 1.0 / self.info.fps if self.info.fps > 0 else 0.04
            t = self.start_seconds
            wall = time.monotonic()
            for raw_rgb in stream_video_frames_in_memory(
                self.data, self.info, start_seconds=self.start_seconds,
                process_holder=self._process_holder, decode_size=self.decode_size
            ):
                if self.isInterruptionRequested():
                    return
                target = wall + (t - self.start_seconds)
                sleep_for = target - time.monotonic()
                if sleep_for > 0:
                    time.sleep(min(sleep_for, interval * 2))
                self.frameReady.emit(t, self.decode_size[0], self.decode_size[1], raw_rgb)
                t += interval
            self.finishedDecoding.emit()
        except Exception as exc:
            self.failed.emit(str(exc))

def _pixmap_from_pil(img: Image.Image) -> QPixmap:
    if img.mode not in ("RGB", "RGBA"):
        img = img.convert("RGBA")
    data = img.tobytes("raw", img.mode)
    fmt = QImage.Format_RGBA8888 if img.mode == "RGBA" else QImage.Format_RGB888
    qimg = QImage(data, img.width, img.height, img.width * (4 if img.mode == "RGBA" else 3), fmt)
    return QPixmap.fromImage(qimg.copy())

def _pixmap_from_png_bytes(data: bytes) -> QPixmap:
    img = QImage.fromData(data, "PNG")
    return QPixmap.fromImage(img)

class FadeStack(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.stack = QStackedWidget(self)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0,0,0,0)
        layout.addWidget(self.stack)
        self._anim = None

    def setWidget(self, widget: QWidget):
        self.stack.addWidget(widget)

    def showIndex(self, index: int):
        if index < 0 or index >= self.stack.count():
            return
        if self.stack.currentIndex() == index:
            return
        self._anim = None
        self.stack.setCurrentIndex(index)
        current = self.stack.currentWidget()
        if current is not None:
            current.raise_()
            current.update()

class BastetEmblem(QWidget):
    """Monumental living emblem — driven by SacredBackdrop.frameTick (no private timer)."""
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setMinimumSize(220, 220)
        self.setMaximumSize(260, 260)
        self.setSizePolicy(QSizePolicy.Fixed, QSizePolicy.Fixed)
        self._phase = 0.0

    def on_frame(self, phase: float) -> None:
        self._phase = phase
        self.update()

    def paintEvent(self, event):
        import math
        painter = QPainter()
        if not painter.begin(self):
            return
        try:
            painter.setRenderHint(QPainter.Antialiasing, True)
            painter.setRenderHint(QPainter.TextAntialiasing, True)
            c = QPoint(self.width() // 2, self.height() // 2)
            size = min(self.width(), self.height())
            # Strict clipping bound: radius * 1.9 <= 0.48 * size
            radius = size * 0.248
            breath = 0.5 + 0.5 * math.sin(self._phase * 0.7)
            halo_r = radius * (1.55 + 0.22 * breath)

            # Breathing halo (fades fully inside widget)
            halo = QRadialGradient(c.x(), c.y(), halo_r)
            halo.setColorAt(0.0, _rgba(TEMPLE_GOLD_SUN, int(70 + 45 * breath)))
            halo.setColorAt(0.35, _rgba(TEMPLE_AMBER, int(22 + 18 * breath)))
            halo.setColorAt(0.7, _rgba(TEMPLE_GOLD_BRONZE, int(8 + 6 * breath)))
            halo.setColorAt(1.0, _rgba(TEMPLE_AMBER, 0))
            painter.setPen(Qt.NoPen)
            painter.setBrush(halo)
            painter.drawEllipse(QPointF(c), halo_r, halo_r)

            # Slowly rotating secondary sunburst rays
            painter.setPen(QPen(_rgba(TEMPLE_GOLD_BRONZE, int(110 + 40 * breath)), 1))
            rot = self._phase * 0.35
            for i in range(24):
                a = math.radians(i * 15) + rot
                rin = radius * 1.12
                rout = radius * (1.42 if i % 2 == 0 else 1.28)
                x1 = c.x() + math.cos(a) * rin
                y1 = c.y() + math.sin(a) * rin
                x2 = c.x() + math.cos(a) * rout
                y2 = c.y() + math.sin(a) * rout
                painter.drawLine(QPointF(x1, y1), QPointF(x2, y2))

            # Core disc
            painter.setBrush(QColor(TEMPLE_CARD_ELEVATED))
            painter.setPen(QPen(QColor(TEMPLE_GOLD_SUN), 2.1))
            painter.drawEllipse(QPointF(c), radius, radius)
            painter.setBrush(Qt.NoBrush)
            painter.setPen(QPen(_rgba(TEMPLE_GOLD_PALE, 160), 1))
            painter.drawEllipse(QPointF(c), radius * 0.86, radius * 0.86)
            painter.setPen(QPen(_rgba(TEMPLE_GOLD_BRONZE, 140), 1))
            painter.drawEllipse(QPointF(c), radius * 0.72, radius * 0.72)

            # Central glyph
            painter.setPen(QColor(TEMPLE_GOLD_PALE))
            glyph_size = max(24, int(radius * 0.82))
            painter.setFont(_font(glyph_size, "Segoe UI Symbol"))
            painter.drawText(QRectF(0, c.y() - radius * 0.60, self.width(), radius * 0.95),
                             Qt.AlignCenter, "⚕")
            painter.setPen(QColor(TEMPLE_GOLD_ANTIQUE))
            text_size = max(9, int(radius * 0.18))
            painter.setFont(_font(text_size, "Georgia", True))
            painter.drawText(QRectF(0, c.y() + radius * 0.42, self.width(), 25),
                             Qt.AlignCenter, "SACRED CHAMBER")
        finally:
            if painter.isActive():
                painter.end()
class HubView(QWidget):
    openView = Signal(str)
    def __init__(self, parent=None):
        super().__init__(parent)
        root = QVBoxLayout(self)
        root.setContentsMargins(50, 24, 50, 24)
        root.setSpacing(10)

        logo_wrap = QVBoxLayout()
        logo_wrap.setSpacing(3)
        self.logo = BastetEmblem()
        logo_wrap.addWidget(self.logo, 0, Qt.AlignHCenter)
        title = QLabel("BASTETCIPHER")
        title.setAlignment(Qt.AlignCenter)
        title.setFont(_font(40, "Georgia", True))
        title.setStyleSheet(f"color:{TEMPLE_GOLD_SUN}; letter-spacing:2px;")
        logo_wrap.addWidget(title)
        subtitle = QLabel("SACRED CHAMBER  ·  TEMPLE PORTAL")
        subtitle.setAlignment(Qt.AlignCenter)
        subtitle.setFont(_font(13, "Georgia", True))
        subtitle.setStyleSheet(f"color:{TEMPLE_GOLD_ANTIQUE};")
        logo_wrap.addWidget(subtitle)
        root.addLayout(logo_wrap)

        divider = QHBoxLayout()
        divider.setContentsMargins(70, 4, 70, 0)
        line1 = QFrame(); line1.setFixedHeight(1); line1.setStyleSheet(f"background:{TEMPLE_GOLD_BRONZE};")
        line2 = QFrame(); line2.setFixedHeight(1); line2.setStyleSheet(f"background:{TEMPLE_GOLD_BRONZE};")
        glyphs = QLabel("✧   ✦   ✧   ✦   ✧")
        glyphs.setAlignment(Qt.AlignCenter)
        glyphs.setStyleSheet(f"color:{TEMPLE_GOLD_ANTIQUE};")
        divider.addWidget(line1, 1); divider.addWidget(glyphs); divider.addWidget(line2, 1)
        root.addLayout(divider)

        prompt = QLabel("Choose thy path through the temple")
        prompt.setAlignment(Qt.AlignCenter)
        prompt.setFont(_font(14, "Georgia", False, True))
        prompt.setStyleSheet(f"color:{TEMPLE_TEXT_MUTED};")
        root.addWidget(prompt)

        portal_row = QHBoxLayout()
        portal_row.setContentsMargins(14, 8, 14, 8)
        portal_row.setSpacing(128)
        portal_row.setAlignment(Qt.AlignCenter)

        self.gen_btn = PortalButton("۞", "CIPHER GENERATOR",
                           "Forge a deterministic high-entropy secret from phrase + PIM.")
        self.vault_btn = PortalButton("▦", "SACRED VAULT",
                             "Encrypt, unlock, preview, export and purge protected .bca archives.")
        self.gen_btn.clicked.connect(lambda: self.openView.emit("generator"))
        self.vault_btn.clicked.connect(lambda: self.openView.emit("vault"))
        gen = self.gen_btn
        vault = self.vault_btn

        center_card = GlowFrame(radius=34)
        center_card.setFixedSize(170, 190)
        center_l = QVBoxLayout(center_card)
        center_l.setContentsMargins(14, 12, 14, 12)
        center_l.setSpacing(1)
        center_icon = QLabel("🛡")
        center_icon.setAlignment(Qt.AlignCenter)
        center_font = QFont()
        center_font.setFamilies([
            "Segoe UI Emoji", "Apple Color Emoji", "Noto Color Emoji",
            "Segoe UI Symbol", "DejaVu Sans", "Symbola"
        ])
        center_font.setPixelSize(max(28, round(44 * CURRENT_UI_SCALE)))
        center_icon.setFont(center_font)
        center_icon.setStyleSheet(f"color:{TEMPLE_GOLD_SUN};")
        center_l.addWidget(center_icon)
        center_runes = QLabel("✧  ·  ✦  ·  ✧")
        center_runes.setAlignment(Qt.AlignCenter)
        center_runes.setFont(_font(12, "Segoe UI"))
        center_runes.setStyleSheet(f"color:{TEMPLE_GOLD_ANTIQUE};")
        center_l.addWidget(center_runes)
        center_caption = QLabel("SECURE\nBY DESIGN")
        center_caption.setAlignment(Qt.AlignCenter)
        center_caption.setFont(_font(13, "Georgia", True))
        center_caption.setStyleSheet(f"color:{TEMPLE_GOLD_PALE};")
        center_l.addWidget(center_caption)
        center_sub = QLabel("RAM ISOLATION")
        center_sub.setAlignment(Qt.AlignCenter)
        center_sub.setFont(_font(9, "Consolas", True))
        center_sub.setStyleSheet(f"color:{TEMPLE_EMERALD};")
        center_l.addWidget(center_sub)

        # Colonnina per spingere la card centrale verso il basso
        center_col = QVBoxLayout()
        center_col.addSpacing(65)          # Regola questo valore se la vuoi ancora più in basso o più in alto
        center_col.addWidget(center_card)
        center_col.addStretch(1)

        portal_row.addWidget(gen, 0, Qt.AlignCenter)
        portal_row.addLayout(center_col)  # Inserita la colonnina al posto del widget diretto
        portal_row.addWidget(vault, 0, Qt.AlignCenter)
        root.addLayout(portal_row, 1)

        footer = QHBoxLayout()
        footer.setContentsMargins(0, 2, 0, 0)
        lock_status = QLabel(("⛨  ANTI-SWAP ACTIVE" if memory_lock_available() else "⚠  ANTI-SWAP NOT GUARANTEED"))
        lock_status.setAlignment(Qt.AlignCenter)
        lock_status.setFont(_font(11, "Consolas", True))
        lock_status.setStyleSheet(
            f"color:{TEMPLE_EMERALD if memory_lock_available() else TEMPLE_AMBER};"
            f"background:{TEMPLE_CARD_ELEVATED}; border:1px solid {TEMPLE_GOLD_BRONZE};"
            f"border-radius:14px; padding:8px 18px;"
        )
        footer.addStretch(1); footer.addWidget(lock_status); footer.addStretch(1)
        root.addLayout(footer)

class GeneratorView(QWidget):
    def __init__(self, app, parent=None):
        super().__init__(parent)
        self.app = app
        self._last_cipher = ""
        self._thread = None
        self._build()

    def _build(self):
        outer = QVBoxLayout(self)
        outer.setContentsMargins(60, 8, 60, 26)
        outer.setSpacing(12)
        outer.addWidget(SectionHeader(
            "Cipher Generator",
            "Turn a secret phrase into a high-entropy password",
            "🔒"
        ))

        card = GlowFrame(radius=22)
        grid = QGridLayout(card)
        grid.setContentsMargins(28, 26, 28, 24)
        grid.setHorizontalSpacing(18)
        grid.setVerticalSpacing(10)

        sacred = QLabel("𓂀  SACRED INPUTS")
        sacred.setFont(_font(13, "Georgia", True))
        sacred.setStyleSheet(f"color:{TEMPLE_GOLD_ANTIQUE};")
        grid.addWidget(sacred, 0, 0, 1, 2)
        line = QFrame()
        line.setFixedHeight(1)
        line.setStyleSheet(f"background:{TEMPLE_GOLD_BRONZE};")
        grid.addWidget(line, 1, 0, 1, 2)

        grid.addWidget(self._label("Secret Phrase / Word"), 2, 0, 1, 2)
        phrase_wrap = QWidget()
        phrase_layout = QHBoxLayout(phrase_wrap)
        phrase_layout.setContentsMargins(0,0,0,0)
        self.phrase_entry = QLineEdit()
        self.phrase_entry.setPlaceholderText("Your secret phrase...")
        self.phrase_entry.setEchoMode(QLineEdit.Password)
        self.phrase_entry.setFont(_font(14, "Consolas"))
        self.phrase_entry.returnPressed.connect(self._on_generate)
        self.toggle_btn = QToolButton()
        self.toggle_btn.setText("𓁹")
        self.toggle_btn.setCursor(Qt.PointingHandCursor)
        self.toggle_btn.clicked.connect(self._toggle_phrase_visibility)
        phrase_layout.addWidget(self.phrase_entry, 1)
        phrase_layout.addWidget(self.toggle_btn)
        grid.addWidget(phrase_wrap, 3, 0, 1, 2)

        grid.addWidget(self._label("PIM (Personal Iteration Modifier — digits only)"), 4, 0)
        self.pim_entry = QLineEdit()
        self.pim_entry.setPlaceholderText("E.g. 1234")
        self.pim_entry.setFont(_font(14, "Consolas"))
        self.pim_entry.textChanged.connect(self._sanitize_pim)
        self.pim_entry.returnPressed.connect(self._on_generate)
        grid.addWidget(self.pim_entry, 5, 0)

        grid.addWidget(self._label("Amplifier (0–9999 extra characters)"), 4, 1)
        self.amp_entry = QLineEdit("0")
        self.amp_entry.setFont(_font(14, "Consolas"))
        self.amp_entry.textChanged.connect(self._sanitize_amp)
        grid.addWidget(self.amp_entry, 5, 1)

        self.error_label = QLabel()
        self.error_label.setWordWrap(True)
        self.error_label.setStyleSheet(f"color:{TEMPLE_AMBER};")
        grid.addWidget(self.error_label, 6, 0, 1, 2)

        self.generate_btn = QPushButton("𓅓  INITIALIZE SEQUENCE  𓅓")
        self.generate_btn.setObjectName("primaryButton")
        self.generate_btn.setFont(_font(16, "Georgia", True))
        self.generate_btn.clicked.connect(self._on_generate)
        grid.addWidget(self.generate_btn, 7, 0, 1, 2)

        status_row = QHBoxLayout()
        self.generate_spinner = SacredSpinner()
        self.status_label = QLabel()
        self.status_label.setFont(_font(12, "Georgia", False, True))
        self.status_label.setStyleSheet(f"color:{TEMPLE_GOLD_ANTIQUE};")
        status_row.addWidget(self.generate_spinner)
        status_row.addWidget(self.status_label, 1)
        grid.addLayout(status_row, 8, 0, 1, 2)

        self.progress = QProgressBar()
        self.progress.setRange(0, 100)
        self.progress.setValue(0)
        self.progress.hide()
        grid.addWidget(self.progress, 9, 0, 1, 2)
        outer.addWidget(card)

        self.output_card = GlowFrame(accent=TEMPLE_GOLD_SUN, radius=22)
        out = QVBoxLayout(self.output_card)
        out.setContentsMargins(28, 24, 28, 22)
        title = QLabel("✧ THE GENERATED STRING")
        title.setFont(_font(19, "Georgia", True))
        title.setStyleSheet(f"color:{TEMPLE_EMERALD};")
        out.addWidget(title)

        self.output_box = QPlainTextEdit()
        self.output_box.setReadOnly(True)
        self.output_box.setFont(_font(14, "Consolas"))
        self.output_box.setMinimumHeight(98)
        out.addWidget(self.output_box)

        btn_row = QHBoxLayout()
        self.copy_btn = QPushButton("📋 COPY")
        self.open_vault_btn = QPushButton("🗝️  BRIDGE TO VAULT")
        self.clear_btn = QPushButton("🗑️ PURGE")
        self.clear_btn.setObjectName("dangerButton")
        self.copy_btn.clicked.connect(self._copy_output)
        self.open_vault_btn.clicked.connect(self._open_in_vault)
        self.clear_btn.clicked.connect(self._clear_output)
        for b in (self.copy_btn, self.open_vault_btn, self.clear_btn):
            btn_row.addWidget(b)
        out.addLayout(btn_row)

        self.stats_label = QLabel()
        self.stats_label.setFont(_font(11, "Consolas"))
        self.stats_label.setStyleSheet(f"color:{TEMPLE_GOLD_ANTIQUE};")
        self.stats_label.setWordWrap(True)
        out.addWidget(self.stats_label)
        self.output_card.hide()
        outer.addWidget(self.output_card)

        self._show_phrase = False

    def _label(self, text):
        label = QLabel(text)
        label.setFont(_font(13, "Segoe UI", True))
        label.setStyleSheet(f"color:{TEMPLE_TEXT_BODY};")
        return label

    def _sanitize_pim(self, value):
        digits_only = "".join(c for c in value if c.isdigit())[:32]
        if digits_only.startswith("0") and len(digits_only) > 1:
            digits_only = digits_only.lstrip("0") or "0"
        if digits_only != value:
            self.pim_entry.blockSignals(True)
            self.pim_entry.setText(digits_only)
            self.pim_entry.blockSignals(False)

    def _sanitize_amp(self, value):
        digits = "".join(c for c in value if c.isdigit())
        if not digits:
            return
        n = min(int(digits), 9999)
        normalized = str(n)
        if normalized != value:
            self.amp_entry.blockSignals(True)
            self.amp_entry.setText(normalized)
            self.amp_entry.blockSignals(False)

    def _toggle_phrase_visibility(self):
        self._show_phrase = not self._show_phrase
        self.phrase_entry.setEchoMode(QLineEdit.Normal if self._show_phrase else QLineEdit.Password)

    def _set_busy(self, busy: bool, label: str = ""):
        for w in (self.phrase_entry, self.pim_entry, self.amp_entry):
            w.setEnabled(not busy)
        self.generate_btn.setEnabled(not busy)
        if busy:
            self.generate_spinner.start()
            self.status_label.setText(label)
            self.progress.show()
        else:
            self.generate_spinner.stop()
            self.progress.hide()

    def _on_generate(self):
        if self._thread is not None:
            try:
                if self._thread.isRunning():
                    return
            except RuntimeError:
                self._thread = None
        phrase = self.phrase_entry.text().strip()
        pim = self.pim_entry.text().strip()
        amp_raw = self.amp_entry.text().strip() or "0"
        if not phrase or not pim or not PIM_RE.match(pim):
            self.error_label.setText("⚠ Enter a valid phrase and a PIM of 1-32 digits.")
            return
        try:
            amp = max(0, min(9999, int(amp_raw)))
        except ValueError:
            amp = 0
        self.error_label.clear()
        self.output_card.hide()
        self._set_busy(True, "Generating...")

        def worker(progress_emit):
            return run_cipher_pipeline(phrase, pim, amp, progress_emit)

        thread = TaskThread(worker, self)
        self._thread = thread
        thread.progress.connect(self._update_progress)
        thread.succeeded.connect(self._on_success)
        thread.failed.connect(self._on_error)
        thread.finished.connect(self._on_generate_thread_finished)
        thread.finished.connect(thread.deleteLater)
        thread.finished.connect(lambda: self._release_generate_thread(thread))
        thread.start()

    def _release_generate_thread(self, thread):
        if self._thread is thread:
            self._thread = None

    @Slot()
    def _on_generate_thread_finished(self):
        # The finished signal is delivered while the QThread wrapper is still
        # valid. Only clear our reference here; QObject deletion is requested
        # separately via deleteLater().
        pass

    @Slot(int, str)
    def _update_progress(self, pct, msg):
        self.progress.setValue(pct)
        self.status_label.setText(msg)

    @Slot(object)
    def _on_success(self, result):
        self._last_cipher = result.final_cipher
        self.output_box.setPlainText(result.final_cipher)
        self.stats_label.setText(
            f"Length: {len(result.final_cipher)} characters   ·   "
            f"PBKDF2 iterations: {result.iterations:,}   ·   "
            f"Amplifier: {'+' + str(result.amplifier) if result.amplifier else 'disabled'}   ·   "
            f"Salt: {result.salt_hex[:12]}…"
        )
        self.output_card.show()
        self.status_label.clear()
        self._set_busy(False)

    @Slot(str)
    def _on_error(self, message):
        self.status_label.clear()
        self._set_busy(False)
        QMessageBox.critical(self, "Generation failed", message)

    def _copy_output(self):
        if not self._last_cipher:
            return
        QApplication.clipboard().setText(self._last_cipher)
        self.copy_btn.setText("✓ COPIED")
        QTimer.singleShot(1800, lambda: self.copy_btn.setText("📋 COPY"))

    def _open_in_vault(self):
        if self._last_cipher:
            self.app._open_cipher_in_vault(self._last_cipher)

    def _clear_output(self):
        cipher = self._last_cipher
        self._last_cipher = ""
        if QApplication.clipboard().text() == cipher:
            QApplication.clipboard().clear()
        self.output_box.clear()
        self.stats_label.clear()
        self.output_card.hide()

class VaultView(QWidget):
    def __init__(self, app, parent=None):
        super().__init__(parent)
        self.app = app
        self._open_entries: list[VaultDecryptedEntry] = []
        self._pending_create_entries: list[VaultFileEntry] = []
        self._active_video_tmp_paths: list[str] = []
        self._threads: list[QThread] = []
        self._bca_path = None
        self.create_pw_entry = None
        self.create_pw_confirm_entry = None
        self.open_pw_entry = None
        self._build()

    def _build(self):
        root = QVBoxLayout(self)
        root.setContentsMargins(60, 8, 60, 30)
        root.setSpacing(12)
        root.addWidget(SectionHeader(
            "⏣ Sacred Vault ⏣",
            "AES-256-GCM · AES-256-CBC · PBKDF2-HMAC-SHA512 · All in RAM",
            "𓁹"
        ))
        self.tabs = QTabWidget()
        self.tabs.setDocumentMode(True)
        self.create_tab = QWidget()
        self.open_tab = QWidget()
        self.tabs.addTab(self.create_tab, "CREATE ARCHIVE")
        self.tabs.addTab(self.open_tab, "OPEN ARCHIVE")
        root.addWidget(self.tabs, 1)
        self._build_create_tab()
        self._build_open_tab()

    def _field(self, parent_layout, label_text, placeholder="", password=False):
        label = QLabel(label_text)
        label.setFont(_font(12, "Segoe UI", True))
        label.setStyleSheet(f"color:{TEMPLE_TEXT_BODY};")
        parent_layout.addWidget(label)
        edit = QLineEdit()
        edit.setPlaceholderText(placeholder)
        edit.setFont(_font(13, "Consolas"))
        if password:
            edit.setEchoMode(QLineEdit.Password)
        parent_layout.addWidget(edit)
        return edit

    def _build_create_tab(self):
        outer = QVBoxLayout(self.create_tab)
        outer.setContentsMargins(24, 24, 24, 24)
        outer.setSpacing(12)

        file_card = GlowFrame(radius=18)
        file_layout = QVBoxLayout(file_card)
        file_layout.setContentsMargins(20, 18, 20, 18)
        file_layout.addWidget(self._section_label("FILES TO PROTECT"))
        self.create_list = QListWidget()
        self.create_list.setSelectionMode(QAbstractItemView.NoSelection)
        self.create_list.setMinimumHeight(170)
        file_layout.addWidget(self.create_list)
        file_btns = QHBoxLayout()
        self.add_files_btn = QPushButton("➕ ADD FILES")
        clear_btn = QPushButton("PURGE LIST")
        clear_btn.setObjectName("dangerButton")
        self.add_spinner = SacredSpinner()
        self.add_files_btn.clicked.connect(self._add_files)
        clear_btn.clicked.connect(self._clear_create_list)
        file_btns.addWidget(self.add_files_btn)
        file_btns.addWidget(clear_btn)
        file_btns.addWidget(self.add_spinner)
        file_btns.addStretch(1)
        file_layout.addLayout(file_btns)
        outer.addWidget(file_card)

        auth_card = GlowFrame(radius=18)
        auth = QGridLayout(auth_card)
        auth.setContentsMargins(20,18,20,18)
        auth.setHorizontalSpacing(14)
        auth.addWidget(self._section_label("VAULT SEAL"), 0, 0, 1, 2)
        self.create_pw_entry = self._field(auth, "ARCHIVE PASSWORD", "Password to encrypt...", True)
        self.create_pw_confirm_entry = self._field(auth, "CONFIRM PASSWORD", "Repeat the password...", True)
        auth.addWidget(QLabel(), 4, 0)
        self.create_status = QLabel()
        self.create_status.setFont(_font(12, "Georgia", False, True))
        self.create_status.setStyleSheet(f"color:{TEMPLE_GOLD_ANTIQUE};")
        self.create_spinner = SacredSpinner()
        row = QHBoxLayout()
        row.addWidget(self.create_spinner)
        row.addWidget(self.create_status, 1)
        auth.addLayout(row, 4, 0, 1, 2)
        self.create_progress = QProgressBar()
        self.create_progress.setRange(0,100)
        self.create_progress.hide()
        auth.addWidget(self.create_progress, 5, 0, 1, 2)
        self.create_btn = QPushButton("🔒  FORGE ARCHIVE  🔒")
        self.create_btn.setObjectName("primaryButton")
        self.create_btn.setFont(_font(15, "Georgia", True))
        self.create_btn.clicked.connect(self._on_create_archive)
        auth.addWidget(self.create_btn, 6, 0, 1, 2)
        outer.addWidget(auth_card)
        outer.addStretch(1)

    def _build_open_tab(self):
        outer = QVBoxLayout(self.open_tab)
        outer.setContentsMargins(24,24,24,24)
        outer.setSpacing(12)

        select = GlowFrame(radius=18)
        sl = QVBoxLayout(select)
        sl.setContentsMargins(22,22,22,22)
        self.open_dz_label = QLabel("📁  SELECT A .BCA ARCHIVE")
        self.open_dz_label.setAlignment(Qt.AlignCenter)
        self.open_dz_label.setFont(_font(21, "Georgia", True))
        self.open_dz_label.setStyleSheet(f"color:{TEMPLE_GOLD_SUN};")
        self.open_dz_sub = QLabel("Will be opened only in memory: no data written to disk")
        self.open_dz_sub.setAlignment(Qt.AlignCenter)
        self.open_dz_sub.setFont(_font(12, "Georgia", False, True))
        self.open_dz_sub.setStyleSheet(f"color:{TEMPLE_GOLD_ANTIQUE};")
        browse = QPushButton("BROWSE .BCA")
        browse.clicked.connect(self._choose_bca_file)
        sl.addWidget(self.open_dz_label)
        sl.addWidget(self.open_dz_sub)
        sl.addWidget(browse, 0, Qt.AlignHCenter)
        outer.addWidget(select)

        auth = GlowFrame(radius=18)
        al = QVBoxLayout(auth)
        al.setContentsMargins(22,18,22,18)
        al.addWidget(self._section_label("UNSEALING CREDENTIAL"))
        self.open_pw_entry = self._field(al, "ARCHIVE PASSWORD", "Password used to encrypt it...", True)
        self.open_pw_entry.returnPressed.connect(self._on_open_archive)
        self.open_status = QLabel()
        self.open_status.setFont(_font(12,"Georgia",False,True))
        self.open_status.setStyleSheet(f"color:{TEMPLE_GOLD_ANTIQUE};")
        al.addWidget(self.open_status)
        self.open_spinner = SacredSpinner()
        progress_row = QHBoxLayout()
        progress_row.addWidget(self.open_spinner)
        self.open_progress = QProgressBar()
        self.open_progress.setRange(0,100)
        self.open_progress.hide()
        progress_row.addWidget(self.open_progress,1)
        al.addLayout(progress_row)
        self.open_btn = QPushButton("𓁹  UNSEAL THE VAULT  𓁹")
        self.open_btn.setObjectName("primaryButton")
        self.open_btn.setFont(_font(15,"Georgia",True))
        self.open_btn.clicked.connect(self._on_open_archive)
        al.addWidget(self.open_btn)
        outer.addWidget(auth)

        self.entries_card = GlowFrame(radius=18)
        ec = QVBoxLayout(self.entries_card)
        ec.setContentsMargins(18,18,18,18)
        top = QHBoxLayout()
        top.addWidget(self._section_label("UNSEALED CONTENT"))
        top.addStretch(1)
        self.close_vault_btn = QPushButton("PURGE VAULT FROM RAM")
        self.close_vault_btn.setObjectName("dangerButton")
        self.close_vault_btn.clicked.connect(self._close_vault)
        top.addWidget(self.close_vault_btn)
        ec.addLayout(top)
        self.entries_scroll = QScrollArea()
        self.entries_scroll.setWidgetResizable(True)
        self.entries_container = QWidget()
        self.entries_layout = QVBoxLayout(self.entries_container)
        self.entries_layout.setContentsMargins(4,4,4,4)
        self.entries_layout.setSpacing(7)
        self.entries_scroll.setWidget(self.entries_container)
        ec.addWidget(self.entries_scroll,1)
        self.entries_card.hide()
        outer.addWidget(self.entries_card,1)

    def _section_label(self, text):
        l = QLabel(text)
        l.setFont(_font(12,"Georgia",True))
        l.setStyleSheet(f"color:{TEMPLE_GOLD_ANTIQUE};")
        return l

    def _set_busy(self, spinner, controls, busy):
        for w in controls:
            w.setEnabled(not busy)
        if busy: spinner.start()
        else: spinner.stop()

    def _retain_thread(self, thread):
        self._threads.append(thread)
        thread.finished.connect(lambda th=thread: self._forget_thread(th))

    def _forget_thread(self, thread):
        try:
            self._threads.remove(thread)
        except ValueError:
            pass

    def _add_files(self):
        paths, _ = QFileDialog.getOpenFileNames(self, "Select files to protect")
        if not paths:
            return
        self._set_busy(self.add_spinner, [self.add_files_btn], True)
        def worker(_progress):
            new_entries=[]
            errors=[]
            for path in paths:
                try:
                    with open(path,"rb") as f:
                        raw=f.read()
                    new_entries.append(VaultFileEntry(os.path.basename(path), bytearray(raw)))
                except OSError as exc:
                    errors.append((path,str(exc)))
            return new_entries, errors
        t=TaskThread(worker,self)
        t.succeeded.connect(self._on_files_loaded)
        t.failed.connect(lambda msg: QMessageBox.critical(self,"File read error",msg))
        t.finished.connect(lambda: (self._set_busy(self.add_spinner,[self.add_files_btn],False), t.deleteLater()))
        self._retain_thread(t)
        t.start()

    @Slot(object)
    def _on_files_loaded(self,result):
        new_entries,errors=result
        self._pending_create_entries.extend(new_entries)
        self._refresh_create_list()
        for path,msg in errors:
            QMessageBox.critical(self,"File read error",f"{path}: {msg}")

    def _refresh_create_list(self):
        self.create_list.clear()
        for entry in self._pending_create_entries:
            self.create_list.addItem(f"📄 {entry.name}   ·   {len(entry.data)/1024:.1f} KB")

    def _clear_create_list(self):
        for entry in self._pending_create_entries:
            wipe_bytearray(entry.data)
        self._pending_create_entries.clear()
        self._refresh_create_list()

    def _on_create_archive(self):
        if not self._pending_create_entries:
            QMessageBox.warning(self,"Vault","Add at least one file to protect.")
            return
        pw1=self.create_pw_entry.text()
        pw2=self.create_pw_confirm_entry.text()
        if not pw1:
            QMessageBox.warning(self,"Vault","Enter a password.")
            return
        if pw1!=pw2:
            QMessageBox.warning(self,"Vault","The two passwords do not match.")
            return
        save_path,_=QFileDialog.getSaveFileName(
            self,"Save archive as...",filter="BastetCipher Archive (*.bca)"
        )
        if not save_path:
            return
        if not save_path.lower().endswith(".bca"):
            save_path += ".bca"
        password_buf=bytearray(pw1.encode("utf-8"))
        entries=self._pending_create_entries
        self._pending_create_entries=[]
        self._refresh_create_list()
        self._set_busy(self.create_spinner,[self.create_pw_entry,self.create_pw_confirm_entry,self.create_btn,self.add_files_btn],True)
        self.create_progress.show()
        self.create_progress.setValue(0)
        self.create_status.setText("Forging archive...")

        def worker(progress_emit):
            try:
                archive=build_bca(entries,password_buf,progress_emit)
                with open(save_path,"wb") as f:
                    f.write(bytes(archive))
                wipe_bytearray(archive)
                return save_path
            finally:
                wipe_bytearray(password_buf)
        t=TaskThread(worker,self)
        t.progress.connect(self._update_create_progress)
        t.succeeded.connect(self._on_create_success)
        t.failed.connect(self._on_create_error)
        t.finished.connect(lambda: t.deleteLater())
        self._retain_thread(t)
        t.start()

    @Slot(int,str)
    def _update_create_progress(self,pct,msg):
        self.create_progress.setValue(pct)
        self.create_status.setText(msg)

    @Slot(object)
    def _on_create_success(self,path):
        self.create_spinner.stop()
        self.create_progress.hide()
        self.create_pw_entry.clear()
        self.create_pw_confirm_entry.clear()
        self._set_busy(self.create_spinner,[self.create_pw_entry,self.create_pw_confirm_entry,self.create_btn,self.add_files_btn],False)
        self.create_status.setText(f"✓ Archive created: {path}")
        self.create_status.setStyleSheet(f"color:{TEMPLE_EMERALD};")

    @Slot(str)
    def _on_create_error(self,message):
        self.create_spinner.stop()
        self.create_progress.hide()
        self._set_busy(self.create_spinner,[self.create_pw_entry,self.create_pw_confirm_entry,self.create_btn,self.add_files_btn],False)
        QMessageBox.critical(self,"Archive creation failed",message)

    def _choose_bca_file(self):
        path,_=QFileDialog.getOpenFileName(self,"Select .bca archive",filter="BastetCipher Archive (*.bca);;All files (*)")
        if not path:
            return
        self._bca_path=path
        self.open_dz_label.setText(f"📦  {os.path.basename(path)}")
        self.open_dz_sub.setText("Ready to unlock — will be read only once")

    def _on_open_archive(self):
        if not self._bca_path:
            QMessageBox.warning(self,"Vault","Select a .bca archive first.")
            return
        pw=self.open_pw_entry.text()
        if not pw:
            QMessageBox.warning(self,"Vault","Enter the password.")
            return
        path=self._bca_path
        password_buf=bytearray(pw.encode("utf-8"))
        self.open_pw_entry.clear()
        self._set_busy(self.open_spinner,[self.open_pw_entry,self.open_btn],True)
        self.open_progress.show()
        self.open_progress.setValue(0)
        self.open_status.setText("Reading file...")
        self.open_status.setStyleSheet(f"color:{TEMPLE_GOLD_ANTIQUE};")

        def worker(progress_emit):
            try:
                with open(path,"rb") as f:
                    raw=bytearray(f.read())
                return parse_bca(raw,password_buf,progress_emit)
            finally:
                wipe_bytearray(password_buf)
        t=TaskThread(worker,self)
        t.progress.connect(self._update_open_progress)
        t.succeeded.connect(self._on_open_success)
        t.failed.connect(self._on_open_error)
        t.finished.connect(lambda: t.deleteLater())
        self._retain_thread(t)
        t.start()

    @Slot(int,str)
    def _update_open_progress(self,pct,msg):
        self.open_progress.setValue(pct)
        self.open_status.setText(msg)

    @Slot(object)
    def _on_open_success(self,entries):
        self.open_spinner.stop()
        self.open_progress.hide()
        self._set_busy(self.open_spinner,[self.open_pw_entry,self.open_btn],False)
        self._open_entries=entries
        self.open_status.setText(f"✓ Vault unlocked · {len(entries)} file(s) · data only in RAM")
        self.open_status.setStyleSheet(f"color:{TEMPLE_EMERALD};")
        self._render_entries_list()
        self.entries_card.show()

    @Slot(str)
    def _on_open_error(self,message):
        self.open_spinner.stop()
        self.open_progress.hide()
        self._set_busy(self.open_spinner,[self.open_pw_entry,self.open_btn],False)
        friendly = "Wrong password or corrupted/tampered archive." if ("Layer 1" in message or "Layer 2" in message) else message
        QMessageBox.critical(self,"Vault",friendly)

    def _render_entries_list(self):
        while self.entries_layout.count():
            item=self.entries_layout.takeAt(0)
            w=item.widget()
            if w: w.deleteLater()
        for entry in self._open_entries:
            row=GlowFrame(accent=TEMPLE_GOLD_BRONZE,radius=12)
            rl=QHBoxLayout(row)
            rl.setContentsMargins(14,10,10,10)
            info=QVBoxLayout()
            name=QLabel(entry.name)
            name.setFont(_font(13,"Segoe UI",True))
            name.setStyleSheet(f"color:{TEMPLE_TEXT_BODY};")
            status=QLabel(
                ("✓ Integrity Verified" if entry.crc_ok else "⚠ Integrity Warning")
                + f"    ·    {len(entry.data)/1024:.1f} KB"
            )
            status.setFont(_font(10,"Consolas"))
            status.setStyleSheet(f"color:{TEMPLE_EMERALD if entry.crc_ok else TEMPLE_AMBER};")
            info.addWidget(name)
            info.addWidget(status)
            rl.addLayout(info,1)
            kind=classify_extension(entry.name)
            if kind != ViewerKind.UNSUPPORTED:
                prev=QPushButton("👁 Preview")
                prev.clicked.connect(lambda _=False,e=entry:self._preview_entry(e))
                rl.addWidget(prev)
            exp=QPushButton("⇩ Export")
            exp.clicked.connect(lambda _=False,e=entry:self._export_entry(e))
            rl.addWidget(exp)
            self.entries_layout.addWidget(row)
        self.entries_layout.addStretch(1)

    def _preview_entry(self,entry):
        kind=classify_extension(entry.name)
        if kind == ViewerKind.VIDEO and _SYSTEM in ("Windows","Darwin"):
            box=QMessageBox(self)
            box.setWindowTitle("Security Notice — Video Preview")
            box.setIcon(QMessageBox.Warning)
            box.setText(
                f"Notice regarding '{entry.name}':\n\n"
                "On Windows/macOS, video playback requires a temporary file on disk.\n\n"
                "The temporary file is securely shredded when the preview closes. "
                "On Linux, playback uses the RAM-backed path when available.\n\n"
                "Proceed?"
            )
            box.setStandardButtons(QMessageBox.Yes|QMessageBox.No)
            if box.exec()!=QMessageBox.Yes:
                return
        data=bytes(entry.data)
        dialog=QDialog(self)
        dialog.setWindowTitle(f"Preview — {entry.name}")
        dialog.resize(920,760)
        dialog.setStyleSheet(APP_QSS)
        apply_screen_capture_protection(dialog)
        if kind==ViewerKind.IMAGE:
            self._preview_image(dialog,data)
        elif kind==ViewerKind.PDF:
            self._preview_pdf(dialog,data)
        elif kind==ViewerKind.TEXT:
            self._preview_text(dialog,data)
        elif kind==ViewerKind.AUDIO:
            self._preview_audio(dialog,data,entry.name)
        elif kind==ViewerKind.VIDEO:
            self._preview_video(dialog,data,entry.name)
        else:
            QLabel("No preview available for this file type.\nUse Export to save it explicitly to disk.").show()
        dialog.exec()

    def _preview_image(self,dialog,data):
        base=render_image_in_memory(data)
        animated=bool(getattr(base,"is_animated",False) and getattr(base,"n_frames",1)>1)
        root=QVBoxLayout(dialog)
        toolbar=QHBoxLayout()
        zoom_label=QLabel("Zoom: 100%")
        zoom_label.setFont(_font(11,"Consolas"))
        minus=QPushButton("−")
        plus=QPushButton("+")
        fit=QPushButton("FIT")
        toolbar.addWidget(zoom_label)
        toolbar.addStretch(1)
        toolbar.addWidget(minus); toolbar.addWidget(fit); toolbar.addWidget(plus)
        root.addLayout(toolbar)
        scroll=QScrollArea()
        scroll.setWidgetResizable(True)
        image_label=QLabel()
        image_label.setAlignment(Qt.AlignCenter)
        image_label.setStyleSheet(f"background:{TEMPLE_BG};")
        scroll.setWidget(image_label)
        root.addWidget(scroll,1)
        state={"scale":1.0,"frame":0,"timer":None}

        def render():
            try:
                if animated:
                    base.seek(state["frame"])
                    frame=base.convert("RGBA")
                    suffix=f"  ·  GIF frame {state['frame']+1}/{base.n_frames}"
                else:
                    frame=base
                    suffix=""
                w=max(1,round(frame.width*state["scale"]))
                h=max(1,round(frame.height*state["scale"]))
                shown=frame.resize((w,h),Image.Resampling.LANCZOS) if (w,h)!=frame.size else frame
                image_label.setPixmap(_pixmap_from_pil(shown))
                zoom_label.setText(f"Zoom: {round(state['scale']*100)}%{suffix}")
            except Exception:
                pass

        def change(f):
            state["scale"]=max(0.05,min(8.0,state["scale"]*f))
            render()
        minus.clicked.connect(lambda:change(1/1.2))
        plus.clicked.connect(lambda:change(1.2))
        fit.clicked.connect(lambda: (state.__setitem__("scale", min(
            max(1,scroll.viewport().width()-30)/base.width,
            max(1,scroll.viewport().height()-30)/base.height, 1.0
        )),render()))
        state["scale"]=min(
            max(1,dialog.width()-60)/base.width,
            max(1,dialog.height()-110)/base.height,1.0
        )
        render()
        if animated:
            timer=QTimer(dialog)
            timer.timeout.connect(lambda: (state.__setitem__("frame",(state["frame"]+1)%base.n_frames),render()))
            try:
                delay=max(20,int(base.info.get("duration",100)))
            except Exception:
                delay=100
            timer.start(delay)
            state["timer"]=timer

    def _preview_pdf(self,dialog,data):
        root=QVBoxLayout(dialog)
        loading=QLabel("◐  Rendering PDF securely in memory...")
        loading.setAlignment(Qt.AlignCenter)
        loading.setFont(_font(14,"Georgia",False,True))
        loading.setStyleSheet(f"color:{TEMPLE_GOLD_ANTIQUE};")
        root.addWidget(loading,1)
        def worker(_progress):
            return render_pdf_pages_in_memory(data,dpi=100,max_pages=30)
        t=TaskThread(worker,dialog)
        def success(pages):
            while root.count():
                item=root.takeAt(0)
                w=item.widget()
                if w: w.deleteLater()
            toolbar=QHBoxLayout()
            search=QLineEdit()
            search.setPlaceholderText("Search text in PDF...")
            find_btn=QPushButton("FIND")
            prev_btn=QPushButton("‹")
            next_btn=QPushButton("›")
            zoom_out=QPushButton("−")
            zoom_in=QPushButton("+")
            match=QLabel(f"Page 1 / {max(1,len(pages))}")
            toolbar.addWidget(search,1)
            toolbar.addWidget(find_btn); toolbar.addWidget(prev_btn); toolbar.addWidget(next_btn)
            toolbar.addStretch(1); toolbar.addWidget(zoom_out); toolbar.addWidget(zoom_in); toolbar.addWidget(match)
            root.addLayout(toolbar)
            scroll=QScrollArea()
            scroll.setWidgetResizable(True)
            cont=QWidget()
            lay=QVBoxLayout(cont)
            lay.setAlignment(Qt.AlignHCenter|Qt.AlignTop)
            scroll.setWidget(cont)
            root.addWidget(scroll,1)
            zoom={"v":1.0}
            page_labels=[]
            for page in pages:
                frame=GlowFrame(accent=TEMPLE_GOLD_BRONZE,radius=12)
                fl=QVBoxLayout(frame)
                img=QLabel()
                img.setAlignment(Qt.AlignCenter)
                base=QImage.fromData(page.png_bytes,"PNG")
                img.setPixmap(QPixmap.fromImage(base))
                fl.addWidget(img)
                cap=QLabel(f"Page {page.index+1}")
                cap.setAlignment(Qt.AlignCenter)
                cap.setStyleSheet(f"color:{TEMPLE_GOLD_BRONZE};")
                fl.addWidget(cap)
                lay.addWidget(frame)
                page_labels.append((img,base))
            search_state={"matches":[],"idx":0}
            def apply_zoom():
                for img,base in page_labels:
                    img.setPixmap(QPixmap.fromImage(base).scaled(
                        int(base.width()*zoom["v"]),int(base.height()*zoom["v"]),
                        Qt.KeepAspectRatio,Qt.SmoothTransformation
                    ))
                match.setText(f"Zoom {round(zoom['v']*100)}%")
            def do_zoom(f):
                zoom["v"]=max(.5,min(2.0,zoom["v"]*f)); apply_zoom()
            zoom_in.clicked.connect(lambda:do_zoom(1.2))
            zoom_out.clicked.connect(lambda:do_zoom(1/1.2))
            def find_text(direction=0):
                q=search.text().strip().casefold()
                if not q:
                    search_state["matches"]=[]; search_state["idx"]=0; match.setText(f"Page 1 / {max(1,len(pages))}"); return
                matches=[p.index for p in pages if q in p.text.casefold()]
                if matches != search_state["matches"]:
                    search_state["matches"]=matches; search_state["idx"]=0
                elif matches:
                    search_state["idx"]=(search_state["idx"]+direction)%len(matches)
                if not matches:
                    match.setText("No matches"); return
                idx=search_state["matches"][search_state["idx"]]
                match.setText(f"Match {search_state['idx']+1} / {len(matches)}  ·  page {idx+1}")
                bar=scroll.verticalScrollBar()
                target_widget=lay.itemAt(idx).widget()
                if target_widget:
                    scroll.ensureWidgetVisible(target_widget)
            find_btn.clicked.connect(lambda:find_text(0)); prev_btn.clicked.connect(lambda:find_text(-1)); next_btn.clicked.connect(lambda:find_text(1))
            search.returnPressed.connect(lambda:find_text(1))
        def failure(msg):
            loading.setText(f"Could not display PDF:\n{msg}")
            loading.setStyleSheet(f"color:{TEMPLE_AMBER};")
        t.succeeded.connect(success); t.failed.connect(failure)
        t.finished.connect(lambda:t.deleteLater())
        t.start()

    def _preview_text(self,dialog,data):
        root=QVBoxLayout(dialog)
        box=QPlainTextEdit()
        box.setReadOnly(True)
        box.setFont(_font(12,"Consolas"))
        box.setPlainText(decode_text_in_memory(data))
        root.addWidget(box)

    def _preview_audio(self,dialog,data,name):
        root=QVBoxLayout(dialog)
        icon=QLabel("🎵"); icon.setAlignment(Qt.AlignCenter); icon.setFont(_font(52))
        root.addWidget(icon)
        title=QLabel(name); title.setAlignment(Qt.AlignCenter); title.setFont(_font(18,"Georgia",True))
        root.addWidget(title)
        status=QLabel("Playing from RAM..."); status.setAlignment(Qt.AlignCenter); root.addWidget(status)
        duration=get_audio_duration_seconds(data)
        slider=MediaSlider(Qt.Horizontal); slider.setRange(0,1000 if duration else 1); root.addWidget(slider)
        volume_row=QHBoxLayout(); volume_row.addWidget(QLabel("🔊 Volume")); vol=QSlider(Qt.Horizontal); vol.setRange(0,100); vol.setValue(80); volume_row.addWidget(vol,1); root.addLayout(volume_row)
        time_label=QLabel("0:00 / " + (self._fmt_time(duration) if duration else "—:—")); time_label.setAlignment(Qt.AlignCenter); root.addWidget(time_label)
        btns=QHBoxLayout(); play=QPushButton("⏸ Pause"); stop=QPushButton("⏹ Stop"); btns.addWidget(play); btns.addWidget(stop); root.addLayout(btns)
        state={"session":-1,"offset":0.0,"stopped":False}
        try:
            state["session"]=play_audio_in_memory(data)
            set_audio_volume(.8)
        except Exception as exc:
            status.setText(f"Playback error: {exc}"); play.setEnabled(False); stop.setEnabled(False)
        def slider_release():
            if duration:
                target=slider.value()/1000*duration
                try:
                    state["session"]=play_audio_in_memory(data,start_seconds=target)
                    state["offset"]=target; state["stopped"]=False; set_audio_volume(vol.value()/100); play.setText("⏸ Pause")
                except Exception: pass
        slider.sliderReleased.connect(slider_release)
        vol.valueChanged.connect(lambda v:set_audio_volume(v/100))
        def toggle():
            if state["stopped"] or state["session"]!=current_audio_session():
                try:
                    state["session"]=play_audio_in_memory(data,start_seconds=state["offset"]); state["stopped"]=False
                    set_audio_volume(vol.value()/100); play.setText("⏸ Pause")
                except Exception: pass
                return
            if is_audio_playing():
                pause_audio(); play.setText("▶ Play")
            else:
                unpause_audio(); play.setText("⏸ Pause")
        play.clicked.connect(toggle)
        def do_stop():
            stop_audio(); state["stopped"]=True; state["offset"]=0; slider.setValue(0); play.setText("▶ Play")
            status.setText("Stopped")
        stop.clicked.connect(do_stop)
        timer=QTimer(dialog)
        def poll():
            if state["session"]!=current_audio_session():
                play.setText("▶ Play")
                return
            if not state["stopped"] and is_audio_playing():
                pos=state["offset"]+get_audio_position_seconds()
                if duration:
                    if not slider.isSliderDown():
                        slider.setValue(min(1000,int(pos/duration*1000)))
                    time_label.setText(f"{self._fmt_time(pos)} / {self._fmt_time(duration)}")
        timer.timeout.connect(poll); timer.start(300)

        def close_audio():
            try: stop_audio()
            except Exception: pass
            dialog.accept()
        dialog.finished.connect(lambda _: close_audio())

    @staticmethod
    def _fmt_time(seconds):
        s=max(0,int(seconds or 0))
        return f"{s//60}:{s%60:02d}"

    def _preview_video(self,dialog,data,name):
        root=QVBoxLayout(dialog)
        top=QHBoxLayout()
        icon=QLabel("🎬"); icon.setFont(_font(28)); top.addWidget(icon)
        title=QLabel(name); title.setFont(_font(15,"Georgia",True)); top.addWidget(title)
        top.addStretch(1)
        status=QLabel("Reading video info...")
        top.addWidget(status)
        root.addLayout(top)

        worker=TaskThread(lambda _p: probe_video_in_memory(data),dialog)
        def probed(info):
            status.setText("")
            video_label=QLabel()
            video_label.setAlignment(Qt.AlignCenter)
            video_label.setMinimumSize(320,240)
            video_label.setStyleSheet(f"background:{TEMPLE_BG};")
            root.addWidget(video_label,1)
            slider=MediaSlider(Qt.Horizontal); slider.setRange(0,1000 if info.duration>0 else 1); root.addWidget(slider)
            row=QHBoxLayout()
            row.addWidget(QLabel("🔊 Volume"))
            vol=QSlider(Qt.Horizontal); vol.setRange(0,100); vol.setValue(80); row.addWidget(vol,1)
            play=QPushButton("⏸ Pause"); stop=QPushButton("⏹ Stop"); time_label=QLabel(f"0:00 / {self._fmt_time(info.duration)}")
            row.addWidget(play); row.addWidget(stop); row.addWidget(time_label)
            root.addLayout(row)
            decode_size=_fit_decode_size(info.width,info.height,max(640,video_label.width()*2),max(360,video_label.height()*2))
            state={"thread":None,"playing":True,"offset":0.0,"session":-1,"generation":0,"last_time":0.0}
            wav_audio=None
            if info.has_audio:
                try: wav_audio=extract_video_audio_as_wav(data)
                except Exception: wav_audio=None
            if wav_audio:
                try: state["session"]=play_audio_in_memory(wav_audio); set_audio_volume(.8)
                except Exception: state["session"]=-1
            pump=QTimer(dialog)
            def frame(t,w,h,rgb, th=None):
                # Discard stale frames from previous seek generations
                if th is not None and state.get("thread") is not th:
                    return
                img=QImage(rgb,w,h,w*3,QImage.Format_RGB888).copy()
                pix=QPixmap.fromImage(img)
                video_label.setPixmap(pix.scaled(video_label.size(),Qt.KeepAspectRatio,Qt.SmoothTransformation))
                state["last_time"]=t
                if info.duration and not slider.isSliderDown():
                    slider.setValue(min(1000,int(t/info.duration*1000)))
                time_label.setText(f"{self._fmt_time(t)} / {self._fmt_time(info.duration)}")
            def start_decode(at=0.0):
                if state["thread"]:
                    try:
                        state["thread"].request_stop()
                        state["thread"].wait(800)
                    except Exception: pass
                state["generation"]+=1
                # Do not parent to dialog: prevents C++ destruction while thread still running
                th=VideoDecodeThread(data,info,at,decode_size,None)
                th.frameReady.connect(lambda t,w,h,rgb, th=th: frame(t,w,h,rgb,th))
                th.failed.connect(lambda msg: status.setText(f"Video decode error: {msg}"))
                state["thread"]=th; th.start()
            start_decode(0.0)
            def toggle():
                state["playing"]=not state["playing"]
                if state["playing"]:
                    start_decode(state["last_time"])
                    if wav_audio:
                        try: state["session"]=play_audio_in_memory(wav_audio,start_seconds=state["last_time"]); set_audio_volume(vol.value()/100)
                        except Exception: pass
                    play.setText("⏸ Pause")
                else:
                    if state["session"]!=-1: pause_audio()
                    if state["thread"]: state["thread"].request_stop()
                    play.setText("▶ Play")
            play.clicked.connect(toggle)
            def stop_all():
                state["playing"]=False; slider.setValue(0); state["last_time"]=0
                try: stop_audio()
                except Exception: pass
                if state["thread"]: state["thread"].request_stop()
                play.setText("▶ Play")
            stop.clicked.connect(stop_all)
            vol.valueChanged.connect(lambda v:set_audio_volume(v/100))
            def seek():
                if info.duration:
                    target=slider.value()/1000*info.duration
                    start_decode(target)
                    if wav_audio:
                        try:
                            state["session"]=play_audio_in_memory(wav_audio,start_seconds=target); set_audio_volume(vol.value()/100)
                            if not state["playing"]: pause_audio()
                        except Exception: pass
            slider.sliderReleased.connect(seek)
            pump.start(30)
            def cleanup():
                pump.stop()
                th = state.get("thread")
                if th is not None:
                    try:
                        th.request_stop()
                        th.wait(1500)
                    except Exception:
                        pass
                    state["thread"] = None
                try: stop_audio()
                except Exception: pass
            dialog.finished.connect(lambda _: cleanup())
            # Ensure threads are stopped synchronously before dialog (and its children) are destroyed
            def _video_close_event(event):
                cleanup()
                event.accept()
            dialog.closeEvent = _video_close_event
        def probe_fail(msg):
            status.setText("Could not read video. Falling back to system player…")
            self._preview_video_external_fallback(dialog,data,name,status)
        worker.succeeded.connect(probed); worker.failed.connect(probe_fail); worker.finished.connect(lambda:worker.deleteLater())
        worker.start()

    def _preview_video_external_fallback(self,dialog,data,name,status_label):
        import tempfile
        ram_disk="/dev/shm" if os.path.isdir("/dev/shm") and os.access("/dev/shm",os.W_OK) else None
        tmp_path=None
        try:
            suffix="."+name.rsplit(".",1)[-1].lower() if "." in name else ".mp4"
            fd,tmp_path=tempfile.mkstemp(suffix=suffix,dir=ram_disk)
            with os.fdopen(fd,"wb") as f: f.write(data)
            self._active_video_tmp_paths.append(tmp_path)
            if sys.platform.startswith("win"):
                os.startfile(tmp_path)
            elif sys.platform=="darwin":
                subprocess.Popen(["open",tmp_path])
            else:
                subprocess.Popen(["xdg-open",tmp_path])
        except Exception as exc:
            status_label.setText(f"Could not open system player: {exc}")
        def cleanup():
            if tmp_path:
                _secure_shred_file(tmp_path)
                if tmp_path in self._active_video_tmp_paths:
                    self._active_video_tmp_paths.remove(tmp_path)
        dialog.finished.connect(lambda _:cleanup())

    def _export_entry(self,entry):
        path,_=QFileDialog.getSaveFileName(self,f"Export {entry.name} as...",entry.name)
        if not path: return
        data=bytes(entry.data)
        def worker(_p):
            with open(path,"wb") as f: f.write(data)
            return path
        t=TaskThread(worker,self)
        t.succeeded.connect(lambda p:QMessageBox.information(self,"Vault",f"File exported to:\n{p}"))
        t.failed.connect(lambda msg:QMessageBox.critical(self,"Export failed",msg))
        t.start()
        t.finished.connect(lambda:t.deleteLater())

    def _close_vault(self):
        for entry in self._open_entries: wipe_bytearray(entry.data)
        self._open_entries=[]
        self._render_entries_list()
        self.entries_card.hide()
        self._bca_path=None
        self.open_dz_label.setText("📁  SELECT A .BCA ARCHIVE")
        self.open_dz_sub.setText("Will be opened only in memory: no data written to disk")
        self.open_status.setText("Vault closed · Data wiped from RAM.")
        self.open_status.setStyleSheet(f"color:{TEMPLE_GOLD_BRONZE};")
        self.open_pw_entry.clear()

    def wipe_all_on_exit(self):
        for entry in self._open_entries: wipe_bytearray(entry.data)
        for entry in self._pending_create_entries: wipe_bytearray(entry.data)
        self._open_entries=[]; self._pending_create_entries=[]
        try: self.create_pw_entry.clear(); self.create_pw_confirm_entry.clear(); self.open_pw_entry.clear()
        except Exception: pass
        try: stop_audio()
        except Exception: pass
        for tmp in self._active_video_tmp_paths: _secure_shred_file(tmp)
        self._active_video_tmp_paths.clear()

class BastetCipherApp(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setObjectName("root")
        self.setWindowTitle("BastetCipher — Sacred Chamber")
        apply_app_icon(self)
        screen=QApplication.primaryScreen().availableGeometry()
        scale=compute_ui_scale(screen.width(),screen.height())
        apply_ui_scale(scale)
        target_w=min(int(screen.width()*0.75),1800)
        target_h=min(int(screen.height()*0.82),1100)
        target_w=max(target_w,960)
        target_h=max(target_h,700)
        self.resize(target_w,target_h)
        self.setMinimumSize(min(900,screen.width()),min(650,screen.height()))
        configure_style(self)

        shell=QWidget()
        shell.setObjectName("root")
        root=QVBoxLayout(shell)
        root.setContentsMargins(0,0,0,0)
        root.setSpacing(0)
        self.backdrop=SacredBackdrop(shell)
        self.backdrop.lower()

        content=QWidget(shell)
        content_layout=QVBoxLayout(content)
        content_layout.setContentsMargins(0,0,0,0)
        content_layout.setSpacing(0)

        self.fade=FadeStack(content)
        self.hub=HubView()
        self.generator=GeneratorView(self)
        self.vault=VaultView(self)
        self.fade.setWidget(self.hub)
        self.fade.setWidget(self.generator)
        self.fade.setWidget(self.vault)
        content_layout.addWidget(self.fade)
        root.addWidget(content,1)

        self.nav=QFrame()
        self.nav.setStyleSheet(
            f"QFrame{{background:rgba(23,19,13,235); border-top:1px solid {TEMPLE_GOLD_BRONZE};}}"
        )
        nav_l=QHBoxLayout(self.nav)
        nav_l.setContentsMargins(18,10,18,10)
        self.back_btn=QPushButton("◀  RETURN TO TEMPLE PORTAL")
        self.back_btn.setObjectName("ghostButton")
        self.back_btn.clicked.connect(self._show_hub)
        self.nav_title=QLabel("")
        self.nav_title.setFont(_font(14,"Georgia",True))
        self.nav_title.setStyleSheet(f"color:{TEMPLE_GOLD_SUN};")
        nav_l.addWidget(self.back_btn)
        nav_l.addWidget(self.nav_title)
        nav_l.addStretch(1)
        self.capture_status=QLabel("Capture shield: initializing")
        self.capture_status.setFont(_font(10,"Consolas"))
        self.capture_status.setStyleSheet(f"color:{TEMPLE_GOLD_BRONZE};")
        nav_l.addWidget(self.capture_status)
        self.nav.hide()
        root.insertWidget(0,self.nav)

        self.setCentralWidget(shell)
        # Unified animation: one timer in SacredBackdrop drives hub widgets
        self.backdrop.frameTick.connect(self.hub.logo.on_frame)
        self.backdrop.frameTick.connect(self.hub.gen_btn.on_frame)
        self.backdrop.frameTick.connect(self.hub.vault_btn.on_frame)
        self.hub.openView.connect(self._show_view)
        self._show_hub()
        QTimer.singleShot(120, self._apply_capture_protection)

    def _apply_capture_protection(self):
        ok = apply_screen_capture_protection(self)
        state = getattr(self, "_capture_protection", "unavailable")
        self.capture_status.setText(f"Capture shield: {state}")
        self.capture_status.setStyleSheet(
            f"color:{TEMPLE_EMERALD if ok else TEMPLE_GOLD_BRONZE};"
        )

    def resizeEvent(self,event):
        super().resizeEvent(event)
        self.backdrop.setGeometry(self.centralWidget().rect())

    def _show_hub(self):
        self.nav.hide()
        self.fade.showIndex(0)
        self.backdrop.start_animation()

    def _show_view(self,key):
        idx={"generator":1,"vault":2}.get(key,0)
        self.nav_title.setText("Cipher Generator" if key=="generator" else "Sacred Vault")
        self.nav.show()
        self.fade.showIndex(idx)
        # Pause ambient particles while on opaque generator/vault views
        self.backdrop.stop_animation()

    def _open_cipher_in_vault(self,cipher):
        self._show_view("vault")
        self.vault.tabs.setCurrentIndex(1)
        self.vault.open_pw_entry.setText(cipher)
        QTimer.singleShot(120,self.vault.open_pw_entry.setFocus)

    def closeEvent(self,event):
        try:
            self.backdrop.stop_animation()
            self.vault.wipe_all_on_exit()
            for thread in self.findChildren(QThread):
                try:
                    if isinstance(thread, VideoDecodeThread):
                        thread.request_stop()
                    elif thread.isRunning():
                        thread.requestInterruption()
                except Exception:
                    pass
            for dialog in self.findChildren(QDialog):
                try:
                    dialog.close()
                except Exception:
                    pass
            for thread in self.findChildren(QThread):
                try:
                    if thread.isRunning():
                        thread.wait(3000)
                except Exception:
                    pass
        except Exception:
            pass
        event.accept()

def main() -> int:
    harden_process()
    app=QApplication(sys.argv)
    apply_base_appearance()
    app.setApplicationName("BastetCipher")
    app.setApplicationDisplayName("BastetCipher — Sacred Chamber")
    window=BastetCipherApp()
    window.show()
    return app.exec()

if __name__ == "__main__":
    sys.exit(main())
