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
            self.last_error = f"Exception during lock: {exc}"
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
            raise ValueError("Size must be positive")
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
        raise BCADecryptError("Invalid ciphertext length.")
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded = decryptor.update(data) + decryptor.finalize()
    if not padded:
        raise BCADecryptError("Void Payload.")
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
        raise BCAFormatError("File too short to be a valid .bca archive.")
    if d[0:4] != BCA_MAGIC:
        raise BCAFormatError("Unrecognized file (magic bytes mismatch).")
    if d[4] != BCA_VERSION:
        raise BCAFormatError("Archive version not supported.")
    salt = bytes(d[5:37])
    iterations = struct.unpack("<I", d[37:41])[0]
    if iterations != BCA_ITERS:
        raise BCAFormatError("Invalid PBKDF2 parameter for this archive.")
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
                    raise BCAFormatError(f"Archive truncated while reading {field}.")
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
                    raise BCAFormatError("Invalid file name in archive.") from exc
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
                raise BCAFormatError("Archive contains unexpected data.")
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
IMAGE_EXTENSIONS = {".png", ".jpg", ".jpeg", ".gif", ".bmp", ".webp", ".tiff", ".svg", ".ico"}
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
CUSTOM_BACKGROUND_BASE64: Optional[str] = "data:image/webp;base64,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"
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
        self._bg_scaled = None
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
                painter.fillRect(rect, _rgba("#060504", 145))
            else:
                grad = QLinearGradient(0, 0, w, h)
                grad.setColorAt(0.0, QColor("#040302"))
                grad.setColorAt(0.40, QColor("#080605"))
                grad.setColorAt(1.0, QColor("#030201"))
                painter.fillRect(rect, grad)
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
            painter.setPen(QPen(_rgba(TEMPLE_GOLD_BRONZE, 14), 1))
            step = max(48, int(78 * CURRENT_UI_SCALE))
            for x in range(0, w + step, step):
                painter.drawLine(x, 0, x, h)
            for y in range(0, h + step, step):
                painter.drawLine(0, y, w, y)
            painter.setPen(Qt.NoPen)
            for i in range(18):
                cx = (0.07 + 0.86 * ((i * 0.37) % 1.0)) * w
                cy = (0.05 + 0.90 * ((i * 0.61) % 1.0)) * h
                a = 10 + int(12 * (0.5 + 0.5 * math.sin(self._phase + i)))
                painter.setBrush(_rgba(TEMPLE_GOLD_PALE, a))
                painter.drawEllipse(QPointF(cx, cy), 1.1, 1.1)
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
            grad = QLinearGradient(r.topLeft(), r.bottomLeft())
            grad.setColorAt(0.0, QColor("#1c1610"))
            grad.setColorAt(0.5, QColor("#12100c"))
            grad.setColorAt(1.0, QColor("#0e0b08"))
            path = QPainterPath()
            path.addRoundedRect(r, self._radius, self._radius)
            painter.fillPath(path, grad)
            vignette = QRadialGradient(r.center(), max(r.width(), r.height()) * 0.72)
            vignette.setColorAt(0.0, _rgba("#000000", 0))
            vignette.setColorAt(0.7, _rgba("#000000", 18))
            vignette.setColorAt(1.0, _rgba("#000000", 55))
            painter.fillPath(path, vignette)
            painter.setPen(QPen(_rgba(self._accent, 155), 1.6))
            painter.drawPath(path)
            inner = r.adjusted(4.5, 4.5, -4.5, -4.5)
            inner_path = QPainterPath()
            inner_path.addRoundedRect(inner, max(8, self._radius - 5), max(8, self._radius - 5))
            painter.setPen(QPen(_rgba(TEMPLE_GOLD_PALE, 28), 1))
            painter.drawPath(inner_path)
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
            aura = QRadialGradient(r.center().x(), r.top() + r.height() * 0.28, r.width() * 0.55)
            aura.setColorAt(0.0, _rgba(TEMPLE_AMBER if ha > 0.3 else TEMPLE_GOLD_BRONZE, int(90 + 70 * ha)))
            aura.setColorAt(0.35, _rgba(TEMPLE_GOLD_BRONZE, int(28 + 40 * ha)))
            aura.setColorAt(0.7, _rgba(TEMPLE_LAPIS, int(20 + 15 * ha)))
            aura.setColorAt(1.0, _rgba("#000000", 0))
            painter.fillPath(path, aura)
            painter.setBrush(Qt.NoBrush)
            painter.setPen(QPen(_rgba(TEMPLE_GOLD_SUN if ha > 0.4 else TEMPLE_GOLD_BRONZE, int(160 + 70 * ha)), 1.9))
            painter.drawEllipse(r)
            if ha > 0.05:
                pulse = 0.5 + 0.5 * math.sin(self._phase * 2.2)
                ring_r = r.adjusted(-4 - 3 * pulse * ha, -4 - 3 * pulse * ha, 4 + 3 * pulse * ha, 4 + 3 * pulse * ha)
                painter.setPen(QPen(_rgba(TEMPLE_GOLD_PALE, int(35 + 55 * ha * pulse)), 1.2))
                painter.drawEllipse(ring_r)
            inner = r.adjusted(7, 7, -7, -7)
            painter.setPen(QPen(_rgba(TEMPLE_GOLD_PALE, int(28 + 55 * ha)), 1))
            painter.drawEllipse(inner)
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
            glyph_rect = QRectF(r.left(), r.top() + 16, r.width(), 94)
            painter.setPen(QColor(TEMPLE_GOLD_PALE if ha > 0.4 else TEMPLE_GOLD_SUN))
            painter.setFont(_font(50, "Segoe UI Symbol"))
            painter.drawText(glyph_rect, Qt.AlignHCenter | Qt.AlignVCenter, self.icon_text)
            title_rect = QRectF(r.left() + 22, r.top() + 115, r.width() - 44, 36)
            painter.setPen(QColor(TEMPLE_GOLD_PALE if ha > 0.4 else TEMPLE_GOLD_SUN))
            painter.setFont(_font(19, "Georgia", True))
            painter.drawText(title_rect, Qt.AlignCenter, self.title_text)
            subtitle_rect = QRectF(r.left() + 42, r.top() + 158, r.width() - 84, 78)
            painter.setPen(QColor(TEMPLE_TEXT_BODY))
            painter.setFont(_font(12, "Segoe UI"))
            painter.drawText(subtitle_rect, Qt.AlignCenter | Qt.TextWordWrap, self.subtitle_text)
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
    def mousePressEvent(self, event):
        if event.button() == Qt.LeftButton and self.orientation() == Qt.Horizontal:
            x = event.position().x() if hasattr(event, "position") else event.x()
            ratio = max(0.0, min(1.0, float(x) / max(1, self.width())))
            value = self.minimum() + int(ratio * (self.maximum() - self.minimum()))
            self.setValue(value)
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
        layout.setContentsMargins(0, 0, 0, 0)
        layout.addWidget(self.stack)
        self._anim = None
        self._effect = None
    def setWidget(self, widget: QWidget):
        self.stack.addWidget(widget)
    def showIndex(self, index: int, animate: bool = True):
        if index < 0 or index >= self.stack.count():
            return
        if self.stack.currentIndex() == index:
            return
        if self._anim is not None:
            self._anim.stop()
            self._anim = None
        if self._effect is not None:
            prev_widget = self._effect.parent()
            if prev_widget is not None:
                prev_widget.setGraphicsEffect(None)
            self._effect = None
        self.stack.setCurrentIndex(index)
        current = self.stack.currentWidget()
        if current is None:
            return
        current.raise_()
        current.update()
        if not animate:
            return
        effect = QGraphicsOpacityEffect(current)
        current.setGraphicsEffect(effect)
        effect.setOpacity(0.0)
        self._effect = effect
        anim = QPropertyAnimation(effect, b"opacity", self)
        anim.setDuration(420)
        anim.setStartValue(0.0)
        anim.setEndValue(1.0)
        anim.setEasingCurve(QEasingCurve.OutCubic)
        def _cleanup():
            if current.graphicsEffect() is effect:
                current.setGraphicsEffect(None)
            if self._effect is effect:
                self._effect = None
            if self._anim is anim:
                self._anim = None
        anim.finished.connect(_cleanup)
        self._anim = anim
        anim.start()
class BastetEmblem(QWidget):
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
            radius = size * 0.248
            breath = 0.5 + 0.5 * math.sin(self._phase * 0.7)
            halo_r = radius * (1.55 + 0.22 * breath)
            halo = QRadialGradient(c.x(), c.y(), halo_r)
            halo.setColorAt(0.0, _rgba(TEMPLE_GOLD_SUN, int(70 + 45 * breath)))
            halo.setColorAt(0.35, _rgba(TEMPLE_AMBER, int(22 + 18 * breath)))
            halo.setColorAt(0.7, _rgba(TEMPLE_GOLD_BRONZE, int(8 + 6 * breath)))
            halo.setColorAt(1.0, _rgba(TEMPLE_AMBER, 0))
            painter.setPen(Qt.NoPen)
            painter.setBrush(halo)
            painter.drawEllipse(QPointF(c), halo_r, halo_r)
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
            painter.setBrush(QColor(TEMPLE_CARD_ELEVATED))
            painter.setPen(QPen(QColor(TEMPLE_GOLD_SUN), 2.1))
            painter.drawEllipse(QPointF(c), radius, radius)
            painter.setBrush(Qt.NoBrush)
            painter.setPen(QPen(_rgba(TEMPLE_GOLD_PALE, 160), 1))
            painter.drawEllipse(QPointF(c), radius * 0.86, radius * 0.86)
            painter.setPen(QPen(_rgba(TEMPLE_GOLD_BRONZE, 140), 1))
            painter.drawEllipse(QPointF(c), radius * 0.72, radius * 0.72)
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
        center_col = QVBoxLayout()
        center_col.addSpacing(65)
        center_col.addWidget(center_card)
        center_col.addStretch(1)
        portal_row.addWidget(gen, 0, Qt.AlignCenter)
        portal_row.addLayout(center_col)
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
        self.toggle_btn.setText("⊘")
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
        if self._show_phrase:
            self.phrase_entry.setEchoMode(QLineEdit.Normal)
            self.toggle_btn.setText("ʘ")
            self.toggle_btn.setStyleSheet(f"color: {TEMPLE_GOLD_SUN}; border: 1px solid {TEMPLE_GOLD_SUN};")
        else:
            self.phrase_entry.setEchoMode(QLineEdit.Password)
            self.toggle_btn.setText("⊘")
            self.toggle_btn.setStyleSheet("")
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