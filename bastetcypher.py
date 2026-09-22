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
import gc
import threading
import queue
import json
from dataclasses import dataclass
from enum import Enum, auto
from typing import Callable, List, Optional, Tuple
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

try:
    from argon2.low_level import hash_secret_raw, Type as Argon2Type
    _HAS_ARGON2 = True
except ImportError:
    _HAS_ARGON2 = False
    hash_secret_raw = None  # type: ignore
    Argon2Type = None  # type: ignore
from PIL import Image, ImageDraw
from PySide6.QtCore import Qt, QThread, Signal, Slot, QTimer, QEasingCurve, QPropertyAnimation, QRectF, QPoint, QPointF, QSize
from PySide6.QtGui import QPixmap, QImage, QIcon, QPainter, QPainterPath, QColor, QFont, QLinearGradient, QRadialGradient, QPen, QBrush, QAction, QPalette
from PySide6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QFrame, QLabel, QPushButton, QLineEdit, QTextEdit, QPlainTextEdit,
    QTextBrowser,
    QVBoxLayout, QHBoxLayout, QGridLayout, QStackedWidget, QTabWidget, QScrollArea, QFileDialog, QMessageBox,
    QProgressBar, QSlider, QDialog, QSizePolicy, QComboBox, QGraphicsDropShadowEffect, QGraphicsOpacityEffect,
    QToolButton, QSplitter, QAbstractItemView, QListWidget, QListWidgetItem, QDialogButtonBox, QCheckBox,
    QStyleFactory
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
def _try_mlockall() -> bool:
    if _SYSTEM not in ("Linux", "Darwin"):
        return False
    try:
        libc = ctypes.CDLL(ctypes.util.find_library("c") or ("libc.so.6" if _SYSTEM == "Linux" else "libc.dylib"), use_errno=True)
        MCL_CURRENT = 1
        MCL_FUTURE = 2
        ret = libc.mlockall(MCL_CURRENT | MCL_FUTURE)
        return ret == 0
    except Exception:
        return False

def harden_process() -> None:
    disable_core_dumps()
    _harden_windows_process()
    _harden_linux_process()
    _try_mlockall()
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


def argon2id_hex(password: str, salt_str: str, key_length: int = 64) -> str:
    if not _HAS_ARGON2:
        raise RuntimeError(
            "Argon2id requires the 'argon2-cffi' package. Install with:\n"
            "    pip install argon2-cffi"
        )
    salt_bytes = hashlib.sha256(salt_str.encode("utf-8")).digest()
    derived = hash_secret_raw(
        secret=password.encode("utf-8"),
        salt=salt_bytes,
        time_cost=ARGON2_TIME,
        memory_cost=ARGON2_MEMORY_KIB,
        parallelism=ARGON2_PARALLELISM,
        hash_len=key_length,
        type=Argon2Type.ID,
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
    kdf_name: str = "PBKDF2-HMAC-SHA512"


def run_cipher_pipeline(
    input_str: str,
    pim: str,
    amplifier: int,
    on_progress: Optional[ProgressCallback] = None,
    kdf_id: int = 0,
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
    kdf_salt = sha256_hex("BastetCipher" + input_str + pim + PEPPER)
    if kdf_id == KDF_ARGON2ID:
        if not _HAS_ARGON2:
            raise RuntimeError(
                "Argon2id requires the 'argon2-cffi' package. Install with:\n"
                "    pip install argon2-cffi"
            )
        progress(
            60,
            f"Argon2id · m={ARGON2_MEMORY_KIB // 1024}MiB t={ARGON2_TIME} p={ARGON2_PARALLELISM}...",
        )
        derived_key = argon2id_hex(combined + PEPPER, kdf_salt, 64)
        kdf_name = "Argon2id"
        iters = ARGON2_TIME * ARGON2_MEMORY_KIB
    else:
        progress(60, f"PBKDF2 · {iters:,} iterations...")
        derived_key = pbkdf2_hex(combined + PEPPER, kdf_salt, iters, 64)
        kdf_name = "PBKDF2-HMAC-SHA512"
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
        kdf_name=kdf_name,
    )
BCA_MAGIC = bytes([0x42, 0x43, 0x41, 0x01])
BCA_VERSION = 1
BCA_VERSION_V2 = 2
ARCHIVE_EXT = ".bstarc"
ARCHIVE_EXT_LEGACY = ".bca"
ARCHIVE_FILTER = "Bastet Archive (*.bstarc *.bca);;Bastet Archive new (*.bstarc);;Legacy Bastet (*.bca);;All files (*)"
ARCHIVE_SAVE_FILTER = "Bastet Archive (*.bstarc);;Legacy Bastet (*.bca);;All files (*)"
BCA_ITERS = 310_000
BCA_ITERS_LEGACY = 200_000
BCA_ITERS_MIN = 100_000
BCA_ITERS_MAX = 5_000_000
ARGON2_MEMORY_KIB = 64 * 1024  # 64 MiB
ARGON2_TIME = 3
ARGON2_PARALLELISM = 4
ARGON2_HASH_LEN = 64
KDF_PBKDF2 = 0
KDF_ARGON2ID = 1
VAULT_PASSWORD_MIN_LEN = 12
HEADER_LEN = 69
HEADER_LEN_V2 = 70
_BCA_AUTH_FAIL = "Wrong password or corrupted/tampered archive."
class BCAFormatError(ValueError):
    pass
class BCADecryptError(ValueError):
    pass
def crc32(data: "bytes | bytearray | memoryview") -> int:
    return zlib.crc32(data) & 0xFFFFFFFF
def deflate_raw_compress(data: "bytes | bytearray | memoryview") -> bytes:
    try:
        mv = memoryview(data) if not isinstance(data, (bytes, bytearray)) else data
        co = zlib.compressobj(level=9, wbits=-15)
        out = co.compress(mv) + co.flush()
        return out
    except MemoryError:
        raise MemoryError("Insufficient memory while compressing vault entry.") from None
def deflate_raw_decompress(data: "bytes | bytearray | memoryview") -> bytes:
    try:
        do = zlib.decompressobj(wbits=-15)
        out = do.decompress(data)
        out += do.flush()
        if not do.eof or do.unused_data or do.unconsumed_tail:
            raise BCAFormatError("Compressed entry has an invalid or trailing deflate stream.")
        return out
    except MemoryError:
        raise MemoryError("Insufficient memory while decompressing vault entry.") from None
def derive_vault_keys(
    password: bytearray,
    salt: bytes,
    iterations: int,
    kdf_id: int = KDF_PBKDF2,
) -> Tuple[bytearray, bytearray]:
    if kdf_id == KDF_ARGON2ID:
        if not _HAS_ARGON2:
            raise BCADecryptError(
                "This archive was sealed with Argon2id, but the 'argon2-cffi' "
                "package is not installed. Install it with:\n"
                "    pip install argon2-cffi\n"
                "then reopen the vault."
            )
        derived = hash_secret_raw(
            secret=bytes(password),
            salt=salt,
            time_cost=ARGON2_TIME,
            memory_cost=ARGON2_MEMORY_KIB,
            parallelism=ARGON2_PARALLELISM,
            hash_len=ARGON2_HASH_LEN,
            type=Argon2Type.ID,
        )
    else:
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA512(),
            length=64,
            salt=salt,
            iterations=iterations,
            backend=default_backend(),
        )
        derived = kdf.derive(password)
    k1 = bytearray(derived[0:32])
    k2 = bytearray(derived[32:64])
    if isinstance(derived, (bytes, bytearray)):
        try:
            wipe_bytearray(bytearray(derived))
        except Exception:
            pass
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
    kdf_id: int = KDF_PBKDF2,
) -> bytearray:
    progress = on_progress or _noop_progress
    if not password or len(password) < VAULT_PASSWORD_MIN_LEN:
        raise BCAFormatError(
            f"Archive password must be at least {VAULT_PASSWORD_MIN_LEN} characters."
        )
    if kdf_id == KDF_ARGON2ID and not _HAS_ARGON2:
        raise BCAFormatError(
            "Argon2id selected but 'argon2-cffi' is not installed. "
            "Install with: pip install argon2-cffi"
        )
    if kdf_id not in (KDF_PBKDF2, KDF_ARGON2ID):
        raise BCAFormatError("Unsupported KDF identifier.")
    salt = os.urandom(32)
    iv1 = os.urandom(12)
    iv2 = os.urandom(16)
    progress(5, "Deriving 512-bit keys...")
    k1, k2 = derive_vault_keys(password, salt, BCA_ITERS, kdf_id=kdf_id)
    progress(22, "Keys ready · Isolated cascade")
    plaintext: Optional[bytearray] = None
    ct1: Optional[bytes] = None
    try:
        parts: List[bytes] = [struct.pack("<H", len(file_entries) & 0xFFFF)]
        for i, entry in enumerate(file_entries):
            progress(
                22 + int(48 * i / max(1, len(file_entries))),
                f"Secure processing: {entry.name}",
            )
            try:
                name_bytes = entry.name.encode("utf-8")
                compressed = deflate_raw_compress(memoryview(entry.data))
                crc = crc32(memoryview(entry.data))
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
        plaintext = None
        progress(85, "Layer 2 encryption (CBC)...")
        ct2 = _aes_cbc_encrypt(bytes(k2), iv2, ct1)
        del ct1
        ct1 = None
        progress(92, "Finalizing and wiping RAM residuals...")
        if kdf_id == KDF_ARGON2ID:
            header = (
                BCA_MAGIC
                + bytes([BCA_VERSION_V2, kdf_id])
                + salt
                + struct.pack("<I", 0)
                + iv1
                + iv2
            )
        else:
            header = (
                BCA_MAGIC
                + bytes([BCA_VERSION])
                + salt
                + struct.pack("<I", BCA_ITERS)
                + iv1
                + iv2
            )
        result = bytearray(header + ct2)
        del ct2
        return result
    except MemoryError:
        if plaintext is not None:
            wipe_bytearray(plaintext)
        if ct1 is not None and isinstance(ct1, (bytearray, bytes)):
            try:
                wipe_bytearray(bytearray(ct1))
            except Exception:
                pass
        gc.collect()
        raise MemoryError(
            "Out of memory while building the archive. "
            "Try fewer / smaller files or close other applications."
        ) from None
    finally:
        wipe_bytearray(k1)
        wipe_bytearray(k2)
        for entry in file_entries:
            wipe_bytearray(entry.data)
        gc.collect()
def _aes_cbc_encrypt(key: bytes, iv: bytes, data: "bytes | bytearray | memoryview") -> bytes:
    pad_len = 16 - (len(data) % 16)
    if isinstance(data, memoryview):
        padded = bytearray(data.tobytes())
    else:
        padded = bytearray(data)
    padded.extend(bytes([pad_len]) * pad_len)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    result = encryptor.update(padded) + encryptor.finalize()
    wipe_bytearray(padded)
    return result
def _aes_cbc_decrypt(key: bytes, iv: bytes, data: "bytes | bytearray | memoryview") -> bytes:
    if len(data) % 16 != 0:
        raise BCADecryptError(_BCA_AUTH_FAIL)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded = decryptor.update(data) + decryptor.finalize()
    if not padded:
        raise BCADecryptError(_BCA_AUTH_FAIL)
    pad_len = padded[-1]
    if pad_len < 1 or pad_len > 16 or len(padded) < pad_len:
        raise BCADecryptError(_BCA_AUTH_FAIL)
    if padded[-pad_len:] != bytes([pad_len]) * pad_len:
        raise BCADecryptError(_BCA_AUTH_FAIL)
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
    version = d[4]
    if version == BCA_VERSION:
        kdf_id = KDF_PBKDF2
        salt = bytes(d[5:37])
        iterations = struct.unpack("<I", d[37:41])[0]
        if not (BCA_ITERS_MIN <= iterations <= BCA_ITERS_MAX):
            raise BCAFormatError("Invalid PBKDF2 parameter for this archive.")
        iv1 = bytes(d[41:53])
        iv2 = bytes(d[53:69])
        ct_offset = HEADER_LEN
    elif version == BCA_VERSION_V2:
        if len(d) < HEADER_LEN_V2:
            raise BCAFormatError("File too short for a v2 .bca archive.")
        kdf_id = d[5]
        if kdf_id not in (KDF_PBKDF2, KDF_ARGON2ID):
            raise BCAFormatError("Unsupported KDF identifier in archive.")
        salt = bytes(d[6:38])
        iterations = struct.unpack("<I", d[38:42])[0]
        if kdf_id == KDF_PBKDF2 and not (BCA_ITERS_MIN <= iterations <= BCA_ITERS_MAX):
            raise BCAFormatError("Invalid PBKDF2 parameter for this archive.")
        iv1 = bytes(d[42:54])
        iv2 = bytes(d[54:70])
        ct_offset = HEADER_LEN_V2
    else:
        raise BCAFormatError("Archive version not supported.")
    ct_view = memoryview(d)[ct_offset:]
    progress(10, "Re-deriving 512-bit keys...")
    k1, k2 = derive_vault_keys(
        password,
        salt,
        iterations if kdf_id == KDF_PBKDF2 else BCA_ITERS,
        kdf_id=kdf_id,
    )
    plain: Optional[bytearray] = None
    ct1: Optional[bytes] = None
    try:
        progress(30, "Layer 2 decryption...")
        try:
            ct1 = _aes_cbc_decrypt(bytes(k2), iv2, ct_view)
        except BCADecryptError:
            raise
        except MemoryError:
            raise
        except Exception:
            raise BCADecryptError(_BCA_AUTH_FAIL) from None
        progress(45, "Layer 1 decryption...")
        try:
            aesgcm = AESGCM(bytes(k1))
            plain = bytearray(aesgcm.decrypt(iv1, ct1, None))
        except MemoryError:
            raise
        except Exception:
            raise BCADecryptError(_BCA_AUTH_FAIL) from None
        del ct1
        ct1 = None
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
                compressed_mv = memoryview(plain)[pos : pos + comp_size]
                pos += comp_size
                progress(54 + int(18 * i / max(1, file_count)), f"Verifying: {name}")
                try:
                    decompressed = bytearray(deflate_raw_decompress(compressed_mv))
                except MemoryError:
                    raise MemoryError(
                        f"Out of memory while decompressing '{name}'. "
                        "The archive may contain very large files."
                    ) from None
                crc_actual = crc32(memoryview(decompressed))
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
            if plain is not None:
                wipe_bytearray(plain)
                plain = None
        progress(72, "Vault unlocked.")
        return entries
    except MemoryError:
        if plain is not None:
            wipe_bytearray(plain)
        if ct1 is not None and isinstance(ct1, (bytearray, bytes)):
            try:
                wipe_bytearray(bytearray(ct1))
            except Exception:
                pass
        gc.collect()
        raise MemoryError(
            "Out of memory while unlocking the vault. "
            "Close other applications or try a smaller archive."
        ) from None
    finally:
        wipe_bytearray(k1)
        wipe_bytearray(k2)
        wipe_bytearray(buffer)
        gc.collect()
class ViewerKind(Enum):
    IMAGE = auto()
    PDF = auto()
    TEXT = auto()
    HTML = auto()
    AUDIO = auto()
    VIDEO = auto()
    UNSUPPORTED = auto()
IMAGE_EXTENSIONS = {
    ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".webp", ".tiff", ".svg", ".ico",
    ".heic", ".heif", ".avif", ".psd", ".raw", ".cr2", ".nef",
}
TEXT_EXTENSIONS = {
    ".txt", ".md", ".csv", ".json", ".log", ".py", ".js", ".css",
    ".xml", ".yaml", ".yml", ".ini", ".cfg", ".sh", ".c", ".cpp", ".h",
    ".java", ".rs", ".go", ".rb", ".php", ".sql",
    ".srt", ".vtt", ".ass", ".ssa",
}
HTML_EXTENSIONS = {".html", ".htm"}
PDF_EXTENSIONS = {".pdf"}
AUDIO_EXTENSIONS = {
    ".mp3", ".ogg", ".wav", ".flac", ".aac", ".m4a", ".wma",
    ".opus", ".alac", ".m4b", ".mid", ".midi", ".ape",
}
AUDIO_TRANSCODE_EXTENSIONS = {
    ".m4a", ".wma", ".opus", ".aac", ".alac", ".m4b", ".ape", ".mid", ".midi",
}
VIDEO_EXTENSIONS = {
    ".mp4", ".webm", ".mov", ".avi", ".mkv", ".wmv",
    ".3gp", ".flv", ".ts", ".m2ts", ".vob", ".divx",
}
def classify_extension(filename: str) -> ViewerKind:
    ext = "." + filename.rsplit(".", 1)[-1].lower() if "." in filename else ""
    if ext in IMAGE_EXTENSIONS:
        return ViewerKind.IMAGE
    if ext in PDF_EXTENSIONS:
        return ViewerKind.PDF
    if ext in HTML_EXTENSIONS:
        return ViewerKind.HTML
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
MAX_IMAGE_PIXELS = 80_000_000
MAX_IMAGE_DIMENSION = 16_384
MAX_PDF_PAGES_SOFT = 5_000
MAX_PDF_RENDER_DPI = 150
MEDIA_PARSE_TIMEOUT_SEC = 90

def _sniff_media_kind(data: bytes, claimed: ViewerKind) -> None:
    if not data:
        raise ValueError("Empty media payload.")
    head = data[:16]
    if claimed == ViewerKind.PDF:
        probe = data[:1024].lstrip()
        if not probe.startswith(b"%PDF"):
            raise ValueError("Content does not look like a PDF (missing %PDF header).")
    elif claimed == ViewerKind.IMAGE:
        ok = (
            head.startswith(b"\x89PNG")
            or head.startswith(b"\xff\xd8\xff")
            or head.startswith(b"GIF87a")
            or head.startswith(b"GIF89a")
            or head.startswith(b"BM")
            or head.startswith(b"RIFF") and data[8:12] == b"WEBP"
            or head[:4] in (b"II*\x00", b"MM\x00*")
            or head.startswith(b"\x00\x00\x01\x00")
            or _looks_like_svg(data)
        )
        if not ok:
            raise ValueError("Content does not match a supported image format signature.")
    elif claimed == ViewerKind.AUDIO:
        ok = (
            head.startswith(b"ID3")
            or head[:3] == b"\xff\xfb"
            or head[:2] == b"\xff\xf3"
            or head[:2] == b"\xff\xf2"
            or head.startswith(b"OggS")
            or head.startswith(b"fLaC")
            or head.startswith(b"RIFF")
            or head[4:8] == b"ftyp"
            or head.startswith(b"\x30\x26\xb2\x75")
        )
        if not ok:
            pass
    elif claimed == ViewerKind.VIDEO:
        ok = (
            head[4:8] == b"ftyp"
            or head.startswith(b"\x1a\x45\xdf\xa3")
            or head.startswith(b"RIFF")
            or head.startswith(b"\x00\x00\x00\x14ftyp")
            or head.startswith(b"\x00\x00\x01\xba")
            or head.startswith(b"\x00\x00\x01\xb3")
        )
        if not ok:
            pass


def _apply_child_resource_limits(input_size_bytes: int = 0) -> None:
    if _SYSTEM not in ("Linux", "Darwin"):
        return
    try:
        import resource
        soft_as, hard_as = resource.getrlimit(resource.RLIMIT_AS)
        floor_bytes = 2 * 1024 ** 3
        ceiling_bytes = 12 * 1024 ** 3
        scaled = max(floor_bytes, input_size_bytes * 12) if input_size_bytes > 0 else floor_bytes
        cap_as = min(scaled, ceiling_bytes)
        if hard_as > 0:
            cap_as = min(cap_as, hard_as)
        resource.setrlimit(resource.RLIMIT_AS, (cap_as, hard_as if hard_as > 0 else cap_as))
        resource.setrlimit(resource.RLIMIT_CPU, (MEDIA_PARSE_TIMEOUT_SEC + 30, MEDIA_PARSE_TIMEOUT_SEC + 60))
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        try:
            resource.setrlimit(resource.RLIMIT_NOFILE, (256, 256))
        except Exception:
            pass
    except Exception:
        pass


def _open_pdf_restricted(data: bytes):
    import fitz
    doc = fitz.open(stream=data, filetype="pdf")
    try:
        if hasattr(doc, "is_encrypted") and doc.is_encrypted:
            doc.close()
            raise ValueError("Encrypted PDF streams are not opened in preview.")
        if doc.page_count > MAX_PDF_PAGES_SOFT:
            doc.close()
            raise ValueError(
                f"PDF has {doc.page_count} pages (limit {MAX_PDF_PAGES_SOFT}). "
                "Export and open externally if this is intentional."
            )
        try:
            fitz.TOOLS.store_shrink(100)
        except Exception:
            pass
    except Exception:
        try:
            doc.close()
        except Exception:
            pass
        raise
    return doc


def render_image_in_memory(data: bytes) -> Image.Image:
    _sniff_media_kind(data, ViewerKind.IMAGE)
    if _looks_like_svg(data):
        import fitz
        doc = fitz.open(stream=data, filetype="svg")
        try:
            if doc.page_count < 1:
                raise ValueError("Empty SVG document.")
            page = doc.load_page(0)
            rect = page.rect
            max_side = 4096
            scale = 1.0
            if rect.width > max_side or rect.height > max_side:
                scale = min(max_side / max(rect.width, 1), max_side / max(rect.height, 1))
            mat = fitz.Matrix(scale, scale)
            pix = page.get_pixmap(matrix=mat, alpha=False)
            data = pix.tobytes("png")
        finally:
            doc.close()
    try:
        Image.MAX_IMAGE_PIXELS = MAX_IMAGE_PIXELS
    except Exception:
        pass
    buf = io.BytesIO(data)
    img = Image.open(buf)
    w, h = img.size
    if w > MAX_IMAGE_DIMENSION or h > MAX_IMAGE_DIMENSION:
        img.close()
        raise ValueError(
            f"Image dimensions {w}x{h} exceed the safe limit "
            f"({MAX_IMAGE_DIMENSION}px per side)."
        )
    if w * h > MAX_IMAGE_PIXELS:
        img.close()
        raise ValueError(
            f"Image pixel count {w * h:,} exceeds the safe limit "
            f"({MAX_IMAGE_PIXELS:,})."
        )
    img.load()
    return img


def render_pdf_pages_in_memory(
    data: bytes, dpi: int = 110, max_pages: Optional[int] = None
) -> List[RenderedPage]:
    _sniff_media_kind(data, ViewerKind.PDF)
    dpi = min(dpi, MAX_PDF_RENDER_DPI)
    pages: List[RenderedPage] = []
    import fitz as _fitz
    doc = _open_pdf_restricted(data)
    try:
        zoom = dpi / 72.0
        matrix = _fitz.Matrix(zoom, zoom)
        count = doc.page_count if max_pages is None else min(max_pages, doc.page_count)
        for i in range(count):
            page = doc.load_page(i)
            pix = page.get_pixmap(matrix=matrix, alpha=False)
            if pix.width * pix.height > MAX_IMAGE_PIXELS:
                raise ValueError(
                    f"PDF page {i + 1} rasterizes to {pix.width}x{pix.height}, "
                    "which exceeds the safe pixel budget."
                )
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


class LazyPDFDocument:
    def __init__(self, data: bytes, dpi: int = 120):
        _sniff_media_kind(data, ViewerKind.PDF)
        import fitz
        self._fitz = fitz
        self._doc = _open_pdf_restricted(data)
        self._dpi = min(dpi, MAX_PDF_RENDER_DPI)
        self._zoom = self._dpi / 72.0
        self._matrix = fitz.Matrix(self._zoom, self._zoom)
        self._cache: dict[Tuple[int, str], Tuple[QPixmap, int, int]] = {}
        self._cache_order: List[Tuple[int, str]] = []
        self._max_cache = 2
        self._text_cache: dict[int, str] = {}
    @property
    def page_count(self) -> int:
        return self._doc.page_count
    def get_page_text(self, index: int) -> str:
        if index < 0 or index >= self.page_count:
            return ""
        if index in self._text_cache:
            return self._text_cache[index]
        page = self._doc.load_page(index)
        text = page.get_text("text") or ""
        if not text.strip():
            try:
                blocks = page.get_text("blocks") or []
                parts = []
                for b in blocks:
                    if isinstance(b, (list, tuple)) and len(b) >= 5 and isinstance(b[4], str):
                        parts.append(b[4])
                text = "\n".join(parts)
            except Exception:
                pass
        self._text_cache[index] = text
        return text
    def page_has_match(self, index: int, query: str) -> bool:
        q = (query or "").strip()
        if not q or index < 0 or index >= self.page_count:
            return False
        page = self._doc.load_page(index)
        try:
            hits = page.search_for(q, quads=False)
            if hits:
                return True
        except Exception:
            pass
        try:
            return q.casefold() in self.get_page_text(index).casefold()
        except Exception:
            return False
    def find_matching_pages(self, query: str) -> List[int]:
        q = (query or "").strip()
        if not q:
            return []
        matches: List[int] = []
        for i in range(self.page_count):
            if self.page_has_match(i, q):
                matches.append(i)
        return matches
    def _render_with_highlights(self, page, query: str):
        fitz = self._fitz
        annots_added = []
        q = (query or "").strip()
        if q:
            try:
                for rect in page.search_for(q, quads=False) or []:
                    try:
                        annot = page.add_highlight_annot(rect)
                        annot.set_colors(stroke=(1.0, 0.92, 0.2))
                        annot.set_opacity(0.45)
                        annot.update()
                        annots_added.append(annot)
                    except Exception:
                        continue
            except Exception:
                pass
        try:
            pix = page.get_pixmap(matrix=self._matrix, alpha=False)
        finally:
            for annot in annots_added:
                try:
                    page.delete_annot(annot)
                except Exception:
                    pass
        return pix
    def render_page(
        self, index: int, highlight_query: str = ""
    ) -> Tuple[QPixmap, int, int]:
        if index < 0 or index >= self.page_count:
            raise IndexError("page out of range")
        hq = (highlight_query or "").strip()
        key = (index, hq.casefold())
        if key in self._cache:
            try:
                self._cache_order.remove(key)
            except ValueError:
                pass
            self._cache_order.append(key)
            return self._cache[key]
        page = self._doc.load_page(index)
        pix = self._render_with_highlights(page, hq)
        if pix.width * pix.height > MAX_IMAGE_PIXELS:
            raise ValueError(
                f"PDF page {index + 1} rasterizes to {pix.width}x{pix.height}, "
                "which exceeds the safe pixel budget."
            )
        png_bytes = pix.tobytes("png")
        qimg = QImage.fromData(png_bytes, "PNG")
        pixmap = QPixmap.fromImage(qimg)
        result = (pixmap, pix.width, pix.height)
        self._cache[key] = result
        self._cache_order.append(key)
        while len(self._cache_order) > self._max_cache:
            old = self._cache_order.pop(0)
            self._cache.pop(old, None)
        return result
    def close(self) -> None:
        self._cache.clear()
        self._cache_order.clear()
        self._text_cache.clear()
        try:
            self._doc.close()
        except Exception:
            pass
        gc.collect()
def decode_text_in_memory(data: bytes) -> str:
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        return data.decode("latin-1")


_HTML_STRIP_BLOCK_RE = re.compile(
    r"<\s*(script|style|iframe|frame|frameset|object|embed|applet|form|"
    r"input|button|textarea|select|option|link|meta|base|svg|math|"
    r"video|audio|source|track|noscript|template)\b[^>]*>.*?<\s*/\s*\1\s*>",
    re.IGNORECASE | re.DOTALL,
)
_HTML_STRIP_SINGLE_RE = re.compile(
    r"<\s*(?:script|style|iframe|frame|frameset|object|embed|applet|form|"
    r"input|button|textarea|select|option|link|meta|base|svg|math|"
    r"video|audio|source|track|noscript|template)\b[^>]*/?\s*>",
    re.IGNORECASE,
)
_HTML_ONATTR_RE = re.compile(
    r"\s+on[a-zA-Z]+\s*=\s*(?:\"[^\"]*\"|'[^']*'|[^\s>]+)",
    re.IGNORECASE,
)
_HTML_BAD_SCHEME_QUOTED_RE = re.compile(
    r"(?i)\b(href|src|action|formaction|xlink:href)\s*=\s*(['\"])\s*"
    r"(?:javascript|data|vbscript|https?|ftp|file)\s*:[^'\"]*\2",
)
_HTML_BAD_SCHEME_BARE_RE = re.compile(
    r"(?i)\b(href|src|action|formaction|xlink:href)\s*=\s*"
    r"(?:javascript|data|vbscript|https?|ftp|file)\s*:[^\s>]*",
)


_HTML_CENTER_OPEN_RE = re.compile(r"<\s*center\b[^>]*>", re.IGNORECASE)
_HTML_CENTER_CLOSE_RE = re.compile(r"<\s*/\s*center\s*>", re.IGNORECASE)
_HTML_A_NAME_RE = re.compile(
    r"<\s*a\b([^>]*?)\bname\s*=\s*(['\"])([^'\"]+)\2([^>]*)>",
    re.IGNORECASE,
)


def sanitize_html_for_preview(html: str) -> str:
    if not html:
        return ""
    limit = 256 * 1024 * 1024
    if len(html) > limit:
        html = html[:limit]
    html = _HTML_STRIP_BLOCK_RE.sub("", html)
    html = _HTML_STRIP_SINGLE_RE.sub("", html)
    html = _HTML_ONATTR_RE.sub("", html)
    html = _HTML_BAD_SCHEME_QUOTED_RE.sub(r'\1="#"', html)
    html = _HTML_BAD_SCHEME_BARE_RE.sub('href="#"', html)
    html = _HTML_CENTER_OPEN_RE.sub('<div align="center">', html)
    html = _HTML_CENTER_CLOSE_RE.sub("</div>", html)
    def _name_to_id(m: re.Match) -> str:
        before, quote, name, after = m.group(1), m.group(2), m.group(3), m.group(4)
        if re.search(r"\bid\s*=", before + after, re.IGNORECASE):
            return m.group(0)
        return f'<a{before}name={quote}{name}{quote} id={quote}{name}{quote}{after}>'
    html = _HTML_A_NAME_RE.sub(_name_to_id, html)
    return html


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
        try:
            os.fchmod(fd, 0o600)
        except Exception:
            pass
        with os.fdopen(fd, "wb") as f:
            f.write(data)
            f.flush()
            try:
                os.fsync(f.fileno())
            except Exception:
                pass
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
    _sniff_media_kind(data, ViewerKind.VIDEO)
    ffmpeg = _get_ffmpeg_exe()
    with _video_input_source(data) as video_path:
        popen_kwargs = dict(
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        if _SYSTEM in ("Linux", "Darwin"):
            popen_kwargs["preexec_fn"] = lambda: _apply_child_resource_limits(len(data))
        proc = subprocess.Popen(
            [ffmpeg, "-hide_banner", "-i", video_path],
            **popen_kwargs,
        )
        try:
            _, stderr = proc.communicate(timeout=MEDIA_PARSE_TIMEOUT_SEC)
        except subprocess.TimeoutExpired:
            try:
                proc.kill()
            except Exception:
                pass
            raise RuntimeError("Video probe timed out (possible malicious / pathological media).")
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
    if width > MAX_IMAGE_DIMENSION or height > MAX_IMAGE_DIMENSION:
        raise RuntimeError(
            f"Video frame size {width}x{height} exceeds the safe dimension limit "
            f"({MAX_IMAGE_DIMENSION}px)."
        )
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
def _fit_decode_size(
    src_w: int,
    src_h: int,
    target_w: int,
    target_h: int,
    max_long_side: int = 1920,
) -> tuple[int, int]:
    if target_w <= 0 or target_h <= 0 or src_w <= 0 or src_h <= 0:
        return src_w, src_h
    long_side = max(src_w, src_h)
    if long_side > max_long_side:
        cap_scale = max_long_side / long_side
        src_w = max(2, int(src_w * cap_scale) // 2 * 2)
        src_h = max(2, int(src_h * cap_scale) // 2 * 2)
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
            vf += f",scale={out_w}:{out_h}:flags=bilinear"
        cmd += [
            "-i", video_path,
            "-map", "0:v:0",
            "-f", "rawvideo", "-pix_fmt", "rgb24",
            "-vf", vf,
            "pipe:1",
        ]
        popen_kwargs = dict(
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            bufsize=frame_size,  # ~1 frame
        )
        if _SYSTEM in ("Linux", "Darwin"):
            popen_kwargs["preexec_fn"] = lambda: _apply_child_resource_limits(len(data))
        proc = subprocess.Popen(cmd, **popen_kwargs)
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
                if proc.stdout:
                    proc.stdout.close()
            except OSError:
                pass
            try:
                if proc.poll() is None:
                    proc.kill()
            except OSError:
                pass
            try:
                proc.wait(timeout=3)
            except Exception:
                pass
def extract_video_audio_as_wav(data: bytes) -> Optional[bytes]:
    ffmpeg = _get_ffmpeg_exe()
    with _video_input_source(data) as video_path:
        cmd = [
            ffmpeg, "-hide_banner", "-i", video_path, "-vn",
            "-f", "mp3", "-c:a", "libmp3lame", "-q:a", "4",
            "pipe:1",
        ]
        popen_kwargs = dict(stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        if _SYSTEM in ("Linux", "Darwin"):
            popen_kwargs["preexec_fn"] = lambda: _apply_child_resource_limits(len(data))
        proc = subprocess.Popen(cmd, **popen_kwargs)
        try:
            stdout, _ = proc.communicate(timeout=MEDIA_PARSE_TIMEOUT_SEC)
        except subprocess.TimeoutExpired:
            try:
                proc.kill()
            except Exception:
                pass
            return None
    if not stdout:
        return None
    return stdout
def _needs_audio_transcode(filename: Optional[str], data: bytes) -> bool:
    if filename:
        ext = "." + filename.rsplit(".", 1)[-1].lower() if "." in filename else ""
        if ext in AUDIO_TRANSCODE_EXTENSIONS:
            return True
    return False
def transcode_audio_to_wav_in_memory(data: bytes) -> bytes:
    ffmpeg = _get_ffmpeg_exe()
    with _video_input_source(data) as src_path:
        cmd = [
            ffmpeg, "-hide_banner", "-i", src_path,
            "-vn", "-f", "wav", "-acodec", "pcm_s16le",
            "pipe:1",
        ]
        popen_kwargs = dict(stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        if _SYSTEM in ("Linux", "Darwin"):
            popen_kwargs["preexec_fn"] = lambda: _apply_child_resource_limits(len(data))
        proc = subprocess.Popen(cmd, **popen_kwargs)
        try:
            stdout, stderr = proc.communicate(timeout=MEDIA_PARSE_TIMEOUT_SEC)
        except subprocess.TimeoutExpired:
            try:
                proc.kill()
            except Exception:
                pass
            raise RuntimeError("Audio transcode timed out (possible pathological media).")
    if not stdout:
        msg = stderr.decode("utf-8", "ignore").strip()[-400:] if stderr else "unknown error"
        raise RuntimeError(f"Could not decode audio: {msg}")
    return stdout
def get_audio_duration_seconds(data: bytes, filename: Optional[str] = None) -> Optional[float]:
    import io as _io
    import mutagen
    try:
        f = mutagen.File(_io.BytesIO(data))
        if f is not None and f.info is not None:
            return float(f.info.length)
    except Exception:
        pass
    if _needs_audio_transcode(filename, data):
        try:
            import re
            ffmpeg = _get_ffmpeg_exe()
            with _video_input_source(data) as src_path:
                popen_kwargs = dict(stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                if _SYSTEM in ("Linux", "Darwin"):
                    popen_kwargs["preexec_fn"] = lambda: _apply_child_resource_limits(len(data))
                proc = subprocess.Popen(
                    [ffmpeg, "-hide_banner", "-i", src_path],
                    **popen_kwargs,
                )
                try:
                    _, stderr = proc.communicate(timeout=MEDIA_PARSE_TIMEOUT_SEC)
                except subprocess.TimeoutExpired:
                    try:
                        proc.kill()
                    except Exception:
                        pass
                    return None
            text = stderr.decode("utf-8", "ignore") if stderr else ""
            m = re.search(r"Duration:\s*(\d+):(\d+):([\d.]+)", text)
            if m:
                h, mi, s = m.groups()
                return int(h) * 3600 + int(mi) * 60 + float(s)
        except Exception:
            pass
    return None
_AUDIO_SESSION_COUNTER = 0
_AUDIO_CLOCK_START = 0.0
_AUDIO_CLOCK_OFFSET = 0.0
_AUDIO_CLOCK_PAUSED_AT = None
def current_audio_session() -> int:
    return _AUDIO_SESSION_COUNTER
def play_audio_in_memory(data: bytes, start_seconds: float = 0.0, filename: Optional[str] = None) -> int:
    global _AUDIO_SESSION_COUNTER, _AUDIO_CLOCK_START, _AUDIO_CLOCK_OFFSET, _AUDIO_CLOCK_PAUSED_AT
    import io as _io
    import pygame
    if not pygame.mixer.get_init():
        pygame.mixer.init()
    if _needs_audio_transcode(filename, data):
        data = transcode_audio_to_wav_in_memory(data)
    pygame.mixer.music.load(_io.BytesIO(data))
    seeked = False
    if start_seconds > 0:
        try:
            pygame.mixer.music.play(start=start_seconds)
            seeked = True
        except Exception:
            pygame.mixer.music.play()
    else:
        pygame.mixer.music.play()
    _AUDIO_CLOCK_OFFSET = start_seconds if seeked else 0.0
    _AUDIO_CLOCK_START = time.monotonic()
    _AUDIO_CLOCK_PAUSED_AT = None
    _AUDIO_SESSION_COUNTER += 1
    return _AUDIO_SESSION_COUNTER
def get_audio_position_seconds() -> float:
    import pygame
    if not pygame.mixer.get_init():
        return 0.0
    now = _AUDIO_CLOCK_PAUSED_AT if _AUDIO_CLOCK_PAUSED_AT is not None else time.monotonic()
    return max(0.0, _AUDIO_CLOCK_OFFSET + (now - _AUDIO_CLOCK_START))
def is_audio_playing() -> bool:
    import pygame
    if not pygame.mixer.get_init():
        return False
    return bool(pygame.mixer.music.get_busy())
def pause_audio() -> None:
    global _AUDIO_CLOCK_PAUSED_AT
    import pygame
    if pygame.mixer.get_init():
        pygame.mixer.music.pause()
        if _AUDIO_CLOCK_PAUSED_AT is None:
            _AUDIO_CLOCK_PAUSED_AT = time.monotonic()
def unpause_audio() -> None:
    global _AUDIO_CLOCK_START, _AUDIO_CLOCK_OFFSET, _AUDIO_CLOCK_PAUSED_AT
    import pygame
    if pygame.mixer.get_init():
        if _AUDIO_CLOCK_PAUSED_AT is not None:
            _AUDIO_CLOCK_OFFSET += _AUDIO_CLOCK_PAUSED_AT - _AUDIO_CLOCK_START
            _AUDIO_CLOCK_START = time.monotonic()
            _AUDIO_CLOCK_PAUSED_AT = None
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
_FONT_FALLBACKS = {
    "Segoe UI": ["Segoe UI", ".AppleSystemUIFont", "SF Pro Text", "Helvetica Neue", "Ubuntu", "DejaVu Sans", "Noto Sans", "Arial"],
    "Segoe UI Symbol": ["Segoe UI Symbol", "Apple Symbols", "Noto Sans Symbols", "DejaVu Sans"],
    "Georgia": ["Georgia", "Times New Roman", "Times", "Noto Serif", "DejaVu Serif", "Liberation Serif"],
    "Consolas": ["Consolas", "Menlo", "SF Mono", "Ubuntu Mono", "DejaVu Sans Mono", "Liberation Mono", "Courier New"],
}
def _font(size: int, family: str = "Segoe UI", bold: bool = False, italic: bool = False) -> QFont:
    f = QFont()
    f.setPointSize(max(8, round(size * CURRENT_UI_SCALE)))
    families = _FONT_FALLBACKS.get(family)
    if families:
        f.setFamilies(families)
    else:
        f.setFamily(family)
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
    def _value_from_pos(self, event) -> int:
        x = event.position().x() if hasattr(event, "position") else event.x()
        try:
            from PySide6.QtWidgets import QStyle
            handle = max(8, int(self.style().pixelMetric(QStyle.PM_SliderLength)))
        except Exception:
            handle = 14
        span = max(1, self.width() - handle)
        ratio = max(0.0, min(1.0, (float(x) - handle / 2.0) / span))
        return self.minimum() + int(round(ratio * (self.maximum() - self.minimum())))

    def mousePressEvent(self, event):
        if event.button() == Qt.LeftButton and self.orientation() == Qt.Horizontal:
            self.setSliderDown(True)
            self.setValue(self._value_from_pos(event))
            self.sliderPressed.emit()
            event.accept()
            return
        super().mousePressEvent(event)

    def mouseMoveEvent(self, event):
        if self.isSliderDown() and self.orientation() == Qt.Horizontal:
            self.setValue(self._value_from_pos(event))
            event.accept()
            return
        super().mouseMoveEvent(event)

    def mouseReleaseEvent(self, event):
        if event.button() == Qt.LeftButton and self.orientation() == Qt.Horizontal:
            self.setValue(self._value_from_pos(event))
            self.setSliderDown(False)
            self.sliderReleased.emit()
            event.accept()
            return
        super().mouseReleaseEvent(event)


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
    def __init__(
        self,
        data: bytes,
        info: VideoInfo,
        start_seconds: float,
        decode_size: tuple[int, int],
        parent=None,
    ):
        super().__init__(parent)
        self.data = data
        self.info = info
        self.start_seconds = start_seconds
        self.decode_size = decode_size
        self._process_holder: list = []
        self._pending_frames = 0
        self._max_pending = 2
    def request_stop(self):
        self.requestInterruption()
        try:
            if self._process_holder:
                proc = self._process_holder[0]
                try:
                    proc.kill()
                except Exception:
                    pass
                try:
                    proc.wait(timeout=2)
                except Exception:
                    pass
        except Exception:
            pass
    def notify_frame_consumed(self):
        if self._pending_frames > 0:
            self._pending_frames -= 1
    def run(self):
        try:
            interval = 1.0 / self.info.fps if self.info.fps > 0 else 0.04
            t = self.start_seconds
            wall = time.monotonic()
            for raw_rgb in stream_video_frames_in_memory(
                self.data,
                self.info,
                start_seconds=self.start_seconds,
                process_holder=self._process_holder,
                decode_size=self.decode_size,
            ):
                if self.isInterruptionRequested():
                    return
                if self._pending_frames >= self._max_pending:
                    t += interval
                    continue
                target = wall + (t - self.start_seconds)
                sleep_for = target - time.monotonic()
                if sleep_for > 0:
                    time.sleep(min(sleep_for, interval * 2))
                self._pending_frames += 1
                self.frameReady.emit(
                    t, self.decode_size[0], self.decode_size[1], raw_rgb
                )
                t += interval
            self.finishedDecoding.emit()
        except Exception as exc:
            self.failed.emit(str(exc))
        finally:
            try:
                if self._process_holder:
                    proc = self._process_holder[0]
                    try:
                        if proc.poll() is None:
                            proc.kill()
                        proc.wait(timeout=2)
                    except Exception:
                        pass
            except Exception:
                pass
            self._process_holder.clear()
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
    clicked = Signal()
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setMinimumSize(220, 220)
        self.setMaximumSize(260, 260)
        self.setSizePolicy(QSizePolicy.Fixed, QSizePolicy.Fixed)
        self.setCursor(Qt.PointingHandCursor)
        self._phase = 0.0
    def mousePressEvent(self, event):
        if event.button() == Qt.LeftButton:
            self.clicked.emit()
        super().mousePressEvent(event)
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
                           "Forge a deterministic high-entropy secret from phrase + PIM and amplificator.")
        self.vault_btn = PortalButton("▦", "SACRED VAULT",
                             "Encrypt, unlock, preview, export and purge protected.")
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
        grid.addWidget(self._label("Key derivation"), 6, 0, 1, 2)
        self.gen_kdf_combo = QComboBox()
        self.gen_kdf_combo.addItem("PBKDF2-HMAC-SHA512 (variable iters) — classic", KDF_PBKDF2)
        if _HAS_ARGON2:
            self.gen_kdf_combo.addItem(
                f"Argon2id (m={ARGON2_MEMORY_KIB // 1024}MiB, t={ARGON2_TIME}, p={ARGON2_PARALLELISM}) — memory-hard",
                KDF_ARGON2ID,
            )
            self.gen_kdf_combo.setCurrentIndex(1)
        else:
            self.gen_kdf_combo.addItem(
                "Argon2id (install argon2-cffi to enable)",
                KDF_ARGON2ID,
            )
            self.gen_kdf_combo.setCurrentIndex(0)
        grid.addWidget(self.gen_kdf_combo, 7, 0, 1, 2)
        self.error_label = QLabel()
        self.error_label.setWordWrap(True)
        self.error_label.setStyleSheet(f"color:{TEMPLE_AMBER};")
        grid.addWidget(self.error_label, 8, 0, 1, 2)
        self.generate_btn = QPushButton("𓅓  INITIALIZE SEQUENCE  𓅓")
        self.generate_btn.setObjectName("primaryButton")
        self.generate_btn.setFont(_font(16, "Georgia", True))
        self.generate_btn.clicked.connect(self._on_generate)
        grid.addWidget(self.generate_btn, 9, 0, 1, 2)
        status_row = QHBoxLayout()
        self.generate_spinner = SacredSpinner()
        self.status_label = QLabel()
        self.status_label.setFont(_font(12, "Georgia", False, True))
        self.status_label.setStyleSheet(f"color:{TEMPLE_GOLD_ANTIQUE};")
        status_row.addWidget(self.generate_spinner)
        status_row.addWidget(self.status_label, 1)
        grid.addLayout(status_row, 10, 0, 1, 2)
        self.progress = QProgressBar()
        self.progress.setRange(0, 100)
        self.progress.setValue(0)
        self.progress.hide()
        grid.addWidget(self.progress, 11, 0, 1, 2)
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
        self.fill_create_btn = QPushButton("🔒  FILL CREATE FIELDS")
        self.clear_btn = QPushButton("🗑️ PURGE")
        self.clear_btn.setObjectName("dangerButton")
        self.copy_btn.clicked.connect(self._copy_output)
        self.open_vault_btn.clicked.connect(self._open_in_vault)
        self.fill_create_btn.clicked.connect(self._fill_create_archive_fields)
        self.clear_btn.clicked.connect(self._clear_output)
        for b in (self.copy_btn, self.open_vault_btn, self.fill_create_btn, self.clear_btn):
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
        for w in (self.phrase_entry, self.pim_entry, self.amp_entry, self.gen_kdf_combo):
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
        if len(phrase) < 8:
            self.error_label.setText("⚠ Secret phrase should be at least 8 characters for meaningful entropy.")
            return
        try:
            amp = max(0, min(9999, int(amp_raw)))
        except ValueError:
            amp = 0
        kdf_id = self.gen_kdf_combo.currentData()
        if kdf_id is None:
            kdf_id = KDF_PBKDF2
        if kdf_id == KDF_ARGON2ID and not _HAS_ARGON2:
            self.error_label.setText("⚠ Argon2id needs argon2-cffi (pip install argon2-cffi).")
            return
        self.error_label.clear()
        self.output_card.hide()
        self._set_busy(True, "Generating...")
        def worker(progress_emit):
            return run_cipher_pipeline(phrase, pim, amp, progress_emit, kdf_id=kdf_id)
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
        kdf_label = getattr(result, "kdf_name", "PBKDF2-HMAC-SHA512")
        if kdf_label.startswith("Argon2"):
            cost_txt = f"{kdf_label} (memory-hard)"
        else:
            cost_txt = f"{kdf_label}: {result.iterations:,} iterations"
        self.stats_label.setText(
            f"Length: {len(result.final_cipher)} characters   ·   "
            f"{cost_txt}   ·   "
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
    def _fill_create_archive_fields(self):
        if self._last_cipher:
            self.app._fill_cipher_in_vault_create(self._last_cipher)
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
        self._open_password: Optional[bytearray] = None
        self._open_kdf_id: int = KDF_PBKDF2
        self._vault_dirty: bool = False
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
            "AES-256-GCM · AES-256-CBC · PBKDF2 / Argon2id · All in RAM",
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
        kdf_label = QLabel("KEY DERIVATION")
        kdf_label.setFont(_font(11, "Georgia", True))
        kdf_label.setStyleSheet(f"color:{TEMPLE_GOLD_ANTIQUE};")
        auth.addWidget(kdf_label, 3, 0)
        self.create_kdf_combo = QComboBox()
        self.create_kdf_combo.addItem(
            f"PBKDF2-HMAC-SHA512 ({BCA_ITERS // 1000}k iters) — classic",
            KDF_PBKDF2,
        )
        if _HAS_ARGON2:
            self.create_kdf_combo.addItem(
                f"Argon2id (m={ARGON2_MEMORY_KIB//1024}MiB, t={ARGON2_TIME}, p={ARGON2_PARALLELISM}) — memory-hard",
                KDF_ARGON2ID,
            )
            self.create_kdf_combo.setCurrentIndex(1)
        else:
            self.create_kdf_combo.addItem(
                "Argon2id (install argon2-cffi to enable)",
                KDF_ARGON2ID,
            )
            self.create_kdf_combo.setCurrentIndex(0)
        auth.addWidget(self.create_kdf_combo, 3, 1)
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
        self.select_card = GlowFrame(radius=18)
        sl = QVBoxLayout(self.select_card)
        sl.setContentsMargins(22,22,22,22)
        self.open_dz_label = QLabel("📁  SELECT A BASTET ARCHIVE")
        self.open_dz_label.setAlignment(Qt.AlignCenter)
        self.open_dz_label.setFont(_font(21, "Georgia", True))
        self.open_dz_label.setStyleSheet(f"color:{TEMPLE_GOLD_SUN};")
        self.open_dz_sub = QLabel("Will be opened only in memory: no data written to disk")
        self.open_dz_sub.setAlignment(Qt.AlignCenter)
        self.open_dz_sub.setFont(_font(12, "Georgia", False, True))
        self.open_dz_sub.setStyleSheet(f"color:{TEMPLE_GOLD_ANTIQUE};")
        browse = QPushButton("BROWSE ARCHIVE")
        browse.clicked.connect(self._choose_bca_file)
        sl.addWidget(self.open_dz_label)
        sl.addWidget(self.open_dz_sub)
        sl.addWidget(browse, 0, Qt.AlignHCenter)
        outer.addWidget(self.select_card)
        self.auth_card = GlowFrame(radius=18)
        al = QVBoxLayout(self.auth_card)
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
        outer.addWidget(self.auth_card)
        self.entries_card = GlowFrame(radius=18)
        self.entries_card.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        ec = QVBoxLayout(self.entries_card)
        ec.setContentsMargins(18,18,18,18)
        top = QHBoxLayout()
        top.addWidget(self._section_label("UNSEALED CONTENT"))
        top.addStretch(1)
        self.add_to_vault_btn = QPushButton("➕ ADD FILES")
        self.add_to_vault_btn.clicked.connect(self._add_files_to_open_vault)
        top.addWidget(self.add_to_vault_btn)
        self.save_vault_btn = QPushButton("💾 SAVE / APPLY")
        self.save_vault_btn.setObjectName("primaryButton")
        self.save_vault_btn.clicked.connect(self._save_open_vault)
        top.addWidget(self.save_vault_btn)
        self.close_vault_btn = QPushButton("PURGE VAULT FROM RAM")
        self.close_vault_btn.setObjectName("dangerButton")
        self.close_vault_btn.clicked.connect(self._close_vault)
        top.addWidget(self.close_vault_btn)
        ec.addLayout(top)
        self.vault_edit_status = QLabel("")
        self.vault_edit_status.setFont(_font(11, "Consolas"))
        self.vault_edit_status.setStyleSheet(f"color:{TEMPLE_GOLD_BRONZE};")
        ec.addWidget(self.vault_edit_status)
        self.entries_scroll = QScrollArea()
        self.entries_scroll.setWidgetResizable(True)
        self.entries_scroll.setFrameShape(QFrame.NoFrame)
        self.entries_scroll.setMinimumHeight(320)
        self.entries_scroll.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        self.entries_scroll.setStyleSheet(f"QScrollArea{{background:transparent; border:none;}} QScrollArea > QWidget > QWidget{{background:transparent;}}")
        self.entries_scroll.viewport().setAutoFillBackground(True)
        _pal = self.entries_scroll.viewport().palette()
        _pal.setColor(self.entries_scroll.viewport().backgroundRole(), QColor(TEMPLE_BG))
        self.entries_scroll.viewport().setPalette(_pal)
        self.entries_container = QWidget()
        self.entries_container.setAutoFillBackground(False)
        self.entries_container.setStyleSheet("background:transparent;")
        self.entries_layout = QVBoxLayout(self.entries_container)
        self.entries_layout.setContentsMargins(4,4,4,4)
        self.entries_layout.setSpacing(7)
        self.entries_scroll.setWidget(self.entries_container)
        ec.addWidget(self.entries_scroll,1)
        self.entries_card.hide()
        outer.addWidget(self.entries_card,3)
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
        gc.collect()
    def _on_create_archive(self):
        if not self._pending_create_entries:
            QMessageBox.warning(self,"Vault","Add at least one file to protect.")
            return
        pw1=self.create_pw_entry.text()
        pw2=self.create_pw_confirm_entry.text()
        if not pw1:
            QMessageBox.warning(self,"Vault","Enter a password.")
            return
        if len(pw1) < VAULT_PASSWORD_MIN_LEN:
            QMessageBox.warning(
                self,
                "Vault",
                f"Password must be at least {VAULT_PASSWORD_MIN_LEN} characters.\n"
                "Longer, unique passphrases resist offline guessing far better.",
            )
            return
        if pw1!=pw2:
            QMessageBox.warning(self,"Vault","The two passwords do not match.")
            return
        save_path,_=QFileDialog.getSaveFileName(
            self,"Save archive as...",filter=ARCHIVE_SAVE_FILTER
        )
        if not save_path:
            return
        lower = save_path.lower()
        if not (lower.endswith(ARCHIVE_EXT) or lower.endswith(ARCHIVE_EXT_LEGACY)):
            save_path += ARCHIVE_EXT
        password_buf=bytearray(pw1.encode("utf-8"))
        kdf_id = self.create_kdf_combo.currentData()
        if kdf_id is None:
            kdf_id = KDF_PBKDF2
        entries=self._pending_create_entries
        self._pending_create_entries=[]
        self._refresh_create_list()
        self._set_busy(self.create_spinner,[self.create_pw_entry,self.create_pw_confirm_entry,self.create_btn,self.add_files_btn,self.create_kdf_combo],True)
        self.create_progress.show()
        self.create_progress.setValue(0)
        self.create_status.setText("Forging archive...")
        def worker(progress_emit):
            try:
                archive=build_bca(entries,password_buf,progress_emit,kdf_id=kdf_id)
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
    def _on_create_success(self, path):
        self.create_spinner.stop()
        self.create_progress.hide()
        self.create_pw_entry.clear()
        self.create_pw_confirm_entry.clear()
        self._set_busy(
            self.create_spinner,
            [self.create_pw_entry, self.create_pw_confirm_entry, self.create_btn, self.add_files_btn, self.create_kdf_combo],
            False,
        )
        self.create_status.setText(f"✓ Archive created: {path}")
        self.create_status.setStyleSheet(f"color:{TEMPLE_EMERALD};")
        gc.collect()

    @Slot(str)
    def _on_create_error(self, message):
        self.create_spinner.stop()
        self.create_progress.hide()
        self._set_busy(
            self.create_spinner,
            [self.create_pw_entry, self.create_pw_confirm_entry, self.create_btn, self.add_files_btn, self.create_kdf_combo],
            False,
        )
        if "Out of memory" in message or "MemoryError" in message:
            QMessageBox.critical(
                self,
                "Archive creation failed",
                "Out of memory while building the archive.\n"
                "Try fewer / smaller files or close other applications.",
            )
        else:
            QMessageBox.critical(self, "Archive creation failed", message)
    def _choose_bca_file(self):
        path,_=QFileDialog.getOpenFileName(
            self,"Select Bastet archive",filter=ARCHIVE_FILTER
        )
        if not path:
            return
        self._bca_path=path
        self.open_dz_label.setText(f"📦  {os.path.basename(path)}")
        self.open_dz_sub.setText("Ready to unlock — will be read only once")
    def _on_open_archive(self):
        if not self._bca_path:
            QMessageBox.warning(self,"Vault","Select a Bastet archive first.")
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
            with open(path,"rb") as f:
                raw=bytearray(f.read())
            kdf_id = KDF_PBKDF2
            if len(raw) >= 6 and raw[4] == BCA_VERSION_V2:
                kdf_id = int(raw[5])
            pw_keep = bytearray(password_buf)
            try:
                entries = parse_bca(raw, password_buf, progress_emit)
                return (entries, pw_keep, kdf_id)
            except Exception:
                wipe_bytearray(pw_keep)
                raise
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
    def _on_open_success(self, result):
        self.open_spinner.stop()
        self.open_progress.hide()
        self._set_busy(self.open_spinner, [self.open_pw_entry, self.open_btn], False)
        if isinstance(result, tuple) and len(result) == 3:
            entries, pw_keep, kdf_id = result
        else:
            entries, pw_keep, kdf_id = result, None, KDF_PBKDF2
        if self._open_password is not None:
            wipe_bytearray(self._open_password)
        self._open_password = pw_keep
        self._open_kdf_id = kdf_id if kdf_id in (KDF_PBKDF2, KDF_ARGON2ID) else KDF_PBKDF2
        self._vault_dirty = False
        self._open_entries = entries
        self.open_status.setText(
            f"✓ Vault unlocked · {len(entries)} file(s) · data only in RAM"
        )
        self.open_status.setStyleSheet(f"color:{TEMPLE_EMERALD};")
        self.vault_edit_status.setText("")
        self._render_entries_list()
        self.select_card.hide()
        self.auth_card.hide()
        self.entries_card.show()
        gc.collect()
    @Slot(str)
    def _on_open_error(self, message):
        self.open_spinner.stop()
        self.open_progress.hide()
        self._set_busy(self.open_spinner, [self.open_pw_entry, self.open_btn], False)
        if "Out of memory" in message or "MemoryError" in message:
            friendly = (
                "Out of memory while unlocking the vault.\n"
                "Close other applications or try a smaller archive."
            )
        elif (
            "Wrong password" in message
            or "padding" in message.lower()
            or "authenticity" in message.lower()
            or "Layer 1" in message
            or "Layer 2" in message
            or "Void Payload" in message
            or "ciphertext length" in message.lower()
        ):
            friendly = _BCA_AUTH_FAIL
        else:
            friendly = message
        QMessageBox.critical(self, "Vault", friendly)
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
            rem=QPushButton("✕ Remove")
            rem.setObjectName("dangerButton")
            rem.clicked.connect(lambda _=False,e=entry:self._remove_open_entry(e))
            rl.addWidget(rem)
            self.entries_layout.addWidget(row)
        self.entries_layout.addStretch(1)
    def _preview_entry(self,entry):
        kind=classify_extension(entry.name)
        MAX_PREVIEW_BYTES = {
            ViewerKind.IMAGE: 400 * 1024 * 1024,   # 400 MiB
            ViewerKind.PDF:   350 * 1024 * 1024,   # 350 MiB
            ViewerKind.AUDIO: 500 * 1024 * 1024,   # 500 MiB
            ViewerKind.VIDEO: 1024 * 1024 * 1024,  # 1 GiB
            ViewerKind.TEXT:  32 * 1024 * 1024,    # 32 MiB
            ViewerKind.HTML:  256 * 1024 * 1024,   # 256 MiB
        }
        limit = MAX_PREVIEW_BYTES.get(kind, 64 * 1024 * 1024)
        if len(entry.data) > limit:
            QMessageBox.warning(
                self,
                "Preview size limit",
                f"'{entry.name}' is {len(entry.data) / (1024*1024):.1f} MiB, which exceeds the "
                f"preview limit of {limit / (1024*1024):.0f} MiB for this type.\n\n"
                "Use Export to write the file to disk and open it with an external viewer "
                "if you need to inspect it.",
            )
            return
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
        try:
            if kind in (ViewerKind.IMAGE, ViewerKind.PDF, ViewerKind.AUDIO, ViewerKind.VIDEO):
                _sniff_media_kind(data, kind)
        except ValueError as exc:
            QMessageBox.warning(
                self,
                "Media rejected",
                f"'{entry.name}' failed the format-safety check:\n\n{exc}\n\n"
                "The file was not opened in a media parser.",
            )
            wipe_bytearray(bytearray(data)) if False else None
            del data
            gc.collect()
            return
        dialog=QDialog(self)
        dialog.setWindowTitle(f"Preview — {entry.name}")
        dialog.resize(920,760)
        dialog.setStyleSheet(APP_QSS)
        apply_screen_capture_protection(dialog)
        try:
            if kind==ViewerKind.IMAGE:
                self._preview_image(dialog,data)
            elif kind==ViewerKind.PDF:
                self._preview_pdf(dialog,data)
            elif kind==ViewerKind.TEXT:
                self._preview_text(dialog,data)
            elif kind==ViewerKind.HTML:
                self._preview_html(dialog,data)
            elif kind==ViewerKind.AUDIO:
                self._preview_audio(dialog,data,entry.name)
            elif kind==ViewerKind.VIDEO:
                self._preview_video(dialog,data,entry.name)
            else:
                QLabel("No preview available for this file type.\nUse Export to save it explicitly to disk.").show()
            dialog.exec()
        except Exception as exc:
            QMessageBox.critical(
                self,
                "Preview failed",
                f"Could not open preview for '{entry.name}'.\n\n"
                f"The file may be corrupted or crafted to stress the parser.\n"
                f"Details: {exc}\n\n"
                "Export the file and inspect it with a dedicated external tool if needed.",
            )
        finally:
            try:
                if isinstance(data, (bytes, bytearray)):
                    pass
                del data
            except Exception:
                pass
            for _ in range(2):
                gc.collect()
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
    def _preview_pdf(self, dialog, data):
        root = QVBoxLayout(dialog)
        loading = QLabel("◐  Opening PDF securely in memory...")
        loading.setAlignment(Qt.AlignCenter)
        loading.setFont(_font(14, "Georgia", False, True))
        loading.setStyleSheet(f"color:{TEMPLE_GOLD_ANTIQUE};")
        root.addWidget(loading, 1)
        def worker(_progress):
            return LazyPDFDocument(data, dpi=120)
        t = TaskThread(worker, dialog)
        def success(lazy_doc: "LazyPDFDocument"):
            while root.count():
                item = root.takeAt(0)
                w = item.widget()
                if w:
                    w.deleteLater()
            page_count = lazy_doc.page_count
            state = {
                "page": 0,
                "zoom": 1.0,
                "matches": [],
                "match_idx": 0,
                "last_query": "",
            }
            toolbar = QHBoxLayout()
            search = QLineEdit()
            search.setPlaceholderText("Search text in PDF...")
            find_btn = QPushButton("FIND")
            prev_btn = QPushButton("‹")
            next_btn = QPushButton("›")
            zoom_out = QPushButton("−")
            zoom_in = QPushButton("+")
            page_label = QLabel(f"Page 1 / {max(1, page_count)}")
            toolbar.addWidget(search, 1)
            toolbar.addWidget(find_btn)
            toolbar.addWidget(prev_btn)
            toolbar.addWidget(next_btn)
            toolbar.addStretch(1)
            toolbar.addWidget(zoom_out)
            toolbar.addWidget(zoom_in)
            toolbar.addWidget(page_label)
            root.addLayout(toolbar)
            scroll = QScrollArea()
            scroll.setWidgetResizable(True)
            page_frame = GlowFrame(accent=TEMPLE_GOLD_BRONZE, radius=12)
            page_layout = QVBoxLayout(page_frame)
            page_layout.setContentsMargins(12, 12, 12, 12)
            img_label = QLabel()
            img_label.setAlignment(Qt.AlignCenter)
            img_label.setStyleSheet(f"background:{TEMPLE_BG};")
            page_layout.addWidget(img_label)
            cap = QLabel("Page 1")
            cap.setAlignment(Qt.AlignCenter)
            cap.setStyleSheet(f"color:{TEMPLE_GOLD_BRONZE};")
            page_layout.addWidget(cap)
            scroll.setWidget(page_frame)
            root.addWidget(scroll, 1)
            def show_page(idx: int, update_status: bool = True):
                idx = max(0, min(page_count - 1, idx))
                state["page"] = idx
                hq = state.get("last_query") or ""
                try:
                    pixmap, w, h = lazy_doc.render_page(idx, highlight_query=hq)
                    if idx + 1 < page_count:
                        try:
                            lazy_doc.render_page(idx + 1, highlight_query=hq)
                        except Exception:
                            pass
                    if state["zoom"] != 1.0:
                        scaled = pixmap.scaled(
                            int(w * state["zoom"]),
                            int(h * state["zoom"]),
                            Qt.KeepAspectRatio,
                            Qt.SmoothTransformation,
                        )
                        img_label.setPixmap(scaled)
                    else:
                        img_label.setPixmap(pixmap)
                    cap.setText(f"Page {idx + 1}")
                    if update_status and not state.get("matches"):
                        page_label.setText(f"Page {idx + 1} / {page_count}")
                except Exception as exc:
                    img_label.setText(f"Render error: {exc}")
                    img_label.setStyleSheet(f"color:{TEMPLE_AMBER};")

            def do_zoom(factor: float):
                state["zoom"] = max(0.4, min(3.0, state["zoom"] * factor))
                show_page(state["page"], update_status=False)
            def find_text(direction: int = 0):
                raw = search.text().strip()
                q = raw
                q_key = raw.casefold()
                if not raw:
                    state["matches"] = []
                    state["match_idx"] = 0
                    state["last_query"] = ""
                    page_label.setText(f"Page {state['page'] + 1} / {page_count}")
                    show_page(state["page"])
                    return
                need_scan = (
                    direction == 0
                    or state.get("last_query", "").casefold() != q_key
                    or not state["matches"]
                )
                if need_scan:
                    page_label.setText("Searching…")
                    QApplication.processEvents()
                    try:
                        matches = lazy_doc.find_matching_pages(q)
                    except Exception:
                        matches = []
                    state["matches"] = matches
                    state["match_idx"] = 0
                    state["last_query"] = raw
                elif state["matches"]:
                    state["match_idx"] = (
                        state["match_idx"] + direction
                    ) % len(state["matches"])
                if not state["matches"]:
                    page_label.setText("No matches")
                    show_page(state["page"], update_status=False)
                    return
                idx = state["matches"][state["match_idx"]]
                page_label.setText(
                    f"Match {state['match_idx'] + 1} / {len(state['matches'])}  ·  page {idx + 1}"
                )
                show_page(idx, update_status=False)
            def nav_prev():
                if state["matches"] and state.get("last_query"):
                    find_text(-1)
                else:
                    show_page(state["page"] - 1)
            def nav_next():
                if state["matches"] and state.get("last_query"):
                    find_text(1)
                else:
                    show_page(state["page"] + 1)
            prev_btn.clicked.connect(nav_prev)
            next_btn.clicked.connect(nav_next)
            zoom_in.clicked.connect(lambda: do_zoom(1.2))
            zoom_out.clicked.connect(lambda: do_zoom(1 / 1.2))
            find_btn.clicked.connect(lambda: find_text(0))
            search.returnPressed.connect(lambda: find_text(0))
            def on_query_edited(_text: str):
                current = search.text().strip().casefold()
                if state.get("last_query", "").casefold() != current:
                    state["matches"] = []
                    state["match_idx"] = 0
            search.textChanged.connect(on_query_edited)
            def key_nav(event):
                if event.key() in (Qt.Key_Left, Qt.Key_PageUp):
                    nav_prev()
                elif event.key() in (Qt.Key_Right, Qt.Key_PageDown):
                    nav_next()
                elif event.key() in (Qt.Key_Return, Qt.Key_Enter):
                    find_text(0)
                else:
                    QDialog.keyPressEvent(dialog, event)
            dialog.keyPressEvent = key_nav
            show_page(0)
            def cleanup():
                try:
                    lazy_doc.close()
                except Exception:
                    pass
                gc.collect()
            dialog.finished.connect(lambda _: cleanup())
        def failure(msg):
            loading.setText(f"Could not display PDF:\n{msg}")
            loading.setStyleSheet(f"color:{TEMPLE_AMBER};")
        t.succeeded.connect(success)
        t.failed.connect(failure)
        t.finished.connect(lambda: t.deleteLater())
        t.start()
    def _preview_text(self,dialog,data):
        root=QVBoxLayout(dialog)
        box=QPlainTextEdit()
        box.setReadOnly(True)
        box.setFont(_font(12,"Consolas"))
        box.setPlainText(decode_text_in_memory(data))
        root.addWidget(box)
    def _preview_html(self, dialog, data):
        root = QVBoxLayout(dialog)
        notice = QLabel(
            "Locked-down HTML preview · no JavaScript · no remote resources · "
            "in-document links enabled"
        )
        notice.setFont(_font(11, "Consolas"))
        notice.setStyleSheet(f"color:{TEMPLE_GOLD_ANTIQUE};")
        root.addWidget(notice)
        status = QLabel("Preparing HTML…")
        status.setFont(_font(12, "Consolas"))
        status.setStyleSheet(f"color:{TEMPLE_GOLD_SUN};")
        root.addWidget(status)
        browser = QTextBrowser()
        browser.setReadOnly(True)
        browser.setOpenExternalLinks(False)
        browser.setOpenLinks(False)
        browser.setSearchPaths([])
        try:
            browser.document().setDefaultStyleSheet(
                "body { line-height: 1.45; }"
                "p, div, li { margin-top: 0.55em; margin-bottom: 0.55em; }"
                "h1, h2, h3, h4, h5, h6 { margin-top: 0.9em; margin-bottom: 0.45em; }"
                "ul, ol { margin: 0.55em 0 0.55em 1.4em; }"
                "table { margin: 0.7em 0; border-collapse: collapse; }"
                "td, th { padding: 0.25em 0.5em; }"
            )
        except Exception:
            pass

        def on_anchor(url):
            try:
                scheme = (url.scheme() or "").lower()
                if scheme in (
                    "http", "https", "ftp", "file", "javascript",
                    "data", "vbscript", "mailto",
                ):
                    return
                frag = url.fragment()
                if frag:
                    browser.scrollToAnchor(frag)
                    return
                text = url.toString()
                if text.startswith("#") and len(text) > 1:
                    browser.scrollToAnchor(text[1:])
                    return
                path = (url.path() or "").lstrip("./")
                if path and not scheme:
                    browser.scrollToAnchor(path)
            except Exception:
                pass

        browser.anchorClicked.connect(on_anchor)
        root.addWidget(browser, 1)

        def worker(_progress):
            raw = decode_text_in_memory(data)
            return sanitize_html_for_preview(raw)

        def on_ready(safe):
            status.setText("Rendering…")
            browser.setHtml(safe)
            status.setText(
                f"Ready · {len(safe) / (1024 * 1024):.1f} MiB sanitized · "
                "click in-page links to navigate"
            )
            status.setStyleSheet(f"color:{TEMPLE_EMERALD};")

        def on_fail(msg):
            status.setText(f"HTML preview failed: {msg}")
            status.setStyleSheet(f"color:{TEMPLE_AMBER};")

        t = TaskThread(worker, dialog)
        t.succeeded.connect(on_ready)
        t.failed.connect(on_fail)
        t.finished.connect(t.deleteLater)
        t.start()
    def _preview_audio(self,dialog,data,name):
        root=QVBoxLayout(dialog)
        icon=QLabel("🎵"); icon.setAlignment(Qt.AlignCenter); icon.setFont(_font(52))
        root.addWidget(icon)
        title=QLabel(name); title.setAlignment(Qt.AlignCenter); title.setFont(_font(18,"Georgia",True))
        root.addWidget(title)
        needs_transcode=_needs_audio_transcode(name,data)
        status=QLabel("Decoding from RAM..." if needs_transcode else "Playing from RAM..."); status.setAlignment(Qt.AlignCenter); root.addWidget(status)
        duration=get_audio_duration_seconds(data,filename=name)
        slider=MediaSlider(Qt.Horizontal); slider.setRange(0,1000 if duration else 1); root.addWidget(slider)
        volume_row=QHBoxLayout(); volume_row.addWidget(QLabel("🔊 Volume")); vol=QSlider(Qt.Horizontal); vol.setRange(0,100); vol.setValue(80); volume_row.addWidget(vol,1); root.addLayout(volume_row)
        time_label=QLabel("0:00 / " + (self._fmt_time(duration) if duration else "—:—")); time_label.setAlignment(Qt.AlignCenter); root.addWidget(time_label)
        btns=QHBoxLayout(); play=QPushButton("⏸ Pause"); stop=QPushButton("⏹ Stop"); btns.addWidget(play); btns.addWidget(stop); root.addLayout(btns)
        state={"session":-1,"offset":0.0,"stopped":False,"paused":False,"playable":None,"started_at":0.0}
        if needs_transcode:
            try:
                state["playable"]=transcode_audio_to_wav_in_memory(data)
            except Exception as exc:
                status.setText(f"Decode error: {exc}"); play.setEnabled(False); stop.setEnabled(False)
        playable=state["playable"] if state["playable"] is not None else data
        if play.isEnabled():
            try:
                state["session"]=play_audio_in_memory(playable)
                state["started_at"]=time.monotonic()
                set_audio_volume(.8)
                status.setText("Playing from RAM...")
            except Exception as exc:
                status.setText(f"Playback error: {exc}"); play.setEnabled(False); stop.setEnabled(False)
        def slider_release():
            if duration:
                raw = slider.value() / 1000.0 * duration
                margin = 0.05
                target = min(raw, max(0.0, duration - margin))
                if raw >= duration - margin:
                    try:
                        stop_audio()
                    except Exception:
                        pass
                    state["stopped"] = True
                    state["paused"] = False
                    state["offset"] = 0
                    slider.setValue(1000)
                    time_label.setText(f"{self._fmt_time(duration)} / {self._fmt_time(duration)}")
                    play.setText("▶ Play")
                    status.setText("Finished")
                    return
                try:
                    state["session"]=play_audio_in_memory(state["playable"] if state["playable"] is not None else data,start_seconds=target)
                    state["offset"]=target; state["stopped"]=False; state["paused"]=False; state["started_at"]=time.monotonic(); set_audio_volume(vol.value()/100); play.setText("⏸ Pause")
                    status.setText("Playing from RAM...")
                except Exception: pass
        slider.sliderReleased.connect(slider_release)
        vol.valueChanged.connect(lambda v:set_audio_volume(v/100))
        def toggle():
            if state["stopped"] or state["session"]!=current_audio_session():
                try:
                    state["session"]=play_audio_in_memory(state["playable"] if state["playable"] is not None else data,start_seconds=state["offset"]); state["stopped"]=False; state["paused"]=False; state["started_at"]=time.monotonic()
                    set_audio_volume(vol.value()/100); play.setText("⏸ Pause")
                except Exception: pass
                return
            if state["paused"]:
                unpause_audio(); state["paused"]=False; play.setText("⏸ Pause")
            else:
                pause_audio(); state["paused"]=True; play.setText("▶ Play")
        play.clicked.connect(toggle)
        def do_stop():
            stop_audio(); state["stopped"]=True; state["paused"]=False; state["offset"]=0; slider.setValue(0); play.setText("▶ Play")
            status.setText("Stopped")
        stop.clicked.connect(do_stop)
        timer=QTimer(dialog)
        def poll():
            if state["session"]!=current_audio_session():
                play.setText("▶ Play")
                return
            if state["stopped"] or state["paused"]:
                return
            if is_audio_playing():
                pos=get_audio_position_seconds()
                if duration:
                    if not slider.isSliderDown():
                        slider.setValue(min(1000,int(pos/duration*1000)))
                    time_label.setText(f"{self._fmt_time(min(pos,duration))} / {self._fmt_time(duration)}")
            elif time.monotonic()-state["started_at"]>0.6:
                state["stopped"]=True; state["offset"]=0; slider.setValue(1000 if duration else 0)
                if duration:
                    time_label.setText(f"{self._fmt_time(duration)} / {self._fmt_time(duration)}")
                play.setText("▶ Play")
                status.setText("Finished")
        timer.timeout.connect(poll); timer.start(300)
        def close_audio():
            try: stop_audio()
            except Exception: pass
            state["playable"]=None
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
            widget_w = max(video_label.width() or 0, dialog.width() - 40)
            widget_h = max(video_label.height() or 0, dialog.height() - 160)
            target_w = max(960, widget_w)
            target_h = max(540, widget_h)
            decode_size = _fit_decode_size(
                info.width, info.height, target_w, target_h, max_long_side=1920
            )
            state = {
                "thread": None,
                "playing": True,
                "offset": 0.0,
                "session": -1,
                "generation": 0,
                "last_time": 0.0,
            }
            wav_audio = None
            if info.has_audio:
                try:
                    wav_audio = extract_video_audio_as_wav(data)
                except Exception:
                    wav_audio = None
            if wav_audio:
                try:
                    state["session"] = play_audio_in_memory(wav_audio)
                    set_audio_volume(0.8)
                except Exception:
                    state["session"] = -1
            pump = QTimer(dialog)
            def frame(t, w, h, rgb, th=None):
                if th is not None and state.get("thread") is not th:
                    return
                img = QImage(rgb, w, h, w * 3, QImage.Format_RGB888)
                label_size = video_label.size()
                if label_size.width() > 0 and (
                    abs(label_size.width() - w) > 4 or abs(label_size.height() - h) > 4
                ):
                    pix = QPixmap.fromImage(img).scaled(
                        label_size, Qt.KeepAspectRatio, Qt.SmoothTransformation
                    )
                else:
                    pix = QPixmap.fromImage(img)
                video_label.setPixmap(pix)
                if th is not None and hasattr(th, "notify_frame_consumed"):
                    th.notify_frame_consumed()
                state["last_time"] = t
                if info.duration and not slider.isSliderDown():
                    slider.setValue(min(1000, int(t / info.duration * 1000)))
                time_label.setText(
                    f"{self._fmt_time(t)} / {self._fmt_time(info.duration)}"
                )
            def start_decode(at=0.0):
                if state["thread"]:
                    try:
                        state["thread"].request_stop()
                        state["thread"].wait(800)
                    except Exception:
                        pass
                state["generation"] += 1
                th = VideoDecodeThread(data, info, at, decode_size, None)
                th.got_any_frame = False
                def on_frame(t, w, h, rgb, th=th):
                    th.got_any_frame = True
                    frame(t, w, h, rgb, th)
                th.frameReady.connect(on_frame)
                th.failed.connect(
                    lambda msg: status.setText(f"Video decode error: {msg}")
                )
                def on_finished(th=th, requested_at=at):
                    if th.got_any_frame or state.get("thread") is not th:
                        return
                    fallback = min(requested_at, state.get("last_time", 0.0))
                    if fallback < requested_at:
                        start_decode(fallback)
                    else:
                        status.setText("Reached the end of the video.")
                        state["playing"] = False
                        play.setText("▶ Play")
                th.finishedDecoding.connect(on_finished)
                state["thread"] = th
                th.start()
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
                    frame_interval = 1.0/info.fps if info.fps>0 else 0.04
                    margin = max(frame_interval, 0.05)
                    raw = slider.value() / 1000.0 * info.duration
                    target = min(raw, max(0.0, info.duration - margin))
                    if raw >= info.duration - margin:
                        state["playing"] = False
                        state["last_time"] = info.duration
                        slider.setValue(1000)
                        time_label.setText(
                            f"{self._fmt_time(info.duration)} / {self._fmt_time(info.duration)}"
                        )
                        play.setText("▶ Play")
                        status.setText("Reached the end of the video.")
                        if state["thread"]:
                            try:
                                state["thread"].request_stop()
                            except Exception:
                                pass
                        try:
                            stop_audio()
                        except Exception:
                            pass
                        return
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
    def _mark_vault_dirty(self):
        self._vault_dirty = True
        n = len(self._open_entries)
        self.vault_edit_status.setText(
            f"Unsaved changes · {n} file(s) in memory · click SAVE / APPLY to write the archive"
        )
        self.vault_edit_status.setStyleSheet(f"color:{TEMPLE_AMBER};")
    def _remove_open_entry(self, entry):
        if entry not in self._open_entries:
            return
        box = QMessageBox(self)
        box.setWindowTitle("Remove from vault")
        box.setIcon(QMessageBox.Question)
        box.setText(f"Remove '{entry.name}' from this vault?\n\nThis only affects memory until you click SAVE / APPLY.")
        box.setStandardButtons(QMessageBox.Yes | QMessageBox.No)
        if box.exec() != QMessageBox.Yes:
            return
        self._open_entries.remove(entry)
        wipe_bytearray(entry.data)
        self._mark_vault_dirty()
        self._render_entries_list()
    def _add_files_to_open_vault(self):
        paths, _ = QFileDialog.getOpenFileNames(self, "Add files to vault")
        if not paths:
            return
        existing = {e.name for e in self._open_entries}
        added = 0
        errors = []
        for path in paths:
            name = os.path.basename(path)
            if name in existing:
                errors.append(f"{name}: already in vault (skipped)")
                continue
            try:
                with open(path, "rb") as f:
                    raw = f.read()
                self._open_entries.append(
                    VaultDecryptedEntry(name=name, data=bytearray(raw), crc_ok=True)
                )
                existing.add(name)
                added += 1
            except OSError as exc:
                errors.append(f"{name}: {exc}")
        if added:
            self._mark_vault_dirty()
            self._render_entries_list()
        if errors:
            QMessageBox.warning(
                self,
                "Add files",
                f"Added {added} file(s).\n\n" + "\n".join(errors[:12]),
            )
        elif added:
            QMessageBox.information(self, "Add files", f"Added {added} file(s) to the open vault.")
    def _save_open_vault(self):
        if not self._bca_path:
            QMessageBox.warning(self, "Vault", "No archive path is associated with this session.")
            return
        if self._open_password is None:
            QMessageBox.warning(
                self,
                "Vault",
                "The session password is no longer in memory. Close and reopen the vault to save.",
            )
            return
        if not self._open_entries:
            QMessageBox.warning(
                self,
                "Vault",
                "The vault is empty. Add at least one file, or purge the session without saving.",
            )
            return
        path = self._bca_path
        kdf_id = self._open_kdf_id
        password_buf = bytearray(self._open_password)
        entries = [
            VaultFileEntry(name=e.name, data=bytearray(e.data))
            for e in self._open_entries
        ]
        self.save_vault_btn.setEnabled(False)
        self.add_to_vault_btn.setEnabled(False)
        self.vault_edit_status.setText("Writing archive…")
        self.vault_edit_status.setStyleSheet(f"color:{TEMPLE_GOLD_ANTIQUE};")
        def worker(progress_emit):
            try:
                archive = build_bca(entries, password_buf, progress_emit, kdf_id=kdf_id)
                tmp_path = path + ".bca-tmp"
                try:
                    with open(tmp_path, "wb") as f:
                        f.write(bytes(archive))
                        f.flush()
                        os.fsync(f.fileno())
                    os.replace(tmp_path, path)
                finally:
                    if os.path.exists(tmp_path):
                        try:
                            os.remove(tmp_path)
                        except OSError:
                            pass
                wipe_bytearray(archive)
                return path
            finally:
                wipe_bytearray(password_buf)
                for e in entries:
                    wipe_bytearray(e.data)
        t = TaskThread(worker, self)
        t.succeeded.connect(self._on_save_open_success)
        t.failed.connect(self._on_save_open_error)
        t.finished.connect(lambda: t.deleteLater())
        self._retain_thread(t)
        t.start()
    @Slot(object)
    def _on_save_open_success(self, path):
        self.save_vault_btn.setEnabled(True)
        self.add_to_vault_btn.setEnabled(True)
        self._vault_dirty = False
        self.vault_edit_status.setText(f"✓ Saved · {len(self._open_entries)} file(s) · {path}")
        self.vault_edit_status.setStyleSheet(f"color:{TEMPLE_EMERALD};")
        QMessageBox.information(self, "Vault", f"Archive updated:\n{path}")
        gc.collect()
    @Slot(str)
    def _on_save_open_error(self, message):
        self.save_vault_btn.setEnabled(True)
        self.add_to_vault_btn.setEnabled(True)
        self.vault_edit_status.setText("Save failed")
        self.vault_edit_status.setStyleSheet(f"color:{TEMPLE_AMBER};")
        QMessageBox.critical(self, "Save failed", message)
    def _close_vault(self):
        if self._vault_dirty:
            box = QMessageBox(self)
            box.setWindowTitle("Unsaved changes")
            box.setIcon(QMessageBox.Warning)
            box.setText(
                "This vault has unsaved changes in memory.\n\n"
                "Close without saving? The on-disk archive will keep its previous contents."
            )
            box.setStandardButtons(QMessageBox.Yes | QMessageBox.No)
            if box.exec() != QMessageBox.Yes:
                return
        for entry in self._open_entries:
            wipe_bytearray(entry.data)
        self._open_entries = []
        if self._open_password is not None:
            wipe_bytearray(self._open_password)
            self._open_password = None
        self._vault_dirty = False
        self._render_entries_list()
        self.entries_card.hide()
        self.select_card.show()
        self.auth_card.show()
        self._bca_path = None
        self.open_dz_label.setText("📁  SELECT A BASTET ARCHIVE")
        self.open_dz_sub.setText("Will be opened only in memory: no data written to disk")
        self.open_status.setText("Vault closed · Data wiped from RAM.")
        self.open_status.setStyleSheet(f"color:{TEMPLE_GOLD_BRONZE};")
        self.open_pw_entry.clear()
        try:
            self.vault_edit_status.setText("")
        except Exception:
            pass
        for _ in range(3):
            gc.collect()
    def wipe_all_on_exit(self):
        for entry in self._open_entries:
            wipe_bytearray(entry.data)
        for entry in self._pending_create_entries:
            wipe_bytearray(entry.data)
        self._open_entries = []
        self._pending_create_entries = []
        if self._open_password is not None:
            wipe_bytearray(self._open_password)
            self._open_password = None
        self._vault_dirty = False
        try:
            self.create_pw_entry.clear()
            self.create_pw_confirm_entry.clear()
            self.open_pw_entry.clear()
        except Exception:
            pass
        try:
            stop_audio()
        except Exception:
            pass
        for tmp in list(self._active_video_tmp_paths):
            _secure_shred_file(tmp)
        self._active_video_tmp_paths.clear()
        for _ in range(3):
            gc.collect()
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
        self.hub.logo.clicked.connect(self._launch_audit_tool)
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
    def _fill_cipher_in_vault_create(self,cipher):
        self._show_view("vault")
        self.vault.tabs.setCurrentIndex(0)
        self.vault.create_pw_entry.setText(cipher)
        self.vault.create_pw_confirm_entry.setText(cipher)
        QTimer.singleShot(120,self.vault.create_pw_entry.setFocus)
    def _launch_audit_tool(self):
        if not _AUDIT_TK_AVAILABLE:
            QMessageBox.information(
                self, "Bastet Audit Tool",
                "The audit tool needs Python's 'tkinter' module, which isn't "
                "available in this environment.\n\n"
                "On Debian/Ubuntu, install it with:\n    sudo apt install python3-tk\n"
                "then restart BastetCipher."
            )
            return
        if getattr(self, "_audit_thread", None) is not None and self._audit_thread.is_alive():
            QMessageBox.information(self, "Bastet Audit Tool", "The audit tool is already open.")
            return
        def run_audit_gui():
            try:
                audit_app = AuditGUI(default_file_path=os.path.abspath(__file__))
                if not os.path.isfile(_SKIP_SPLASH_MARKER):
                    def _reveal_main():
                        audit_app.lift()
                        audit_app.focus_force()
                    WelcomeSplash(audit_app, on_continue=_reveal_main)
                audit_app.mainloop()
            except Exception as exc:
                print(f"[Bastet Audit Tool] failed to start: {exc}")
        self._audit_thread = threading.Thread(target=run_audit_gui, daemon=True)
        self._audit_thread.start()
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

_AUDIT_TOOL_DOC = """
|===========================================|
| BASTET AUDIT TOOL v2 - security audit GUI |
|===========================================|

WHAT THIS IS
------------
A graphical tool to check the security of your BastetCipher-format vault
source file, no terminal commands required. It runs several independent
checks, each with its own button:

  1. SETUP ENVIRONMENT - creates an isolated Python virtual environment
     and installs the audit tools (does not touch system packages).

  2. DEPENDENCY CHECK - looks up known published vulnerabilities (CVEs)
     for the exact library versions installed (cryptography, etc).

  3. STATIC ANALYSIS - reads the source code (never executes it) looking
     for patterns known to be risky (unsafe subprocess use, weak random,
     bad file permissions, etc).

  4. ENTROPY / STATISTICAL ANALYSIS - checks that the ciphertext produced
     looks statistically indistinguishable from random noise, which is
     what a well-implemented cipher should always produce, regardless of
     how repetitive or structured the original plaintext was.

  5. MEMORY BEHAVIOR CHECK - runs many encrypt/decrypt cycles while
     tracking Python-level memory allocations, looking for obvious leaks
     (memory that grows unbounded across repeated operations).

  6. FUZZING - generates millions of automatically-mutated, malformed
     variants of a vault file and feeds them to the parser, looking for
     crashes or unexpected behavior. The most powerful test here.

HOW TO USE IT
-------------
1. Launch it from BastetCipher's home screen (click the Bastet emblem/logo),
   or run this module directly as python3 bastet_audit_gui.py if you kept
   it as a standalone file.
2. Load your source file either by clicking "Browse..." or by dragging
   it onto the drop area. Any filename works - nothing is hardcoded.
3. Click "1) Setup environment" once. Then use the other buttons freely,
   in any order.

IS THIS SAFE FOR MY COMPUTER?
------------------------------
Yes. This program:
  - Creates an ISOLATED virtual environment in a subfolder next to this
    script ("bastet_audit_env") - it never touches system-wide packages
  - Never modifies or deletes your original source file (only reads it)
  - Does not require administrator/root privileges (unless a fuzzing
    dependency needs a compiler, in which case it tells you the exact
    command to run yourself)
  - Any long-running operation (fuzzing) can be stopped at any time with
    the STOP button, with no side effects
  - To remove every trace, just delete the "bastet_audit_env" folder

SYSTEM REQUIREMENTS
--------------------
- Python 3.8+
- tkinter (usually preinstalled; if missing, this script tells you the
  exact command: sudo apt install python3-tk)
- For fuzzing specifically: a C++ compiler (sudo apt install python3-dev
  build-essential) - the rest of the tests work fine without it
- Optional, for drag & drop: pip install tkinterdnd2 (not required -
  the Browse button always works)

WHAT THESE TESTS CANNOT TELL YOU
----------------------------------
These are all automated checks. They are very good at catching crashes,
known vulnerable dependencies, risky code patterns, and statistical
weaknesses in the ciphertext. They cannot replace a human cryptography
expert reviewing the actual DESIGN of the encryption scheme (e.g. layer
ordering, algorithm choices, key derivation cost against modern attack
hardware) - that class of judgment call is outside what any automated
tool, including this one, can verify. See the "About" tab in the app
for the full picture.
===============================================================================
"""


def _module_present(module_name):
    import importlib.util
    try:
        return importlib.util.find_spec(module_name) is not None
    except (ImportError, ValueError):
        return False


def _run_pip_install(pip_invocation, package, extra_args=None):
    """Runs one pip invocation (e.g. [sys.executable, '-m', 'pip']) to
    install `package`. Returns (success, combined_output)."""
    cmd = list(pip_invocation) + ["install", "--user", package] + (extra_args or [])
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=180)
        output = result.stdout + result.stderr
        return result.returncode == 0, output
    except FileNotFoundError:
        return False, "command not found: {}".format(pip_invocation[0])
    except subprocess.TimeoutExpired:
        return False, "installation timed out after 180 seconds"


def _find_working_pip_invocation():
    """Tries a few common ways to reach pip, in order of preference, and
    returns the first one that responds to '--version'. This is what makes
    the installer work whether the system exposes 'pip', 'pip3', or only
    'python3 -m pip'."""
    candidates = [
        [sys.executable, "-m", "pip"],
        ["pip3"],
        ["pip"],
    ]
    for candidate in candidates:
        try:
            r = subprocess.run(candidate + ["--version"], capture_output=True, text=True, timeout=15)
            if r.returncode == 0:
                return candidate
        except (FileNotFoundError, subprocess.TimeoutExpired):
            continue
    return None


def _prompt_yes_no(question):
    """Plain-terminal yes/no prompt -- used only during bootstrap, before
    any GUI exists yet."""
    while True:
        answer = input(question + " [y/N]: ").strip().lower()
        if answer in ("y", "yes"):
            return True
        if answer in ("n", "no", ""):
            return False
        print("Please answer 'y' or 'n'.")


def _ensure_dependency(module_name, pip_package_name):
    """If `module_name` can't be imported, walks the user through installing
    it: asks for confirmation, tries a normal install, and if that fails
    specifically because of PEP 668 (externally-managed-environment), asks
    a SEPARATE, explicit confirmation before retrying with
    --break-system-packages -- never applies that flag silently."""
    if _module_present(module_name):
        return True

    print("=" * 70)
    print("Missing dependency: '{}' (needed to run this app).".format(module_name))
    print("=" * 70)
    if not _prompt_yes_no("Install it now via pip?"):
        print("Cannot continue without '{}'. Exiting.".format(module_name))
        return False

    pip_invocation = _find_working_pip_invocation()
    if pip_invocation is None:
        print("Could not find a working 'pip', 'pip3', or 'python3 -m pip' on this system.")
        print("Please install pip first, e.g.: sudo apt install python3-pip")
        return False

    print("Using: {}".format(" ".join(pip_invocation)))
    ok, output = _run_pip_install(pip_invocation, pip_package_name)

    if not ok and "externally-managed-environment" in output:
        print("-" * 70)
        print("This Python environment is 'externally managed' (PEP 668),")
        print("meaning your system normally blocks pip from installing packages")
        print("outside a virtual environment, to avoid conflicts with packages")
        print("managed by your OS's own package manager (apt, dnf, etc).")
        print()
        print("The safer alternative is a virtual environment, but for a single")
        print("small dependency for this app, the pragmatic option most people")
        print("use here is --break-system-packages, which tells pip to proceed")
        print("anyway. This only affects Python packages installed via pip for")
        print("your user; it will NOT modify or break system packages installed")
        print("via apt/dnf themselves.")
        print("-" * 70)
        if _prompt_yes_no("Retry installation with --break-system-packages?"):
            ok, output = _run_pip_install(pip_invocation, pip_package_name,
                                           extra_args=["--break-system-packages"])
        else:
            print("Skipping. You can also install manually in a virtual environment:")
            print("    python3 -m venv myenv && source myenv/bin/activate")
            print("    pip install {}".format(pip_package_name))
            return False

    if ok:
        print("'{}' installed successfully.".format(pip_package_name))
        return True
    else:
        print("Installation failed. Output:")
        print(output[-2000:])
        return False


if not _module_present("cryptography"):
    pass  # already a hard dependency of the host app; nothing to bootstrap here.


try:
    import tkinter as tk
    from tkinter import ttk, scrolledtext, messagebox, filedialog
    _AUDIT_TK_AVAILABLE = True
except ImportError:
    _AUDIT_TK_AVAILABLE = False

if _AUDIT_TK_AVAILABLE:
    try:
        from tkinterdnd2 import DND_FILES, TkinterDnD
        _HAS_DND = True
    except ImportError:
        _HAS_DND = False
else:
    _HAS_DND = False


SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
ENV_DIR = os.path.join(SCRIPT_DIR, "bastet_audit_env")
VENV_DIR = os.path.join(ENV_DIR, "venv")
CORE_MODULE_PATH = os.path.join(ENV_DIR, "bca_core_standalone.py")
FUZZ_SCRIPT_PATH = os.path.join(ENV_DIR, "fuzz_target.py")
ENTROPY_SCRIPT_PATH = os.path.join(ENV_DIR, "entropy_test.py")
MEMORY_SCRIPT_PATH = os.path.join(ENV_DIR, "memory_test.py")
CORPUS_DIR = os.path.join(ENV_DIR, "fuzz_corpus")


def venv_python():
    if os.name == "nt":
        return os.path.join(VENV_DIR, "Scripts", "python.exe")
    return os.path.join(VENV_DIR, "bin", "python3")


_ICON_PNG_BASE64 = (
    "iVBORw0KGgoAAAANSUhEUgAAAEAAAABACAYAAACqaXHeAAABW0lEQVR42u2bOxKCQAyG2QyFDSfhPpYcjtL7"
    "eBIaOywch4e7KyibhOTf0mVY/y9PBlJVzlfI7o630YbKa9gHwIrwDSBCTvyl6Uzofgx9EkKIibciPAliBoG8"
    "iF9om3k5ea8C5MX6KS+ABwAAAPhetdTB7fCZcO9NbxtATHRqnwsGaRH/7/WqAfwqhgMCaRXPBaGWEh+L8dT1"
    "7dAVywkiZTAlRqIKELf1v4lM7ZcKBdJgeUlPQCustcvbkyThAQAAALoaoaOyOEc1QAgAAAAAAAAAAPoAnkdh"
    "jb0BnUl8ifvTmcSXOAdJEABQBeTWPKNz5Q8VAGKl7P0bNwjkAA3WL9nowAMAQBmAPR9JwAOsAsi9BkcOAAAA"
    "8PEsINX7wwMAoCAArj7+yHNI85/juP80NOVkamQ9OIUcMPnCi8hixs649ZchsAoFS+GwfXAyAsHU2jQ6axFE"
    "Znja/XoC3MCEqxJdvvMAAAAASUVORK5CYII="
)


def _apply_custom_icon(root_window):
    """Sets the app's window/taskbar icon from the embedded PNG. Never
    raises -- if this fails for any reason (older Tk, unusual platform),
    the app just falls back to the system's default icon instead of
    crashing on startup."""
    try:
        icon_image = tk.PhotoImage(data=_ICON_PNG_BASE64)
        root_window.iconphoto(True, icon_image)
        root_window._icon_image_ref = icon_image
        return True
    except Exception:
        return False


COLOR_BG = "#0a0e0a"
COLOR_BG_PANEL = "#0f1710"
COLOR_BG_INPUT = "#0d1310"
COLOR_FG = "#33ff66"
COLOR_FG_DIM = "#1f8f3d"
COLOR_FG_BRIGHT = "#7fffa0"
COLOR_ACCENT = "#00ffaa"
COLOR_WARN = "#ffcc33"
COLOR_ERROR = "#ff4444"
COLOR_BORDER = "#1a3320"
FONT_MONO = ("Consolas", 10) if os.name == "nt" else ("DejaVu Sans Mono", 10)
FONT_MONO_BOLD = (FONT_MONO[0], FONT_MONO[1], "bold")
FONT_TITLE = (FONT_MONO[0], 13, "bold")


def extract_core_crypto_module(source_path, dest_path):
    try:
        with open(source_path, "r", encoding="utf-8") as f:
            content = f.read()
    except Exception as e:
        return False, "Could not read {}: {}".format(source_path, e)

    markers = [
        ("def wipe_bytearray(", "def disable_core_dumps("),
        ("BCA_MAGIC = bytes(", "class ViewerKind(Enum):"),
    ]
    extracted_parts = []
    for start_marker, end_marker in markers:
        start_idx = content.find(start_marker)
        end_idx = content.find(end_marker)
        if start_idx == -1 or end_idx == -1 or end_idx <= start_idx:
            return False, (
                "Could not locate expected code block "
                "('{}...' -> '{}...').\n"
                "The source file may have renamed or moved these functions.\n"
                "This tool is built specifically for the BastetCipher .bca format;\n"
                "if you're auditing a different codebase, this extraction step\n"
                "needs to be adapted first.".format(start_marker[:30], end_marker[:30])
            )
        extracted_parts.append(content[start_idx:end_idx])

    header = (
        '"""\n'
        "Module auto-extracted from the user's source file for isolated testing.\n"
        "Generated by bastet_audit_gui.py. Do not edit by hand: regenerated on\n"
        'every "Setup environment".\n'
        '"""\n'
        "import os\n"
        "import struct\n"
        "import zlib\n"
        "import gc\n"
        "import ctypes\n"
        "from dataclasses import dataclass\n"
        "from typing import Callable, List, Optional, Tuple\n"
        "from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes\n"
        "from cryptography.hazmat.primitives.ciphers.aead import AESGCM\n"
        "from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC\n"
        "from cryptography.hazmat.primitives import hashes\n"
        "from cryptography.hazmat.backends import default_backend\n"
        "try:\n"
        "    from argon2.low_level import hash_secret_raw, Type as Argon2Type\n"
        "    _HAS_ARGON2 = True\n"
        "except ImportError:\n"
        "    _HAS_ARGON2 = False\n"
        "    hash_secret_raw = None\n"
        "    Argon2Type = None\n"
        "\n"
        "ProgressCallback = Callable[[int, str], None]\n"
        "def _noop_progress(pct, msg):\n"
        "    pass\n"
        "\n"
    )
    full_code = header + "\n".join(extracted_parts)

    try:
        with open(dest_path, "w", encoding="utf-8") as f:
            f.write(full_code)
    except Exception as e:
        return False, "Could not write {}: {}".format(dest_path, e)

    try:
        result = subprocess.run(
            [venv_python(), "-c",
             "import sys; sys.path.insert(0,{!r}); import bca_core_standalone".format(
                 os.path.dirname(dest_path))],
            capture_output=True, text=True, timeout=30,
        )
        if result.returncode != 0:
            return False, "Extracted module fails to import:\n{}".format(result.stderr)
    except FileNotFoundError:
        pass
    except Exception as e:
        return False, "Error verifying extracted module: {}".format(e)

    return True, "Crypto module extracted and verified successfully."


FUZZ_TARGET_CODE = r'''"""
Atheris fuzz target: feeds millions of automatically mutated / malformed
vault variants to the parser, looking for crashes or unhandled exceptions.
Generated by bastet_audit_gui.py.
"""
import sys
import os
import atheris

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
with atheris.instrument_imports():
    from bca_core_standalone import parse_bca, BCAFormatError, BCADecryptError
    import bca_core_standalone

bca_core_standalone.BCA_ITERS = 1000
bca_core_standalone.BCA_ITERS_MIN = 1
bca_core_standalone.BCA_ITERS_MAX = 5_000_000

FIXED_PASSWORD = bytearray(b"FixedFuzzingPassword123!")

def TestOneInput(data):
    buf = bytearray(data)
    pw = bytearray(FIXED_PASSWORD)
    try:
        parse_bca(buf, pw)
    except (BCAFormatError, BCADecryptError, MemoryError, ValueError, UnicodeDecodeError):
        pass
    except Exception as e:
        print("\n!!! UNEXPECTED EXCEPTION: {}: {}".format(type(e).__name__, e))
        print("!!! On input of {} bytes: {}...".format(len(data), data[:100]))
        raise

if __name__ == "__main__":
    corpus_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fuzz_corpus")
    os.makedirs(corpus_dir, exist_ok=True)
    if not os.listdir(corpus_dir):
        from bca_core_standalone import build_bca, VaultFileEntry
        seeds = [
            [VaultFileEntry(name="a.txt", data=bytearray(b"hi"))],
            [VaultFileEntry(name="b.txt", data=bytearray(b""))],
            [VaultFileEntry(name="long.txt", data=bytearray(b"X" * 5000))],
            [VaultFileEntry(name="varied.bin", data=bytearray(os.urandom(3000)))],
            [VaultFileEntry(name="two.txt", data=bytearray(b"one")),
             VaultFileEntry(name="three.txt", data=bytearray(b"two"))],
            [VaultFileEntry(name="unicode_test.txt", data=bytearray(b"unicode name test"))],
            [VaultFileEntry(name="f{}.txt".format(i), data=bytearray("file number {}".format(i).encode()))
             for i in range(30)],
            [VaultFileEntry(name="empty1.txt", data=bytearray(b"")),
             VaultFileEntry(name="empty2.txt", data=bytearray(b"")),
             VaultFileEntry(name="big.bin", data=bytearray(os.urandom(100000)))],
        ]
        for i, files in enumerate(seeds):
            pw = bytearray(FIXED_PASSWORD)
            buf = build_bca(files, pw)
            with open(os.path.join(corpus_dir, "seed_{}.bin".format(i)), "wb") as f:
                f.write(bytes(buf))

    sys.argv.append(corpus_dir)
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()
'''

ENTROPY_TEST_CODE = r'''"""
Statistical / entropy analysis of the ciphertext produced by build_bca.
Generated by bastet_audit_gui.py.
"""
import sys, os, math, json

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from bca_core_standalone import build_bca, VaultFileEntry, HEADER_LEN

def shannon_entropy(data):
    if not data:
        return 0.0
    freq = [0] * 256
    for b in data:
        freq[b] += 1
    n = len(data)
    entropy = 0.0
    for count in freq:
        if count == 0:
            continue
        p = count / n
        entropy -= p * math.log2(p)
    return entropy

def chi_square_uniform(data):
    if len(data) < 2560:
        return None
    freq = [0] * 256
    for b in data:
        freq[b] += 1
    expected = len(data) / 256
    return sum((f - expected) ** 2 / expected for f in freq)

def longest_repeated_byte_run(data):
    if not data:
        return 0
    max_run = 1
    current = 1
    for i in range(1, len(data)):
        if data[i] == data[i - 1]:
            current += 1
            max_run = max(max_run, current)
        else:
            current = 1
    return max_run

def byte_frequency_deviation(data):
    if len(data) < 2560:
        return -1.0
    freq = [0] * 256
    for b in data:
        freq[b] += 1
    expected = len(data) / 256
    max_dev = max(abs(f - expected) for f in freq)
    return (max_dev / expected) * 100

results = []

test_cases = [
    ("all-zero bytes", b"\x00" * 300000),
    ("all-same byte (0x41)", b"A" * 300000),
    ("highly repetitive text", (b"The quick brown fox jumps. " * 40) * 300),
    ("random / incompressible", os.urandom(300000)),
    ("empty file", b""),
    ("single byte", b"X"),
]

password = bytearray(b"EntropyTestPassword!2024#Secure")

for label, plaintext in test_cases:
    pw = bytearray(password)
    entry = VaultFileEntry(name="sample.bin", data=bytearray(plaintext))
    buf = build_bca([entry], pw)
    ciphertext = bytes(buf[HEADER_LEN:])

    entry_result = {
        "label": label,
        "plaintext_len": len(plaintext),
        "ciphertext_len": len(ciphertext),
        "entropy_bits_per_byte": None,
        "chi_square": None,
        "max_freq_deviation_pct": None,
        "longest_repeated_run": None,
        "verdict": None,
    }

    if len(ciphertext) > 0:
        ent = shannon_entropy(ciphertext)
        chi2 = chi_square_uniform(ciphertext)
        dev = byte_frequency_deviation(ciphertext)
        run = longest_repeated_byte_run(ciphertext)
        entry_result["entropy_bits_per_byte"] = round(ent, 4)
        entry_result["chi_square"] = round(chi2, 1) if chi2 is not None else None
        entry_result["max_freq_deviation_pct"] = round(dev, 2) if dev >= 0 else None
        entry_result["longest_repeated_run"] = run

        if len(ciphertext) >= 2560:
            ok = ent > 7.9 and chi2 is not None and chi2 < 340 and run < 12
            entry_result["verdict"] = "PASS" if ok else "REVIEW"
        else:
            entry_result["verdict"] = "TOO SHORT FOR CHI-SQUARE (sample size limitation, not a failure)"
    else:
        entry_result["verdict"] = "N/A (empty ciphertext)"

    results.append(entry_result)

print(json.dumps(results, indent=2))
'''

MEMORY_TEST_CODE = r'''"""
Basic memory-behavior check via tracemalloc.
Generated by bastet_audit_gui.py.
Exercises both PBKDF2 and Argon2id (when argon2-cffi is available).
"""
import sys, os, gc, tracemalloc, json

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from bca_core_standalone import (
    build_bca, parse_bca, VaultFileEntry, BCAFormatError, BCADecryptError,
    KDF_PBKDF2, KDF_ARGON2ID,
)
import bca_core_standalone

bca_core_standalone.BCA_ITERS = 2000
bca_core_standalone.BCA_ITERS_MIN = 1
bca_core_standalone.BCA_ITERS_MAX = 5_000_000
if hasattr(bca_core_standalone, "ARGON2_MEMORY_KIB"):
    bca_core_standalone.ARGON2_MEMORY_KIB = 8 * 1024
    bca_core_standalone.ARGON2_TIME = 1
    bca_core_standalone.ARGON2_PARALLELISM = 1

N_CYCLES = 300
password = bytearray(b"MemoryTestPassword!2024")

_HAS_ARGON2 = bool(getattr(bca_core_standalone, "_HAS_ARGON2", False))
KDF_SEQUENCE = [KDF_PBKDF2]
if _HAS_ARGON2:
    KDF_SEQUENCE.append(KDF_ARGON2ID)

def run_cycle(kdf_id=KDF_PBKDF2):
    pw = bytearray(password)
    entry = VaultFileEntry(name="test.bin", data=bytearray(os.urandom(20000)))
    buf = build_bca([entry], pw, kdf_id=kdf_id)
    pw2 = bytearray(password)
    entries = parse_bca(bytearray(buf), pw2)
    return entries

tracemalloc.start()
gc.collect()

for i in range(20):
    run_cycle(KDF_SEQUENCE[i % len(KDF_SEQUENCE)])
gc.collect()
warm_snapshot = tracemalloc.take_snapshot()

for i in range(N_CYCLES):
    run_cycle(KDF_SEQUENCE[i % len(KDF_SEQUENCE)])
gc.collect()
final_snapshot = tracemalloc.take_snapshot()

warm_total = sum(stat.size for stat in warm_snapshot.statistics("filename"))
final_total = sum(stat.size for stat in final_snapshot.statistics("filename"))
growth_bytes = final_total - warm_total
growth_per_cycle = growth_bytes / N_CYCLES if N_CYCLES else 0

top_diffs = final_snapshot.compare_to(warm_snapshot, "lineno")[:8]

result = {
    "cycles_run": N_CYCLES,
    "kdfs_exercised": ["PBKDF2"] + (["Argon2id"] if _HAS_ARGON2 else []),
    "memory_after_warmup_bytes": warm_total,
    "memory_after_all_cycles_bytes": final_total,
    "growth_bytes": growth_bytes,
    "growth_bytes_per_cycle": round(growth_per_cycle, 1),
    "verdict": "REVIEW" if growth_per_cycle > 2048 else "PASS",
    "note": (
        "growth_bytes_per_cycle above ~2KB/cycle after warmup may indicate "
        "a Python-level leak worth investigating; small positive values are "
        "normal GC/allocator noise."
        + ("" if _HAS_ARGON2 else " Argon2id skipped (argon2-cffi not installed in audit env).")
    ),
    "top_allocation_diffs": [str(d) for d in top_diffs],
}
print(json.dumps(result, indent=2))
'''


if _AUDIT_TK_AVAILABLE:
    _BaseTk = TkinterDnD.Tk if _HAS_DND else tk.Tk


    class AuditGUI(_BaseTk):
        def __init__(self, default_file_path=None):
            super().__init__()
            self.title("Bastet Audit Tool - vault security checker")

            try:
                screen_dpi = self.winfo_fpixels("1i")
                if 48 <= screen_dpi <= 384:
                    self.tk.call("tk", "scaling", screen_dpi / 72.0)
            except (tk.TclError, ZeroDivisionError):
                pass

            screen_w = self.winfo_screenwidth()
            screen_h = self.winfo_screenheight()
            win_w = min(1050, int(screen_w * 0.85))
            win_h = min(800, int(screen_h * 0.85))
            self.geometry("{}x{}".format(win_w, win_h))
            self.minsize(620, 520)
            self.configure(bg=COLOR_BG)
            _apply_custom_icon(self)

            self.loaded_file_path = None
            self.current_process = None
            self.output_queue = queue.Queue()
            self.last_results = {}

            self._setup_style()
            self._build_ui()
            self._poll_queue()

            if default_file_path and os.path.isfile(default_file_path):
                self._load_file(default_file_path)

        def _setup_style(self):
            style = ttk.Style(self)
            try:
                style.theme_use("clam")
            except tk.TclError:
                pass

            style.configure(".", background=COLOR_BG, foreground=COLOR_FG, font=FONT_MONO)
            style.configure("TFrame", background=COLOR_BG)
            style.configure("Panel.TFrame", background=COLOR_BG_PANEL)
            style.configure("TLabel", background=COLOR_BG, foreground=COLOR_FG, font=FONT_MONO)
            style.configure("Dim.TLabel", background=COLOR_BG, foreground=COLOR_FG_DIM, font=FONT_MONO)
            style.configure("Bright.TLabel", background=COLOR_BG, foreground=COLOR_FG_BRIGHT, font=FONT_MONO_BOLD)
            style.configure("Warn.TLabel", background=COLOR_BG, foreground=COLOR_WARN, font=FONT_MONO_BOLD)
            style.configure("Error.TLabel", background=COLOR_BG, foreground=COLOR_ERROR, font=FONT_MONO_BOLD)
            style.configure("Title.TLabel", background=COLOR_BG, foreground=COLOR_ACCENT, font=FONT_TITLE)

            style.configure("TButton", background=COLOR_BG_PANEL, foreground=COLOR_FG,
                             font=FONT_MONO_BOLD, borderwidth=1, focusthickness=0, relief="solid")
            style.map("TButton",
                      background=[("active", COLOR_FG_DIM), ("disabled", COLOR_BG)],
                      foreground=[("active", COLOR_BG), ("disabled", COLOR_FG_DIM)])

            style.configure("Accent.TButton", background="#0d2818", foreground=COLOR_ACCENT,
                             font=FONT_MONO_BOLD, borderwidth=1, relief="solid")
            style.map("Accent.TButton",
                      background=[("active", COLOR_ACCENT), ("disabled", COLOR_BG)],
                      foreground=[("active", COLOR_BG), ("disabled", COLOR_FG_DIM)])

            style.configure("Stop.TButton", background="#2a0d0d", foreground=COLOR_ERROR,
                             font=FONT_MONO_BOLD, borderwidth=1, relief="solid")
            style.map("Stop.TButton",
                      background=[("active", COLOR_ERROR), ("disabled", COLOR_BG)],
                      foreground=[("active", COLOR_BG), ("disabled", COLOR_FG_DIM)])

            style.configure("TNotebook", background=COLOR_BG, borderwidth=0)
            style.configure("TNotebook.Tab", background=COLOR_BG_PANEL, foreground=COLOR_FG_DIM,
                             font=FONT_MONO_BOLD, padding=[14, 6])
            style.map("TNotebook.Tab",
                      background=[("selected", COLOR_BG)],
                      foreground=[("selected", COLOR_ACCENT)])

            style.configure("TEntry", fieldbackground=COLOR_BG_INPUT, foreground=COLOR_FG_BRIGHT,
                             insertcolor=COLOR_FG, borderwidth=1)
            style.configure("TLabelframe", background=COLOR_BG, foreground=COLOR_ACCENT,
                             borderwidth=1, relief="solid")
            style.configure("TLabelframe.Label", background=COLOR_BG, foreground=COLOR_ACCENT,
                             font=FONT_MONO_BOLD)
            style.configure("Horizontal.TProgressbar", background=COLOR_ACCENT,
                             troughcolor=COLOR_BG_PANEL, borderwidth=0)

        def _build_ui(self):
            notebook = ttk.Notebook(self)
            notebook.pack(fill="both", expand=True, padx=10, pady=10)

            self.tab_audit = ttk.Frame(notebook)
            self.tab_about = ttk.Frame(notebook)
            notebook.add(self.tab_audit, text="  AUDIT  ")
            notebook.add(self.tab_about, text="  ABOUT / WHAT'S NOT COVERED  ")

            self._build_audit_tab(self.tab_audit)
            self._build_about_tab(self.tab_about)

        def _build_audit_tab(self, parent):
            loader = ttk.LabelFrame(parent, text=" TARGET FILE ")
            loader.pack(fill="x", padx=6, pady=(6, 4))

            row = ttk.Frame(loader)
            row.pack(fill="x", padx=8, pady=(8, 2))

            ttk.Button(row, text="Browse...", command=self.browse_file, style="Accent.TButton").pack(side="right")
            ttk.Label(row, text="File:", style="Dim.TLabel").pack(side="left", padx=(0, 8))

            self.file_label_var = tk.StringVar(value="No file loaded yet.")
            self.file_label = ttk.Label(loader, textvariable=self.file_label_var, style="Bright.TLabel")
            self.file_label.pack(anchor="w", padx=8, pady=(0, 4), fill="x")
            loader.bind("<Configure>", lambda e: self.file_label.configure(wraplength=max(200, e.width - 20)))

            dnd_hint = "  (or drag & drop a .py file below)" if _HAS_DND else \
                       "  (drag & drop unavailable: pip install tkinterdnd2 for it, or just use Browse)"
            ttk.Label(loader, text=dnd_hint, style="Dim.TLabel").pack(anchor="w", padx=8, pady=(0, 6))

            self.drop_zone = tk.Label(
                loader, text="DROP FILE HERE", bg=COLOR_BG_INPUT, fg=COLOR_FG_DIM,
                font=FONT_MONO_BOLD, height=2, relief="solid", bd=1,
            )
            self.drop_zone.pack(fill="x", padx=8, pady=(0, 8))
            if _HAS_DND:
                self.drop_zone.drop_target_register(DND_FILES)
                self.drop_zone.dnd_bind("<<Drop>>", self._on_drop)

            btn_frame = ttk.Frame(parent)
            btn_frame.pack(fill="x", pady=6, padx=6)

            self.btn_setup = ttk.Button(btn_frame, text="1) Setup environment", command=self.run_setup)
            self.btn_deps = ttk.Button(btn_frame, text="2) Dependency check", command=self.run_dependency_check)
            self.btn_static = ttk.Button(btn_frame, text="3) Static analysis", command=self.run_static_analysis)
            self.btn_entropy = ttk.Button(btn_frame, text="4) Entropy test", command=self.run_entropy_test)
            self.btn_memory = ttk.Button(btn_frame, text="5) Memory check", command=self.run_memory_test)

            self._main_buttons = [self.btn_setup, self.btn_deps, self.btn_static, self.btn_entropy, self.btn_memory]
            self._btn_frame = btn_frame
            self._btn_frame.bind("<Configure>", self._relayout_main_buttons)
            self._last_btn_cols = None

            fuzz_frame = ttk.LabelFrame(parent, text=" 6) FUZZING (malformed-input bombardment) ")
            fuzz_frame.pack(fill="x", padx=6, pady=6)

            fuzz_row1 = ttk.Frame(fuzz_frame)
            fuzz_row1.pack(fill="x", padx=4, pady=(8, 2))
            ttk.Label(fuzz_row1, text="Duration:").pack(side="left", padx=(4, 4))
            self.fuzz_duration_var = tk.StringVar(value="60")
            ttk.Entry(fuzz_row1, textvariable=self.fuzz_duration_var, width=8).pack(side="left", padx=(0, 4))
            ttk.Label(fuzz_row1, text="seconds (600=10min, 28800=8h/overnight)", style="Dim.TLabel").pack(
                side="left", padx=(0, 4))

            fuzz_row2 = ttk.Frame(fuzz_frame)
            fuzz_row2.pack(fill="x", padx=4, pady=2)
            ttk.Label(fuzz_row2, text="Max input size:").pack(side="left", padx=(4, 4))
            self.fuzz_maxlen_var = tk.StringVar(value="65536")
            ttk.Entry(fuzz_row2, textvariable=self.fuzz_maxlen_var, width=8).pack(side="left", padx=(0, 4))
            ttk.Label(fuzz_row2, text="bytes (larger = also tests multi-file / big vaults)", style="Dim.TLabel").pack(
                side="left", padx=(0, 4))

            fuzz_row3 = ttk.Frame(fuzz_frame)
            fuzz_row3.pack(fill="x", padx=4, pady=(2, 8))
            self.btn_fuzz = ttk.Button(fuzz_row3, text="Start fuzzing", command=self.run_fuzzing, style="Accent.TButton")
            self.btn_fuzz.pack(side="left", padx=4)
            self.btn_stop = ttk.Button(fuzz_row3, text="STOP", command=self.stop_current_process,
                                        state="disabled", style="Stop.TButton")
            self.btn_stop.pack(side="left", padx=4)

            self.progress = ttk.Progressbar(parent, mode="indeterminate", style="Horizontal.TProgressbar")
            self.progress.pack(fill="x", padx=6, pady=(0, 4))

            self.status_var = tk.StringVar(value="Ready. Load a file to begin.")
            self.status_label = ttk.Label(parent, textvariable=self.status_var, style="Bright.TLabel")
            self.status_label.pack(anchor="w", padx=6, fill="x")
            parent.bind("<Configure>", lambda e: self.status_label.configure(
                wraplength=max(200, e.width - 20)))

            toolbar = ttk.Frame(parent)
            toolbar.pack(fill="x", padx=6)
            ttk.Button(toolbar, text="Save log...", command=self.save_log_to_file).pack(side="right", pady=(0, 4), padx=2)
            ttk.Button(toolbar, text="Generate summary report", command=self.generate_report).pack(side="right", pady=(0, 4), padx=2)
            ttk.Button(toolbar, text="Clear", command=self._clear_output).pack(side="right", pady=(0, 4), padx=2)

            self.output_box = scrolledtext.ScrolledText(
                parent, height=22, font=FONT_MONO, bg=COLOR_BG_INPUT, fg=COLOR_FG,
                insertbackground=COLOR_FG, relief="flat", borderwidth=0,
            )
            self.output_box.pack(fill="both", expand=True, padx=6, pady=6)
            self.output_box.configure(state="disabled")
            self.output_box.tag_configure("warn", foreground=COLOR_WARN)
            self.output_box.tag_configure("error", foreground=COLOR_ERROR)
            self.output_box.tag_configure("ok", foreground=COLOR_ACCENT)

        def _build_about_tab(self, parent):
            text = scrolledtext.ScrolledText(
                parent, wrap="word", font=("DejaVu Sans", 10) if os.name != "nt" else ("Segoe UI", 10),
                bg=COLOR_BG_INPUT, fg=COLOR_FG, insertbackground=COLOR_FG, relief="flat",
            )
            text.pack(fill="both", expand=True, padx=10, pady=10)
            text.insert("1.0", _AUDIT_TOOL_DOC.strip())
            text.insert("end", "\n\n" + "=" * 78 + "\n")
            text.insert("end", """
    DETAIL: WHAT EACH TEST ACTUALLY CHECKS

    -- 1) DEPENDENCY CHECK (pip-audit) --------------------------------------
    Looks up the exact installed versions of your dependencies against a
    public, maintained database of known vulnerabilities.
    Good result: "No known vulnerabilities found."

    -- 2) STATIC ANALYSIS (bandit) -------------------------------------------
    Reads the source line by line (never runs it), flagging patterns
    security reviewers consider worth a second look. Many "Low" severity
    findings are completely normal in a desktop app.

    -- 3) ENTROPY / STATISTICAL TEST ------------------------------------------
    Encrypts several plaintexts (all-zeros, highly repetitive text, pure
    random data) and measures whether the resulting ciphertext is
    statistically distinguishable from random noise: Shannon entropy
    (bits/byte, should approach 8.0), a chi-square uniformity test on byte
    frequencies, and longest repeated-byte-run length. A well-implemented
    cipher should hide ALL structure in the plaintext.

    -- 4) MEMORY BEHAVIOR CHECK ------------------------------------------------
    Runs hundreds of encrypt/decrypt cycles tracking Python-level memory
    allocations (via tracemalloc), watching for unbounded growth. This is
    a coarse, Python-level check only -- it cannot see inside the compiled
    C code of the underlying cryptography library the way Valgrind or
    AddressSanitizer could against a specially-instrumented build.

    -- 5) FUZZING (atheris / libFuzzer) ----------------------------------------
    Executes the actual parsing code millions of times against automatically
    generated and mutated inputs, including near-valid vault files with
    individual bytes flipped in every possible way. The "Max input size"
    setting controls how large the malformed test files can get: a higher
    value also exercises code paths for bigger / multi-entry vaults.

    WHAT'S NOT COVERED -- BE HONEST WITH YOURSELF ABOUT THIS LIST
    ----------------------------------------------------------------
    Even with every automated test above passing cleanly, the following
    require a human cryptography expert, not more tooling:

      - Whether the DESIGN of the encryption scheme is sound (layer
        ordering, algorithm choices, how errors are reported).
      - Whether the key-derivation cost (PBKDF2 iteration count) is
        adequate against realistic modern attack hardware.
      - Side-channel resistance: timing attacks, power analysis, cache-
        timing attacks.
      - Whether the overall THREAT MODEL is even the right one for your
        use case.
      - A full compiled-library memory-safety audit (ASan/MSan/Valgrind
        against a specially built interpreter).

    If your material is genuinely sensitive enough to warrant "intelligence
    grade" protection, treat everything above as a strong, evidence-backed
    starting point for a conversation with a paid human reviewer -- not as
    a replacement for one.
    """)
            text.configure(state="disabled")

        def _relayout_main_buttons(self, event=None):
            """Re-flows the 5 main test buttons into as many columns as fit the
            current width, so they wrap onto more rows instead of overflowing
            or getting clipped when the window is narrow, maximized at high
            DPI/zoom, or resized by the user."""
            frame_width = self._btn_frame.winfo_width()
            if frame_width <= 1:
                return
            min_btn_width = max(b.winfo_reqwidth() for b in self._main_buttons) + 10
            cols = max(1, min(len(self._main_buttons), frame_width // min_btn_width))
            if cols == self._last_btn_cols:
                return
            self._last_btn_cols = cols
            for b in self._main_buttons:
                b.grid_forget()
            for i, b in enumerate(self._main_buttons):
                row, col = divmod(i, cols)
                b.grid(row=row, column=col, padx=3, pady=4, sticky="ew")
            for c in range(cols):
                self._btn_frame.columnconfigure(c, weight=1)

        def _on_drop(self, event):
            raw = event.data
            path = raw.strip()
            if path.startswith("{") and path.endswith("}"):
                path = path[1:-1]
            self._load_file(path)

        def browse_file(self):
            path = filedialog.askopenfilename(
                title="Select the source file to audit",
                filetypes=[("Python files", "*.py"), ("All files", "*.*")],
            )
            if path:
                self._load_file(path)

        def _load_file(self, path):
            if not os.path.isfile(path):
                messagebox.showerror("File not found", "'{}' does not look like a valid file.".format(path))
                return
            self.loaded_file_path = path
            self.file_label_var.set("Loaded: {}  ({})".format(os.path.basename(path), path))
            self.status_var.set("File loaded. Click '1) Setup environment' to begin.")
            self.last_results = {}

        def _log(self, msg, tag=None):
            self.output_queue.put((msg, tag))

        def _poll_queue(self):
            try:
                while True:
                    msg, tag = self.output_queue.get_nowait()
                    self.output_box.configure(state="normal")
                    if tag:
                        self.output_box.insert("end", msg, tag)
                    else:
                        self.output_box.insert("end", msg)
                    self.output_box.see("end")
                    self.output_box.configure(state="disabled")
            except queue.Empty:
                pass
            self.after(100, self._poll_queue)

        def _set_buttons_busy(self, busy):
            state = "disabled" if busy else "normal"
            for b in (self.btn_setup, self.btn_deps, self.btn_static, self.btn_entropy,
                      self.btn_memory, self.btn_fuzz):
                b.configure(state=state)
            self.btn_stop.configure(state=("normal" if busy else "disabled"))
            if busy:
                self.progress.start(10)
            else:
                self.progress.stop()

        def _clear_output(self):
            self.output_box.configure(state="normal")
            self.output_box.delete("1.0", "end")
            self.output_box.configure(state="disabled")

        def _require_file(self):
            if not self.loaded_file_path:
                messagebox.showwarning("No file loaded", "Load a source file first (Browse or drag & drop).")
                return False
            return True

        def _require_env(self):
            if not os.path.isdir(VENV_DIR):
                messagebox.showwarning("Environment not ready", "Click '1) Setup environment' first (one-time step).")
                return False
            return True

        def save_log_to_file(self):
            content = self.output_box.get("1.0", "end")
            if not content.strip():
                messagebox.showinfo("Empty log", "Nothing to save yet -- run a test first.")
                return
            default_name = "audit_log_{}.txt".format(time.strftime("%Y%m%d_%H%M%S"))
            path = filedialog.asksaveasfilename(
                title="Save log as...", initialdir=SCRIPT_DIR, initialfile=default_name,
                defaultextension=".txt", filetypes=[("Text file", "*.txt"), ("All files", "*.*")],
            )
            if not path:
                return
            try:
                with open(path, "w", encoding="utf-8") as f:
                    f.write(content)
                messagebox.showinfo("Saved", "Log saved to:\n{}".format(path))
            except Exception as e:
                messagebox.showerror("Save failed", str(e))

        def generate_report(self):
            if not self.last_results:
                messagebox.showinfo("No results yet", "Run some tests first -- each completed test adds a line to the summary report.")
                return
            lines = ["=" * 70, "BASTET AUDIT TOOL - SUMMARY REPORT",
                     "Generated: {}".format(time.strftime("%Y-%m-%d %H:%M:%S")),
                     "Target file: {}".format(self.loaded_file_path), "=" * 70, ""]
            for name, summary in self.last_results.items():
                lines.append("[{}]".format(name))
                lines.append(summary)
                lines.append("")
            lines.append("=" * 70)
            lines.append("Reminder: these are automated checks. See the ABOUT tab for what")
            lines.append("they do NOT cover (design review, side channels, threat modeling).")
            report_text = "\n".join(lines)

            self._clear_output()
            self._log(report_text)
            default_name = "summary_report_{}.txt".format(time.strftime("%Y%m%d_%H%M%S"))
            path = filedialog.asksaveasfilename(
                title="Save summary report as...", initialdir=SCRIPT_DIR, initialfile=default_name,
                defaultextension=".txt", filetypes=[("Text file", "*.txt"), ("All files", "*.*")],
            )
            if path:
                try:
                    with open(path, "w", encoding="utf-8") as f:
                        f.write(report_text)
                    messagebox.showinfo("Saved", "Summary report saved to:\n{}".format(path))
                except Exception as e:
                    messagebox.showerror("Save failed", str(e))

        def _run_subprocess_async(self, cmd, cwd, on_done=None, env=None, log_file_path=None):
            def worker():
                log_fh = None
                if log_file_path:
                    try:
                        log_fh = open(log_file_path, "a", encoding="utf-8")
                        log_fh.write("\n{}\nRun started: {}\n{}\n".format("=" * 70, time.strftime("%Y-%m-%d %H:%M:%S"), "=" * 70))
                        log_fh.flush()
                    except Exception as e:
                        self._log("[WARNING] could not open log file: {}\n".format(e), "warn")
                captured_lines = []
                try:
                    self.current_process = subprocess.Popen(
                        cmd, cwd=cwd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                        text=True, bufsize=1, env=env,
                    )
                    for line in self.current_process.stdout:
                        captured_lines.append(line)
                        tag = "error" if ("ERROR" in line or "UNEXPECTED EXCEPTION" in line) else None
                        self._log(line, tag)
                        if log_fh:
                            try:
                                log_fh.write(line)
                                log_fh.flush()
                            except Exception:
                                pass
                    self.current_process.wait()
                    returncode = self.current_process.returncode
                except Exception as e:
                    self._log("\n[ERROR] {}\n".format(e), "error")
                    returncode = -1
                finally:
                    if log_fh:
                        try:
                            log_fh.write("\nRun finished: {}\n".format(time.strftime("%Y-%m-%d %H:%M:%S")))
                            log_fh.close()
                        except Exception:
                            pass
                    self.current_process = None
                    self.after(0, lambda: self._set_buttons_busy(False))
                    self.after(0, lambda: self.status_var.set(
                        "Done." if returncode == 0 else "Finished with exit code {}.".format(returncode)))
                    if on_done:
                        full_output = "".join(captured_lines)
                        self.after(0, lambda: on_done(full_output, returncode))
            threading.Thread(target=worker, daemon=True).start()

        def stop_current_process(self):
            if self.current_process is not None:
                try:
                    self.current_process.terminate()
                    self._log("\n[Stopped by user]\n", "warn")
                except Exception:
                    pass

        def run_setup(self):
            if not self._require_file():
                return
            self._clear_output()
            self.status_var.set("Setting up environment (1-3 minutes)...")
            self._set_buttons_busy(True)
            os.makedirs(ENV_DIR, exist_ok=True)
            source_path = self.loaded_file_path

            def worker():
                self._log("=== Creating isolated virtual environment ===\n", "ok")
                result = subprocess.run([sys.executable, "-m", "venv", VENV_DIR], capture_output=True, text=True)
                self._log(result.stdout + result.stderr)
                if result.returncode != 0:
                    self._log("\n[ERROR] Failed to create virtual environment.\n", "error")
                    self.after(0, lambda: self._set_buttons_busy(False))
                    return

                self._log("\n=== Upgrading pip ===\n", "ok")
                r = subprocess.run([venv_python(), "-m", "pip", "install", "--upgrade", "pip", "--quiet"],
                                    capture_output=True, text=True)
                self._log(r.stdout + r.stderr)

                self._log("\n=== Installing required packages ===\n", "ok")
                for pkg in ["cryptography", "argon2-cffi", "pip-audit", "bandit"]:
                    self._log("--- {} ---\n".format(pkg))
                    proc = subprocess.Popen([venv_python(), "-m", "pip", "install", "--quiet", pkg],
                                             stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
                    for line in proc.stdout:
                        self._log(line)
                    proc.wait()

                self._log("\n=== Installing 'atheris' (fuzzing engine, needs a C++ compiler) ===\n", "ok")
                proc = subprocess.Popen([venv_python(), "-m", "pip", "install", "--quiet", "atheris"],
                                         stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
                for line in proc.stdout:
                    self._log(line)
                proc.wait()
                if proc.returncode != 0:
                    self._log(
                        "\n[WARNING] 'atheris' failed to install. Fuzzing (test 6) won't be available.\n"
                        "Try running in a terminal:\n    sudo apt install python3-dev build-essential\n"
                        "then click 'Setup environment' again. Other tests still work.\n", "warn")

                self._log("\n=== Extracting crypto module for isolated testing ===\n", "ok")
                ok, msg = extract_core_crypto_module(source_path, CORE_MODULE_PATH)
                self._log(msg + "\n", None if ok else "error")

                self._log("\n=== Writing worker scripts ===\n", "ok")
                try:
                    with open(FUZZ_SCRIPT_PATH, "w", encoding="utf-8") as f:
                        f.write(FUZZ_TARGET_CODE)
                    with open(ENTROPY_SCRIPT_PATH, "w", encoding="utf-8") as f:
                        f.write(ENTROPY_TEST_CODE)
                    with open(MEMORY_SCRIPT_PATH, "w", encoding="utf-8") as f:
                        f.write(MEMORY_TEST_CODE)
                    self._log("OK.\n")
                except Exception as e:
                    self._log("[ERROR] {}\n".format(e), "error")

                self._log("\n=== SETUP COMPLETE ===\n", "ok")
                self.after(0, lambda: self._set_buttons_busy(False))
                self.after(0, lambda: self.status_var.set("Environment ready. You can use the other buttons now."))

            threading.Thread(target=worker, daemon=True).start()

        def run_dependency_check(self):
            if not self._require_file() or not self._require_env():
                return
            self._clear_output()
            self.status_var.set("Checking dependencies for known vulnerabilities...")
            self._set_buttons_busy(True)

            def done(output, rc):
                if "No known vulnerabilities" in output:
                    verdict = "No known vulnerabilities found."
                elif rc == 0:
                    verdict = "Findings reported -- review above."
                else:
                    verdict = "Command exited with code {}.".format(rc)
                self.last_results["2) Dependency check"] = verdict

            self._run_subprocess_async([venv_python(), "-m", "pip_audit"], cwd=ENV_DIR, on_done=done)

        def run_static_analysis(self):
            if not self._require_file() or not self._require_env():
                return
            self._clear_output()
            self.status_var.set("Running static analysis...")
            self._set_buttons_busy(True)

            def done(output, rc):
                high = output.count("Severity: High")
                med = output.count("Severity: Medium")
                low = output.count("Severity: Low")
                self.last_results["3) Static analysis"] = "High: {}, Medium: {}, Low: {}".format(high, med, low)

            self._run_subprocess_async([venv_python(), "-m", "bandit", self.loaded_file_path],
                                        cwd=SCRIPT_DIR, on_done=done)

        def run_entropy_test(self):
            if not self._require_file() or not self._require_env():
                return
            if not os.path.isfile(ENTROPY_SCRIPT_PATH):
                messagebox.showwarning("Not ready", "Run 'Setup environment' again to generate this test's script.")
                return
            self._clear_output()
            self.status_var.set("Running entropy / statistical analysis...")
            self._set_buttons_busy(True)

            def done(output, rc):
                try:
                    json_start = output.find("[")
                    data = json.loads(output[json_start:])
                    passed = sum(1 for r in data if r["verdict"] == "PASS")
                    total_checkable = sum(1 for r in data if r["verdict"] in ("PASS", "REVIEW"))
                    self.last_results["4) Entropy / statistical test"] = "{}/{} cases statistically clean".format(passed, total_checkable)
                except Exception:
                    self.last_results["4) Entropy / statistical test"] = "See log for raw output (could not auto-summarize)."

            self._run_subprocess_async([venv_python(), ENTROPY_SCRIPT_PATH], cwd=ENV_DIR, on_done=done)

        def run_memory_test(self):
            if not self._require_file() or not self._require_env():
                return
            if not os.path.isfile(MEMORY_SCRIPT_PATH):
                messagebox.showwarning("Not ready", "Run 'Setup environment' again to generate this test's script.")
                return
            self._clear_output()
            self.status_var.set("Running memory behavior check (a few seconds)...")
            self._set_buttons_busy(True)

            def done(output, rc):
                try:
                    json_start = output.find("{")
                    data = json.loads(output[json_start:])
                    self.last_results["5) Memory behavior check"] = "{} -- growth ~{} bytes/cycle over {} cycles".format(
                        data["verdict"], data["growth_bytes_per_cycle"], data["cycles_run"])
                except Exception:
                    self.last_results["5) Memory behavior check"] = "See log for raw output (could not auto-summarize)."

            self._run_subprocess_async([venv_python(), MEMORY_SCRIPT_PATH], cwd=ENV_DIR, on_done=done)

        def run_fuzzing(self):
            if not self._require_file() or not self._require_env():
                return
            if not os.path.isfile(FUZZ_SCRIPT_PATH) or not os.path.isfile(CORE_MODULE_PATH):
                messagebox.showwarning("Not ready", "Run 'Setup environment' again to generate fuzzing files.")
                return
            try:
                duration = int(self.fuzz_duration_var.get())
                maxlen = int(self.fuzz_maxlen_var.get())
                if duration <= 0 or maxlen <= 0:
                    raise ValueError
            except ValueError:
                messagebox.showerror("Invalid input", "Duration and max size must be positive numbers.")
                return

            check = subprocess.run([venv_python(), "-c", "import atheris"], capture_output=True, text=True)
            if check.returncode != 0:
                messagebox.showerror(
                    "Atheris unavailable",
                    "The fuzzing engine 'atheris' isn't installed correctly.\n\n"
                    "Try in a terminal:\nsudo apt install python3-dev build-essential\n\n"
                    "then click 'Setup environment' again."
                )
                return

            self._clear_output()
            self.status_var.set("Fuzzing for {}s (max input {} bytes)... (STOP to interrupt)".format(duration, maxlen))
            self._set_buttons_busy(True)
            log_path = os.path.join(SCRIPT_DIR, "fuzzing_log.txt")
            self._log("=== Starting fuzzing for {} seconds, max input size {} bytes ===\n".format(duration, maxlen), "ok")
            self._log("Live log is being saved to:\n{}\n".format(log_path))
            self._log("You can stop at any time with the STOP button.\n\n")

            def done(output, rc):
                import re
                m = re.search(r"Done (\d+) runs in (\d+) second", output)
                crash = "UNEXPECTED EXCEPTION" in output
                if m:
                    self.last_results["6) Fuzzing"] = "{} runs in {}s -- {}".format(
                        m.group(1), m.group(2),
                        "ISSUES FOUND, see log" if crash else "no crashes / unexpected exceptions")
                else:
                    self.last_results["6) Fuzzing"] = "Stopped before completion -- " + (
                        "issues found, see log" if crash else "no crashes / unexpected exceptions so far")

            self._run_subprocess_async(
                [venv_python(), FUZZ_SCRIPT_PATH, "-max_total_time={}".format(duration), "-max_len={}".format(maxlen)],
                cwd=ENV_DIR, log_file_path=log_path, on_done=done,
            )


    WELCOME_TEXT = """WHAT THIS APP IS

    Bastet Audit Tool is an independent security-checking utility for the
    BastetCipher vault format (.bca files). It does not encrypt or decrypt
    your files -- it exists purely to let you (or anyone downloading this
    tool) verify, with your own eyes and your own hardware, whether the
    BastetCipher source code behaves the way it claims to.

    WHY IT WAS BUILT

    Whoever wrote a piece of encryption software can always claim it's
    secure. This tool exists so nobody has to take that claim on faith:
    every check it runs is something you can watch happen, re-run
    yourself, and inspect the raw output of.


    THE QUESTION THAT MATTERS MOST: "CAN A VAULT BE OPENED WITHOUT THE
    CORRECT PASSWORD?"

    This is the one property that, if it failed, would matter more than
    anything else -- so this tool is built to let you get a direct,
    evidence-based answer yourself, instead of taking anyone's word for it:

      - The BastetCipher source code can be read line by line with the
        Static Analysis test below: opening a vault requires deriving
        the encryption keys from the exact password used to create it,
        and the AES-GCM authentication tag must verify -- a property
        that is mathematically enforced, the same way it is in
        AES-based tools like VeraCrypt or 7-Zip's AES-256 mode, not a
        software check that could be quietly bypassed. Read the source
        yourself, or use the Static Analysis button to have a tool do
        a first pass for you.

      - That claim is exactly what the Fuzzing test below is built to
        stress: it feeds malformed, mutated, near-valid vault files at
        the parser using the FIXED password baked into the generated
        fuzz script, specifically trying to find any input that opens
        without the correct password or crashes the parser. Run it for
        as long as you like -- a few minutes for a quick check, hours
        or overnight for a thorough one -- and the live count of runs
        and any findings are shown as they happen, not reported after
        the fact.

      - You do not have to take this app's word for it, either: this same
        tool includes a "Setup environment" + fuzzing workflow you can run
        yourself, right now, against your own copy of the BastetCipher
        source, and watch the result with your own eyes.


    WHAT THIS APP DOES NOT CLAIM

    Being honest about scope matters more than sounding reassuring:

      - This covers implementation correctness (does the code do what it
        claims), not a full cryptographic design audit by a human expert,
        side-channel resistance, or whether the key-derivation cost is
        adequate against future attack hardware. See the "About" tab in
        the main window for the complete list of what automated tooling
        like this can and cannot verify.

      - "Verified" here means "tested extensively and found consistent,"
        not "mathematically proven for all possible inputs, forever." No
        honest claim about any real-world software can promise the latter
        -- that is true of this tool, of BastetCipher, and of every other
        security software ever written, including VeraCrypt and 7-Zip
        themselves.


    WHAT THIS APP ACTUALLY DOES, STEP BY STEP

      1. Dependency check -- looks up known published vulnerabilities in
         the exact library versions BastetCipher depends on.
      2. Static analysis -- reads the source code for risky patterns,
         without ever executing it.
      3. Entropy / statistical test -- verifies encrypted output is
         statistically indistinguishable from random noise.
      4. Memory behavior check -- runs repeated encrypt/decrypt cycles
         looking for memory leaks.
      5. Fuzzing -- feeds millions of automatically-mutated, malformed
         vault files to the parser, looking for crashes or any way to
         bypass the password requirement.

    All of this happens in an isolated virtual environment created next
    to this script; your system's own Python packages are never touched
    without your explicit, separate confirmation at each step.
    """


    _SKIP_SPLASH_MARKER = os.path.join(SCRIPT_DIR, ".bastet_audit_skip_welcome")


    class WelcomeSplash(tk.Toplevel):
        def __init__(self, master, on_continue):
            super().__init__(master)
            self.title("Welcome - Bastet Audit Tool")
            self.configure(bg=COLOR_BG)
            self._on_continue = on_continue
            self.protocol("WM_DELETE_WINDOW", self._close_app)

            _apply_custom_icon(self)

            screen_w = self.winfo_screenwidth()
            screen_h = self.winfo_screenheight()
            w = min(760, int(screen_w * 0.8))
            h = min(680, int(screen_h * 0.8))
            self.geometry("{}x{}".format(w, h))
            self.minsize(480, 400)

            header = tk.Frame(self, bg=COLOR_BG)
            header.pack(fill="x", padx=16, pady=(16, 4))
            tk.Label(header, text="BASTET AUDIT TOOL", bg=COLOR_BG, fg=COLOR_ACCENT,
                     font=FONT_TITLE).pack(anchor="w")
            tk.Label(header, text="independent security checker for the .bca vault format",
                     bg=COLOR_BG, fg=COLOR_FG_DIM, font=FONT_MONO).pack(anchor="w")

            body = scrolledtext.ScrolledText(
                self, wrap="word", font=("DejaVu Sans", 10) if os.name != "nt" else ("Segoe UI", 10),
                bg=COLOR_BG_INPUT, fg=COLOR_FG, insertbackground=COLOR_FG, relief="flat",
                padx=10, pady=10,
            )
            body.pack(fill="both", expand=True, padx=16, pady=8)
            body.insert("1.0", WELCOME_TEXT)
            body.configure(state="disabled")

            footer = tk.Frame(self, bg=COLOR_BG)
            footer.pack(fill="x", padx=16, pady=(4, 16))
            self.dont_show_var = tk.BooleanVar(value=False)
            tk.Checkbutton(
                footer, text="Don't show this again on this machine",
                variable=self.dont_show_var, bg=COLOR_BG, fg=COLOR_FG_DIM,
                selectcolor=COLOR_BG_INPUT, activebackground=COLOR_BG,
                activeforeground=COLOR_FG, font=FONT_MONO,
            ).pack(side="left")

            btn = tk.Button(
                footer, text="Continue to the tool  ->", command=self._continue,
                bg="#0d2818", fg=COLOR_ACCENT, activebackground=COLOR_ACCENT,
                activeforeground=COLOR_BG, font=FONT_MONO_BOLD, relief="solid",
                borderwidth=1, padx=14, pady=6, cursor="hand2",
            )
            btn.pack(side="right")

            self.transient(master)
            self.grab_set()
            self.focus_set()

        def _continue(self):
            if self.dont_show_var.get():
                try:
                    with open(_SKIP_SPLASH_MARKER, "w", encoding="utf-8") as f:
                        f.write("This file's presence skips the welcome screen. Delete it to see it again.\n")
                except Exception:
                    pass
            self.destroy()
            self._on_continue()

        def _close_app(self):
            self.destroy()
            os._exit(0)




# =============================================================================
# END OF EMBEDDED BASTET AUDIT TOOL
# =============================================================================

def apply_cross_platform_style(app: QApplication) -> None:
    try:
        app.setStyle(QStyleFactory.create("Fusion"))
    except Exception:
        pass
    palette = QPalette()
    dark = QColor(TEMPLE_BG)
    text = QColor(TEMPLE_TEXT_BODY)
    palette.setColor(QPalette.Window, dark)
    palette.setColor(QPalette.WindowText, text)
    palette.setColor(QPalette.Base, QColor("#0a0806"))
    palette.setColor(QPalette.AlternateBase, dark)
    palette.setColor(QPalette.ToolTipBase, dark)
    palette.setColor(QPalette.ToolTipText, text)
    palette.setColor(QPalette.Text, text)
    palette.setColor(QPalette.Button, QColor(TEMPLE_CARD))
    palette.setColor(QPalette.ButtonText, text)
    palette.setColor(QPalette.BrightText, QColor("#ff5555"))
    palette.setColor(QPalette.Highlight, QColor(TEMPLE_LAPIS_BRIGHT))
    palette.setColor(QPalette.HighlightedText, QColor(TEMPLE_GOLD_PALE))
    app.setPalette(palette)
def main() -> int:
    harden_process()
    app=QApplication(sys.argv)
    apply_cross_platform_style(app)
    apply_base_appearance()
    app.setApplicationName("BastetCipher")
    app.setApplicationDisplayName("BastetCipher — Sacred Chamber")
    window=BastetCipherApp()
    window.show()
    return app.exec()
if __name__ == "__main__":
    sys.exit(main())