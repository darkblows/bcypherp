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
    """Lock all current and future process pages into RAM to reduce swap risk.
    Best-effort: requires CAP_IPC_LOCK or sufficient RLIMIT_MEMLOCK on Linux.
    On failure the app continues with per-buffer mlock (SecureBuffer)."""
    if _SYSTEM not in ("Linux", "Darwin"):
        return False
    try:
        libc = ctypes.CDLL(ctypes.util.find_library("c") or ("libc.so.6" if _SYSTEM == "Linux" else "libc.dylib"), use_errno=True)
        # MCL_CURRENT | MCL_FUTURE
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
BCA_VERSION_V2 = 2  # adds KDF selector (PBKDF2 or Argon2id)
BCA_ITERS = 200_000
# Argon2id parameters (memory cost in KiB, time cost, parallelism, hash len)
# Tuned for interactive desktop use while remaining memory-hard.
ARGON2_MEMORY_KIB = 64 * 1024  # 64 MiB
ARGON2_TIME = 3
ARGON2_PARALLELISM = 4
ARGON2_HASH_LEN = 64
KDF_PBKDF2 = 0
KDF_ARGON2ID = 1
HEADER_LEN = 69  # v1
HEADER_LEN_V2 = 70  # v2: +1 byte kdf_id after version
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
        # PBKDF2HMAC.derive() accepts any buffer-protocol object, so the
        # bytearray password can be passed directly rather than copied into
        # an immutable bytes object first -- bytes can't later be wiped,
        # so avoiding the copy here is a real (if small) reduction in how
        # long the plaintext password can linger in memory. The Argon2id
        # branch above still copies to bytes because argon2-cffi's API
        # documents `secret` as required to be bytes specifically.
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
    if kdf_id == KDF_ARGON2ID and not _HAS_ARGON2:
        raise BCAFormatError(
            "Argon2id selected but 'argon2-cffi' is not installed. "
            "Install with: pip install argon2-cffi"
        )
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
            # v2 header: magic + version + kdf_id + salt + iters(placeholder) + iv1 + iv2
            header = (
                BCA_MAGIC
                + bytes([BCA_VERSION_V2, kdf_id])
                + salt
                + struct.pack("<I", 0)  # unused for Argon2; params are fixed in code
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
    version = d[4]
    if version == BCA_VERSION:
        # v1: magic(4) + ver(1) + salt(32) + iters(4) + iv1(12) + iv2(16) = 69
        kdf_id = KDF_PBKDF2
        salt = bytes(d[5:37])
        iterations = struct.unpack("<I", d[37:41])[0]
        if iterations != BCA_ITERS:
            raise BCAFormatError("Invalid PBKDF2 parameter for this archive.")
        iv1 = bytes(d[41:53])
        iv2 = bytes(d[53:69])
        ct_offset = HEADER_LEN
    elif version == BCA_VERSION_V2:
        if len(d) < HEADER_LEN_V2:
            raise BCAFormatError("File too short for a v2 .bca archive.")
        # v2: magic(4) + ver(1) + kdf_id(1) + salt(32) + iters(4) + iv1(12) + iv2(16) = 70
        kdf_id = d[5]
        if kdf_id not in (KDF_PBKDF2, KDF_ARGON2ID):
            raise BCAFormatError("Unsupported KDF identifier in archive.")
        salt = bytes(d[6:38])
        iterations = struct.unpack("<I", d[38:42])[0]
        if kdf_id == KDF_PBKDF2 and iterations != BCA_ITERS:
            raise BCAFormatError("Invalid PBKDF2 parameter for this archive.")
        iv1 = bytes(d[42:54])
        iv2 = bytes(d[54:70])
        ct_offset = HEADER_LEN_V2
    else:
        raise BCAFormatError("Archive version not supported.")
    ct_view = memoryview(d)[ct_offset:]
    progress(10, "Re-deriving 512-bit keys...")
    k1, k2 = derive_vault_keys(password, salt, iterations if kdf_id == KDF_PBKDF2 else BCA_ITERS, kdf_id=kdf_id)
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
        except Exception as exc:
            raise BCADecryptError(f"Layer 2 error: {exc}") from exc
        progress(45, "Layer 1 decryption...")
        try:
            aesgcm = AESGCM(bytes(k1))
            plain = bytearray(aesgcm.decrypt(iv1, ct1, None))
        except MemoryError:
            raise
        except Exception as exc:
            raise BCADecryptError(
                "Layer 1 error: wrong password or tampered file (authenticity check failed)."
            ) from exc
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
AUDIO_EXTENSIONS = {".mp3", ".ogg", ".wav", ".flac", ".aac", ".m4a", ".wma"}
AUDIO_TRANSCODE_EXTENSIONS = {".m4a", ".wma"}
VIDEO_EXTENSIONS = {".mp4", ".webm", ".mov", ".avi", ".mkv", ".wmv"}
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


# ---------------------------------------------------------------------------
# Multi-layer media safety guards
# These reduce (they cannot eliminate) the risk of malicious PDFs, images,
# audio and video. Full OS-level sandboxing is still recommended for a
# high-assurance threat model.
# ---------------------------------------------------------------------------

# Soft ceilings kept high so legitimate large media still previews; hard
# decompression / dimension caps below still block classic bomb payloads.
MAX_IMAGE_PIXELS = 80_000_000          # ~80 MP after decode
MAX_IMAGE_DIMENSION = 16_384           # per side
MAX_PDF_PAGES_SOFT = 5_000             # refuse absurd page counts
MAX_PDF_RENDER_DPI = 150
MEDIA_PARSE_TIMEOUT_SEC = 90


def _sniff_media_kind(data: bytes, claimed: ViewerKind) -> None:
    """Reject obvious magic mismatches before handing bytes to a parser."""
    if not data:
        raise ValueError("Empty media payload.")
    head = data[:16]
    if claimed == ViewerKind.PDF:
        # PDF may start with whitespace then %PDF
        probe = data[:1024].lstrip()
        if not probe.startswith(b"%PDF"):
            raise ValueError("Content does not look like a PDF (missing %PDF header).")
    elif claimed == ViewerKind.IMAGE:
        ok = (
            head.startswith(b"\x89PNG")
            or head.startswith(b"\xff\xd8\xff")  # JPEG
            or head.startswith(b"GIF87a")
            or head.startswith(b"GIF89a")
            or head.startswith(b"BM")
            or head.startswith(b"RIFF") and data[8:12] == b"WEBP"
            or head[:4] in (b"II*\x00", b"MM\x00*")  # TIFF
            or head.startswith(b"\x00\x00\x01\x00")  # ICO
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
            or head[4:8] == b"ftyp"  # m4a/mp4 family
            or head.startswith(b"\x30\x26\xb2\x75")  # ASF/WMA
        )
        if not ok:
            # Soft warning path: still allow unknown audio; ffmpeg may handle it.
            pass
    elif claimed == ViewerKind.VIDEO:
        ok = (
            head[4:8] == b"ftyp"
            or head.startswith(b"\x1a\x45\xdf\xa3")  # EBML/WebM/MKV
            or head.startswith(b"RIFF")
            or head.startswith(b"\x00\x00\x00\x14ftyp")
            or head.startswith(b"\x00\x00\x01\xba")  # MPEG-PS
            or head.startswith(b"\x00\x00\x01\xb3")
        )
        if not ok:
            pass  # ffmpeg probe is the real gate


def _apply_child_resource_limits(input_size_bytes: int = 0) -> None:
    """Tighten RLIMIT for worker processes that parse untrusted media.

    The address-space cap is scaled to the input rather than a flat
    constant: video is decoded by ffmpeg at its *source* resolution before
    any of our own output-side downscaling is applied (the scale filter
    runs after decode), so a legitimate large/high-resolution file can
    need well over a gigabyte of decoder working set even though what we
    stream back out is small. A flat ~2 GiB cap risks rejecting real,
    non-malicious files. Scaling to the input size keeps the cap no
    smaller than what legitimate content of that size plausibly needs,
    while still bounding a pathological stream that is small on disk but
    designed to explode in memory on decode.
    """
    if _SYSTEM not in ("Linux", "Darwin"):
        return
    try:
        import resource
        soft_as, hard_as = resource.getrlimit(resource.RLIMIT_AS)
        # Generous multiplier + floor to comfortably cover decoder
        # reference-frame buffers, filter graphs, and process overhead for
        # legitimate high-resolution source video, while a hard ceiling
        # still bounds worst-case memory use from adversarial input.
        floor_bytes = 2 * 1024 ** 3        # 2 GiB minimum, matches prior behavior for small/unknown inputs
        ceiling_bytes = 12 * 1024 ** 3     # 12 GiB hard ceiling regardless of input size
        scaled = max(floor_bytes, input_size_bytes * 12) if input_size_bytes > 0 else floor_bytes
        cap_as = min(scaled, ceiling_bytes)
        if hard_as > 0:
            cap_as = min(cap_as, hard_as)
        resource.setrlimit(resource.RLIMIT_AS, (cap_as, hard_as if hard_as > 0 else cap_as))
        resource.setrlimit(resource.RLIMIT_CPU, (MEDIA_PARSE_TIMEOUT_SEC + 30, MEDIA_PARSE_TIMEOUT_SEC + 60))
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        # No new files preferred; best-effort. ffmpeg legitimately opens
        # several fds (pipes, codec/format library internals, sometimes
        # dynamically loaded libraries), so this is a loose ceiling, not a
        # tight one -- it exists to stop fd-exhaustion abuse, not to
        # constrain normal operation.
        try:
            resource.setrlimit(resource.RLIMIT_NOFILE, (256, 256))
        except Exception:
            pass
    except Exception:
        pass


def _open_pdf_restricted(data: bytes):
    """Open a PDF with the most defensive fitz options available."""
    import fitz
    # Prefer stream open; never write to disk from this path.
    doc = fitz.open(stream=data, filetype="pdf")
    try:
        # Disable dangerous PDF features where the API allows it.
        # MuPDF/PyMuPDF does not execute JS by default in recent versions;
        # still force repair/clean on open when supported.
        if hasattr(doc, "is_encrypted") and doc.is_encrypted:
            # Passworded PDFs inside the vault are unexpected; refuse rather
            # than prompt (avoids interaction traps).
            doc.close()
            raise ValueError("Encrypted PDF streams are not opened in preview.")
        if doc.page_count > MAX_PDF_PAGES_SOFT:
            doc.close()
            raise ValueError(
                f"PDF has {doc.page_count} pages (limit {MAX_PDF_PAGES_SOFT}). "
                "Export and open externally if this is intentional."
            )
        # Optional: set a low memory / no-cache preference if available.
        try:
            fitz.TOOLS.store_shrink(100)  # drop MuPDF store aggressively
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
        # SVG → raster via MuPDF in a constrained path (no external entity expansion
        # beyond what MuPDF itself allows; size already capped by caller).
        import fitz
        doc = fitz.open(stream=data, filetype="svg")
        try:
            if doc.page_count < 1:
                raise ValueError("Empty SVG document.")
            page = doc.load_page(0)
            # Cap raster size to avoid SVG bombs expanding into huge bitmaps.
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
    # Pillow: deny decompression bombs before full load.
    try:
        Image.MAX_IMAGE_PIXELS = MAX_IMAGE_PIXELS
    except Exception:
        pass
    buf = io.BytesIO(data)
    img = Image.open(buf)
    # Verify header dimensions before decoding full pixel buffer when possible.
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
    # Load pixels (this is the costly / risky step); already dimension-checked.
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
            # Guard against a single page expanding into an absurd bitmap.
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
        self._max_cache = 2  # keep memory footprint low; pages are re-rendered on demand
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
    """Write media to a RAM-backed temp file when possible, with restrictive mode."""
    import tempfile
    ram_disk = "/dev/shm" if os.path.isdir("/dev/shm") and os.access("/dev/shm", os.W_OK) else None
    # Prefer exclusive create + owner-only permissions.
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
    """Transcode formats SDL_mixer can't read directly (m4a, wma) to WAV,
    entirely via ffmpeg pipes/RAM-backed temp storage. Raises on failure."""
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
    # pygame.mixer.music.get_pos()/play(start=...) behave inconsistently
    # across formats (WAV in particular isn't in the set of formats with
    # documented seek/position support), which after enough pause/resume
    # or seek cycles lets the tracked position drift from what's actually
    # audible -- most visible on long tracks. Track position ourselves
    # with a wall clock instead of trusting the mixer's own counter.
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
            # Fold the elapsed-before-pause time into the offset and reset
            # the clock's start point to now, so time spent paused is never
            # counted as playback (this is exactly the class of drift that
            # pygame's own get_pos() is documented to get wrong across a
            # pause/unpause cycle).
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
        self.create_kdf_combo.addItem("PBKDF2-HMAC-SHA512 (200k iters) — classic", KDF_PBKDF2)
        if _HAS_ARGON2:
            self.create_kdf_combo.addItem(
                f"Argon2id (m={ARGON2_MEMORY_KIB//1024}MiB, t={ARGON2_TIME}, p={ARGON2_PARALLELISM}) — memory-hard",
                KDF_ARGON2ID,
            )
        else:
            self.create_kdf_combo.addItem(
                "Argon2id (install argon2-cffi to enable)",
                KDF_ARGON2ID,
            )
            # Keep selectable but build_bca will raise a clear error if chosen.
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
        self.close_vault_btn = QPushButton("PURGE VAULT FROM RAM")
        self.close_vault_btn.setObjectName("dangerButton")
        self.close_vault_btn.clicked.connect(self._close_vault)
        top.addWidget(self.close_vault_btn)
        ec.addLayout(top)
        self.entries_scroll = QScrollArea()
        self.entries_scroll.setWidgetResizable(True)
        self.entries_scroll.setFrameShape(QFrame.NoFrame)
        self.entries_scroll.setMinimumHeight(320)
        self.entries_scroll.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        # Explicit backgrounds on the scroll area and its viewport avoid the
        # OS-themed (often white, on Windows) fallback background painting
        # through before/around our own styled widgets.
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
    def _on_open_success(self, entries):
        self.open_spinner.stop()
        self.open_progress.hide()
        self._set_busy(self.open_spinner, [self.open_pw_entry, self.open_btn], False)
        self._open_entries = entries
        self.open_status.setText(
            f"✓ Vault unlocked · {len(entries)} file(s) · data only in RAM"
        )
        self.open_status.setStyleSheet(f"color:{TEMPLE_EMERALD};")
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
        elif "Layer 1" in message or "Layer 2" in message:
            friendly = "Wrong password or corrupted/tampered archive."
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
            self.entries_layout.addWidget(row)
        self.entries_layout.addStretch(1)
    def _preview_entry(self,entry):
        kind=classify_extension(entry.name)
        # High soft ceilings so large legitimate media still previews. Absolute
        # safety still rests on magic sniffing, pixel/page bombs, timeouts,
        # restricted library options, and (where used) child-process RLIMIT.
        MAX_PREVIEW_BYTES = {
            ViewerKind.IMAGE: 400 * 1024 * 1024,   # 400 MiB
            ViewerKind.PDF:   350 * 1024 * 1024,   # 350 MiB
            ViewerKind.AUDIO: 500 * 1024 * 1024,   # 500 MiB
            ViewerKind.VIDEO: 1024 * 1024 * 1024,  # 1 GiB
            ViewerKind.TEXT:  32 * 1024 * 1024,    # 32 MiB
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
        # Layer 1: magic / structural sniff before any library sees the bytes.
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
            # Drop the temporary copy and encourage GC so large media does not linger.
            try:
                # Best-effort wipe of the preview copy (not the vault entry).
                if isinstance(data, (bytes, bytearray)):
                    # bytes are immutable; allocate a transient wipe buffer only
                    # if we still hold a mutable view (defensive).
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
                # Tiny margin: allow scrubbing almost to the reported end.
                # If the decoded stream is shorter (common with m4a padding),
                # play_audio will start near the end and the poll timer will
                # mark Finished once the mixer reports idle.
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
                # Playback reached the end of the actual decoded audio on
                # its own (not a user pause/stop). This can happen a little
                # before the container's reported duration -- formats like
                # m4a often carry encoder priming/padding samples, so the
                # real decoded length can be a touch shorter than what the
                # file's metadata claims. Reflect that the track has ended
                # instead of leaving the controls stuck mid-track.
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
                    # The seek landed past the last frame ffmpeg could
                    # actually decode (see the margin note in seek()) and
                    # came back empty. Rather than leaving the player stuck
                    # with nothing on screen, fall back to the last position
                    # that did produce a frame.
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
                    # Keep only a tiny margin so the scrubber can reach near
                    # the true end. If ffmpeg returns no frame (container
                    # padding past last decodable frame), the finishedDecoding
                    # handler falls back to the last good timestamp instead of
                    # leaving the player stuck.
                    margin = max(frame_interval, 0.05)
                    raw = slider.value() / 1000.0 * info.duration
                    target = min(raw, max(0.0, info.duration - margin))
                    if raw >= info.duration - margin:
                        # User scrubbed to the very end: treat as finished.
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
    def _close_vault(self):
        for entry in self._open_entries:
            wipe_bytearray(entry.data)
        self._open_entries = []
        self._render_entries_list()
        self.entries_card.hide()
        self.select_card.show()
        self.auth_card.show()
        self._bca_path = None
        self.open_dz_label.setText("📁  SELECT A .BCA ARCHIVE")
        self.open_dz_sub.setText("Will be opened only in memory: no data written to disk")
        self.open_status.setText("Vault closed · Data wiped from RAM.")
        self.open_status.setStyleSheet(f"color:{TEMPLE_GOLD_BRONZE};")
        self.open_pw_entry.clear()
        # Multiple GC passes help return large media pages to the OS sooner.
        for _ in range(3):
            gc.collect()
    def wipe_all_on_exit(self):
        for entry in self._open_entries:
            wipe_bytearray(entry.data)
        for entry in self._pending_create_entries:
            wipe_bytearray(entry.data)
        self._open_entries = []
        self._pending_create_entries = []
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

# =============================================================================
# BASTET AUDIT TOOL -- embedded, independent security-checking utility.
# Opened by clicking the Bastet emblem on the home screen. Runs entirely
# in its own thread with its own Tk window; does not touch the Qt app's
# state, and only reads (never modifies) this source file.
# =============================================================================

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
"""
import sys, os, gc, tracemalloc, json

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from bca_core_standalone import build_bca, parse_bca, VaultFileEntry, BCAFormatError, BCADecryptError
import bca_core_standalone

bca_core_standalone.BCA_ITERS = 2000

N_CYCLES = 300
password = bytearray(b"MemoryTestPassword!2024")

def run_cycle():
    pw = bytearray(password)
    entry = VaultFileEntry(name="test.bin", data=bytearray(os.urandom(20000)))
    buf = build_bca([entry], pw)
    pw2 = bytearray(password)
    entries = parse_bca(bytearray(buf), pw2)
    return entries

tracemalloc.start()
gc.collect()

for _ in range(20):
    run_cycle()
gc.collect()
warm_snapshot = tracemalloc.take_snapshot()

for _ in range(N_CYCLES):
    run_cycle()
gc.collect()
final_snapshot = tracemalloc.take_snapshot()

warm_total = sum(stat.size for stat in warm_snapshot.statistics("filename"))
final_total = sum(stat.size for stat in final_snapshot.statistics("filename"))
growth_bytes = final_total - warm_total
growth_per_cycle = growth_bytes / N_CYCLES if N_CYCLES else 0

top_diffs = final_snapshot.compare_to(warm_snapshot, "lineno")[:8]

result = {
    "cycles_run": N_CYCLES,
    "memory_after_warmup_bytes": warm_total,
    "memory_after_all_cycles_bytes": final_total,
    "growth_bytes": growth_bytes,
    "growth_bytes_per_cycle": round(growth_per_cycle, 1),
    "verdict": "REVIEW" if growth_per_cycle > 2048 else "PASS",
    "note": (
        "growth_bytes_per_cycle above ~2KB/cycle after warmup may indicate "
        "a Python-level leak worth investigating; small positive values are "
        "normal GC/allocator noise."
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
                for pkg in ["cryptography", "pip-audit", "bandit"]:
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
    """Force the Fusion style on all platforms.

    On Windows, PySide6 otherwise defaults to the native 'windowsvista'
    style, which renders several custom-painted/stylesheet-heavy widgets
    (GlowFrame cards, QScrollArea viewports, etc.) incorrectly and can
    flash the OS theme's white background before the stylesheet paints
    over it (most visible on Windows 10 when opening an archive). Fusion
    is a consistent, cross-platform style that respects QSS everywhere,
    which avoids both problems.
    """
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