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
from PIL import Image, ImageTk
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
def harden_process() -> None:
    disable_core_dumps()
_APP_ICON_DATA = "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAADcAAABDCAMAAAAPtm2jAAAClFBMVEUAAACcjDfFnWC/m2TQrGzLrHHJqG3btGnYuHWfl2zauG7guGreuGhOaF/btWzatGflvGnetmrGr28TFyXhumjq4szfuWgrYWnOs3JsjXnkuWbatGzjuWWBjm0TGCjKsHLmvGY4goQhb3fhuGa/oWdjkXzhzJzlt2Kxp3fjuWXPrGVRiHziwoCjj1vu4L/iuGIgbXjjuF4mgI/nu2Let2fUrmPmu2NSjoc6cnIsfYPkt1+qoWzluWESGy/w5cXouV7gtmLRtGuvpZzVy7PnuV17l3jftF3nuWCXoXX06Mjlt2FikYJAhIIdd4TEpmXkt14weX3muGCYnm6AeHQSVGJSh30mKjroul7NrGLYtWa1pWcdeogadIDpul6Al3Pjtl/HrGQ5OUXouVtMh39lkXjmuF6ImnLnumEqgoj16cjhtVyeo29KiX8beIZVhnrouFuNnHFej32qomjctV9vkXvoul5Eh4Iff4y+qmaAmHUzfoIbdoHnuWPhtl+uqGxTiX0mf4jnuFrZr1jKrWIwg4f26cbftWDVsV+bmmpejHrnuWGzpmgZfIvpuVrnuVvZs2DZsFcffYjftGB9mXPpuln15sXitlsdf4sdeYbpuFnmuFygpG0bfYf36sjlt1/puVkafIsiV17mtFzltVXluFvpu1pShnYYf40SGi3ouFrbtVrouls+iYMaf41YkHzqulxwlnTquVjntla+qlwZfozouFkXfYvquVkvgoTot1XqulkQGS767MeDmWwWfo3quVVWjnoWgJDru1zquVTHrFwVfYv868fsuljsuVPfuFnFs2nHrlu2q2Sdo2aNnmpulnRqknRdjXNGhXgyhYErg4MlgYYUgpMaf4kVgJATgJASgI4Ufo352if6AAAA2XRSTlMAAgUICw8VFhseICMnKCsvNTU1Nzk9PD0+PkBDR0hJS0xMUVNTU1VYXF5eXmBgY2JiZ2doa2psbGxvcXFzcnl5eXh8f35/gIKDhIaHhoaJjI2QkZGRk5OUlZeXlpaZmJqcnJ+foaSlp6eoqaioqKusrKyusbCys7O1tLW1tra3tra5uLm6vL29vL2+vr7AxcXFxcfIy8zMz87S09XU1tfZ2tvc3d/g4eHh4+Xn5ubp6urt7O3t8PHy8/T39/j5+Pr7+/z9/fz//v/+//////7+/v///v/+///+IOtThQAABoRJREFUeNqdlv9fUlcYxw8CwoCBOnOGNGnYzFYhwyyMJW4mxmqMtkZpzIahm+aYOdBMKmZT1wSjCNNMWGpEpoSBBBUEzLTvSxPv5f4zi0y7e73aXtw+P93nPOd97/nyOc+54L+VVEsAbyNRRAqwC8cIRoKpOIwUrWqQE5mJbOpX0jFQSZLgcNcWZUS/peuSX5KUMKYOHh5AAitHVgViA/V+DT5BTuH7JQDZtbvTyrV2KHTQp0gMYwdrppBDHaMaidp5RguFaoLshBayr2csVu2QxDePIB6thsd6+hJZ1vRII2QaLHwVFQ6aoMZIegJcqaMX+tmIW/q6sR7qHRaDNyobvWKazoC7h78c8jvcgU4NKo/PWnoiDKKNaG6BBhzpr4c9OhD7w4zm+pd6F3jQnKUF7nUylkPGRC/0L47g4b+agqWOjB5ne8g2zFoOWUM2qL0NlSfXWXCLXrxxIBXVLraMBU4XL4fFHZNuiwSVT917gwbi4t7ZnYdqZ/lPROuNy6GxCzrpZ6HyeTV3FruXPdsjR49/4mdI66ctHQz/SeiIEz1/WfWz0pf9pLMndGhDyC1j7s6lN1V1usfOyNF20h2dFRMBIHKLZgN7magMNdgINXopi8/e41Cjn4rKMg8EZgv5RJBSy7ob26kCKMnP2Mc6lSAuVafb3qNAJ2v3IHeZqhTAcpGvI7Z9aAeSXDVRrYcZf7lHC9U4SWj3VtmQ6yQXC2RFCssXoJ1NaKvxHCcDh/vxAN93OHRyuBBtFt1OZGF34UwWoEau0q7B7q1c9NxPtbtNOg7IUrW6W06h68SmrZPwNfrVCBXgrI/r14Tg7hw+Kk05tWarVG0wqKXrRBRUe0GOCQ6sqX9sxYFM3qO5ckEosFaKAhkKl0d/oKLigM7plFNfY/s2TEGC8rlHvEzQRu54Pr/5k8kvDRI5AdCK0unMYnOw47sG+xQEhcaav9P5lbRFQ8il+i8nP/li/nkHuQ0oDdSzCNS8eqXXKmrLI0/4gh5DRbU9BkOTtoGxUDRq39PkN8tlJE6byDqx6sMTU8hZikEJWBFj2qFQdCCbMxJRCQmbvqpssIXgmFt7+PTQVUv7EVMoaq+u0OkIImVwiJ1jg6cOpRmnWQCneTi+fXV3YKtLLlZ3JG2ai8VisPtQp69PyuMWKR2O+l4IRq5lJunUYsVEeaB79fa7D/U4AJKNT6fclfnvFwcjfSKw7iYSGPip3VfFIH6AB9tW4Dn9lp8CyN00ILZG/KXv51e6F54ak+Pngl4yjsSgXWKhRFaWpPq1/dehCRl148XPruBecCt+W1E42tJ6OZMgkUtEZfuh2MJ4CWN93LpOZfbHld2mHMf0jJNo5fC4GXjyb/fufX7rPfDBpxvv3d5BEl86LSI7Z2YcG853V36crXS+3BqO/8nN3ubKXclcSRW139J/6VJVxo7b9y5+e+vKrW8vvuBSy+om6hgKCffd/ZUN528+8XNe7bLuzjwEQV9Jh800Ih5HYJQOaz768fa5r7//+tztH9frrcXpNArDPLL3TyQWm7+jYyxVmrystZsFgl0NH+Y0lTGyKQAQhCO16zdu27FtY0GbT4rHrXqnpG5DfsMugWDz2izuchXLdd3/ewFGAg35+xu2UBbNwdU7HMOjFsv2fQCAzMtH9+cfnULghaf3XbmoEyesO3ZQIDAh9nd5ajFxsS2ZFxQzH8yXxIO08QWoO19w8FidkATQokuarj+fG18pM+RWLR7+d4p83GTWA+hCajwilo/PzV1vktDR0OIkiwqy8Mme5AxhfzxOkk2w2FLWg4Wn65buhQJhHhm8WRRXEqcvXh5pxj4aKFSwHsyWJHS1W3kv5yZ2yal5gK9kPrqQ2G9BhlNTXKrx6lMBX5HLV1H+4oDERCpSKoriB1VYFZSqcPHqgk1Z5hnfOpAMsEo0NDSkAthVVvHN9rfhlMeQXwYBdqm7oMYRHHZO3xU9PkowmOOiY+AMZ6NaL9FrVijU0ykYuL4jsDZM9BTTOQxMnPVs9IcwcUQsGcLE4Ry/wz8ESSPBIEbO+Xu02UdhstlMApuYOIcPH4ebPTR6SnpKSgohcY4Q1sImV6oxEpkOYxknKdwK945m6GWyEVYYA0cJn4Btw2xNWQaPjuV79BecfTC3Vi8USrFwKV4T7LbwpKNxMRLn2J7z8GQHH2AVx9cK2cwizBzF0dPa4k0HmMXwDoY54C3EnZaBtxFO9j/2+gcTFmwsHz6V1QAAAABJRU5ErkJggg=="
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
    out = do.decompress(data) + do.flush()
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
    salt = bytes(d[5:37])
    iterations = struct.unpack("<I", d[37:41])[0]
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
            file_count = struct.unpack_from("<H", plain, pos)[0]
            pos += 2
            for i in range(file_count):
                name_len = struct.unpack_from("<H", plain, pos)[0]
                pos += 2
                name = plain[pos : pos + name_len].decode("utf-8")
                pos += name_len
                crc_expected = struct.unpack_from("<I", plain, pos)[0]
                pos += 4
                orig_size = struct.unpack_from("<I", plain, pos)[0]
                pos += 4
                comp_size = struct.unpack_from("<I", plain, pos)[0]
                pos += 4
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
                RenderedPage(index=i, png_bytes=png_bytes, width=pix.width, height=pix.height)
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
            try:
                os.remove(tmp_path)
                removed = True
                break
            except OSError:
                if attempt < 4:
                    time.sleep(0.1)
        if not removed:
            try:
                os.remove(tmp_path)
            except OSError:
                pass
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
def stream_video_frames_in_memory(data: bytes, info: VideoInfo, start_seconds: float = 0.0, process_holder: Optional[list] = None):
    ffmpeg = _get_ffmpeg_exe()
    frame_size = info.width * info.height * 3
    if frame_size <= 0:
        raise RuntimeError("Invalid video dimensions.")
    with _video_input_source(data) as video_path:
        cmd = [ffmpeg, "-hide_banner"]
        if start_seconds > 0:
            cmd += ["-ss", f"{start_seconds:.3f}"]
        cmd += [
            "-i", video_path,
            "-map", "0:v:0",
            "-f", "rawvideo", "-pix_fmt", "rgb24",
            "-vf", f"fps={info.fps}",
            "pipe:1",
        ]
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
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
GOLD = "#c9a84c"
CUSTOMGOLD = "#544A00"
GOLD_BRIGHT = "#f0c040"
GOLD_DARK = "#7a5c1e"
STONE = "#2a2318"
STONE_MID = "#3d3220"
STONE_LIGHT = "#5a4a2a"
STONE_PALE = "#8a7550"
GLOW_AMBER = "#ff8c00"
EMERALD = "#00c896"
SAND = "#d4b483"
DEEP = "#0f0c06"
INK = "#1a1408"
DANGER = "#ff5555"
DANGER_DARK = "#4a1414"
SUCCESS = "#00c896"
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
    root.configure(fg_color=DEEP)
class Styled:
    @staticmethod
    def frame_kwargs(border: bool = True) -> dict:
        kw = dict(fg_color=STONE, corner_radius=14)
        if border:
            kw.update(border_width=1, border_color=GOLD_DARK)
        return kw
    @staticmethod
    def primary_button_kwargs() -> dict:
        return dict(
            fg_color=GOLD_DARK,
            hover_color=GOLD,
            text_color=DEEP,
            font=FONT_BUTTON,
            corner_radius=10,
            height=max(38, round(56 * CURRENT_UI_SCALE)),
        )
    @staticmethod
    def secondary_button_kwargs() -> dict:
        return dict(
            fg_color=STONE_MID,
            hover_color=STONE_LIGHT,
            text_color=SAND,
            font=FONT_BODY,
            corner_radius=10,
            height=max(32, round(48 * CURRENT_UI_SCALE)),
            border_width=1,
            border_color=GOLD_DARK,
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
            fg_color=INK,
            border_color=GOLD_DARK,
            text_color=SAND,
            font=FONT_BODY,
            corner_radius=8,
            height=max(30, round(44 * CURRENT_UI_SCALE)),
        )
    @staticmethod
    def label_title_kwargs() -> dict:
        return dict(text_color=GOLD_BRIGHT, font=FONT_TITLE)
    @staticmethod
    def label_header_kwargs() -> dict:
        return dict(text_color=GOLD, font=FONT_HEADER)
    @staticmethod
    def label_body_kwargs() -> dict:
        return dict(text_color=SAND, font=FONT_BODY)
    @staticmethod
    def label_muted_kwargs() -> dict:
        return dict(text_color=STONE_PALE, font=FONT_BODY_ITALIC)
PIM_RE = re.compile(r"^\d{1,32}$")
class GeneratorView(ctk.CTkFrame):
    def __init__(self, master, **kwargs):
        super().__init__(master, fg_color=DEEP, **kwargs)
        self._build()
    def _build(self) -> None:
        header = ctk.CTkLabel(
            self, text="𓆃  Cipher Generator  𓆃", **Styled.label_header_kwargs()
        )
        header.pack(pady=(18, 4))
        tagline = ctk.CTkLabel(
            self,
            text="Turn a secret phrase into a high-entropy password",
            **Styled.label_muted_kwargs(),
        )
        tagline.pack(pady=(0, 18))
        card = ctk.CTkFrame(self, **Styled.frame_kwargs())
        card.pack(padx=24, pady=8, fill="x")
        ctk.CTkLabel(card, text="Secret Phrase / Word", **Styled.label_body_kwargs()).pack(
            anchor="w", padx=20, pady=(12, 4)
        )
        phrase_row = ctk.CTkFrame(card, fg_color="transparent")
        phrase_row.pack(fill="x", padx=20)
        self.phrase_var = tk.StringVar()
        self.phrase_entry = ctk.CTkEntry(
            phrase_row,
            textvariable=self.phrase_var,
            show="•",
            placeholder_text="Your secret phrase...",
            **Styled.entry_kwargs(),
        )
        self.phrase_entry.pack(side="left", fill="x", expand=True)
        self._show_phrase = False
        self.toggle_btn = ctk.CTkButton(
            phrase_row,
            text="👁",
            width=42,
            command=self._toggle_phrase_visibility,
            **Styled.secondary_button_kwargs(),
        )
        self.toggle_btn.pack(side="left", padx=(8, 0))
        ctk.CTkLabel(
            card, text="PIM (Personal Iteration Modifier — digits only, max 32)",
            **Styled.label_body_kwargs(),
        ).pack(anchor="w", padx=20, pady=(12, 4))
        self.pim_var = tk.StringVar()
        self.pim_var.trace_add("write", self._sanitize_pim)
        self.pim_entry = ctk.CTkEntry(
            card, textvariable=self.pim_var, placeholder_text="E.g. 1234",
            **Styled.entry_kwargs(),
        )
        self.pim_entry.pack(fill="x", padx=20)
        ctk.CTkLabel(
            card, text="Amplifier (0–9999 extra characters)",
            **Styled.label_body_kwargs(),
        ).pack(anchor="w", padx=20, pady=(12, 4))
        self.amp_var = tk.StringVar(value="0")
        self.amp_var.trace_add("write", self._sanitize_amp)
        self.amp_entry = ctk.CTkEntry(
            card, textvariable=self.amp_var, **Styled.entry_kwargs()
        )
        self.amp_entry.pack(fill="x", padx=20)
        self.error_label = ctk.CTkLabel(
            card, text="", text_color="#ff6b6b", font=FONT_BODY
        )
        self.error_label.pack(padx=20, pady=(10, 0))
        self.generate_btn = ctk.CTkButton(
            card, text="𓅓  Generate Cipher  𓅓", command=self._on_generate,
            **Styled.primary_button_kwargs(),
        )
        self.generate_btn.pack(pady=20, padx=20, fill="x")
        self.phrase_entry.bind("<Return>", lambda e: self._on_generate())
        self.pim_entry.bind("<Return>", lambda e: self._on_generate())
        self.status_label = ctk.CTkLabel(card, text="", **Styled.label_muted_kwargs())
        self.status_label.pack(pady=(0, 14))
        self.progress = ctk.CTkProgressBar(card, progress_color=GOLD_BRIGHT, fg_color=INK)
        self.progress.set(0)
        self.output_card = ctk.CTkFrame(self, **Styled.frame_kwargs())
        ctk.CTkLabel(
            self.output_card, text="Generated Cipher", **Styled.label_body_kwargs()
        ).pack(anchor="w", padx=20, pady=(12, 4))
        self.output_box = ctk.CTkTextbox(
            self.output_card, height=70, fg_color=INK, text_color=EMERALD,
            font=FONT_MONO, wrap="word", corner_radius=8,
        )
        self.output_box.pack(fill="x", padx=20)
        self.output_box.configure(state="disabled")
        btn_row = ctk.CTkFrame(self.output_card, fg_color="transparent")
        btn_row.pack(fill="x", padx=20, pady=14)
        self.copy_btn = ctk.CTkButton(
            btn_row, text="📋 Copy to Clipboard", command=self._copy_output,
            **Styled.secondary_button_kwargs(),
        )
        self.copy_btn.pack(side="left", expand=True, fill="x", padx=(0, 6))
        self.open_vault_btn = ctk.CTkButton(
            btn_row, text="🔒 Open in Vault", command=self._open_in_vault,
            **Styled.secondary_button_kwargs(),
        )
        self.open_vault_btn.pack(side="left", expand=True, fill="x", padx=6)
        self.clear_btn = ctk.CTkButton(
            btn_row, text="🗑 Wipe from Memory", command=self._clear_output,
            **Styled.danger_button_kwargs(),
        )
        self.clear_btn.pack(side="left", expand=True, fill="x", padx=(6, 0))
        self.stats_label = ctk.CTkLabel(
            self.output_card, text="", font=FONT_MONO_SMALL, text_color=STONE_PALE,
            justify="left",
        )
        self.stats_label.pack(anchor="w", padx=20, pady=(0, 16))
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
        self.toggle_btn.configure(text="𓁹" if self._show_phrase else "👁")
    def _on_generate(self) -> None:
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
        self.generate_btn.configure(state="disabled", text="Generating...")
        self.progress.pack(fill="x", padx=20, pady=(0, 10))
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
        self.output_card.pack(padx=24, pady=(8, 24), fill="x")
        self.generate_btn.configure(state="normal", text="𓅓  Generate Cipher  𓅓")
        self.progress.pack_forget()
        self.status_label.configure(text="")
    def _on_error(self, message: str) -> None:
        self.generate_btn.configure(state="normal", text="𓅓  Generate Cipher  𓅓")
        self.progress.pack_forget()
        self.status_label.configure(text="")
        messagebox.showerror("Error", f"Generation failed: {message}")
    def _copy_output(self) -> None:
        if not self._last_cipher:
            return
        self.clipboard_clear()
        self.clipboard_append(self._last_cipher)
        self.copy_btn.configure(text="✓ Copied!")
        self.after(1800, lambda: self.copy_btn.configure(text="📋 Copy to Clipboard"))
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
        super().__init__(master, fg_color=DEEP, **kwargs)
        self._open_entries: list[VaultDecryptedEntry] = []
        self._pending_create_entries: list[VaultFileEntry] = []
        self._active_video_tmp_paths: list[str] = []
        self._build()
    def _build(self) -> None:
        header = ctk.CTkLabel(
            self, text="𓁹  Sacred Vault  𓁹", **Styled.label_header_kwargs()
        )
        header.pack(pady=(18, 4))
        ctk.CTkLabel(
            self,
            text="AES-256-GCM · AES-256-CBC · PBKDF2-HMAC-SHA512 · deflate-raw · All in RAM",
            **Styled.label_muted_kwargs(),
        ).pack(pady=(0, 18))
        self.tabs = ctk.CTkTabview(
            self, 
            fg_color=STONE, 
            segmented_button_selected_color=GOLD_DARK,
            segmented_button_selected_hover_color=CUSTOMGOLD,
            segmented_button_fg_color=INK, 
            segmented_button_unselected_color=STONE_MID,
            segmented_button_unselected_hover_color=STONE_LIGHT,
            text_color=SAND,
        )
        self.tabs._segmented_button.configure(font=FONT_BUTTON, height=45) 
        self.tabs.pack(padx=24, pady=8, fill="both", expand=True)
        self.tabs.pack(padx=24, pady=8, fill="both", expand=True)
        self.tab_create = self.tabs.add("Create Archive")
        self.tab_open = self.tabs.add("Open Archive")
        self._build_create_tab()
        self._build_open_tab()
    def _build_create_tab(self) -> None:
        t = self.tab_create
        ctk.CTkLabel(t, text="Files to protect", **Styled.label_body_kwargs()).pack(
            anchor="w", padx=16, pady=(12, 4)
        )
        self.file_list_box = ctk.CTkTextbox(
            t, height=140, fg_color=INK, text_color=SAND, font=FONT_MONO_SMALL,
            corner_radius=8,
        )
        self.file_list_box.pack(fill="x", padx=16)
        self.file_list_box.configure(state="disabled")
        btn_row = ctk.CTkFrame(t, fg_color="transparent")
        btn_row.pack(fill="x", padx=16, pady=10)
        self.add_files_btn_ref = ctk.CTkButton(
            btn_row, text="➕ Add files...", command=self._add_files,
            **Styled.secondary_button_kwargs(),
        )
        self.add_files_btn_ref.pack(side="left", padx=(0, 6))
        ctk.CTkButton(
            btn_row, text="🗑 Clear list", command=self._clear_create_list,
            **Styled.danger_button_kwargs(),
        ).pack(side="left", padx=(6, 0))
        ctk.CTkLabel(t, text="Archive password", **Styled.label_body_kwargs()).pack(
            anchor="w", padx=16, pady=(10, 4)
        )
        self.create_pw_var = tk.StringVar()
        ctk.CTkEntry(
            t, textvariable=self.create_pw_var, show="•",
            placeholder_text="Password to encrypt the archive...",
            **Styled.entry_kwargs(),
        ).pack(fill="x", padx=16)

        ctk.CTkLabel(t, text="Confirm password", **Styled.label_body_kwargs()).pack(
            anchor="w", padx=16, pady=(10, 4)
        )
        self.create_pw_confirm_var = tk.StringVar()
        ctk.CTkEntry(
            t, textvariable=self.create_pw_confirm_var, show="•",
            placeholder_text="Repeat the password...",
            **Styled.entry_kwargs(),
        ).pack(fill="x", padx=16)
        self.create_status = ctk.CTkLabel(t, text="", **Styled.label_muted_kwargs())
        self.create_status.pack(pady=(10, 0))
        self.create_progress = ctk.CTkProgressBar(t, progress_color=GOLD_BRIGHT, fg_color=INK)
        self.create_btn = ctk.CTkButton(
            t, text="🔒  Create and save .bca archive  🔒", command=self._on_create_archive,
            **Styled.primary_button_kwargs(),
        )
        self.create_btn.pack(fill="x", padx=16, pady=16)
    def _add_files(self) -> None:
        paths = filedialog.askopenfilenames(title="Select files to protect")
        if not paths:
            return
        self.add_files_btn_ref.configure(state="disabled", text="Loading files...")
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
        self.add_files_btn_ref.configure(state="normal", text="➕ Add files...")
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
        self.create_btn.configure(state="disabled", text="Creating...")
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
        self.create_btn.configure(state="normal", text="🔒  Create and save .bca archive  🔒")
        self.create_progress.pack_forget()
        self.create_status.configure(text=f"✓ Archive created: {path}", text_color=EMERALD)
        self._refresh_create_list()
    def _on_create_error(self, message: str) -> None:
        self.create_btn.configure(state="normal", text="🔒  Create and save .bca archive  🔒")
        self.create_progress.pack_forget()
        self.create_status.configure(text="")
        messagebox.showerror("Error", f"Archive creation failed: {message}")
    def _build_open_tab(self) -> None:
        t = self.tab_open
        self.open_dropzone = ctk.CTkFrame(t, **Styled.frame_kwargs(border=True))
        self.open_dropzone.pack(fill="x", padx=16, pady=(16, 8))
        self.open_dz_label = ctk.CTkLabel(
            self.open_dropzone, text="📁  Select a .bca archive",
            font=FONT_HEADER, text_color=GOLD,
        )
        self.open_dz_label.pack(pady=(20, 6))
        self.open_dz_sub = ctk.CTkLabel(
            self.open_dropzone,
            text="Will be opened only in memory: no data written to disk",
            **Styled.label_muted_kwargs(),
        )
        self.open_dz_sub.pack(pady=(0, 16))
        ctk.CTkButton(
            self.open_dropzone, text="Choose file...", command=self._choose_bca_file,
            **Styled.secondary_button_kwargs(),
        ).pack(pady=(0, 20))
        self._bca_path: str | None = None
        ctk.CTkLabel(t, text="Archive password", **Styled.label_body_kwargs()).pack(
            anchor="w", padx=16, pady=(6, 4)
        )
        self.open_pw_var = tk.StringVar()
        self.open_pw_entry = ctk.CTkEntry(
            t, textvariable=self.open_pw_var, show="•",
            placeholder_text="Password used to encrypt it...",
            **Styled.entry_kwargs(),
        )
        self.open_pw_entry.pack(fill="x", padx=16)
        self.open_pw_entry.bind("<Return>", lambda e: self._on_open_archive())
        self.open_status = ctk.CTkLabel(t, text="", **Styled.label_muted_kwargs())
        self.open_status.pack(pady=(10, 0))
        self.open_progress = ctk.CTkProgressBar(t, progress_color=GOLD_BRIGHT, fg_color=INK)
        self.open_btn = ctk.CTkButton(
            t, text="🔓  Unlock Vault  🔓", command=self._on_open_archive,
            **Styled.primary_button_kwargs(),
        )
        self.open_btn.pack(fill="x", padx=16, pady=16)
        self.entries_frame = ctk.CTkScrollableFrame(
            t, fg_color=STONE_MID, corner_radius=10, height=220,
        )
        self.close_vault_btn = ctk.CTkButton(
            t, text="🔒 Close Vault and wipe data from RAM",
            command=self._close_vault, **Styled.danger_button_kwargs(),
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
        self.open_btn.configure(state="disabled", text="Unlocking...")
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
        self.open_btn.configure(state="normal", text="🔓  Unlock Vault  🔓")
        self.open_progress.pack_forget()
        self.open_status.configure(
            text=f"✓ Vault unlocked · {len(entries)} file(s) · data only in RAM",
            text_color=EMERALD,
        )
        self._open_entries = entries
        self._render_entries_list()
        self.entries_frame.pack(fill="both", expand=True, padx=16, pady=(10, 6))
        self.close_vault_btn.pack(fill="x", padx=16, pady=(0, 16))
        self.entries_frame.update_idletasks()
    def _on_open_error(self, message: str) -> None:
        self.open_btn.configure(state="normal", text="🔓  Unlock Vault  🔓")
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
            row = ctk.CTkFrame(self.entries_frame, fg_color=STONE, corner_radius=8)
            row.pack(fill="x", pady=4, padx=4)
            icon = "✓" if entry.crc_ok else "⚠"
            color = EMERALD if entry.crc_ok else DANGER
            ctk.CTkLabel(
                row, text=f"{icon} {entry.name}", text_color=color, font=FONT_BODY
            ).pack(side="left", padx=10, pady=8)
            ctk.CTkLabel(
                row, text=f"{len(entry.data)/1024:.1f} KB", text_color=STONE_PALE,
                font=FONT_MONO_SMALL,
            ).pack(side="left", padx=6)
            btns = ctk.CTkFrame(row, fg_color="transparent")
            btns.pack(side="right", padx=8, pady=6)
            kind = classify_extension(entry.name)
            if kind != ViewerKind.UNSUPPORTED:
                ctk.CTkButton(
                    btns, text="👁 Preview", width=100,
                    command=lambda e=entry: self._preview_entry(e),
                    **Styled.secondary_button_kwargs(),
                ).pack(side="left", padx=4)
            ctk.CTkButton(
                btns, text="💾 Export", width=90,
                command=lambda e=entry: self._export_entry(e),
                **Styled.secondary_button_kwargs(),
            ).pack(side="left", padx=4)
    def _preview_entry(self, entry: VaultDecryptedEntry) -> None:
        kind = classify_extension(entry.name)
        win = ctk.CTkToplevel(self)
        win.title(f"Preview — {entry.name}")
        win.geometry("800x700")
        win.configure(fg_color=DEEP)
        win.attributes("-topmost", True)
        win.after(150, lambda: [win.attributes("-topmost", False), win.focus_force()])
        app = self.winfo_toplevel()
        if hasattr(app, "_app_icon_photo"):
            win.after(250, lambda: win.iconphoto(False, app._app_icon_photo))
        try:
            if kind == ViewerKind.IMAGE:
                self._preview_image(win, bytes(entry.data))
            elif kind == ViewerKind.PDF:
                self._preview_pdf(win, bytes(entry.data))
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
                text_color=DANGER,
            ).pack(pady=40)
    def _preview_image(self, win: ctk.CTkToplevel, data: bytes) -> None:
        original_img = render_image_in_memory(data)
        canvas = tk.Canvas(win, bg=DEEP, highlightthickness=0)
        canvas.pack(expand=True, fill="both", padx=10, pady=10)
        max_w, max_h = 760, 640
        orig_w, orig_h = original_img.size
        fit_scale = min(max_w / orig_w, max_h / orig_h, 1.0)
        state = {"scale": fit_scale, "photo": None, "job": None}
        MIN_SCALE = 0.05
        MAX_SCALE = 8.0
        def render_at_scale() -> None:
            scale = state["scale"]
            new_w = max(1, round(orig_w * scale))
            new_h = max(1, round(orig_h * scale))
            resized = original_img.resize((new_w, new_h), Image.LANCZOS)
            photo = ImageTk.PhotoImage(resized)
            state["photo"] = photo
            canvas.delete("all")
            canvas_w = max(canvas.winfo_width(), 1)
            canvas_h = max(canvas.winfo_height(), 1)
            canvas.create_image(canvas_w // 2, canvas_h // 2, image=photo, anchor="center")
            canvas.configure(scrollregion=(0, 0, new_w, new_h))
        def on_mousewheel(event) -> None:
            direction = 1 if event.delta > 0 else -1
            zoom_step(direction)
        def on_scroll_up(_event=None) -> None:
            zoom_step(1)
        def on_scroll_down(_event=None) -> None:
            zoom_step(-1)
        def zoom_step(direction: int) -> None:
            factor = 1.1 if direction > 0 else (1 / 1.1)
            new_scale = state["scale"] * factor
            state["scale"] = max(MIN_SCALE, min(MAX_SCALE, new_scale))
            if state["job"] is not None:
                win.after_cancel(state["job"])
            state["job"] = win.after(30, render_at_scale)
        canvas.bind("<MouseWheel>", on_mousewheel)
        canvas.bind("<Button-4>", on_scroll_up)
        canvas.bind("<Button-5>", on_scroll_down)
        canvas.bind("<Configure>", lambda _e: render_at_scale())
        win.after(50, render_at_scale)
    def _preview_pdf(self, win: ctk.CTkToplevel, data: bytes) -> None:
        pages = render_pdf_pages_in_memory(data, dpi=100, max_pages=30)
        scroll = ctk.CTkScrollableFrame(win, fg_color=DEEP)
        scroll.pack(expand=True, fill="both", padx=10, pady=10)
        photo_refs: list = []
        win.pdf_photo_refs = photo_refs
        for page in pages:
            import io as _io
            pil_img = Image.open(_io.BytesIO(page.png_bytes))
            pil_img.thumbnail((760, 1000))
            photo = ImageTk.PhotoImage(pil_img)
            photo_refs.append(photo)
            lbl = tk.Label(scroll, image=photo, bg=DEEP)
            lbl.pack(pady=8)
            ctk.CTkLabel(
                scroll, text=f"Page {page.index + 1}", text_color=STONE_PALE,
                font=FONT_MONO_SMALL,
            ).pack()
    def _preview_text(self, win: ctk.CTkToplevel, data: bytes) -> None:
        text = decode_text_in_memory(data)
        box = ctk.CTkTextbox(win, fg_color=INK, text_color=SAND, font=FONT_MONO_SMALL, wrap="word")
        box.pack(expand=True, fill="both", padx=10, pady=10)
        box.insert("1.0", text)
        box.configure(state="disabled")
    def _preview_audio(self, win: ctk.CTkToplevel, data: bytes, name: str) -> None:
        ctk.CTkLabel(win, text="🎵", font=scaled_font(64), text_color=GOLD_BRIGHT).pack(pady=(60, 10))
        ctk.CTkLabel(win, text=name, **Styled.label_header_kwargs()).pack(pady=(0, 20))
        status_label = ctk.CTkLabel(win, text="Playing from RAM...", **Styled.label_muted_kwargs())
        status_label.pack(pady=(0, 10))
        duration = get_audio_duration_seconds(data)
        time_label = ctk.CTkLabel(win, text="0:00 / 0:00", font=FONT_MONO_SMALL, text_color=SAND)
        time_label.pack(pady=(0, 4))
        state = {"seeking": False, "poll_job": None, "started": False, "seek_offset": 0.0, "session": -1}
        def fmt(seconds: float) -> str:
            seconds = max(0, int(seconds))
            return f"{seconds // 60}:{seconds % 60:02d}"
        slider = ctk.CTkSlider(
            win, from_=0, to=(duration if duration else 1), number_of_steps=1000,
            progress_color=GOLD_BRIGHT, button_color=GOLD, button_hover_color=GOLD_BRIGHT,
            fg_color=INK,
        )
        slider.set(0)
        slider.pack(fill="x", padx=60, pady=(0, 10))
        if not duration:
            slider.configure(state="disabled")
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

                    if pause_btn is not None:
                        pause_btn.configure(text="⏸ Pause")
                except Exception:
                    pass
        slider.bind("<Button-1>", on_slider_press)
        slider.bind("<ButtonRelease-1>", on_slider_release)
        try:
            state["session"] = play_audio_in_memory(data)
            state["started"] = True
        except Exception as exc:
            error_message = str(exc)
            status_label.configure(text=f"Playback error: {error_message}", text_color=DANGER)
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
                if state["session"] != current_audio_session():
                    try:
                        state["session"] = play_audio_in_memory(data, start_seconds=state["seek_offset"])
                        pause_btn.configure(text="⏸ Pause")
                        status_label.configure(text="Playing from RAM...", text_color=STONE_PALE)
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
                slider.set(0)
                state["seek_offset"] = 0.0
                time_label.configure(text=f"0:00 / {fmt(duration) if duration else '—:—'}")
            ctk.CTkButton(
                btn_row, text="⏹ Stop", command=do_stop,
                **Styled.secondary_button_kwargs(),
            ).pack(side="left", padx=6)
        def poll():
            if state["session"] != current_audio_session():
                if state["session"] != -1:
                    status_label.configure(
                        text="⏸ Playback taken over by another audio window.",
                        text_color=STONE_PALE,
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
        ctk.CTkLabel(win, text="🎬", font=scaled_font(40), text_color=GOLD_BRIGHT).pack(pady=(14, 4))
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
        video_area = tk.Frame(win, bg=DEEP)
        video_area.pack(side="top", expand=True, fill="both", padx=10, pady=(0, 6))
        video_area.pack_propagate(False)
        video_label = tk.Label(video_area, bg=DEEP)
        video_label.pack(expand=True, fill="both")
        controls = ctk.CTkFrame(win, fg_color="transparent")
        controls.pack(side="bottom", fill="x", padx=20, pady=(0, 4))
        slider = ctk.CTkSlider(
            controls, from_=0, to=max(info.duration, 1), number_of_steps=1000,
            progress_color=GOLD_BRIGHT, button_color=GOLD, button_hover_color=GOLD_BRIGHT,
            fg_color=INK,
        )
        slider.set(0)
        slider.pack(fill="x", pady=(0, 8))
        if info.duration <= 0:
            slider.configure(state="disabled")
        btn_row = ctk.CTkFrame(win, fg_color="transparent")
        btn_row.pack(side="bottom", pady=(0, 12))
        play_pause_btn = ctk.CTkButton(btn_row, text="⏸ Pause", **Styled.secondary_button_kwargs())
        play_pause_btn.pack(side="left", padx=6)
        stop_btn = ctk.CTkButton(btn_row, text="⏹ Stop", **Styled.secondary_button_kwargs())
        stop_btn.pack(side="left", padx=6)
        time_label = ctk.CTkLabel(btn_row, text="0:00 / 0:00", font=FONT_MONO_SMALL, text_color=SAND)
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
        }
        photo_refs: list = []
        wav_audio = None
        if info.has_audio:
            try:
                wav_audio = extract_video_audio_as_wav(data)
            except Exception:
                wav_audio = None
        def decoder_worker(generation: int, start_seconds: float) -> None:
            try:
                frame_interval = 1.0 / info.fps if info.fps > 0 else 0.04
                t = start_seconds
                proc_holder: list = []
                state["active_processes"].append(proc_holder)
                for raw_rgb in stream_video_frames_in_memory(
                    data, info, start_seconds=start_seconds, process_holder=proc_holder
                ):
                    if state["decoder_generation"] != generation or state["stopped"]:
                        return
                    try:
                        state["frame_queue"].put((t, raw_rgb), timeout=2)
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
        def render_frame(raw_rgb: bytes) -> None:
            img = Image.frombytes("RGB", (info.width, info.height), raw_rgb)
            max_w = max(video_label.winfo_width(), 320)
            max_h = max(video_label.winfo_height(), 240)
            img.thumbnail((max_w, max_h))
            photo = ImageTk.PhotoImage(img)
            photo_refs.clear()
            photo_refs.append(photo)
            video_label.configure(image=photo)
        if wav_audio:
            try:
                state["audio_session"] = play_audio_in_memory(wav_audio)
            except Exception:
                state["audio_session"] = -1
        start_decoder(0.0)
        status_label.pack_forget()
        def pump() -> None:
            if state["stopped"]:
                return
            if state["playing"] and not state["seeking"]:
                try:
                    frame_time, raw_rgb = state["frame_queue"].get_nowait()
                    render_frame(raw_rgb)
                    state["current_frame_time"] = frame_time
                    if not state["seeking"]:
                        slider.set(min(frame_time, info.duration) if info.duration else 0)
                    time_label.configure(text=f"{fmt(frame_time)} / {fmt(info.duration)}")
                except queue.Empty:
                    if state["eof"] and state["frame_queue"].empty():
                        state["playing"] = False
                        play_pause_btn.configure(text="▶ Replay")
            state["job"] = win.after(max(1, int(1000 / max(info.fps, 1))), pump)
        def toggle_play() -> None:
            if not state["playing"] and play_pause_btn.cget("text") == "▶ Replay":
                start_decoder(0.0)
                if wav_audio:
                    try:
                        state["audio_session"] = play_audio_in_memory(wav_audio)
                    except Exception:
                        state["audio_session"] = -1
                state["playing"] = True
                play_pause_btn.configure(text="⏸ Pause")
                return
            state["playing"] = not state["playing"]
            if state["playing"]:
                if state["audio_session"] != -1:
                    unpause_audio()
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
            start_decoder(0.0)
            state["playing"] = False
        def on_slider_press(_event=None) -> None:
            state["seeking"] = True
        def on_slider_release(_event=None) -> None:
            target = slider.get()
            start_decoder(target)
            if wav_audio:
                try:
                    state["audio_session"] = play_audio_in_memory(wav_audio, start_seconds=target)
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
            status_label.configure(text=f"Could not open system player: {error_message}", text_color=DANGER)
        def on_close() -> None:
            if tmp_path:
                try:
                    os.remove(tmp_path)
                except OSError:
                    pass
                if tmp_path in self._active_video_tmp_paths:
                    self._active_video_tmp_paths.remove(tmp_path)
            win.destroy()
        win.protocol("WM_DELETE_WINDOW", on_close)
    def _export_entry(self, entry: VaultDecryptedEntry) -> None:
        path = filedialog.asksaveasfilename(
            title=f"Export {entry.name} as...", initialfile=entry.name
        )
        if not path:
            return
        try:
            with open(path, "wb") as f:
                f.write(bytes(entry.data))
            messagebox.showinfo("Vault", f"File exported to:\n{path}")
        except OSError as exc:
            messagebox.showerror("Error", f"Export failed: {exc}")
    def _close_vault(self) -> None:
        for entry in self._open_entries:
            wipe_bytearray(entry.data)
        self._open_entries = []
        for child in self.entries_frame.winfo_children():
            child.destroy()
        self.entries_frame.pack_forget()
        self.close_vault_btn.pack_forget()
        self.open_status.configure(text="Vault closed · Data wiped from RAM.", text_color=STONE_PALE)
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
            try:
                os.remove(tmp_path)
            except OSError:
                pass
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
        self.configure(fg_color=DEEP)
        self._build_layout()
        self.update_idletasks()
        apply_screen_capture_protection(self)
        self.protocol("WM_DELETE_WINDOW", self._on_close)
    def _build_layout(self) -> None:
        sidebar_width = max(150, round(190 * CURRENT_UI_SCALE))
        sidebar = ctk.CTkFrame(self, fg_color=STONE, width=sidebar_width, corner_radius=0)
        sidebar.pack(side="left", fill="y")
        sidebar.pack_propagate(False)
        ctk.CTkLabel(
            sidebar, text="𓃭", font=scaled_font(44), text_color=GOLD_BRIGHT
        ).pack(pady=(28, 4))
        ctk.CTkLabel(
            sidebar, text="BASTET\nCIPHER", font=scaled_font(22, "Georgia", "bold"),
            text_color=GOLD, justify="center",
        ).pack(pady=(0, 30))
        self.nav_buttons: dict[str, ctk.CTkButton] = {}
        self._add_nav_button(sidebar, "generator", "🔑  Generate")
        self._add_nav_button(sidebar, "vault", "𓁹  Vault")
        lock_status = "🔒 Anti-swap active" if memory_lock_available() else "⚠ Anti-swap not guaranteed"
        ctk.CTkLabel(
            sidebar, text=lock_status, font=scaled_font(14),
            text_color=SAND if memory_lock_available() else "#ff9a5a",
            wraplength=160, justify="center",
        ).pack(side="bottom", pady=16, padx=10)
        self.content = ctk.CTkScrollableFrame(self, fg_color=DEEP, corner_radius=0)
        self.content.pack(side="left", fill="both", expand=True)
        self.views: dict[str, ctk.CTkFrame] = {}
        self.generator_view = GeneratorView(self.content)
        self.vault_view = VaultView(self.content)
        self.views["generator"] = self.generator_view
        self.views["vault"] = self.vault_view
        self._show_view("generator")
    def _add_nav_button(self, parent, key: str, text: str) -> None:
        btn = ctk.CTkButton(
            parent, text=text, anchor="w", corner_radius=8, height=42,
            fg_color="transparent", hover_color=STONE_MID, text_color=SAND,
            font=scaled_font(19),
            command=lambda: self._show_view(key),
        )
        btn.pack(fill="x", padx=14, pady=4)
        self.nav_buttons[key] = btn
    def _show_view(self, key: str) -> None:
        for k, view in self.views.items():
            view.pack_forget()
        for k, btn in self.nav_buttons.items():
            btn.configure(fg_color=GOLD_DARK if k == key else "transparent")
        self.views[key].pack(fill="both", expand=True)
    def _open_cipher_in_vault(self, cipher: str) -> None:
        if not cipher:
            return
        self._show_view("vault")
        self.vault_view.tabs.set("Open Archive")
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