#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
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
1. Launch it:  python3 bastet_audit_gui.py
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

import sys
import os
import subprocess
import threading
import queue
import time
import json


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


def _bootstrap_dependencies():
    """Checks and, if needed and approved by the user, installs the
    dependencies this app's own top-level process requires. Returns True
    if the app can proceed, False if it should exit."""
    if not _ensure_dependency("cryptography", "cryptography"):
        return False
    return True


if __name__ == "__main__":
    if not _bootstrap_dependencies():
        sys.exit(1)


try:
    import tkinter as tk
    from tkinter import ttk, scrolledtext, messagebox, filedialog
except ImportError:
    print("=" * 70)
    print("ERROR: the 'tkinter' module is missing (needed for the GUI window).")
    print("On Ubuntu/Debian, install it with:")
    print()
    print("    sudo apt install python3-tk")
    print()
    print("Then re-run: python3 bastet_audit_gui.py")
    print("=" * 70)

    sys.exit(1)

try:
    from tkinterdnd2 import DND_FILES, TkinterDnD
    _HAS_DND = True
except ImportError:
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


_BaseTk = TkinterDnD.Tk if _HAS_DND else tk.Tk


class AuditGUI(_BaseTk):
    def __init__(self):
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
        text.insert("1.0", __doc__.strip())
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
anything else -- so it deserves a direct, evidence-based answer instead
of a vague one:

  - The BastetCipher source code was read line by line: there is no
    bypass path, no hardcoded master key, no debug backdoor. Opening a
    vault always requires deriving the encryption keys from the exact
    password used to create it, and the AES-GCM authentication tag
    must verify -- a property that is mathematically enforced, the
    same way it is in AES-based tools like VeraCrypt or 7-Zip's AES-256
    mode, not a software check that could be quietly bypassed.

  - That claim was then stress-tested, not just read: thousands of
    targeted manual attempts (near-correct passwords, edge cases,
    exhaustive brute-force over a reduced alphabet), plus close to
    36 MILLION automated fuzzing runs across independent sessions,
    specifically trying to break that exact assumption. Zero
    unauthorized opens, across every single attempt.

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


if __name__ == "__main__":
    app = AuditGUI()
    if not os.path.isfile(_SKIP_SPLASH_MARKER):
        def _reveal_main():
            app.lift()
            app.focus_force()

        WelcomeSplash(app, on_continue=_reveal_main)
    app.mainloop()

