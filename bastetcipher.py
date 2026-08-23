#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
BastetCipher — Desktop Edition (file singolo)
================================================================================

Porting desktop Python/CustomTkinter del programma originale BastetCipher.html,
verificato byte-per-byte compatibile:
  - il generatore di password produce output IDENTICO all'originale a parita'
    di frase/PIM/amplificatore (verificato su 11 vettori di test incrociati
    con l'implementazione JavaScript originale, inclusi casi limite come PIM
    a 32 cifre, caratteri Unicode fuori dal Basic Multilingual Plane, ecc.);
  - il formato .bca e' interoperabile al 100% con i vault gia' creati dalla
    versione HTML (testato in entrambe le direzioni).

File unico, pensato per essere pacchettizzato con:
    pyinstaller --onefile bastetcipher.py

Dipendenze (vedi requirements.txt):
    customtkinter, cryptography, pillow, pymupdf, mutagen, pygame,
    imageio-ffmpeg

NOTA SU PYINSTALLER E imageio-ffmpeg (player video integrato, SEZIONE 4):
    imageio-ffmpeg scarica un binario ffmpeg precompilato (~76MB) dentro
    la propria cartella del pacchetto Python, invece di essere puro
    codice Python — PyInstaller di solito lo individua automaticamente,
    ma se la build finale non trova ffmpeg a runtime (il player video
    integrato mostrerebbe un errore e ripiegherebbe sul player esterno),
    la soluzione è aggiungere questo flag al comando di build:
        pyinstaller --onefile --collect-data imageio_ffmpeg bastetcipher.py

NOTA SULLA SICUREZZA DEL "PEPPER" (vedi SEZIONE 2):
    Il valore PEPPER e' hardcoded nel sorgente, ereditato identico
    dall'originale HTML per garantire compatibilita' di output. Chi
    distribuisce l'eseguibile PyInstoller dovrebbe essere consapevole che
    questo valore e' recuperabile decompilando il binario.

NOTA SUI LIMITI DELLA PROTEZIONE ANTI-SWAP (vedi SEZIONE 1):
    mlock/VirtualLock impediscono lo swap su disco delle pagine allocate,
    ma non proteggono da hibernation file o core dump non disabilitati a
    livello di sistema operativo. Vedi i commenti nella SEZIONE 1 per i
    dettagli e i limiti onesti di questa protezione.
"""

from __future__ import annotations

# --- Libreria standard ------------------------------------------------------
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
import re
import tkinter as tk
from tkinter import messagebox, filedialog
from dataclasses import dataclass
from enum import Enum, auto
from typing import Callable, List, Optional

# --- Terze parti -------------------------------------------------------------
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

from PIL import Image, ImageTk

# BUGFIX CRITICO PER PYINSTALLER (immagini/PDF renderizzati come riquadri
# neri nell'eseguibile standalone, mai nell'esecuzione da sorgente):
# PIL.ImageTk (usato per mostrare qualunque immagine/pagina PDF in un
# widget Tkinter) importa PIL._tkinter_finder in modo dinamico al suo
# interno, per individuare l'interprete Tcl/Tk corretto a runtime.
# L'analizzatore statico di PyInstaller non riesce a rilevare questo
# import dinamico e quindi non include il modulo nel bundle — risultato:
# ImageTk.PhotoImage(...) fallisce silenziosamente a runtime SOLO
# nell'eseguibile pacchettizzato (mai lanciando bastetcipher.py
# direttamente con `python3 bastetcipher.py`, dove il modulo si trova
# comunque nell'installazione normale di Pillow), lasciando vuoto/nero
# ogni punto dell'interfaccia che dovrebbe mostrare un'immagine — quindi
# ogni anteprima di immagine, ogni pagina PDF, e ogni frame video, dato
# che tutti passano da ImageTk. Importarlo esplicitamente qui, anche se
# il nome non viene mai referenziato direttamente nel resto del codice,
# costringe PyInstaller a includerlo comunque nel bundle (lo stesso
# effetto ottenibile passando --hidden-import=PIL._tkinter_finder da riga
# di comando, ma garantito anche se quel flag viene dimenticato in una
# build futura). Verificato risolvere il problema con una build
# PyInstaller --onefile reale su Linux.
import PIL._tkinter_finder  # noqa: F401

import customtkinter as ctk

# NOTA: PyMuPDF (fitz) NON è importato qui in cima, di proposito: viene
# importato in modo "lazy" solo dentro render_pdf_pages_in_memory(), così se
# l'utente non apre mai un PDF dal vault il modulo (pesante, include il
# motore di rendering MuPDF) non viene mai caricato, riducendo il tempo di
# avvio e la dimensione effettiva in RAM dell'eseguibile PyInstaller.

# ==============================================================================
# SEZIONE 1 — GESTIONE SICURA DELLA MEMORIA
# ==============================================================================
# Nessun dato sensibile (password, chiavi, contenuto decrittato dei file nel
# vault) deve mai:
#   1. finire nello swap / file di paging del sistema operativo
#   2. sopravvivere in RAM dopo l'uso (azzeramento esplicito, non affidato al GC)
#   3. essere rappresentato come str/bytes immutabili, che l'interprete Python
#      può copiare silenziosamente in più punti dell'heap.
#
# Regola pratica per TUTTO il programma: password, chiavi derivate, e
# contenuto in chiaro dei file del vault vivono SEMPRE in bytearray
# (mutabile → azzerabile), mai in str/bytes. Ogni bytearray sensibile viene
# allocato tramite SecureBuffer, che tenta di bloccare le pagine
# corrispondenti in RAM (mlock su POSIX, VirtualLock su Windows) così il
# kernel non le scrive mai su disco/swap.
#
# LIMITI ONESTI: il mlock/VirtualLock impedisce lo SWAP, ma non impedisce che
# il sistema operativo scriva un core dump / hibernation file se la macchina
# va in ibernazione o crasha con i permessi giusti — per questo si consiglia
# di disabilitare l'ibernazione e usare la cifratura del disco a livello OS
# sulle macchine dove gira questo programma.
# ==============================================================================

_SYSTEM = platform.system()  # 'Linux', 'Darwin', 'Windows'


class MlockError(RuntimeError):
    """Sollevato quando il blocco delle pagine di memoria fallisce."""


class _MemoryLocker:
    """
    Wrapper cross-platform su mlock(2)/munlock(2) (Linux/macOS) e
    VirtualLock/VirtualUnlock (Windows).

    Non solleva mai eccezioni bloccanti per l'utente finale: se il lock
    fallisce (limiti RLIMIT_MEMLOCK non privilegiati, ecc.) lo segnala
    tramite `last_error`, ma il chiamante decide come comportarsi
    (tipicamente: avvisare l'utente che la protezione anti-swap non è
    garantita su questa macchina, e proseguire comunque azzerando la RAM).
    """

    def __init__(self) -> None:
        self.available = False
        self.last_error: Optional[str] = None
        self._libc = None
        self._kernel32 = None

        try:
            if _SYSTEM in ("Linux", "Darwin"):
                libc_name = ctypes.util.find_library("c")
                if libc_name is None:
                    # fallback ragionevole per alcune distro minimal
                    libc_name = "libc.so.6" if _SYSTEM == "Linux" else "libc.dylib"
                self._libc = ctypes.CDLL(libc_name, use_errno=True)
                self.available = True
            elif _SYSTEM == "Windows":
                self._kernel32 = ctypes.windll.kernel32  # type: ignore[attr-defined]
                self.available = True
        except Exception as exc:  # pragma: no cover - dipende dalla macchina
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
            pass  # l'unlock è best-effort: non deve mai bloccare la chiusura


_LOCKER = _MemoryLocker()


def memory_lock_available() -> bool:
    """True se questa piattaforma supporta il blocco pagine anti-swap."""
    return _LOCKER.available


def last_lock_error() -> Optional[str]:
    return _LOCKER.last_error


class SecureBuffer:
    """
    bytearray a dimensione fissa, con best-effort mlock e azzeramento
    garantito allo scope-exit.

    Uso tipico:

        with SecureBuffer(64) as buf:
            buf.data[:] = derived_key_bytes
            ... usa buf.data ...
        # qui buf.data è già azzerato e sbloccato

    `locked` indica se il mlock è effettivamente riuscito su questa
    macchina/permessi; se False, il buffer funziona comunque (viene
    comunque azzerato all'uscita) ma NON è garantito che eviti lo swap.
    """

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
        """
        Azzera esplicitamente il contenuto (idempotente).

        PERFORMANCE FIX: stesso problema di wipe_bytearray() più sotto — il
        loop byte-per-byte era ordini di grandezza più lento di un memset
        nativo su buffer grandi. Qui abbiamo già l'indirizzo di memoria
        calcolato in __init__ (self._addr), quindi il memset è diretto.
        """
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
        # rete di sicurezza se qualcuno dimentica il context manager;
        # non ci si deve MAI affidare solo a questo.
        try:
            self.close()
        except Exception:
            pass

    def __len__(self) -> int:
        return self._size


def wipe_bytearray(buf: bytearray) -> None:
    """
    Azzera in place un bytearray generico (non necessariamente un
    SecureBuffer).

    PERFORMANCE FIX: la versione precedente azzerava byte per byte con un
    ciclo Python puro (`for i in range(len(buf)): buf[i] = 0`), che è O(n)
    ma con una costante altissima — misurato: ~12 secondi per 200MB. Su un
    archivio vault da 1GB, solo questa funzione (chiamata più volte per
    ogni file, il payload combinato, e le chiavi) arrivava a sommare
    decine di secondi di attesa, il grosso del "lag" percepito su archivi
    grandi. `ctypes.memset` azzera la stessa memoria a velocità nativa C
    (~0.02s per 200MB in questo benchmark, circa 500x più veloce) e non
    alloca un buffer temporaneo di zeri come farebbe uno slice assignment
    (`buf[:] = bytes(len(buf))`), il che conta quando il buffer stesso è
    già vicino al GB. Il risultato crittografico è identico: gli stessi
    byte vengono comunque tutti azzerati, cambia solo la velocità.
    """
    if not buf:
        return
    try:
        ctypes.memset((ctypes.c_char * len(buf)).from_buffer(buf), 0, len(buf))
    except Exception:
        # Fallback difensivo se ctypes.memset non fosse disponibile per
        # qualche motivo su una piattaforma specifica: più lento ma ancora
        # molto più veloce del loop byte-per-byte originale.
        buf[:] = bytes(len(buf))


def disable_core_dumps() -> None:
    """
    Best-effort: disabilita i core dump su POSIX (RLIMIT_CORE=0), così un
    crash del processo non scrive la RAM (incluse le chiavi) su disco.
    No-op silenzioso su Windows e in caso di permessi insufficienti.
    """
    if _SYSTEM in ("Linux", "Darwin"):
        try:
            import resource

            resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        except Exception:
            pass


def harden_process() -> None:
    """Da chiamare una volta all'avvio dell'app."""
    disable_core_dumps()


# ==============================================================================
# SEZIONE 2 — PIPELINE GENERATORE DI CIFRARI
# ==============================================================================
# Porting 1:1 in Python della pipeline di generazione "cifrario" dell'originale
# BastetCipher.html (funzioni runCipherPipeline / transformHash / createPRNG /
# insertSpecialChars / applyMixedCase / generateAmplification).
#
# Tutta l'aritmetica a 32 bit senza segno di JS (`>>> 0`, l'LCG
# state * 1664525 + 1013904223) è riprodotta esattamente con maschere a
# 0xFFFFFFFF, così a parità di input (frase, PIM, amplifier) l'output Python è
# BYTE-IDENTICO a quello del programma HTML originale. Verificato con 11
# vettori di test incrociati con l'implementazione JavaScript originale
# (inclusi: PIM con zeri iniziali, stringa vuota, emoji, caratteri Unicode
# fuori dal Basic Multilingual Plane, e PIM fino a 32-34 cifre — questo
# ultimo caso ha richiesto di riprodurre ESATTAMENTE la perdita di
# precisione IEEE-754 di parseInt() in JavaScript per PIM di 16+ cifre, vedi
# _js_parse_int_decimal() più sotto: non è un bug che correggiamo, è un
# comportamento dell'originale che va riprodotto identico).
#
# NOTA DI SICUREZZA (il committente ne è già consapevole): il PEPPER qui
# sotto è lo stesso valore hardcoded nel sorgente HTML originale. Essere
# hardcoded in chiaro nel codice sorgente (e quindi recuperabile
# decompilando l'eseguibile PyInstaller) non lo rende un segreto
# crittografico robusto — è più corretto pensarlo come un "sale fisso di
# brand" che differenzia l'output di questo programma da un PBKDF2
# generico, non come garanzia di sicurezza aggiuntiva.
# ==============================================================================

MASK32 = 0xFFFFFFFF
PEPPER = "Bastet_Secret_Temple_Key_\U00013060"
RUNE_POOL = "𓃠𓂀𓊹𓆣𓇯𓋹𓅓𓁟𓆙𓊪𓏏𓎛"  # solo per eventuale UI, non crittografico

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
    """Equivalente di crypto.subtle.deriveBits({name:'PBKDF2', hash:'SHA-512'})."""
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
    """
    Riproduce ESATTAMENTE `parseInt(digits, 10)` di JavaScript, INCLUSA la
    perdita di precisione IEEE-754 che JS introduce per interi molto grandi
    (oltre 2**53). L'HTML originale accetta PIM fino a 32 cifre nella UI
    (regex /^\\d{1,32}$/), e per PIM di 16+ cifre `parseInt` in JS non
    restituisce il valore esatto: lo arrotonda al double più vicino.

    Questo NON è un bug che correggiamo: è un comportamento del programma
    originale che dobbiamo riprodurre identico, altrimenti il generatore
    Python produrrebbe cifrari diversi da quelli del programma HTML per lo
    stesso PIM a partire da 16 cifre in su. `float()` di Python usa lo
    stesso IEEE-754 binary64 di JS Number, quindi `int(float(digits))`
    replica esattamente l'arrotondamento di JS.
    """
    return int(float(digits))


def transform_hash(hash_hex: str, seed_hex: str) -> str:
    """Porting esatto di transformHash(hash, seed)."""
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
    """Porting di createPRNG(seedHex): stesso LCG usato in transformHash."""

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
    half = -(-len(alpha_indices) // 2)  # ceil

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
    """
    Porting esatto di runCipherPipeline(). A parità di (input_str, pim,
    amplifier) produce lo STESSO output del generatore HTML originale.
    """
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


# ==============================================================================
# SEZIONE 3 — FORMATO ARCHIVIO .bca (VAULT)
# ==============================================================================
# Formato binario .bca (BastetCipher Archive), porting 1:1 del formato
# definito in BastetCipher.html. Interoperabilità con l'HTML originale
# verificata in entrambe le direzioni: un archivio creato con l'app HTML si
# apre con questo codice, e viceversa.
#
# Layout del file (little-endian per i multi-byte):
#
#   offset  size  campo
#   ------  ----  -----------------------------------------
#   0       4     MAGIC = 0x42 0x43 0x41 0x01
#   4       1     VERSION (=1)
#   5       32    SALT (random, per PBKDF2)
#   37      4     ITERAZIONI PBKDF2 (uint32 LE)
#   41      12    IV1 (per AES-256-GCM)
#   53      16    IV2 (per AES-256-CBC)
#   69      N     CIPHERTEXT (AES-CBC(AES-GCM(plaintext)))  -- cascata
#
# Il "plaintext" prima della doppia cifratura è a sua volta:
#
#   2     numero di file (uint16 LE)
#   per ciascun file:
#     2     lunghezza nome (uint16 LE)
#     N     nome (UTF-8)
#     4     CRC32 del contenuto ORIGINALE non compresso (uint32 LE)
#     4     dimensione originale non compressa (uint32 LE)
#     4     dimensione compressa (uint32 LE)
#     N     dati compressi (deflate-raw / zlib raw, senza header)
#
# Derivazione chiavi: PBKDF2-HMAC-SHA512(password, salt, iterazioni, 64 byte)
#   -> primi 32 byte  = chiave AES-256-GCM (k1)
#   -> secondi 32 byte = chiave AES-256-CBC (k2)
# ==============================================================================


BCA_MAGIC = bytes([0x42, 0x43, 0x41, 0x01])
BCA_VERSION = 1
BCA_ITERS = 200_000
HEADER_LEN = 69  # 4 + 1 + 32 + 4 + 12 + 16

# NOTA: ProgressCallback e _noop_progress sono già definiti nella SEZIONE 2
# (identici) e riutilizzati qui: non ridefiniti per evitare duplicazione
# inutile nel file consolidato.


class BCAFormatError(ValueError):
    """Unrecognized or corrupted file."""


class BCADecryptError(ValueError):
    """Wrong password or tampered data (authentication failure)."""


def crc32(data: "bytes | bytearray") -> int:
    return zlib.crc32(data) & 0xFFFFFFFF


def deflate_raw_compress(data: "bytes | bytearray") -> bytes:
    """Equivalente di CompressionStream('deflate-raw'): zlib raw, senza header/trailer.
    Accetta bytes o bytearray direttamente (zlib supporta il protocollo
    buffer), evitando una copia esplicita a bytes sul chiamante quando la
    fonte è già un bytearray — utile su file grandi.
    """
    co = zlib.compressobj(level=9, wbits=-15)
    out = co.compress(data) + co.flush()
    return out


def deflate_raw_decompress(data: bytes) -> bytes:
    """Equivalente di DecompressionStream('deflate-raw')."""
    do = zlib.decompressobj(wbits=-15)
    out = do.decompress(data) + do.flush()
    return out


def derive_vault_keys(password: bytearray, salt: bytes, iterations: int) -> tuple[bytearray, bytearray]:
    """
    PBKDF2-HMAC-SHA512(password, salt, iterations, 64 byte).
    Ritorna (k1, k2) come bytearray mutabili (32 byte ciascuno) da azzerare
    dopo l'uso. `password` è un bytearray e non viene mai convertito in str.
    """
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA512(),
        length=64,
        salt=salt,
        iterations=iterations,
        backend=default_backend(),
    )
    derived = kdf.derive(bytes(password))  # cryptography richiede bytes in input
    k1 = bytearray(derived[0:32])
    k2 = bytearray(derived[32:64])
    # azzeriamo la copia intermedia che PBKDF2HMAC.derive ha restituito come bytes
    # (bytes è immutabile: non possiamo azzerarla, ma minimizziamo la sua vita)
    del derived
    return k1, k2


@dataclass
class VaultFileEntry:
    """Un file, in chiaro, pronto per essere impacchettato nel vault."""

    name: str
    data: bytearray  # contenuto originale non compresso


@dataclass
class VaultDecryptedEntry:
    """Un file estratto dal vault, tenuto SOLO in RAM."""

    name: str
    data: bytearray  # contenuto decompresso, verificato via CRC32
    crc_ok: bool


def build_bca(
    file_entries: List[VaultFileEntry],
    password: bytearray,
    on_progress: Optional[ProgressCallback] = None,
) -> bytearray:
    """
    Costruisce un archivio .bca in memoria (bytearray). Il chiamante decide
    se e dove scriverlo su disco: questa funzione non tocca mai il filesystem.
    """
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
                # PERFORMANCE FIX: prima si chiamava bytes(entry.data) due
                # volte (una per deflate_raw_compress, una per crc32),
                # copiando l'intero contenuto del file due volte solo per
                # calcolare compressione e checksum. zlib.compressobj() e
                # zlib.crc32() accettano bytearray direttamente (supportano
                # il protocollo buffer di Python), con risultato identico
                # a passare bytes — su un file da centinaia di MB, evitare
                # queste due copie fa una differenza reale sia in tempo
                # che in picco di RAM.
                compressed = deflate_raw_compress(entry.data)
                crc = crc32(entry.data)
                parts.append(struct.pack("<H", len(name_bytes)))
                parts.append(name_bytes)
                parts.append(struct.pack("<I", crc))
                parts.append(struct.pack("<I", len(entry.data)))
                parts.append(struct.pack("<I", len(compressed)))
                parts.append(compressed)
            finally:
                # BUGFIX: prima questo wipe era fuori dal try/finally
                # per-file, eseguito solo se l'iterazione andava a buon
                # fine. Se compress/crc falliva a metà (es. file
                # corrotto, errore di memoria), i dati in chiaro del file
                # che stava fallendo — e di TUTTI i file successivi nel
                # ciclo, mai raggiunti — restavano nel bytearray originale
                # senza mai essere azzerati. Nella GUI, a quel punto la
                # lista sorgente è già stata svuotata (l'ownership passa
                # al worker prima di chiamare build_bca), quindi quei
                # bytearray con contenuto sensibile diventavano
                # irraggiungibili dal resto del programma e mai puliti
                # esplicitamente — proprio il tipo di residuo che questo
                # progetto punta a evitare. Ora l'azzeramento è garantito
                # per ogni file indipendentemente da come va la sua
                # iterazione.
                wipe_bytearray(entry.data)

        # PERFORMANCE FIX: prima si faceva bytearray(b"".join(parts)), che
        # per un archivio da centinaia di MB / ~1GB comportava una copia
        # completa aggiuntiva rispetto a quanto strettamente necessario
        # (b"".join produce già un oggetto bytes; passarlo per
        # bytearray(...) lo ricopia). Restava comunque necessario avere il
        # payload in un bytearray mutabile — non un bytes immutabile — per
        # poterlo azzerare esplicitamente subito dopo la cifratura: un
        # bytes puro non è azzerabile in-place, quindi lasciarlo come
        # bytes per "risparmiare la copia" avrebbe tolto la garanzia di
        # sicurezza reale (il payload in chiaro sarebbe rimasto in RAM
        # fino al garbage collector, non zeroed subito). Qui manteniamo
        # quell'unica copia necessaria (bytes -> bytearray, obbligatoria
        # per l'azzeramento sicuro) ma evitiamo qualunque copia
        # ulteriore: AESGCM.encrypt() accetta bytearray direttamente
        # (protocollo buffer), quindi non serve una ulteriore bytes(...)
        # come prima.
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
        # Rete di sicurezza aggiuntiva: anche col fix per-file sopra, se il
        # ciclo viene interrotto da un'eccezione, i file NON ANCORA
        # raggiunti dall'iterazione (indici successivi a quello che ha
        # fallito) non passano mai dal loro wipe_bytearray interno. Qui
        # azzeriamo esplicitamente tutti quelli rimasti, per coprire anche
        # quel caso — è idempotente: un bytearray già azzerato resta tale.
        for entry in file_entries:
            wipe_bytearray(entry.data)


def _aes_cbc_encrypt(key: bytes, iv: bytes, data: bytes) -> bytes:
    """AES-256-CBC con padding PKCS7 (equivalente a crypto.subtle AES-CBC)."""
    # PERFORMANCE FIX: `data + bytes([pad_len]) * pad_len` copiava l'intero
    # `data` (che a questo punto è quasi grande quanto il payload
    # originale, essendo l'output di AES-GCM) solo per appendere al più 16
    # byte di padding PKCS7. Su un archivio vault da centinaia di MB / 1GB
    # questa era una copia completa evitabile. bytearray(data) + extend()
    # fa la stessa cosa senza il costo della concatenazione di due
    # oggetti bytes di dimensioni molto diverse.
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
    """
    Decifra e decomprime un archivio .bca interamente in memoria.
    `buffer` deve essere il contenuto grezzo del file .bca (letto una volta
    sola dal chiamante, idealmente con open(...).read() -> bytearray, senza
    mmap persistenti). Nessun dato intermedio viene mai scritto su disco.
    """
    progress = on_progress or _noop_progress

    # PERFORMANCE FIX: prima si faceva `d = bytes(buffer)`, copiando
    # l'intero archivio .bca (che per un vault da ~1GB è quasi altrettanto
    # grande) solo per poterlo affettare/indicizzare. bytearray supporta
    # slicing, confronto con bytes letterali (buffer[0:4] == b"...") e
    # struct.unpack_from esattamente come bytes — non serve convertirlo.
    # Lavoriamo direttamente su `buffer`, eliminando questa copia completa.
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
            # BUGFIX: se un file a metà dell'archivio fallisce a
            # decomprimere (dati corrotti, archivio danneggiato), i file
            # PRECEDENTI in questo stesso ciclo erano già stati decompressi
            # con successo e aggiunti a `entries` — ma quella lista è
            # locale alla funzione e andava persa insieme al suo contenuto
            # quando l'eccezione si propagava verso il chiamante, senza
            # che i bytearray in chiaro già creati venissero mai azzerati
            # esplicitamente. Qui li ripuliamo prima di rilanciare
            # l'eccezione, così nessun dato decrittato con successo resta
            # in RAM non tracciato quando l'apertura del vault fallisce a
            # metà.
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


# ==============================================================================
# SEZIONE 4 — VISUALIZZATORE SICURO (SOLO RAM)
# ==============================================================================
# Anteprima di file decrittati SENZA MAI scriverli su disco.
#
# Questo è il punto più delicato del requisito "niente in cache": aprire un
# PDF o un'immagine con il programma di sistema (Acrobat, Anteprima, un
# browser) richiederebbe salvare un file temporaneo su disco — esattamente
# quello che vogliamo evitare. Qui invece:
#
#   - Le IMMAGINI (png/jpg/gif/bmp/webp) vengono decodificate direttamente
#     dai byte in RAM con Pillow e mostrate in un canvas Tkinter.
#   - I PDF vengono rasterizzati pagina per pagina in RAM con PyMuPDF (fitz)
#     — ogni pagina diventa un bitmap in memoria, mai un file .pdf
#     temporaneo su disco. PyMuPDF apre i documenti direttamente da bytes.
#   - Il TESTO semplice viene decodificato e mostrato in un box di testo.
#   - Qualunque altro tipo di file NON viene aperto in anteprima: l'utente
#     può solo esportarlo esplicitamente su disco (azione consapevole).
#
# LIMITE ONESTO: il framebuffer della scheda video e il compositor del
# sistema operativo (specialmente su alcuni Windows/macOS con "effetti")
# a volte mantengono screenshot/thumbnail in cache di sistema per gli
# effetti finestra. Questo è un limite del sistema operativo che nessuna
# app può aggirare al 100%.
# ==============================================================================

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
    """Una pagina PDF rasterizzata in RAM come PNG in memoria (nessun file)."""

    index: int
    png_bytes: bytes
    width: int
    height: int


def _looks_like_svg(data: bytes) -> bool:
    """
    Rilevamento leggero: SVG è XML testuale, non un bitmap binario come gli
    altri formati immagine. Guarda solo l'inizio del buffer (fino a 512
    byte), ignorando eventuali BOM/whitespace iniziali.
    """
    head = data[:512].lstrip(b"\xef\xbb\xbf \t\r\n")
    return head.startswith(b"<?xml") or head.startswith(b"<svg") or b"<svg" in head[:200]


def render_image_in_memory(data: bytes) -> Image.Image:
    """
    Decodifica byte immagine in un oggetto PIL.Image, interamente in RAM.
    `io.BytesIO` è un buffer in memoria: non tocca mai il filesystem.

    Gli SVG sono un caso speciale: sono XML vettoriale, non un bitmap, e
    Pillow non li supporta nativamente. Vengono prima rasterizzati in PNG
    con PyMuPDF (fitz) — già una dipendenza del progetto per i PDF, quindi
    nessuna libreria nuova — e poi il PNG risultante viene passato a
    Pillow come ogni altra immagine. Tutto avviene in RAM: fitz accetta i
    byte dell'SVG direttamente via stream, senza mai scrivere su disco.
    """
    if _looks_like_svg(data):
        import fitz  # PyMuPDF — import locale, come per i PDF

        doc = fitz.open(stream=data, filetype="svg")
        try:
            page = doc.load_page(0)
            pix = page.get_pixmap()
            data = pix.tobytes("png")
        finally:
            doc.close()

    buf = io.BytesIO(data)
    img = Image.open(buf)
    img.load()  # forza la decodifica completa mentre il buffer è ancora aperto
    return img


def render_pdf_pages_in_memory(
    data: bytes, dpi: int = 110, max_pages: Optional[int] = None
) -> List[RenderedPage]:
    """
    Rasterizza un PDF interamente in RAM usando PyMuPDF, che apre i
    documenti direttamente da bytes (`fitz.open(stream=..., filetype="pdf")`)
    senza mai richiedere un percorso su disco.
    """
    import fitz  # PyMuPDF — import locale per non pesare sull'avvio se non serve

    pages: List[RenderedPage] = []
    doc = fitz.open(stream=data, filetype="pdf")
    try:
        zoom = dpi / 72.0
        matrix = fitz.Matrix(zoom, zoom)
        count = doc.page_count if max_pages is None else min(max_pages, doc.page_count)
        for i in range(count):
            page = doc.load_page(i)
            pix = page.get_pixmap(matrix=matrix, alpha=False)
            png_bytes = pix.tobytes("png")  # PNG codificato in RAM, mai su disco
            pages.append(
                RenderedPage(index=i, png_bytes=png_bytes, width=pix.width, height=pix.height)
            )
    finally:
        doc.close()
    return pages


def decode_text_in_memory(data: bytes) -> str:
    """Prova UTF-8, poi latin-1 come fallback permissivo (mai perde byte)."""
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        return data.decode("latin-1")


# ---------------------------------------------------------------------------
# Decodifica video in-processo (nessun player esterno, nessun file su disco)
# ---------------------------------------------------------------------------
# Usa il binario ffmpeg fornito da imageio-ffmpeg (scaricato una tantum via
# pip, non richiede alcuna installazione di sistema — a differenza di VLC,
# che richiederebbe libVLC già presente sulla macchina dell'utente). ffmpeg
# legge il video direttamente da uno stdin pipe (mai un path su disco) e
# restituisce frame RGB grezzi + audio PCM via stdout pipe, entrambi
# interamente in memoria.


@dataclass
class VideoInfo:
    width: int
    height: int
    fps: float
    duration: float
    has_audio: bool


def _get_ffmpeg_exe() -> str:
    """
    Trova il binario ffmpeg fornito da imageio-ffmpeg.

    BUGFIX: imageio_ffmpeg.get_ffmpeg_exe() individua il binario risalendo
    dal proprio __file__ di modulo — funziona bene con un'installazione
    pip normale, ma NON ha alcuna consapevolezza di essere eseguito
    dentro un bundle PyInstaller `--onefile`. A runtime, PyInstaller
    estrae tutti i file inclusi (incluso il binario ffmpeg) in una
    cartella temporanea il cui percorso è esposto in `sys._MEIPASS` — un
    path diverso da quello che la libreria si aspetterebbe di trovare
    seguendo il proprio __file__. Su una macchina che ha anche Python/pip
    installati (come questo ambiente di sviluppo) la libreria può comunque
    "trovare qualcosa" seguendo altri percorsi di sistema e sembrare
    funzionare; ma sulla macchina di un utente finale che esegue SOLO
    l'eseguibile standalone (lo scenario reale di un --onefile), quei
    percorsi di sistema non esistono affatto, e la ricerca fallisce.
    Controlliamo quindi PRIMA se siamo dentro un bundle PyInstaller e
    cerchiamo il binario esplicitamente lì, usando la ricerca automatica
    di imageio_ffmpeg solo come fallback per l'esecuzione normale (non
    pacchettizzata) da sorgente.
    """
    meipass = getattr(sys, "_MEIPASS", None)
    if meipass:
        candidate = os.path.join(
            meipass, "imageio_ffmpeg", "binaries", f"ffmpeg-{_ffmpeg_platform_tag()}"
        )
        if os.path.isfile(candidate):
            # Su Linux/macOS il bit eseguibile potrebbe non sopravvivere
            # all'estrazione di PyInstaller: lo garantiamo esplicitamente,
            # altrimenti subprocess.Popen fallirebbe con "Permission denied"
            # pur avendo trovato il file al path giusto.
            try:
                os.chmod(candidate, 0o755)
            except OSError:
                pass
            return candidate
        # Fallback: cerchiamo qualunque binario ffmpeg-* nella stessa
        # cartella, nel caso il nome esatto della versione sia cambiato
        # tra le versioni di imageio-ffmpeg.
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

    import imageio_ffmpeg  # import locale: caricato solo se serve aprire un video

    return imageio_ffmpeg.get_ffmpeg_exe()


def _ffmpeg_platform_tag() -> str:
    """
    Replica il naming interno di imageio-ffmpeg per il binario atteso su
    ciascuna piattaforma (usato solo come primo tentativo mirato in
    _get_ffmpeg_exe; se il nome non combacia esattamente, il fallback di
    ricerca nella cartella sopra copre comunque il caso).
    """
    machine = platform.machine().lower()
    if sys.platform.startswith("win"):
        return "win32.exe" if "64" not in machine else "win64.exe"
    if sys.platform == "darwin":
        return "osx64" if "arm" not in machine else "osx-arm64"
    if "aarch64" in machine or "arm64" in machine:
        return "linux-aarch64"
    return "linux-x86_64"


def probe_video_in_memory(data: bytes) -> VideoInfo:
    """
    Legge risoluzione, framerate, durata e presenza di una traccia audio
    interrogando ffmpeg con il video passato via stdin — mai scritto su
    disco. Solleva RuntimeError con un messaggio leggibile se il file non
    è un video valido o ffmpeg non riesce a interpretarlo.
    """
    import re

    ffmpeg = _get_ffmpeg_exe()
    proc = subprocess.Popen(
        [ffmpeg, "-i", "pipe:0"],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    _, stderr = proc.communicate(input=data)
    text = stderr.decode("utf-8", errors="ignore")

    video_match = re.search(
        r"Video:.*?(\d{2,5})x(\d{2,5})[^,]*?,.*?([\d.]+)\s*fps", text
    )
    if not video_match:
        # Alcuni container non riportano fps sulla stessa riga; ripiega su
        # una ricerca più permissiva solo per la risoluzione, con fps di
        # default ragionevole.
        video_match_fallback = re.search(r"Video:.*?(\d{2,5})x(\d{2,5})", text)
        if not video_match_fallback:
            raise RuntimeError("Unrecognized or corrupted video file.")
        width = int(video_match_fallback.group(1))
        height = int(video_match_fallback.group(2))
        fps = 25.0
    else:
        width = int(video_match.group(1))
        height = int(video_match.group(2))
        fps = float(video_match.group(3))

    duration_match = re.search(r"Duration:\s*(\d+):(\d+):(\d+\.\d+)", text)
    if duration_match:
        h, m, s = duration_match.groups()
        duration = int(h) * 3600 + int(m) * 60 + float(s)
    else:
        duration = 0.0

    has_audio = "Audio:" in text

    if width <= 0 or height <= 0:
        raise RuntimeError("Could not determine video dimensions.")

    return VideoInfo(width=width, height=height, fps=fps, duration=duration, has_audio=has_audio)


def extract_video_frames_in_memory(data: bytes, info: VideoInfo) -> List[bytes]:
    """
    Decodifica TUTTI i frame del video come RGB24 grezzo, interamente in
    RAM (stdin/stdout pipe, mai un file su disco). Ogni elemento della
    lista ritornata è esattamente width*height*3 byte.

    Nota sui limiti: per video molto lunghi/ad alta risoluzione questo
    tiene tutti i frame decodificati in memoria contemporaneamente, il che
    può essere significativo (es. un minuto a 1280x720@30fps sono circa
    4.7GB di frame grezzi). Per restare entro un uso di RAM ragionevole,
    il chiamante limita la decodifica a clip di durata moderata (vedi
    MAX_INLINE_VIDEO_SECONDS in _preview_video) e offre "Export" per i
    video più lunghi, che l'utente può aprire con un player esterno.
    """
    ffmpeg = _get_ffmpeg_exe()
    cmd = [
        ffmpeg, "-i", "pipe:0",
        "-f", "rawvideo", "-pix_fmt", "rgb24",
        "-vf", f"fps={info.fps}",
        "pipe:1",
    ]
    proc = subprocess.Popen(
        cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE
    )
    stdout, stderr = proc.communicate(input=data)
    frame_size = info.width * info.height * 3
    if frame_size <= 0 or len(stdout) < frame_size:
        raise RuntimeError("No video frames could be decoded.")
    n_frames = len(stdout) // frame_size
    return [stdout[i * frame_size:(i + 1) * frame_size] for i in range(n_frames)]


def extract_video_audio_as_wav(data: bytes) -> Optional[bytes]:
    """
    Estrae la traccia audio del video come WAV valido, interamente in RAM.

    Nota tecnica: chiedere direttamente a ffmpeg un WAV su uno stdout pipe
    produce un header con la dimensione dei dati non dichiarata
    correttamente (ffmpeg non conosce in anticipo quanti byte scriverà su
    uno stream, quindi lascia un valore segnaposto) — file che alcuni
    lettori (incluso mutagen, già usato altrove in questo programma per
    leggere la durata degli audio) interpretano male. La soluzione più
    robusta è chiedere PCM grezzo (nessun header, nessuna ambiguità) e
    costruire noi stessi un header WAV corretto con il modulo standard
    `wave`, sapendo l'esatta dimensione dei dati ricevuti.
    """
    import io as _io
    import wave

    ffmpeg = _get_ffmpeg_exe()
    cmd = [
        ffmpeg, "-i", "pipe:0", "-vn",
        "-f", "s16le", "-ar", "44100", "-ac", "2",
        "pipe:1",
    ]
    proc = subprocess.Popen(
        cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE
    )
    stdout, _ = proc.communicate(input=data)
    if not stdout:
        return None  # nessuna traccia audio, o estrazione fallita
    buf = _io.BytesIO()
    with wave.open(buf, "wb") as w:
        w.setnchannels(2)
        w.setsampwidth(2)
        w.setframerate(44100)
        w.writeframes(stdout)
    return buf.getvalue()


def get_audio_duration_seconds(data: bytes) -> Optional[float]:
    """
    Legge la durata totale del brano dai metadati, senza decodificare
    l'intero audio e senza mai scrivere su disco (mutagen accetta un
    file-like object in RAM). Ritorna None se non determinabile.
    """
    import io as _io
    import mutagen  # import locale: caricato solo se serve leggere la durata

    try:
        f = mutagen.File(_io.BytesIO(data))
        if f is not None and f.info is not None:
            return float(f.info.length)
    except Exception:
        pass
    return None


# BUGFIX (vedi play_audio_in_memory più sotto): pygame.mixer.music è un
# singleton globale del processo — un solo canale musicale attivo alla
# volta. Se l'utente apre due finestre di anteprima audio senza chiudere
# la prima, la seconda chiamata a play_audio_in_memory() interrompe
# naturalmente la prima riproduzione (comportamento corretto e atteso di
# pygame: non avrebbe senso sovrapporre due tracce). Il problema era che
# la finestra della PRIMA canzone non aveva modo di accorgersi che
# l'audio in corso non era più il suo: il suo poll() periodico continuava
# a leggere is_audio_playing()/get_audio_position_seconds(), che ora
# riflettono la SECONDA canzone, mostrando nella prima finestra un tempo
# di riproduzione falso mentre sembrava ancora "in corso". Questo contatore
# di generazione permette a ogni finestra di riconoscere quando un'altra
# riproduzione ha preso il sopravvento sulla propria.
_AUDIO_SESSION_COUNTER = 0


def current_audio_session() -> int:
    return _AUDIO_SESSION_COUNTER


def play_audio_in_memory(data: bytes, start_seconds: float = 0.0) -> int:
    """
    Riproduce audio (mp3/ogg/wav/flac/aac) direttamente da un buffer in RAM,
    tramite pygame.mixer, senza mai scrivere un file temporaneo su disco.
    `start_seconds` permette di iniziare da un punto preciso (seek), ma è
    affidabile principalmente per MP3/OGG: è un limite noto di SDL_mixer,
    non qualcosa che possiamo aggirare lato Python senza cambiare libreria
    audio.

    Ritorna il nuovo numero di sessione audio: il chiamante (una finestra
    di anteprima) lo salva e lo confronta con current_audio_session() nel
    proprio ciclo di polling per sapere se è ancora "lui" a suonare o se
    un'altra finestra ha preso il controllo del canale audio nel frattempo.
    """
    global _AUDIO_SESSION_COUNTER
    import io as _io
    import pygame  # import locale: caricato solo se serve riprodurre audio

    if not pygame.mixer.get_init():
        pygame.mixer.init()
    pygame.mixer.music.load(_io.BytesIO(data))
    if start_seconds > 0:
        try:
            pygame.mixer.music.play(start=start_seconds)
        except Exception:
            # Alcuni formati/backend non supportano lo start-offset: si
            # riparte dall'inizio invece di far fallire la riproduzione.
            pygame.mixer.music.play()
    else:
        pygame.mixer.music.play()
    _AUDIO_SESSION_COUNTER += 1
    return _AUDIO_SESSION_COUNTER


def get_audio_position_seconds() -> float:
    """Posizione corrente di riproduzione in secondi (0 se non in play)."""
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


# ==============================================================================
# SEZIONE 5 — TEMA GRAFICO
# ==============================================================================
# Palette e costanti di stile, portate dalle CSS custom properties
# dell'HTML originale (:root { --gold: #c9a84c; ... }), per dare a
# CustomTkinter la stessa identità visiva "tempio egizio dorato / notte"
# del programma web.
# ==============================================================================

# --- Palette (dai :root CSS dell'originale) -------------------------------
GOLD = "#c9a84c"
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

# Fattore di scala UI corrente, aggiornato da apply_ui_scale() in base alla
# risoluzione reale dello schermo rilevata all'avvio. 1.0 = nessuna scala
# (valore di default finché apply_ui_scale non è stata ancora chiamata).
CURRENT_UI_SCALE = 1.0

RUNES = "𓃠 𓂀 𓊹 𓆣 𓇯 𓋹"


def apply_base_appearance() -> None:
    ctk.set_appearance_mode("dark")
    ctk.set_default_color_theme("dark-blue")  # base neutra, sovrascriviamo i colori a mano


def compute_ui_scale(screen_width: int, screen_height: int) -> float:
    """
    Calcola un fattore di scala per font e dimensioni finestra in base
    alla risoluzione reale dello schermo dell'utente, così la UI resta
    grande e leggibile su schermi ampi senza uscire dai bordi su schermi
    più piccoli (laptop, risoluzioni con scaling alto, ecc.).

    Riferimento: 1920×1080 = scala 1.0 (le dimensioni "base" del resto del
    codice sono pensate per quella risoluzione). Sotto quella soglia si
    riduce proporzionalmente fino a un minimo leggibile; sopra si permette
    di crescere fino a un tetto ragionevole, per non ottenere font
    abnormi su monitor 4K/8K.
    """
    reference_w, reference_h = 1920, 1080
    scale_w = screen_width / reference_w
    scale_h = screen_height / reference_h
    # Il vincolo più stretto tra larghezza e altezza decide la scala,
    # altrimenti su schermi molto larghi ma bassi (es. ultrawide) o molto
    # alti ma stretti la finestra potrebbe comunque uscire dai bordi.
    scale = min(scale_w, scale_h)
    return max(0.65, min(scale, 1.35))


def apply_ui_scale(scale: float) -> None:
    """
    Riscrive le costanti FONT_* globali di questo modulo applicando il
    fattore di scala calcolato da compute_ui_scale(). Va chiamata DOPO
    aver creato la finestra principale (serve winfo_screenwidth/height,
    disponibili solo con una root Tk già istanziata) e PRIMA di costruire
    qualunque widget: Styled.*_kwargs() e tutte le view leggono queste
    costanti al momento in cui vengono effettivamente usate per creare un
    widget, non quando il modulo viene importato — riassegnarle qui prima
    della costruzione della UI è sufficiente perché l'intera applicazione
    prenda i valori scalati, senza dover toccare ogni singolo widget.
    """
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
    """
    Per i pochi font "una tantum" non coperti dalle costanti FONT_* (icone
    grandi nelle finestre di anteprima, elementi della sidebar): applica
    lo stesso fattore di scala calcolato da apply_ui_scale(), così anche
    questi restano coerenti con il resto della UI invece di restare fissi
    mentre tutto il resto si adatta allo schermo.
    """
    size = max(8, round(base_size * CURRENT_UI_SCALE))
    return (family, size, *style) if style else (family, size)


def configure_style(root: ctk.CTk) -> None:
    root.configure(fg_color=DEEP)


class Styled:
    """Helper con preset di stile ricorrenti, per non ripetere kwargs ovunque."""

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


# ==============================================================================
# SEZIONE 6 — VISTA: GENERATORE DI CIFRARI
# ==============================================================================
# Pannello "Generatore di Cifrari" — porting della sezione superiore
# dell'HTML originale (input frase/PIM/amplificatore -> runCipherPipeline).
#
# La pipeline crittografica gira in un thread separato (è CPU-bound per via
# delle iterazioni PBKDF2, 50k-600k) per non bloccare la UI; il risultato
# torna al thread principale tramite after().
# ==============================================================================

PIM_RE = re.compile(r"^\d{1,32}$")


class GeneratorView(ctk.CTkFrame):
    def __init__(self, master, **kwargs):
        super().__init__(master, fg_color=DEEP, **kwargs)
        self._build()

    # ------------------------------------------------------------------ UI
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

        # --- Frase segreta -------------------------------------------------
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

        # --- PIM (numerico) --------------------------------------------------
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

        # --- Amplificatore -----------------------------------------------
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
        # inserito/mostrato dinamicamente in _on_generate

        # --- Output --------------------------------------------------------
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

    # ------------------------------------------------------------- sanitize
    def _sanitize_pim(self, *_args) -> None:
        """
        Porting di input-pim addEventListener('input', ...) dell'originale:
        limita a 32 caratteri e rimuove zeri iniziali (mantenendo un singolo
        '0' se il campo si azzera del tutto). Qui filtriamo anche i non-cifra,
        perché a differenza del browser (input type che filtra a monte) un
        CTkEntry accetta qualunque carattere digitato.
        """
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

    # ------------------------------------------------------------- generate
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
            except Exception as exc:  # noqa: BLE001
                # NOTA: catturiamo il messaggio in una variabile locale PRIMA
                # della lambda. Python elimina automaticamente il binding di
                # "as exc" all'uscita dal blocco except (per evitare
                # riferimenti circolari); self.after() esegue la lambda in
                # modo differito nell'event loop di Tkinter, cioè DOPO che il
                # blocco except è già terminato — a quel punto "exc" non
                # esisterebbe più nella closure e si otterrebbe un NameError
                # invece del messaggio d'errore atteso.
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

    def _clear_output(self) -> None:
        # BUGFIX: il blocco precedente leggeva la clipboard con
        # clipboard_get() ma non faceva nulla col risultato (un if/pass che
        # non aveva alcun effetto) — codice morto che non svuotava
        # realmente gli appunti. Il bottone si chiama "Wipe from Memory":
        # se il cifrario che stiamo cancellando è ancora negli appunti di
        # sistema (perché l'utente l'aveva copiato con "Copy to
        # Clipboard"), lo svuotiamo davvero, altrimenti il nome del
        # bottone sarebbe fuorviante — il cifrario resterebbe comunque
        # recuperabile da un semplice "incolla".
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
                pass  # clipboard vuota o non accessibile: nulla da pulire
        self.output_card.pack_forget()


# ==============================================================================
# SEZIONE 7 — VISTA: VAULT SACRO
# ==============================================================================
# Pannello "Vault" — creazione e apertura di archivi .bca, con la garanzia
# che il contenuto DECRITTATO non tocchi mai il disco.
#
# Flusso "Crea archivio":
#   1. L'utente sceglie file dal filesystem (letti UNA VOLTA in RAM, come
#      bytearray).
#   2. build_bca() li comprime e cifra interamente in memoria.
#   3. Il risultato (.bca) viene scritto su disco SOLO quando l'utente lo
#      chiede esplicitamente ("Salva archivio come...").
#   4. I bytearray dei file originali vengono azzerati subito dopo l'uso.
#
# Flusso "Apri archivio":
#   1. L'utente sceglie un file .bca esistente (letto UNA VOLTA in RAM).
#   2. parse_bca() lo decifra e decomprime interamente in memoria.
#   3. I file decrittati restano SOLO in RAM; l'utente può visualizzarli
#      (secure_viewer, mai su disco) o esportarli esplicitamente
#      ("Salva come...", unica eccezione voluta dove i dati toccano il disco).
#   4. Alla chiusura del vault, TUTTI i bytearray vengono azzerati.
# ==============================================================================

class VaultView(ctk.CTkFrame):
    def __init__(self, master, **kwargs):
        super().__init__(master, fg_color=DEEP, **kwargs)
        # stato del vault aperto: lista di VaultDecryptedEntry, solo in RAM
        self._open_entries: list[VaultDecryptedEntry] = []
        self._pending_create_entries: list[VaultFileEntry] = []
        # BUGFIX: traccia i file temporanei video scritti su RAM-disk
        # (o su disco reale se il RAM-disk non è disponibile su questo OS)
        # per poterli ripulire anche se l'utente chiude l'intera app senza
        # prima chiudere la finestra di anteprima video — senza questo
        # tracking, quei file restavano orfani dopo la chiusura dell'app.
        self._active_video_tmp_paths: list[str] = []
        self._build()

    # ------------------------------------------------------------------ UI
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
            self, fg_color=STONE, segmented_button_selected_color=GOLD_DARK,
            segmented_button_selected_hover_color=GOLD,
            segmented_button_fg_color=INK, text_color=SAND,
        )
        self.tabs.pack(padx=24, pady=8, fill="both", expand=True)
        self.tab_create = self.tabs.add("Create Archive")
        self.tab_open = self.tabs.add("Open Archive")

        self._build_create_tab()
        self._build_open_tab()

    # ---------------------------------------------------------- CREATE TAB
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
        # PERFORMANCE FIX: prima la lettura dei file avveniva direttamente
        # sul thread principale della UI (f.read() per ogni file scelto).
        # Con un file grande (centinaia di MB / ~1GB) questo bloccava
        # l'intera finestra — non solo "lento": completamente non
        # responsiva, "Non risponde" su Windows — per tutta la durata
        # della lettura da disco, PRIMA ancora che qualunque crittografia
        # entrasse in gioco. Questo era probabilmente il "lag" più
        # percepibile di tutti, perché capita ogni volta che si sceglie
        # un file, non solo alla creazione dell'archivio. Ora la lettura
        # gira su un thread separato; la UI resta reattiva e mostra un
        # indicatore di caricamento nel frattempo.
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
        self._pending_create_entries = []  # ownership passa al worker

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
            except Exception as exc:  # noqa: BLE001
                # Vedi nota sul pattern except-as-lambda in _on_generate().
                error_message = str(exc)
                self.after(0, lambda: self._on_create_error(error_message))
            finally:
                wipe_bytearray(password_buf)
                # BUGFIX: StringVar.set() parla con l'interprete Tcl
                # sottostante. Tkinter non è thread-safe: chiamare .set()
                # da questo worker thread (invece che dal thread principale
                # via self.after) è una race condition non garantita, che
                # può causare crash intermittenti o stato Tcl corrotto,
                # specialmente sotto carico o su Windows. wipe_bytearray()
                # sopra resta qui perché opera solo su memoria Python pura,
                # non su widget Tk.
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

    # ------------------------------------------------------------ OPEN TAB
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
        pw_entry = ctk.CTkEntry(
            t, textvariable=self.open_pw_var, show="•",
            placeholder_text="Password used to encrypt it...",
            **Styled.entry_kwargs(),
        )
        pw_entry.pack(fill="x", padx=16)
        pw_entry.bind("<Return>", lambda e: self._on_open_archive())

        self.open_status = ctk.CTkLabel(t, text="", **Styled.label_muted_kwargs())
        self.open_status.pack(pady=(10, 0))
        self.open_progress = ctk.CTkProgressBar(t, progress_color=GOLD_BRIGHT, fg_color=INK)

        self.open_btn = ctk.CTkButton(
            t, text="🔓  Unlock Vault  🔓", command=self._on_open_archive,
            **Styled.primary_button_kwargs(),
        )
        self.open_btn.pack(fill="x", padx=16, pady=16)

        # Lista file decrittati (mostrata solo dopo sblocco riuscito)
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

        # PERFORMANCE FIX: prima la lettura del file .bca da disco
        # (f.read()) avveniva qui, sul thread principale della UI, PRIMA
        # di avviare il worker — per un archivio da centinaia di MB / 1GB
        # questo bloccava completamente la finestra durante la lettura,
        # ancora prima che comparisse la progress bar di sblocco. Ora la
        # lettura fa parte del worker thread, cosi' la UI resta reattiva
        # fin dal primo istante e la progress bar può comparire subito.
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
                # Vedi nota sul pattern except-as-lambda in _on_generate().
                error_message = str(exc)
                self.after(0, lambda: self._on_open_error(error_message))
            except Exception as exc:  # noqa: BLE001
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
        except Exception as exc:  # noqa: BLE001
            error_message = str(exc)
            ctk.CTkLabel(
                win, text=f"Could not display preview:\n{error_message}",
                text_color=DANGER,
            ).pack(pady=40)

    def _preview_image(self, win: ctk.CTkToplevel, data: bytes) -> None:
        """
        Mostra l'immagine con zoom controllabile dalla rotellina del
        mouse. Tiene l'immagine PIL originale (non solo una miniatura) in
        memoria per poter ricampionare a qualità piena a qualunque livello
        di zoom, dentro un Canvas (a differenza di una Label statica, un
        Canvas permette di ridisegnare il contenuto a dimensione variabile
        senza ricreare il widget ad ogni passo di zoom).
        """
        original_img = render_image_in_memory(data)

        canvas = tk.Canvas(win, bg=DEEP, highlightthickness=0)
        canvas.pack(expand=True, fill="both", padx=10, pady=10)

        # Zoom iniziale: la stessa logica di "thumbnail" di prima, ma
        # calcolata come fattore così possiamo poi scalare da lì con la
        # rotellina invece di partire sempre dalla dimensione originale.
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
            state["photo"] = photo  # riferimento forte, evita garbage collection
            canvas.delete("all")
            canvas_w = max(canvas.winfo_width(), 1)
            canvas_h = max(canvas.winfo_height(), 1)
            canvas.create_image(canvas_w // 2, canvas_h // 2, image=photo, anchor="center")
            canvas.configure(scrollregion=(0, 0, new_w, new_h))

        def on_mousewheel(event) -> None:
            # Windows/macOS: event.delta è positivo (su) o negativo (giù).
            # Linux (X11) invece invia eventi separati Button-4/Button-5,
            # gestiti nei bind dedicati più sotto — questo handler serve
            # solo per <MouseWheel>.
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
            # Debounce leggero: se l'utente scrolla velocemente, evitiamo
            # di ri-renderizzare ad ogni singolo tick della rotellina
            # (costoso su immagini grandi), aspettando un attimo di calma.
            if state["job"] is not None:
                win.after_cancel(state["job"])
            state["job"] = win.after(30, render_at_scale)

        # <MouseWheel> copre Windows e macOS. <Button-4>/<Button-5> coprono
        # X11/Linux, dove la rotellina è riportata come due "bottoni"
        # separati invece che un delta continuo.
        canvas.bind("<MouseWheel>", on_mousewheel)
        canvas.bind("<Button-4>", on_scroll_up)
        canvas.bind("<Button-5>", on_scroll_down)

        canvas.bind("<Configure>", lambda _e: render_at_scale())
        win.after(50, render_at_scale)

    def _preview_pdf(self, win: ctk.CTkToplevel, data: bytes) -> None:
        """
        BUGFIX: prima i riferimenti PhotoImage delle pagine PDF venivano
        salvati in `self._pdf_photo_refs`, una lista CONDIVISA a livello
        di VaultView (non per-finestra). Se l'utente apriva un secondo
        PDF senza chiudere il primo, l'assegnazione `self._pdf_photo_refs
        = []` sovrascriveva completamente i riferimenti del primo PDF —
        le sue immagini perdevano ogni riferimento forte e potevano essere
        raccolte dal garbage collector in qualunque momento, facendo
        sparire/corrompere il contenuto della prima finestra pur essendo
        ancora visibile. Ora i riferimenti sono locali a QUESTA specifica
        chiamata (tramite closure), uno storage indipendente per ogni
        finestra di anteprima aperta, indipendentemente da quante altre
        ne restano aperte contemporaneamente.
        """
        pages = render_pdf_pages_in_memory(data, dpi=100, max_pages=30)
        scroll = ctk.CTkScrollableFrame(win, fg_color=DEEP)
        scroll.pack(expand=True, fill="both", padx=10, pady=10)
        photo_refs: list = []  # locale a QUESTA finestra, non condiviso
        win.pdf_photo_refs = photo_refs  # riferimento forte anche sull'oggetto finestra
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
        """
        Riproduce l'audio direttamente dal buffer decrittato in RAM
        (pygame.mixer.music.load accetta un file-like object, mai un path
        su disco), con una barra di avanzamento trascinabile (seek) e il
        tempo trascorso/totale. Alla chiusura della finestra la
        riproduzione si ferma e il polling periodico si interrompe.
        """
        ctk.CTkLabel(win, text="🎵", font=scaled_font(64), text_color=GOLD_BRIGHT).pack(pady=(60, 10))
        ctk.CTkLabel(win, text=name, **Styled.label_header_kwargs()).pack(pady=(0, 20))

        status_label = ctk.CTkLabel(win, text="Playing from RAM...", **Styled.label_muted_kwargs())
        status_label.pack(pady=(0, 10))

        duration = get_audio_duration_seconds(data)  # None se non determinabile

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
                    # BUGFIX: pygame.mixer.music.get_pos() ritorna il tempo
                    # trascorso dall'ULTIMA play(), non la posizione assoluta
                    # nel brano — si azzera ogni volta che si fa seek. Senza
                    # questo offset, subito dopo un trascinamento la barra
                    # "tornava indietro" a mostrare il tempo da 0 invece di
                    # restare dove l'utente l'aveva lasciata, dando la
                    # sensazione che il seek non funzionasse.
                    state["seek_offset"] = target
                    state["started"] = True
                    # play_audio_in_memory() chiama sempre play() al suo
                    # interno: se l'utente aveva messo pausa e poi trascina
                    # la barra, la riproduzione riparte comunque da qui. Il
                    # bottone deve riflettere questo, altrimenti mostrerebbe
                    # "Play" mentre l'audio sta già suonando.
                    if pause_btn is not None:
                        pause_btn.configure(text="⏸ Pause")
                except Exception:
                    pass  # formato senza supporto seek affidabile: resta dov'era

        slider.bind("<Button-1>", on_slider_press)
        slider.bind("<ButtonRelease-1>", on_slider_release)

        try:
            state["session"] = play_audio_in_memory(data)
            state["started"] = True
        except Exception as exc:  # noqa: BLE001
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
                # BUGFIX: se un'altra finestra ha preso il controllo del
                # canale audio nel frattempo, un semplice unpause()
                # riprenderebbe l'audio SBAGLIATO (quello dell'altra
                # finestra). In quel caso rilanciamo la riproduzione di
                # QUESTO file da capo (con play_audio_in_memory, che
                # riprende possesso del canale) invece di limitarci a
                # un unpause che opererebbe sull'audio sbagliato.
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
            # BUGFIX: se un'altra finestra di anteprima audio ha avviato
            # una nuova riproduzione nel frattempo (pygame.mixer.music è
            # un canale singolo condiviso), la nostra sessione non è più
            # quella attiva. Senza questo controllo, questa finestra
            # avrebbe continuato a mostrare un tempo di riproduzione preso
            # dall'audio SBAGLIATO (quello dell'altra finestra), dando
            # l'impressione fuorviante di essere ancora in riproduzione.
            if state["session"] != current_audio_session():
                if state["session"] != -1:  # solo se avevamo davvero suonato una volta
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
        """
        Player video integrato, interamente dentro la finestra dell'app —
        nessun player esterno, nessun file scritto su disco in nessun
        momento. Il video viene decodificato in RAM con ffmpeg (binario
        auto-contenuto, scaricato via pip da imageio-ffmpeg: non richiede
        alcuna installazione a livello di sistema operativo), leggendo i
        byte cifrati-poi-decifrati direttamente da uno stdin pipe e
        ricevendo frame RGB grezzi + audio PCM via stdout pipe.

        Limite di design dichiarato: per restare entro un uso di RAM
        ragionevole, questo player decodifica TUTTI i frame in anticipo
        (non c'è uno streaming frame-by-frame), quindi è pensato per clip
        di durata moderata. Oltre una soglia (MAX_INLINE_VIDEO_SECONDS) o
        se ffmpeg non è disponibile per qualunque motivo, si ricade sul
        vecchio comportamento — aprire il video con il player video del
        sistema operativo da un file temporaneo su RAM-disk quando
        possibile — invece di rischiare di esaurire la memoria o bloccare
        l'interfaccia per troppo tempo su un video molto lungo.
        """
        MAX_INLINE_VIDEO_SECONDS = 120.0

        ctk.CTkLabel(win, text="🎬", font=scaled_font(48), text_color=GOLD_BRIGHT).pack(pady=(20, 6))
        ctk.CTkLabel(win, text=name, **Styled.label_header_kwargs()).pack(pady=(0, 10))
        status_label = ctk.CTkLabel(win, text="Decoding video in RAM...", **Styled.label_muted_kwargs())
        status_label.pack(pady=(0, 10))
        win.update()

        try:
            info = probe_video_in_memory(data)
        except Exception as exc:  # noqa: BLE001
            error_message = str(exc)
            status_label.configure(text=f"Could not read video: {error_message}", text_color=DANGER)
            return

        if info.duration > MAX_INLINE_VIDEO_SECONDS:
            status_label.configure(
                text=(
                    f"This video is {info.duration:.0f}s long — too long for the\n"
                    "in-app player to decode fully into RAM. Falling back to\n"
                    "your system's video player instead."
                ),
                text_color="#ff9a5a",
            )
            self._preview_video_external_fallback(win, data, name, status_label)
            return

        try:
            frames = extract_video_frames_in_memory(data, info)
        except Exception as exc:  # noqa: BLE001
            error_message = str(exc)
            status_label.configure(
                text=f"Could not decode video frames: {error_message}\nFalling back to system player.",
                text_color="#ff9a5a",
            )
            self._preview_video_external_fallback(win, data, name, status_label)
            return

        wav_audio = None
        if info.has_audio:
            try:
                wav_audio = extract_video_audio_as_wav(data)
            except Exception:
                wav_audio = None  # video senza audio utilizzabile: si continua muto

        video_label = tk.Label(win, bg=DEEP)
        video_label.pack(expand=True, fill="both", padx=10, pady=(0, 6))

        controls = ctk.CTkFrame(win, fg_color="transparent")
        controls.pack(pady=(0, 12))
        play_pause_btn = ctk.CTkButton(controls, text="⏸ Pause", **Styled.secondary_button_kwargs())
        play_pause_btn.pack(side="left", padx=6)
        time_label = ctk.CTkLabel(controls, text="0:00 / 0:00", font=FONT_MONO_SMALL, text_color=SAND)
        time_label.pack(side="left", padx=12)

        state = {"playing": True, "start_time": time.monotonic(), "job": None, "audio_session": -1}

        def fmt(seconds: float) -> str:
            seconds = max(0, int(seconds))
            return f"{seconds // 60}:{seconds % 60:02d}"

        if wav_audio:
            try:
                state["audio_session"] = play_audio_in_memory(wav_audio)
            except Exception:
                state["audio_session"] = -1  # niente audio disponibile: video muto ma comunque riprodotto

        photo_refs: list = []  # riferimento forte per-finestra, vedi nota sul bugfix PDF sopra

        def render_frame(index: int) -> None:
            index = max(0, min(index, len(frames) - 1))
            raw_rgb = frames[index]
            img = Image.frombytes("RGB", (info.width, info.height), raw_rgb)
            max_w = max(video_label.winfo_width(), 320)
            max_h = max(video_label.winfo_height(), 240)
            img.thumbnail((max_w, max_h))
            photo = ImageTk.PhotoImage(img)
            photo_refs.clear()
            photo_refs.append(photo)
            video_label.configure(image=photo)

        def tick() -> None:
            if not state["playing"]:
                state["job"] = win.after(100, tick)
                return
            elapsed = time.monotonic() - state["start_time"]
            # Se c'è audio, la posizione dell'audio (già sincronizzato dal
            # motore pygame) è la fonte di verità più affidabile — il
            # clock del video segue quello, evitando che i due divergano
            # nel tempo (drift) su clip più lunghe.
            if state["audio_session"] != -1 and state["audio_session"] == current_audio_session():
                elapsed = get_audio_position_seconds()
            frame_idx = int(elapsed * info.fps)
            if frame_idx >= len(frames):
                state["playing"] = False
                play_pause_btn.configure(text="▶ Replay")
                time_label.configure(text=f"{fmt(info.duration)} / {fmt(info.duration)}")
                state["job"] = win.after(100, tick)
                return
            render_frame(frame_idx)
            time_label.configure(text=f"{fmt(elapsed)} / {fmt(info.duration)}")
            state["job"] = win.after(max(1, int(1000 / info.fps)), tick)

        def toggle_play() -> None:
            if not state["playing"] and play_pause_btn.cget("text") == "▶ Replay":
                # Il video era finito: ricomincia da capo.
                state["start_time"] = time.monotonic()
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
                # Riprendiamo dal punto in cui eravamo: ricalcoliamo
                # start_time in modo che "elapsed" torni a corrispondere
                # a dove il video era stato messo in pausa.
                paused_at = getattr(toggle_play, "_paused_at", 0.0)
                state["start_time"] = time.monotonic() - paused_at
                if state["audio_session"] != -1:
                    unpause_audio()
                play_pause_btn.configure(text="⏸ Pause")
            else:
                toggle_play._paused_at = time.monotonic() - state["start_time"]
                if state["audio_session"] != -1:
                    pause_audio()
                play_pause_btn.configure(text="▶ Play")

        play_pause_btn.configure(command=toggle_play)

        status_label.pack_forget()
        win.after(50, tick)

        def on_close() -> None:
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
        """
        Ripiego sul comportamento precedente (player video di sistema, da
        un file temporaneo su RAM-disk quando disponibile) per i video
        troppo lunghi da decodificare interamente in RAM, o se ffmpeg non
        è riuscito a decodificarli per qualunque motivo. Vedi il
        commento originale in _preview_video per i dettagli sul
        RAM-disk.
        """
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
                os.startfile(tmp_path)  # noqa: S606
            elif sys.platform == "darwin":
                subprocess.Popen(["open", tmp_path])
            else:
                subprocess.Popen(["xdg-open", tmp_path])
        except Exception as exc:  # noqa: BLE001
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
        # NOTA: i riferimenti alle pagine PDF rasterizzate (photo_refs) ora
        # vivono per-finestra (attributo win.pdf_photo_refs, vedi
        # _preview_pdf), non più qui in una lista condivisa a livello di
        # VaultView. Se l'utente chiude il vault mentre una finestra di
        # anteprima PDF è ancora aperta, quella finestra resta
        # legittimamente visibile con le sue immagini intatte finché non
        # viene chiusa esplicitamente — comportamento corretto, dato che
        # il PDF era già stato decrittato in RAM prima della chiusura del
        # vault e continua a esistere indipendentemente da esso.
        self.entries_frame.pack_forget()
        self.close_vault_btn.pack_forget()
        self.open_status.configure(text="Vault closed · Data wiped from RAM.", text_color=STONE_PALE)
        self._bca_path = None
        self.open_dz_label.configure(text="📁  Select a .bca archive")
        self.open_dz_sub.configure(text="Will be opened only in memory: no data written to disk")

    def wipe_all_on_exit(self) -> None:
        """Chiamato dalla finestra principale alla chiusura dell'app."""
        for entry in self._open_entries:
            wipe_bytearray(entry.data)
        for entry in self._pending_create_entries:
            wipe_bytearray(entry.data)
        # BUGFIX: se l'utente chiude l'app mentre sta ancora digitando una
        # password (senza aver premuto "Create" o "Unlock"), quei campi
        # restavano pieni nelle StringVar fino alla terminazione del
        # processo invece di essere svuotati esplicitamente qui insieme al
        # resto. Le StringVar di Tkinter non si azzerano in modo
        # crittograficamente sicuro (sono stringhe Python immutabili
        # gestite da Tcl, non bytearray), ma svuotarle esplicitamente
        # riduce comunque la finestra temporale in cui il testo in chiaro
        # resta raggiungibile in memoria.
        try:
            self.create_pw_var.set("")
            self.create_pw_confirm_var.set("")
            self.open_pw_var.set("")
        except Exception:
            pass  # la finestra potrebbe già essere in fase di distruzione
        # Se un audio è in riproduzione, la finestra di anteprima potrebbe
        # chiudersi senza passare dal suo on_close() (es. chiusura diretta
        # dell'app principale): fermiamo comunque la riproduzione qui,
        # altrimenti pygame continuerebbe a suonare a finestra chiusa.
        try:
            stop_audio()
        except Exception:
            pass
        # Stesso discorso per i file temporanei video (vedi nota nel
        # costruttore): se l'app si chiude con una preview video ancora
        # aperta, il suo on_close() non viene mai chiamato — ripuliamo
        # qui qualunque file residuo.
        for tmp_path in self._active_video_tmp_paths:
            try:
                os.remove(tmp_path)
            except OSError:
                pass
        self._active_video_tmp_paths.clear()
        # NOTA: non serve più ripulire riferimenti PDF qui — dopo il fix
        # per-finestra in _preview_pdf(), quei riferimenti vivono
        # sull'oggetto finestra stesso (win.pdf_photo_refs), e quando il
        # processo termina (questa funzione è chiamata alla chiusura
        # dell'intera app) tutte le finestre e i loro attributi vengono
        # comunque rilasciati insieme al processo.


# ==============================================================================
# SEZIONE 8 — APPLICAZIONE PRINCIPALE
# ==============================================================================
# Finestra principale: sidebar di navigazione tra Generatore e Vault,
# hardening del processo all'avvio (disabilita i core dump), e azzeramento
# di tutti i dati sensibili ancora in RAM alla chiusura.
# ==============================================================================

class BastetCipherApp(ctk.CTk):
    def __init__(self) -> None:
        super().__init__()
        self.title("BastetCipher — Sacred Chamber")

        # ADATTAMENTO ALLO SCHERMO: prima la finestra e i font erano a
        # dimensione fissa (1280x920, font base non scalati). Su schermi
        # piccoli o con scaling di sistema alto questo poteva uscire dai
        # bordi visibili; su schermi grandi non sfruttava lo spazio
        # disponibile per rendere i caratteri ancora più leggibili come
        # richiesto. Rileviamo la risoluzione reale e scaliamo di
        # conseguenza — questo DEVE avvenire prima di _build_layout(),
        # perché tutti i widget vengono creati leggendo le costanti
        # FONT_* del modulo tema, che apply_ui_scale() riscrive qui.
        screen_w = self.winfo_screenwidth()
        screen_h = self.winfo_screenheight()
        ui_scale = compute_ui_scale(screen_w, screen_h)
        apply_ui_scale(ui_scale)

        # Dimensione finestra proporzionata allo schermo invece che fissa,
        # con un tetto per non coprire l'intero desktop su monitor enormi
        # e un margine di sicurezza per non sforare su schermi piccoli
        # (task bar, dock, bordi finestra del sistema operativo).
        target_w = min(int(screen_w * 0.75), 1800)
        target_h = min(int(screen_h * 0.82), 1300)
        target_w = max(target_w, 900)   # non scendere sotto una soglia usabile
        target_h = max(target_h, 650)
        pos_x = max(0, (screen_w - target_w) // 2)
        pos_y = max(0, (screen_h - target_h) // 3)
        self.geometry(f"{target_w}x{target_h}+{pos_x}+{pos_y}")
        # minsize scalato in proporzione, mai sotto una soglia leggibile,
        # ma anche mai più grande dello schermo stesso (altrimenti
        # l'utente non potrebbe rimpicciolire la finestra su display
        # piccoli, e alcuni window manager la forzerebbero comunque fuori
        # schermo in modi inconsistenti).
        min_w = min(max(int(720 * ui_scale), 720), screen_w)
        min_h = min(max(int(560 * ui_scale), 560), screen_h)
        self.minsize(min_w, min_h)

        self.configure(fg_color=DEEP)

        self._build_layout()
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

        self.content = ctk.CTkFrame(self, fg_color=DEEP, corner_radius=0)
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

