#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Heri Cipher Tool - Aplikasi Enkripsi & Dekripsi berbasis CLI
Author: Heri Herlambang
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import os
import platform
import shutil
import subprocess
from abc import ABC, abstractmethod
from getpass import getpass
from typing import Iterator, Optional

__author__ = "Heri Herlambang"
__version__ = "1.0.0"
__app_name__ = "Heri Cipher Tool"

try:
    from cryptography.exceptions import InvalidTag
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

    CRYPTO_AVAILABLE = True
except ImportError:
    CRYPTO_AVAILABLE = False


class CipherError(Exception):
    """Error yang dilempar saat proses enkripsi/dekripsi gagal."""


class BaseCipher(ABC):
    name: str = "Base"
    key_prompt: str = "Masukkan kunci"
    secret_key: bool = False

    @abstractmethod
    def encrypt(self, plaintext: str, key: str) -> str:
        pass

    @abstractmethod
    def decrypt(self, ciphertext: str, key: str) -> str:
        pass


class CaesarCipher(BaseCipher):
    name = "Caesar Cipher"
    key_prompt = "Masukkan kunci geser (angka bulat, contoh: 3)"

    @staticmethod
    def _parse_key(key: str) -> int:
        try:
            return int(key.strip())
        except ValueError:
            raise CipherError("Kunci Caesar harus berupa angka bulat.")

    @staticmethod
    def _shift(text: str, shift: int) -> str:
        hasil = []
        for ch in text:
            if "a" <= ch <= "z":
                hasil.append(chr((ord(ch) - ord("a") + shift) % 26 + ord("a")))
            elif "A" <= ch <= "Z":
                hasil.append(chr((ord(ch) - ord("A") + shift) % 26 + ord("A")))
            else:
                hasil.append(ch)
        return "".join(hasil)

    def encrypt(self, plaintext: str, key: str) -> str:
        return self._shift(plaintext, self._parse_key(key))

    def decrypt(self, ciphertext: str, key: str) -> str:
        return self._shift(ciphertext, -self._parse_key(key))


class HeriCipher(BaseCipher):
    name = "Heri Cipher (Substitution-XOR)"
    key_prompt = "Passphrase tambahan (kosongkan untuk memakai kunci nama saja)"
    secret_key = True

    NAME_KEY = "Heri Herlambang"
    _SALT = b"HeriCipher-v1"
    _ITERATIONS = 100_000

    def _derive_seed(self, passphrase: str) -> bytes:
        secret = f"{self.NAME_KEY}|{passphrase}".encode("utf-8")
        return hashlib.pbkdf2_hmac("sha256", secret, self._SALT, self._ITERATIONS, dklen=32)

    @staticmethod
    def _keystream(seed: bytes, label: bytes) -> Iterator[int]:
        counter = 0
        while True:
            blok = hashlib.sha256(seed + label + counter.to_bytes(8, "big")).digest()
            yield from blok
            counter += 1

    def _build_sbox(self, seed: bytes) -> tuple[list[int], list[int]]:
        sbox = list(range(256))
        stream = self._keystream(seed, b"sbox")
        for i in range(255, 0, -1):
            r = (next(stream) << 8) | next(stream)
            j = r % (i + 1)
            sbox[i], sbox[j] = sbox[j], sbox[i]
        inv = [0] * 256
        for idx, val in enumerate(sbox):
            inv[val] = idx
        return sbox, inv

    def encrypt(self, plaintext: str, key: str) -> str:
        seed = self._derive_seed(key)
        sbox, _ = self._build_sbox(seed)
        ks = self._keystream(seed, b"xor")

        out = bytearray()
        prev = 0
        for b in plaintext.encode("utf-8"):
            c = sbox[(b + prev) & 0xFF] ^ next(ks)
            out.append(c)
            prev = c
        return base64.b64encode(bytes(out)).decode("ascii")

    def decrypt(self, ciphertext: str, key: str) -> str:
        try:
            data = base64.b64decode(ciphertext.strip(), validate=True)
        except (binascii.Error, ValueError):
            raise CipherError("Ciphertext bukan Base64 yang valid.")

        seed = self._derive_seed(key)
        _, inv = self._build_sbox(seed)
        ks = self._keystream(seed, b"xor")

        out = bytearray()
        prev = 0
        for c in data:
            b = (inv[c ^ next(ks)] - prev) & 0xFF
            out.append(b)
            prev = c
        try:
            return out.decode("utf-8")
        except UnicodeDecodeError:
            raise CipherError("Dekripsi gagal: passphrase salah atau data rusak.")


class AES256Cipher(BaseCipher):
    name = "AES-256 (GCM)"
    key_prompt = "Masukkan password"
    secret_key = True

    _SALT_LEN = 16
    _NONCE_LEN = 12
    _TAG_LEN = 16

    @staticmethod
    def _require_crypto() -> None:
        if not CRYPTO_AVAILABLE:
            raise CipherError(
                "Pustaka 'cryptography' belum terpasang.\n"
                "  Jalankan: pip install cryptography"
            )

    @staticmethod
    def _derive_key(password: str, salt: bytes) -> bytes:
        kdf = Scrypt(salt=salt, length=32, n=2**15, r=8, p=1)
        return kdf.derive(password.encode("utf-8"))

    def encrypt(self, plaintext: str, key: str) -> str:
        self._require_crypto()
        if not key:
            raise CipherError("Password AES tidak boleh kosong.")

        salt = os.urandom(self._SALT_LEN)
        nonce = os.urandom(self._NONCE_LEN)
        aes_key = self._derive_key(key, salt)
        ct = AESGCM(aes_key).encrypt(nonce, plaintext.encode("utf-8"), None)
        return base64.b64encode(salt + nonce + ct).decode("ascii")

    def decrypt(self, ciphertext: str, key: str) -> str:
        self._require_crypto()
        if not key:
            raise CipherError("Password AES tidak boleh kosong.")

        try:
            raw = base64.b64decode(ciphertext.strip(), validate=True)
        except (binascii.Error, ValueError):
            raise CipherError("Ciphertext bukan Base64 yang valid.")

        minimal = self._SALT_LEN + self._NONCE_LEN + self._TAG_LEN
        if len(raw) < minimal:
            raise CipherError("Ciphertext terlalu pendek / format tidak dikenali.")

        salt = raw[: self._SALT_LEN]
        nonce = raw[self._SALT_LEN : self._SALT_LEN + self._NONCE_LEN]
        ct = raw[self._SALT_LEN + self._NONCE_LEN :]

        aes_key = self._derive_key(key, salt)
        try:
            return AESGCM(aes_key).decrypt(nonce, ct, None).decode("utf-8")
        except InvalidTag:
            raise CipherError("Dekripsi gagal: password salah atau data telah diubah.")
        except UnicodeDecodeError:
            raise CipherError("Hasil dekripsi bukan teks UTF-8 yang valid.")


def copy_to_clipboard(text: str) -> bool:
    try:
        import pyperclip  # type: ignore

        pyperclip.copy(text)
        return True
    except Exception:
        pass

    try:
        import tkinter

        root = tkinter.Tk()
        root.withdraw()
        root.clipboard_clear()
        root.clipboard_append(text)
        root.update()
        root.destroy()
        return True
    except Exception:
        pass

    sistem = platform.system()
    if sistem == "Darwin":
        kandidat = [["pbcopy"]]
    elif sistem == "Windows":
        kandidat = []
    else:
        kandidat = [
            ["wl-copy"],
            ["xclip", "-selection", "clipboard"],
            ["xsel", "--clipboard", "--input"],
            ["termux-clipboard-set"],
        ]
    for cmd in kandidat:
        if shutil.which(cmd[0]):
            try:
                subprocess.run(cmd, input=text.encode("utf-8"), check=True, timeout=5)
                return True
            except (subprocess.SubprocessError, OSError):
                continue
    return False


def save_to_file(text: str, path: str) -> None:
    path = os.path.expanduser(path.strip())
    if not path:
        raise ValueError("Nama file tidak boleh kosong.")
    if os.path.exists(path):
        jawab = input(f"File '{path}' sudah ada. Timpa? (y/n): ").strip().lower()
        if jawab != "y":
            raise ValueError("Penyimpanan dibatalkan.")
    with open(path, "w", encoding="utf-8") as f:
        f.write(text)


def print_banner() -> None:
    lebar = 56
    garis = "=" * lebar
    print(garis)
    print(f"{__app_name__.upper():^{lebar}}")
    print(f"{'Enkripsi & Dekripsi Teks':^{lebar}}")
    print(garis)
    print(f"{'Author  : ' + __author__:^{lebar}}")
    print(f"{'Versi   : ' + __version__:^{lebar}}")
    print(garis)


def ask_choice(prompt: str, valid: set[str]) -> str:
    while True:
        pilihan = input(prompt).strip()
        if pilihan in valid:
            return pilihan
        print("  [!] Pilihan tidak valid, coba lagi.")


def ask_text(mode: str) -> str:
    label = "teks asli" if mode == "encrypt" else "ciphertext"
    while True:
        teks = input(f"\nMasukkan {label}: ")
        if teks.strip():
            return teks
        print("  [!] Teks tidak boleh kosong.")


def ask_key(cipher: BaseCipher) -> str:
    if cipher.secret_key:
        try:
            return getpass(f"{cipher.key_prompt}: ")
        except Exception:
            return input(f"{cipher.key_prompt}: ")
    return input(f"{cipher.key_prompt}: ")


def output_menu(result: str) -> None:
    while True:
        print("\nOpsi hasil:")
        print("  1. Salin ke clipboard")
        print("  2. Simpan ke file")
        print("  0. Kembali ke menu utama")
        pilihan = ask_choice("Pilih [0-2]: ", {"0", "1", "2"})

        if pilihan == "1":
            if copy_to_clipboard(result):
                print("  [OK] Hasil disalin ke clipboard.")
            else:
                print("  [!] Clipboard tidak tersedia. Coba: pip install pyperclip")
        elif pilihan == "2":
            path = input("  Nama file tujuan (contoh: hasil.txt): ")
            try:
                save_to_file(result, path)
                print(f"  [OK] Hasil disimpan ke: {os.path.abspath(os.path.expanduser(path.strip()))}")
            except (OSError, ValueError) as e:
                print(f"  [!] Gagal menyimpan: {e}")
        else:
            return


CIPHERS: dict[str, BaseCipher] = {
    "1": CaesarCipher(),
    "2": HeriCipher(),
    "3": AES256Cipher(),
}


def choose_cipher() -> Optional[BaseCipher]:
    print("\nPilih algoritma:")
    for nomor, cipher in CIPHERS.items():
        print(f"  {nomor}. {cipher.name}")
    print("  0. Kembali")
    pilihan = ask_choice("Pilih [0-3]: ", {"0", *CIPHERS.keys()})
    return None if pilihan == "0" else CIPHERS[pilihan]


def run_process(mode: str) -> None:
    cipher = choose_cipher()
    if cipher is None:
        return

    teks = ask_text(mode)
    kunci = ask_key(cipher)

    try:
        if mode == "encrypt":
            hasil = cipher.encrypt(teks, kunci)
        else:
            hasil = cipher.decrypt(teks, kunci)
    except CipherError as e:
        print(f"\n  [!] {e}")
        return
    except Exception as e:
        print(f"\n  [!] Terjadi kesalahan tak terduga: {e}")
        return

    judul = "HASIL ENKRIPSI" if mode == "encrypt" else "HASIL DEKRIPSI"
    print(f"\n--- {judul} ({cipher.name}) ---")
    print(hasil)
    print("-" * 40)
    output_menu(hasil)


def show_info() -> None:
    print(f"\n{__app_name__} v{__version__}")
    print(f"Author: {__author__}")
    print("- Caesar Cipher : klasik, hanya untuk belajar.")
    print("- Heri Cipher   : Substitution-XOR berbasis nama 'Heri Herlambang'.")
    print("- AES-256 (GCM) : enkripsi modern, aman untuk penggunaan nyata.")
    if not CRYPTO_AVAILABLE:
        print("\n[!] Pustaka 'cryptography' belum terpasang -> AES-256 nonaktif.")
        print("    Jalankan: pip install cryptography")


def main() -> None:
    print_banner()
    while True:
        print("\nMENU UTAMA")
        print("  1. Enkripsi teks")
        print("  2. Dekripsi teks")
        print("  3. Tentang program")
        print("  0. Keluar")
        pilihan = ask_choice("Pilih [0-3]: ", {"0", "1", "2", "3"})

        if pilihan == "1":
            run_process("encrypt")
        elif pilihan == "2":
            run_process("decrypt")
        elif pilihan == "3":
            show_info()
        else:
            print(f"\nTerima kasih telah memakai {__app_name__} - {__author__}.")
            break


if __name__ == "__main__":
    try:
        main()
    except (KeyboardInterrupt, EOFError):
        print(f"\n\nProgram dihentikan. Sampai jumpa! - {__author__}")