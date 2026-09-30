# -*- coding: utf-8 -*-
"""
caesar_cipher.py - Caesar Cipher (klasik).

Author : Heri Herlambang
Catatan: hanya untuk belajar, TIDAK aman untuk data rahasia.
"""

from cipher_base import BaseCipher, CipherError
from metadata import AUTHOR

__author__ = AUTHOR


class CaesarCipher(BaseCipher):
    """Caesar Cipher: menggeser setiap huruf sejauh N posisi alfabet."""

    name = "Caesar Cipher"
    key_prompt = "Masukkan kunci geser (angka bulat, contoh: 3)"

    @staticmethod
    def _parse_key(key: str) -> int:
        """Validasi kunci: harus berupa bilangan bulat."""
        try:
            return int(key.strip())
        except ValueError:
            raise CipherError("Kunci Caesar harus berupa angka bulat.")

    @staticmethod
    def _shift(text: str, shift: int) -> str:
        """Geser huruf a-z / A-Z; karakter lain dibiarkan apa adanya."""
        hasil = []
        for ch in text:
            if "a" <= ch <= "z":
                hasil.append(chr((ord(ch) - ord("a") + shift) % 26 + ord("a")))
            elif "A" <= ch <= "Z":
                hasil.append(chr((ord(ch) - ord("A") + shift) % 26 + ord("A")))
            else:
                hasil.append(ch)  # angka, spasi, simbol tidak diubah
        return "".join(hasil)

    def encrypt(self, plaintext: str, key: str) -> str:
        return self._shift(plaintext, self._parse_key(key))

    def decrypt(self, ciphertext: str, key: str) -> str:
        # Dekripsi = geser ke arah sebaliknya
        return self._shift(ciphertext, -self._parse_key(key))
