# -*- coding: utf-8 -*-
"""
aes256_cipher.py - AES-256-GCM memakai pustaka `cryptography`.

Author : Heri Herlambang

- Kunci 256-bit diturunkan dari password lewat Scrypt (tahan brute-force)
  dengan salt acak.
- GCM memberi kerahasiaan sekaligus autentikasi (deteksi data diubah).
- Format keluaran: Base64( salt[16] + nonce[12] + ciphertext+tag ).

Dependensi: pip install cryptography
"""

import base64
import binascii
import os

from cipher_base import BaseCipher, CipherError
from metadata import AUTHOR

__author__ = AUTHOR

# Impor bersifat opsional agar program lain tetap jalan bila pustaka belum ada
try:
    from cryptography.exceptions import InvalidTag
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

    CRYPTO_AVAILABLE = True
except ImportError:  # pragma: no cover
    CRYPTO_AVAILABLE = False


class AES256Cipher(BaseCipher):
    """Enkripsi modern AES-256 mode GCM."""

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
        """Turunkan kunci 32 byte (=256 bit) dari password memakai Scrypt."""
        kdf = Scrypt(salt=salt, length=32, n=2**15, r=8, p=1)
        return kdf.derive(password.encode("utf-8"))

    def encrypt(self, plaintext: str, key: str) -> str:
        self._require_crypto()
        if not key:
            raise CipherError("Password AES tidak boleh kosong.")

        salt = os.urandom(self._SALT_LEN)    # salt acak baru tiap enkripsi
        nonce = os.urandom(self._NONCE_LEN)  # nonce acak, tidak boleh dipakai ulang
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

        # Pisahkan kembali komponen: salt | nonce | ciphertext+tag
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
