Heri Cipher Tool adalah aplikasi Command Line Interface (CLI) berkinerja tinggi untuk enkripsi dan dekripsi teks berbasis Python. Aplikasi ini dirancang secara modular dan efisien dengan mengintegrasikan algoritma kriptografi klasik hingga standar enkripsi modern berkelas industri.

Informasi Proyek
Author: Heri Herlambang

Versi: 1.0.0

Bahasa Pemrograman: Python 3.8+

Lisensi: MIT License

Fitur Utama
Multi-Algorithm Support:

Caesar Cipher: Algoritma pergeseran substitusi klasik untuk analisis kriptografi dasar.

Heri Cipher (Substitution-XOR): Algoritma kustom berbasis permutasi S-Box dan keystream chaining yang mengintegrasikan entropi kunci berbasis nama Heri Herlambang.

AES-256-GCM: Enkripsi simetris standar modern dengan Authenticated Encryption with Associated Data (AEAD) serta pembentukan kunci menggunakan algoritma Scrypt.

Output Handling & Otomatisasi:

Fitur penyalinan hasil ke papan klip (clipboard) secara langsung.

Fitur ekspor hasil enkripsi atau dekripsi ke dalam berkas teks (.txt).

Masking & Keamanan Interaktif:

Penyembunyian entri sandi (passphrase input masking) pada terminal menggunakan modul getpass.

Arsitektur Modular:

Penanganan dependensi yang terisolasi sehingga fungsi dasar tetap berjalan tanpa ketergantungan wajib pada pustaka eksternal.

Persyaratan Sistem
Python: Versi 3.8 atau lebih baru.

Pustaka Eksternal (Opsional untuk fitur AES-256 dan Clipboard):

cryptography

pyperclip

Instalasi
1. Kloning Repositori
Bash
git clone https://github.com/username-kamu/heri-cipher-tool.git
cd heri-cipher-tool
2. Instalasi Dependensi
Jalankan perintah berikut untuk menginstal pustaka pendukung:

Bash
pip install cryptography pyperclip
Penggunaan
Jalankan berkas utama melalui terminal atau command line:

Bash
python heri_cipher.py
Struktur Menu Interaktif
Plaintext
========================================================
                   HERI CIPHER TOOL                     
               Enkripsi & Dekripsi Teks                 
========================================================
                  Author  : Heri Herlambang             
                  Versi   : 1.0.0                       
========================================================

MENU UTAMA
  1. Enkripsi teks
  2. Dekripsi teks
  3. Tentang program
  0. Keluar
