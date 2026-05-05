# Laporan Draft Tugas 3 II4021 Kriptografi

> Ganti bagian identitas, foto, tanda tangan, pranala repo, dan pranala video sebelum dikonversi menjadi PDF dengan nama `NIM1_NIM2_NIM3_Tugas3_II4021.pdf`.

## Identitas Kelompok

- Nama/NIM 1:
- Nama/NIM 2:
- Nama/NIM 3:

## Pernyataan

Kami menyatakan bahwa kode program yang dihasilkan bukan merupakan hasil salinan mentah (raw output) dari Generative AI, melainkan hasil pengembangan dan penulisan mandiri.

[Tanda tangan Mahasiswa 1] [Tanda tangan Mahasiswa 2] [Tanda tangan Mahasiswa 3]

[Nama Mahasiswa 1] [Nama Mahasiswa 2] [Nama Mahasiswa 3]

## Teori Singkat

JSON Web Token (JWT) adalah token berbasis JSON yang memuat klaim dan dapat ditandatangani sebagai JWS. Pada aplikasi ini JWT digunakan sebagai bukti autentikasi setelah login. Algoritma yang didukung oleh library adalah ES256, ES384, dan ES512, yaitu ECDSA dengan SHA-256, SHA-384, dan SHA-512.

Elliptic Curve Diffie-Hellman (ECDH) digunakan untuk membentuk shared secret antara dua pengguna. Masing-masing pengguna menyimpan private key sendiri dan mengambil public key lawan dari server. Shared secret yang sama kemudian diproses menggunakan HKDF agar menjadi material kunci yang cocok untuk enkripsi dan MAC.

AES-256-GCM digunakan untuk mengenkripsi pesan. Mode GCM dipilih karena menyediakan enkripsi berbasis nonce/IV dan deteksi perubahan ciphertext saat dekripsi. Selain itu, aplikasi juga menghitung HMAC-SHA-256 atas metadata pesan dan ciphertext untuk memenuhi bonus integritas dan autentikasi pesan.

## Perancangan dan Implementasi

### Server

Implementasi server terdapat pada `server.js`. Server menggunakan modul `http` bawaan Node.js, menyajikan file statis dari folder `public/`, dan menyediakan API:

- `POST /api/register`
- `POST /api/login`
- `GET /api/me`
- `GET /api/contacts`
- `GET /api/messages?with=email`
- `POST /api/messages`

Data disimpan pada `data/db.json`. Password tidak disimpan sebagai plainteks, tetapi diproses dengan `crypto.scryptSync` dan salt unik. Key pair ECDSA untuk JWT server disimpan di `data/jwt-private.pem` dan `data/jwt-public.pem`.

### Library JWT

Library JWT terdapat pada `src/jwt.js`. Fungsi `sign` menerima header, claims, payload, dan private key PEM, lalu menghasilkan token JWS compact serialization. Fungsi `verify` menerima JWT, public key PEM, dan opsi validasi. Validasi mencakup format token, algoritma yang diizinkan, signature, `exp`, `nbf`, `iss`, `sub`, `aud`, dan `jti`.

### Client dan Web Crypto

Implementasi client terdapat pada `public/app.js`, `public/index.html`, dan `public/styles.css`. Seluruh operasi ECDH, HKDF, AES, PBKDF2, dan HMAC dilakukan di browser menggunakan Web Crypto API.

Saat registrasi, browser membuat key pair ECDH P-256. Private key diekspor sebagai PKCS#8, lalu dienkripsi dengan AES-256-GCM. Kunci AES untuk private key diturunkan dari password menggunakan PBKDF2 SHA-256 dengan salt unik. Server menyimpan public key dan private key terenkripsi.

Saat login, server memverifikasi password dan menerbitkan JWT. Browser menerima private key terenkripsi, menurunkan ulang kunci dari password, lalu memulihkan private key ECDH. Private key berada di memori browser dan tidak pernah dikirim ulang sebagai plainteks.

Saat pengguna memilih kontak, browser mengambil public key kontak dari server, menghitung shared secret dengan ECDH, lalu menggunakan HKDF SHA-256 untuk menurunkan dua kunci: kunci AES-256-GCM untuk enkripsi pesan dan kunci HMAC-SHA-256 untuk MAC.

### Docker

Konfigurasi Docker terdapat pada `Dockerfile` dan `docker-compose.yml`. Service menjalankan aplikasi Node.js pada port 3000 dan menggunakan volume `kripto-chat-data` untuk menyimpan folder `data/`.

## Pengujian

### Autentikasi dan Manajemen Pengguna

1. Registrasi valid: akun baru berhasil dibuat dan muncul di `data/db.json` dengan password hash, salt, public key, dan private key terenkripsi.
2. Registrasi email duplikat: server mengembalikan status `409`.
3. Login password benar: server mengembalikan JWT dan data private key terenkripsi.
4. Login password salah: server mengembalikan status `401`.

### JWT

Unit test berada pada `test/jwt.test.js` dan dijalankan dengan:

```bash
npm test
```

Kasus yang diuji mencakup happy path ES256, ES384, ES512, override claims terhadap payload, header invalid, algoritma tidak didukung, private key hilang, payload/claims tidak valid, format token invalid, payload termodifikasi, public key salah, algoritma tidak diizinkan, token expired, token `nbf` belum aktif, dan mismatch klaim.

### ECDH dan KDF

Pengujian manual dilakukan dengan membuat dua akun, login sebagai salah satu akun, memilih kontak akun lain, dan memastikan status antarmuka menampilkan bahwa kunci komunikasi siap. Karena ECDH menghasilkan shared secret yang sama pada kedua sisi, pesan yang dikirim akun pertama dapat didekripsi akun kedua setelah login.

### Enkripsi dan Dekripsi Pesan

Pesan dikirim dari browser sebagai ciphertext, IV, MAC, timestamp, dan metadata email. Server tidak menerima plainteks. Saat penerima membuka percakapan, browser memverifikasi MAC dan mendekripsi pesan. Jika MAC atau ciphertext diubah pada `data/db.json`, antarmuka menampilkan `[MAC tidak valid]` atau `[Pesan tidak dapat didekripsi]`.

### Bonus MAC

MAC dihitung menggunakan HMAC-SHA-256 pada gabungan `senderEmail`, `receiverEmail`, `iv`, `ciphertext`, dan `timestamp`. Verifikasi dilakukan sebelum dekripsi. Jika MAC tidak cocok, pesan ditandai invalid dan tidak didekripsi.

## Kesimpulan

Aplikasi berhasil mengintegrasikan autentikasi JWT ECDSA, pembentukan kunci ECDH, derivasi HKDF, enkripsi AES-256-GCM, dan MAC HMAC-SHA-256 dalam alur chat web. Server berperan sebagai penyimpan akun dan relay pesan terenkripsi tanpa mengetahui plainteks pesan.

## Daftar Pustaka

- RFC 7519: JSON Web Token (JWT)
- MDN Web Docs: Web Crypto API
- Node.js Documentation: Crypto

## Lampiran

- Pranala repositori:
- Pranala video demo:
- Pembagian tugas:
