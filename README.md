# Kripto Chat

Kripto Chat adalah aplikasi chat web untuk Tugas 3 II4021 Kriptografi. Aplikasi ini mendukung registrasi, login dengan JWT bertanda tangan ECDSA, daftar kontak, pembentukan kunci ECDH, derivasi HKDF, enkripsi pesan AES-256-GCM, dan MAC HMAC-SHA-256 untuk integritas pesan.

## Tech Stack

- Server: Node.js native HTTP server.
- Client: HTML, CSS, JavaScript, Web Crypto API.
- Storage: berkas JSON lokal di `data/db.json`.
- JWT: library custom di `src/jwt.js` dengan ES256, ES384, dan ES512.
- Test: `node:test` bawaan Node.js.
- Docker: `Dockerfile` dan `docker-compose.yml`.

## Dependensi

Tidak ada package eksternal. Gunakan Node.js 20+ atau 22+ agar Web Crypto browser modern dan `node:test` tersedia.

## Cara Menjalankan

```bash
npm start
```

Buka `http://localhost:3000`.

Untuk menjalankan test JWT:

```bash
npm test
```

Untuk menjalankan dengan Docker:

```bash
docker compose up --build
```

## Alur Penggunaan

1. Register minimal dua akun dengan email dan password berbeda.
2. Login sebagai akun pertama.
3. Pilih kontak akun kedua.
4. Kirim pesan. Pesan dienkripsi di browser sebelum dikirim ke server.
5. Logout, login sebagai akun kedua, lalu buka kontak akun pertama untuk membaca pesan.

## Environment

- `PORT`: port server, default `3000`.
- `HOST`: host bind server, default `127.0.0.1`. Untuk Docker gunakan `0.0.0.0`.
- Data pengguna, pesan, dan key JWT server tersimpan di folder `data/`.

## Catatan Kriptografi

- Private key ECDH dibuat di browser saat registrasi, diekspor sebagai PKCS#8, lalu dienkripsi dengan AES-256-GCM. Kunci AES untuk private key diturunkan dari password menggunakan PBKDF2 SHA-256 dengan salt unik.
- Password untuk autentikasi server tidak disimpan sebagai plainteks. Server menyimpan hash `scrypt` dan salt unik.
- Shared secret ECDH dihitung di browser menggunakan kurva P-256. Hasilnya diproses dengan HKDF SHA-256 untuk menghasilkan kunci AES-256-GCM dan kunci HMAC-SHA-256 per pasangan pengguna.
- Server hanya menyimpan dan meneruskan ciphertext, IV, MAC, timestamp, dan metadata pengirim/penerima.
- JWT diimplementasikan sebagai JWS compact serialization: `base64url(header).base64url(payload).base64url(signature)`.
