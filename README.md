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


