# Setup CodeMagic — ALVSIA PRO 5.5.1-hardened

Workflow: `alvisia-android` (`ALVSIA PRO 5.5.1-hardened`)  
Branch rilis: `main`  
Package: `com.alvsia.pro`

## 1. Hubungkan repositori

1. Masuk ke Codemagic dan tambahkan repositori GitHub `ALVISIA8/alvsia-pro-550`.
2. Pastikan Codemagic menggunakan konfigurasi `codemagic.yaml` dari branch `main`.
3. Tambahkan environment variable group bernama persis `signing`.

## 2. Tambahkan signing secrets

Masukkan variable berikut ke group `signing` dan tandai sebagai secret:

- `CM_KEYSTORE`: isi Base64 dari file keystore rilis.
- `CM_KEYSTORE_PASSWORD`: password keystore.
- `CM_KEY_ALIAS`: `alvsia`
- `CM_KEY_PASSWORD`: password private key; jika sama dengan password keystore, gunakan nilai yang sama.

Jangan commit file keystore, password, atau hasil Base64 ke GitHub.

### Membuat nilai CM_KEYSTORE dari Termux

Pastikan file yang digunakan adalah keystore rilis yang sertifikatnya cocok dengan pin aplikasi. Contoh jika file berada di lokasi yang telah dipakai proyek:

```bash
base64 -w 0 "$HOME/ALVISIA_KEYSTORE/alvsia-release.jks"
```

Salin seluruh output sebagai nilai `CM_KEYSTORE` di Codemagic. Jangan mengirim output atau password ke chat. Jika keystore rilis berada di lokasi lain, ganti path dengan path file yang benar.

Sertifikat yang diharapkan oleh source aplikasi memiliki SHA-256:

`99b33815c88a17abbcfe22be15250363f6dfc79c11ffc980e71b62b74b1f295c`

Keystore dengan sertifikat berbeda akan ditolak oleh tahap verifikasi.

## 3. Jalankan build

Setelah repositori terhubung dan keempat variable disetel, jalankan workflow `alvisia-android` pada branch `main`, atau push commit ke `main` jika pemicu otomatis aktif. Workflow rilis hanya dipicu oleh push ke `main`; pull request tidak menjalankan workflow rilis.

Build akan memvalidasi signing secrets lebih awal, menjalankan pemeriksaan keamanan, menyegel aset, membangun APK release, menandatangani APK, lalu memverifikasi signature dan certificate pin. APK bertanda tangan yang diharapkan bernama:

`ALVISIA_PRO_5.5.1-hardened_signed.apk`

Unduh APK dari bagian artifacts pada build Codemagic yang berhasil.

## Troubleshooting

- `Missing CM_KEYSTORE` / `Missing CM_KEYSTORE_PASSWORD`: periksa nama variable dan pastikan group bernama `signing` terpasang pada workflow.
- `CM_KEYSTORE is not valid base64`: buat ulang Base64 dari file keystore yang benar dan salin output lengkap.
- `certificate does not match`: keystore bukan keystore rilis yang sertifikatnya dipin oleh source. Jangan menghapus atau mengganti pin hanya untuk melewati verifikasi.
- Build sukses belum membuktikan APK berjalan normal di perangkat; uji instalasi dan login setelah APK terverifikasi.
