# ALVSIA release signing

## Files
- `alvsia-release.keystore` (PKCS12) — pakai ini
- `alvsia-release.jks` — backup
- Password: lihat file **`STORE_PASSWORD.txt`** (folder ALVISIA_KEYSTORE / lampiran zip keystore)
  - Jangan commit password ke chat publik / channel member
  - Backup USB + offline

## Alias
`alvsia`

## CERT_SHA256 (sudah di build.gradle.kts)
`99b33815c88a17abbcfe22be15250363f6dfc79c11ffc980e71b62b74b1f295c`

## Sign
```bash
apksigner sign \
  --ks alvsia-release.keystore \
  --ks-key-alias alvsia \
  --ks-pass pass:ISI_PASSWORD_DARI_STORE_PASSWORD_TXT \
  --key-pass pass:ISI_PASSWORD_DARI_STORE_PASSWORD_TXT \
  --out ALVSIA_PREMIUM_TOOL_4.6_signed.apk \
  app-aligned.apk
```

Key size: RSA **4096**. Validity ~25 tahun.
