# 🕷️ SpiderKey

**SpiderKey** is a personal, source-available encryption system that allows you to generate your own standalone, password-protected **key program** — known as a *SpiderKey*. This key program can encrypt and decrypt entire directories with powerful AES-256 encryption, and is bound to your chosen password. 

Once created, a SpiderKey acts as your personal encryption agent — and losing it (or the password) means permanent data loss by design.

---

## 🔐 What is SpiderKey?

SpiderKey consists of two parts:

- **SpiderKey Generator** – A CLI tool that generates custom SpiderKey programs.
- **SpiderKey (Key Program)** – A self-contained, password-locked executable capable of encrypting and decrypting directories.

SpiderKey supports optional **seed-based generation**: enter the same seed and password, and you'll generate the exact same SpiderKey program — enabling advanced users to recover lost key programs deterministically.

---

## ⚠️ IMPORTANT: Read This First

SpiderKey is built around the principle of **zero trust** and **irrecoverable encryption**.  
That means:

- If you **lose your SpiderKey** or **forget the password**, your data is **gone forever**.
- There is **no cloud**, **no backup**, and **no recovery mechanism**.
- You **must protect your SpiderKey binary and your password** with the same care you protect your encrypted files.

---

## 🚀 Usage

### 1. Generate a SpiderKey Program (Random Mode - Recommended)
```bash
$ spiderkey generate --name mykey --password "MyStrongPassword123"
```

### 2. Optional: Generate with a Seed (for recoverable SpiderKeys)
```bash
$ spiderkey generate --name mykey --password "MyStrongPassword123" --seed "correct horse battery staple"
```

### 3. Encrypt a Directory
```bash
$ ./mykey encrypt --input /path/to/folder --output /path/to/encrypted.spider
```

### 4. Decrypt a File
```bash
$ ./mykey decrypt --input /path/to/encrypted.spider --output /path/to/decrypted_folder
```

### 5. Relocate the SpiderKey (Coming Soon)
```bash
$ ./mykey relocate --to /mnt/usb
```

---

## 🔧 How It Works (Technical Overview)

- A **random 256-bit AES key** is generated to encrypt user data.
- The user password is passed through **Argon2** (a secure, slow key derivation function).
- The AES key is then **encrypted using the password-derived key** and embedded inside the SpiderKey binary.
- On decrypt, the user provides their password → the program derives the key → decrypts the embedded AES key → decrypts the data.

If a **seed** is used, the generator deterministically derives the salt and configuration using `SHA-256(seed)` + password.

---

## 🧪 Planned Features

- [ ] GUI support (desktop app version)
- [ ] Optional file shredding: auto-destroy plaintext files after decryption
- [ ] SpiderKey relocation with automatic secure deletion of previous copies

---

## 🛡 License

**SpiderKey** is a **source-available** project.  
You are allowed to read and use the source code for **personal, non-commercial use only**.

You may **not** copy, modify, redistribute, fork, or reuse any part of this software or its source code in your own projects.

See [LICENSE.txt](./LICENSE.txt) for the full legal terms.

---

## 📩 Contact

For commercial licensing or permission requests, contact:  
`[saeberg01@gmail.com]`  
Copyright © 2025 saesib