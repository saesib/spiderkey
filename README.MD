# 🕷️ SpiderKey

**SpiderKey** is a personal, source-available encryption system that allows you to generate your own standalone, password-protected **key program** — known as a *SpiderKey*. This key program can encrypt and decrypt entire directories with powerful AES-256 encryption, and is bound to your chosen password. 

Once created, a SpiderKey acts as your personal encryption agent — and losing it (or the password) means permanent data loss by design.

---

## 🔐 What is SpiderKey?

SpiderKey consists of two parts:

- **SpiderKey Generator** – A CLI tool that generates custom SpiderKey programs.
- **SpiderKey (Key Program)** – A self-contained, password-locked executable capable of encrypting and decrypting directories.

SpiderKey supports **seed-based generation**: enter the same seed and password, and you'll generate the exact same SpiderKey program — enabling you to recover your SpiderKey if lost. This works because the seed and password is used to deterministically generate the AES encryption key.

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
$ spiderkey generate --name mykey --password "MySecurePassword123"
```

### 2. Generate with a Seed (for recoverable SpiderKeys)
```bash
$ spiderkey generate --name mykey --password "MySecurePassword123" --seed "music tennis mixture river"
```

Using a seed allows you to regenerate the exact same SpiderKey program if you lose it. The seed is used to deterministically generate the AES encryption key, ensuring that the same seed and password will always produce the same SpiderKey.

### 3. Using Your SpiderKey

Once generated, your SpiderKey program provides an interactive CLI with the following commands:

```
Available commands:
  e <folder>            Encrypt a folder
  d <file.spdr>         Decrypt an encrypted file
  shred <file|folder>   Securely delete a file or folder
  help                  Show this help message
  quit / q / exit       Exit the program
```

#### Encrypting a Directory
1. Run your SpiderKey program
2. Type `e <folder>` to encrypt a directory
3. Enter your password when prompted
4. Choose an output name (or use random)
5. Choose a save location
6. Optionally shred the original files after encryption

#### Decrypting a File
1. Run your SpiderKey program
2. Type `d <file.spdr>` to decrypt an encrypted file
3. Enter your password when prompted
4. Files will be extracted to the same directory as the encrypted file
5. Optionally shred the encrypted file after decryption

#### Secure File Deletion
Use the `shred` command to securely delete files or directories:
```bash
shred <file>     # Securely delete a file
shred <folder>   # Securely delete a directory and all contents
```

---

## 🔧 How It Works (Technical Overview)

### Key Generation
- A **random 256-bit AES key** is generated to encrypt user data
- The user password is passed through **Argon2** (a secure, slow key derivation function)
- The AES key is encrypted using the password-derived key and embedded in the SpiderKey binary
- If a seed is used, the generator deterministically derives the AES key using the seed, ensuring the same seed and password will always generate the same SpiderKey

### Encryption Process
1. Directory contents are compressed into a ZIP archive
2. The archive is encrypted in 64MB chunks using AES-GCM
3. Each chunk is encrypted with a unique nonce
4. The encrypted file format includes:
   - 8-byte magic header (`SPDRCHNK`)
   - 4-byte chunk length
   - 12-byte nonce
   - Encrypted chunk data

### Decryption Process
1. User provides password
2. Password is used to derive the key using Argon2
3. The derived key decrypts the embedded AES key
4. The AES key decrypts each chunk of the file
5. The decrypted ZIP is extracted to the target directory

### Security Features
- **AES-256-GCM** for authenticated encryption
- **Argon2** for key derivation (memory-hard, resistant to GPU attacks)
- **Secure file shredding** with multiple overwrite passes
- **No key storage** - keys are derived from password on demand
- **Chunked encryption** for handling large files efficiently

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