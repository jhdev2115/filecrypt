# **FileCrypt – Secure File & Folder Encryption Tool**

FileCrypt is a modern Python-based command-line encryption utility designed for **high-security file protection**, **fast performance**, and **simple real-world usability**. It uses **AES-256-GCM**, one of the strongest authenticated encryption standards, combined with secure shredding, metadata cleaning, QR-code key storage, and multi-threaded processing.

FileCrypt is ideal for anyone who wants secure, privacy-focused encryption with a clean and intuitive workflow.

---

## 🚀 **Features Overview**

### 🔐 Strong Encryption

- AES-256-GCM (authenticated encryption)
- Unique key for every encrypted file
- Automatic extension restoration during decryption

### 🧹 Metadata & Privacy Protection

- File timestamps and permissions cleaned
- Original files securely shredded after successful encryption

### 📁 Folder Encryption with Master Key

- Entire folder encrypted using **one master key**
- Only **one QR code** required per folder
- Multi-threading for high performance

### 📄 Single-File Encryption Mode

- Each file gets its own cryptographic key and QR code
- Automatically deletes the original file after encryption

### 🚀 Multi-Threaded Decryption

- Fast, parallel file restoration when decrypting folders

### 📊 Progress Bars

- Clean and informative `rich`-powered progress indicators

### 🗑 Secure Shredding

- Files overwritten with random data multiple times before deletion

---

## 📦 **Installation**

Make sure you have Python 3.8+ installed.

Install dependencies:

```bash
pip install cryptography qrcode[pil] rich
```

Clone or download FileCrypt, then run:

```bash
python main.py --help
```

---

## 🔧 **Command Usage**

### **1. Encrypt a single file**

```bash
python main.py encrypt <filepath> -o <output_folder>
```

Example:

```bash
python main.py encrypt secret.pdf -o encrypted/
```

Output:

- `*.vault` encrypted file
- `*.vault_key.png` QR code containing the AES key
- Original file securely shredded

---

### **2. Encrypt an entire folder (master key)**

```bash
python main.py encrypt-folder <folder> -o <output_folder>
```

Example:

```bash
python main.py encrypt-folder Documents -o encrypted/
```

Output:

- All files encrypted with **one master key**
- Folder `*_masterkey.png` generated containing QR code
- Original folder securely shredded

---

### **3. Decrypt a single encrypted file**

```bash
python main.py decrypt <vault_file> <key> -o <output_folder>
```

Example:

```bash
python main.py decrypt encrypted/93ab4f.vault 1f8c9d... -o decrypted/
```

Automatically restores original file extension.

---

### **4. Decrypt an entire folder (master key)**

```bash
python main.py decrypt-folder <folder> <master_key> -o <output_folder>
```

Example:

```bash
python main.py decrypt-folder encrypted/ 1f8c9d... -o original/
```

Multi-threaded for maximum speed.

---

### **5. Securely shred a file or folder**

```bash
python main.py shred <path>
```

Example:

```bash
python main.py shred old_secrets/
```

Overwrites data before removal.

---

## ⚠️ **Security Notes**

- **Losing your key means losing your data.**  
  There is no recovery mechanism.
- QR codes should be stored offline or securely.
- Decryption requires the exact key used during encryption.
- Shredding is irreversible—verify outputs before relying on it.

---

## 🛠 **Project Structure**

```
main.py          <- main CLI application
README.md        <- documentation
LICENSE          <- the license that you agree to upon using the program
```

---

## 📄 **License**

See LICENSE.

---

## ❤️ **Contributions**

Feel free to request new features, improvements, or optimizations!

---
