# CodeShield: Secure Code Integrity Verification System

[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/downloads/)
[![Flask](https://img.shields.io/badge/framework-Flask-lightgrey.svg)](https://flask.palletsprojects.com/)
[![Cryptography](https://img.shields.io/badge/security-cryptography%20(OpenSSL)-success.svg)](https://cryptography.io/)
[![Tests](https://img.shields.io/badge/tests-11%20passed-brightgreen.svg)](tests/test_crypto.py)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

> A modern, lightweight cryptographic web application demonstrating software integrity validation, digital signature generation, and tamper detection using **RSA-2048 (RSA-PSS with MGF1/SHA-256)** and **SHA-256 streaming hashing**.

---

## 1. Overview & Objectives

In modern software deployment and CI/CD pipelines, malicious actors can intercept executables, scripts, or package distributions to inject unauthorized payloads (supply-chain attacks).

**CodeShield** provides a transparent, zero-database demonstration of how public-key cryptography safeguards code distribution:

1. **Integrity:** Verifying that software bytes have not been modified, corrupted, or injected in transit.
2. **Authenticity & Non-Repudiation:** Mathematically proving that code originated from the legitimate private key holder.
3. **Tamper Detection:** Demonstrating the **SHA-256 Avalanche Effect**, where even a single altered byte or whitespace causes immediate signature verification failure.

---

## 2. Technology Stack

| Layer | Technology | Purpose |
| :--- | :--- | :--- |
| **Backend** | Python 3 (Flask) | Lightweight, unbloated micro-framework |
| **Cryptography** | `cryptography` library | OpenSSL-backed RSA-2048 key generation & RSA-PSS signing |
| **Hashing** | `hashlib` | SHA-256 streaming chunk digest calculation |
| **Visualization** | `matplotlib` | High-contrast hardware latency comparison charts |
| **Frontend** | HTML5, Bootstrap 5, CSS3, JS | Responsive dark-navy UI with high-contrast elements |

> **Architectural Principle:** Zero external database dependencies, zero tracking, zero cloud services. All cryptographic operations execute 100% locally in memory.

---

## 3. Cryptographic Foundation

```
[ Developer ]
   File --------> SHA-256 Digest --------> RSA-PSS Signing --------> .sig Signature
                                                  ▲
                                         [ RSA Private Key ]

[ Verifier ]
   File --------> SHA-256 Digest ──────┐
                                       ▼
   .sig Signature ────────────────> RSA-PSS Verification ────> VALID (Untampered)
                                       ▲                       INVALID (Modified / Wrong Key)
                               [ RSA Public Key ]
```

### SHA-256 Hashing
- Computes a fixed **256-bit (32-byte)** cryptographic fingerprint of the input file.
- **Streaming Implementation:** Read in 64 KB memory chunks (`calculate_sha256_stream`) to efficiently support large files without memory exhaustion.
- **Avalanche Effect:** A 1-bit difference in source code produces a completely uncorrelated hash output.

### RSA-PSS Digital Signatures
- **Key Pair:** Generates an asymmetric RSA 2048-bit key pair (Private Key $d$, Public Key $e = 65537, n$).
- **Key Encryption:** Private keys can be password-protected using AES-256 (`PKCS#8` with `BestAvailableEncryption`).
- **Probabilistic Signature Scheme (PSS):** Implements modern RSA-PSS padding with MGF1 and SHA-256 salt (`utils.Prehashed(hashes.SHA256())`), providing provable cryptographic security superior to legacy PKCS#1 v1.5.

---

## 4. Project Structure

```text
CodeShield/
├── app.py                  # Flask application server and REST endpoints
├── crypto_utils.py         # Core cryptographic functions (RSA-PSS, SHA-256)
├── requirements.txt        # Production dependencies
├── .gitignore              # Git ignore rules for Python, caches & OS files
├── README.md               # Project documentation
├── templates/              # Jinja2 HTML templates
│   ├── base.html           # Layout, navigation bar, and dark navy theme
│   ├── index.html          # Home landing page and architecture overview
│   ├── sign.html           # Module 1: RSA Key Generation & File Signing
│   ├── verify.html         # Module 2: File Verification & Integrity Checks
│   ├── security.html       # Module 3: Interactive Code Tampering & Attack Tests
│   └── performance.html    # Module 4: Latency & Startup Overhead Benchmark
├── static/
│   ├── style.css           # High-contrast CSS theme and responsive rules
│   └── script.js           # Client-side form handlers and dynamic interactions
├── sample/
│   └── demo.py             # Predefined, safe demonstration script
└── tests/
    └── test_crypto.py      # Automated unit and integration test suite
```

---

## 5. Installation & Quick Start

### 1. Clone the Repository
```bash
git clone https://github.com/aryanshakya1/CodeShield.git
cd CodeShield
```

### 2. Set Up a Virtual Environment (Recommended)
```bash
# Windows
python -m venv venv
venv\Scripts\activate

# macOS / Linux
python3 -m venv venv
source venv/bin/activate
```

### 3. Install Dependencies
```bash
pip install -r requirements.txt
```

### 4. Run the Application
```bash
python app.py
```

Open your browser and navigate to:
```
http://127.0.0.1:5000
```

---

## 6. Module Walkthrough & Features

### Module 1: Key Generation & File Signing (`/sign`)
1. Click **"Generate RSA Keys"** (with optional private key password protection).
2. Download the generated `private_key.pem` and `public_key.pem`.
3. Select any target file (`.py`, `.txt`, `.exe`, `.zip`) or use the bundled sample script (`demo.py`).
4. Select the private key, provide the password, and click **"Sign File"**.
5. Inspect the file's SHA-256 digest, execution latency, and download the resulting `.sig` signature file.

### Module 2: Signature Verification (`/verify`)
1. Upload the target file alongside its `.sig` signature and the signer's `public_key.pem`.
2. Click **"Verify Signature"**.
3. The system checks the file's SHA-256 hash against the decrypted signature:
   - **Valid:** Displays a green confirmation banner (*"Signature Valid — File Integrity Verified"*).
   - **Invalid:** Displays a red warning banner (*"Signature Invalid — File May Have Been Modified"*).

### Module 3: Interactive Security Testing (`/security`)
1. **Automated Security Summary Table:**
   - Evaluates three baseline cryptographic scenarios:
     | Scenario | Expected Result | Reason |
     | :--- | :---: | :--- |
     | **Original file with matching Public Key** | **Valid** | Hashes and mathematical proof match |
     | **Modified file with original Signature** | **Invalid** | Tampered bytes alter the digest |
     | **Original file with Wrong Public Key** | **Invalid** | Signature mathematically bound to original key |
2. **Interactive Live Tampering Playground:**
   - Edit the code directly in the **"Modified / Tampered Code"** box.
   - Click **"Verify Integrity of Modified Code"** to watch the backend hash your custom edits and show real-time verification rejection.
3. **Wrong Public Key Demonstration:**
   - Proves non-repudiation by attempting verification of Alice's signed file using an attacker's public key.

### Module 4: Performance Analysis (`/performance`)
1. Measures real execution latency using Python's high-resolution timer (`time.perf_counter()`):
   - RSA-2048 Key Generation (ms)
   - SHA-256 Hashing (ms)
   - RSA-PSS Signing (ms)
   - RSA-PSS Verification (ms)
2. Displays a dynamically rendered **Matplotlib bar graph**.
3. **Startup Overhead Benchmark:** Runs a predefined safe program (`sample/demo.py`) 5 times directly vs. 5 times with pre-launch signature verification, calculating average additional overhead.

---

## 7. Security Architecture & Guarantees

- **Zero Arbitrary Execution:** User-uploaded files are **never** executed. Only the predefined safe script (`sample/demo.py`) is run during the startup benchmark, and only after successful cryptographic verification.
- **Safe Subprocess Handling:** All subprocess invocations use strict argument lists with `shell=False`.
- **In-Memory Credential Handling:** Private keys and passwords are processed strictly in volatile memory and immediately discarded. Never written to disk or logged.
- **Integrity vs. Antivirus:** CodeShield detects tampering because file bytes changed, not because it performs heuristics or antivirus scanning.
- **Public Key Trust Model:** A valid signature proves integrity relative to the supplied public key. The verifier must obtain the public key through a trusted channel.

---

## 8. Running Automated Tests

A comprehensive test suite of 11 unit and integration tests covers key generation, PKCS#8 decryption, stream hashing, PSS signing, tamper detection, and Flask endpoints:

```bash
python -m unittest tests/test_crypto.py
```

Expected output:
```text
...........
----------------------------------------------------------------------
Ran 11 tests in ~1.5s

OK
```

---

## 9. License

This project is licensed under the **MIT License** — see the [LICENSE](LICENSE) file for details.
