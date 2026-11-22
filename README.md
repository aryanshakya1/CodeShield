# CodeShield — Secure Code Integrity Verification using Digital Signatures

> **Applied Cryptography Lab Project**  
> A simple, clean, and interactive web application demonstrating software integrity verification and non-repudiation through public-key digital signatures.

---

## 1. Project Objective

In modern software deployment, malicious actors can intercept executables, scripts, or package distributions to inject malicious payload (supply-chain attacks).

**CodeShield** demonstrates how cryptographic digital signatures provide:

1. **Integrity:** Assuring that code has not been modified or corrupted since it was signed.
2. **Authenticity & Non-Repudiation:** Assuring that the code was created by the holder of the specific private key.
3. **Detection of Unauthorized Changes:** Detecting even a single bit or whitespace alteration via the SHA-256 Avalanche Effect.

---

## 2. Tools & Technology Stack

| Component         | Technology                   | Description                                          |
| :---------------- | :--------------------------- | :--------------------------------------------------- |
| **Backend**       | Python 3                     | Core language                                        |
| **Web Framework** | Flask                        | Lightweight, unbloated micro-framework               |
| **Cryptography**  | `cryptography` library       | OpenSSL-backed RSA-2048, RSA-PSS (MGF1 with SHA-256) |
| **Hashing**       | `hashlib`                    | SHA-256 streaming digest calculation                 |
| **Visualization** | `matplotlib`                 | High-resolution latency bar chart generation         |
| **Frontend**      | HTML5, Bootstrap 5, CSS3, JS | Clean dark-navy responsive design                    |

> **Design Choice:** Zero databases, zero heavy frontend frameworks, zero cloud dependencies. Runs 100% locally on your laptop.

---

## 3. Cryptographic Foundation

### How SHA-256 Works

- SHA-256 (Secure Hash Algorithm 256-bit) is a cryptographic hash function that takes an arbitrary-length stream of bytes and transforms it into a fixed **256-bit (32-byte)** output hash.
- **Pre-image Resistance:** Computationally infeasible to reverse the hash back into original data.
- **Avalanche Effect:** Altering even a single character in the input causes an unpredictable, dramatic change across more than 50% of the output bits.
- **Streaming Implementation:** In CodeShield, files are processed in 64 KB memory chunks (`calculate_sha256_stream`), allowing large files to be hashed without memory bloat.

### How RSA Digital Signatures Work

- **Key Generation:** Generates an asymmetric RSA 2048-bit key pair:
  - **Private Key ($d$):** Kept strictly secret by the developer. Serialized with AES-256 password encryption (`PKCS#8`).
  - **Public Key ($e, n$):** Distributed publicly (`SubjectPublicKeyInfo`).
- **Signing Scheme (RSA-PSS):**
  $$\text{Digest} = \text{SHA-256}(\text{File})$$
  $$\text{Signature} = \text{Sign}_{K_{\text{private}}}(\text{Digest}, \text{Padding}=\text{PSS})$$
  Uses Probabilistic Signature Scheme (PSS) with MGF1 (Mask Generation Function 1) and SHA-256, providing provable security superior to legacy PKCS#1 v1.5.
- **Verification Scheme:**
  $$\text{Result} = \text{Verify}_{K_{\text{public}}}(\text{File Digest}, \text{Signature})$$
  If valid, returns **Valid**; if any byte was tampered or the key does not match, returns **Invalid**.

---

## 4. Project Structure

```text
CodeShield/
├── app.py                  # Flask web server and API routes
├── crypto_utils.py         # Real cryptographic operations (RSA-PSS, SHA-256)
├── requirements.txt        # Minimal Python dependencies
├── README.md               # Complete lab documentation
├── templates/              # Jinja2 HTML templates
│   ├── base.html           # Dark navy layout, navigation bar, footer
│   ├── index.html          # Home landing page with concept explanation
│   ├── sign.html           # Module 1: RSA Key Generation & File Signing
│   ├── verify.html         # Module 2: File Verification & Integrity Checks
│   ├── security.html       # Module 3: Security & Tampering Demonstrations
│   └── performance.html    # Module 4: Latency & Startup Overhead Benchmark
├── static/
│   ├── style.css           # Custom dark theme, cards, and banners
│   └── script.js           # Client-side handlers and AJAX requests
├── sample/
│   └── demo.py             # Predefined, safe demonstration script
└── tests/
    └── test_crypto.py      # Automated unit and integration test suite
```

---

## 5. Installation & Running Locally

### Step 1: Open Terminal in the Project Directory

```powershell
cd d:\PROJECTS\Applied_Cryptography_PROJECT
```

### Step 2: Install Dependencies

```powershell
pip install -r requirements.txt
```

### Step 3: Launch the Application

```powershell
python app.py
```

### Step 4: Open in Web Browser

Navigate to:

```
http://127.0.0.1:5000
```

---

## 6. How to Use & Demonstrate in Viva

### Step-by-Step Lab Demonstration

1. **Open CodeShield Home Page** (`http://127.0.0.1:5000`):
   - Review the overview of how digital signatures ensure software authenticity and integrity.
2. **Module 1: Sign File** (`/sign`):
   - Click **"Generate RSA Keys"** (optionally provide a password).
   - Download `private_key.pem` and `public_key.pem`.
   - Select or upload a code file (e.g., click **"Download Sample Script (demo.py)"** in the top-right corner).
   - Select the private key, enter the password, and click **"Sign File"**.
   - Review the SHA-256 hash, signing latency, and click **"Download .sig File"**.
3. **Module 2: Verify File** (`/verify`):
   - Upload the original `demo.py`, `demo.py.sig`, and `public_key.pem`.
   - Click **"Verify Signature"**.
   - Observe the green success banner:
     > **Signature Valid — File Integrity Verified**
4. **Demonstrating Tampering**:
   - Open `demo.py` in a text editor (e.g. Notepad) and add a harmless comment: `# modified line`.
   - Save the file.
   - Upload this modified file to `/verify` with the original `.sig` and original `public_key.pem`.
   - Click **"Verify Signature"**.
   - Observe the red failure banner:
     > **Signature Invalid — File May Have Been Modified**
5. **Module 3: Security Testing** (`/security`):
   - Click **"Run Test 1: File Tampering"** to see live side-by-side SHA-256 hash comparison and integrity failure.
   - Click **"Run Test 2: Wrong Public Key"** to see verification failure when an unrelated public key is provided.
   - Review the comparison table:
     | Test | Result |
     | :--- | :--- |
     | Original file with matching Public Key | **Valid** |
     | Modified / Tampered file with original Signature | **Invalid** |
     | Original file with Wrong Public Key | **Invalid** |
6. **Module 4: Performance Analysis** (`/performance`):
   - Click **"Run Performance Benchmark"**.
   - View actual measured execution times:
     - RSA-2048 Key Generation (ms)
     - SHA-256 Hashing (ms)
     - RSA-PSS Signing (ms)
     - RSA-PSS Verification (ms)
   - View the dynamically rendered **Matplotlib bar graph**.
   - Inspect the **Application Startup Overhead** (average over 5 repeated runs of `demo.py`).

---

## 7. Security Guarantees & Non-Claims

- **Zero Arbitrary Execution:** User-uploaded files are **never** executed. Only the predefined safe script (`sample/demo.py`) is run during the startup benchmark, and only after successful cryptographic verification.
- **No `shell=True`:** Subprocess invocations use strict argument lists (`[sys.executable, script_path]`).
- **In-Memory Key Handling:** Private keys and passwords are processed in memory and immediately discarded. Never stored in a database or on the server file system.
- **Integrity vs Antivirus:** CodeShield detects modifications because file bytes changed, not because it performs heuristics or antivirus scanning.
- **Public Key Trust Model:** A valid signature proves integrity relative to the supplied public key. The verifier must acquire the public key through a trusted channel.

---

## 8. Running Automated Tests

To run the complete automated test suite (11 unit and integration tests):

```powershell
python -m unittest tests/test_crypto.py
```

Expected output:

```text
...........
----------------------------------------------------------------------
Ran 11 tests in ~1.7s

OK
```
