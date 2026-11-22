"""
CodeShield - Secure Code Integrity Verification using Digital Signatures
Flask Application Server
"""

import os
import sys
import time
import io
import base64
import tempfile
import subprocess
from flask import Flask, render_template, request, jsonify, send_file, flash, redirect, url_for
from werkzeug.utils import secure_filename

# Set Matplotlib temp dir to avoid permission warnings
os.environ["MPLCONFIGDIR"] = os.path.join(tempfile.gettempdir(), "matplotlib_codeshield")

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

from crypto_utils import (
    generate_rsa_key_pair,
    calculate_sha256_stream,
    sign_digest,
    verify_digest,
    load_private_key_safely,
    load_public_key_safely
)

app = Flask(__name__)
app.config["SECRET_KEY"] = os.urandom(24).hex()
# Limit upload size to 32 Megabytes to prevent DOS
app.config["MAX_CONTENT_LENGTH"] = 32 * 1024 * 1024

# Path to the safe, predefined demonstration program
DEMO_SCRIPT_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "sample", "demo.py")


@app.errorhandler(413)
def request_entity_too_large(error):
    return jsonify({
        "success": False,
        "error": "File size exceeds maximum allowed limit (32 MB)."
    }), 413


@app.errorhandler(500)
def internal_server_error(error):
    return jsonify({
        "success": False,
        "error": "An internal server error occurred."
    }), 500


# ---------------------------------------------------------
# View Routes
# ---------------------------------------------------------

@app.route("/")
def index():
    """Home Page"""
    return render_template("index.html")


@app.route("/sign")
def sign_page():
    """Module 1: Digital Signature Generation Page"""
    return render_template("sign.html")


@app.route("/verify")
def verify_page():
    """Module 2: Signature Verification Page"""
    return render_template("verify.html")


@app.route("/security")
def security_page():
    """Module 3: Security Testing Demonstration Page"""
    return render_template("security.html")


@app.route("/performance")
def performance_page():
    """Module 4: Performance Analysis Page"""
    return render_template("performance.html")


@app.route("/api/download-demo-sample")
def download_demo_sample():
    """Allow user to download the sample harmless demo.py file for testing."""
    if os.path.exists(DEMO_SCRIPT_PATH):
        return send_file(
            DEMO_SCRIPT_PATH,
            as_attachment=True,
            download_name="demo.py",
            mimetype="text/x-python"
        )
    return jsonify({"success": False, "error": "Sample file not found."}), 404


# ---------------------------------------------------------
# API Endpoints
# ---------------------------------------------------------

@app.route("/api/generate-keys", methods=["POST"])
def api_generate_keys():
    """
    Generate an RSA 2048-bit key pair.
    Keys are returned in memory to the user and never stored on the server.
    """
    try:
        data = request.get_json(silent=True) or {}
        password = data.get("password", "").strip() or None

        t0 = time.perf_counter()
        private_pem, public_pem = generate_rsa_key_pair(password)
        elapsed_ms = (time.perf_counter() - t0) * 1000

        return jsonify({
            "success": True,
            "private_key": private_pem.decode("utf-8"),
            "public_key": public_pem.decode("utf-8"),
            "encrypted": bool(password),
            "generation_time_ms": round(elapsed_ms, 2)
        })
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 400


@app.route("/api/sign-file", methods=["POST"])
def api_sign_file():
    """
    Sign an uploaded file using a provided RSA private key.
    Calculates SHA-256 hash using streaming and generates an RSA-PSS signature.
    Files and keys are processed purely in-memory and discarded.
    """
    try:
        if "file" not in request.files:
            return jsonify({"success": False, "error": "Target file to sign is missing."}), 400

        file_obj = request.files["file"]
        if not file_obj.filename:
            return jsonify({"success": False, "error": "No file selected."}), 400

        # Read private key from uploaded file or text field
        private_key_pem = b""
        if "private_key" in request.files and request.files["private_key"].filename:
            private_key_pem = request.files["private_key"].read()
        elif "private_key_text" in request.form:
            private_key_pem = request.form["private_key_text"].encode("utf-8")

        if not private_key_pem or not private_key_pem.strip():
            return jsonify({"success": False, "error": "Private key is required to sign."}), 400

        password = request.form.get("password", "").strip() or None

        # 1. Calculate streaming SHA-256 hash
        t0 = time.perf_counter()
        hex_hash, digest_bytes = calculate_sha256_stream(file_obj.stream)
        hashing_time_ms = (time.perf_counter() - t0) * 1000

        # 2. Sign prehashed digest using RSA-PSS
        t_sign_0 = time.perf_counter()
        signature_bytes = sign_digest(private_key_pem, password, digest_bytes)
        signing_time_ms = (time.perf_counter() - t_sign_0) * 1000

        # File size
        file_obj.seek(0, os.SEEK_END)
        file_size = file_obj.tell()

        sig_base64 = base64.b64encode(signature_bytes).decode("ascii")
        sig_hex = signature_bytes.hex()

        return jsonify({
            "success": True,
            "filename": secure_filename(file_obj.filename) or "signed_file",
            "file_size": file_size,
            "sha256_hash": hex_hash,
            "signature_base64": sig_base64,
            "signature_hex": sig_hex,
            "signature_len": len(signature_bytes),
            "hashing_time_ms": round(hashing_time_ms, 2),
            "signing_time_ms": round(signing_time_ms, 2),
            "total_time_ms": round(hashing_time_ms + signing_time_ms, 2)
        })

    except ValueError as ve:
        return jsonify({"success": False, "error": str(ve)}), 400
    except Exception as e:
        return jsonify({"success": False, "error": f"Signing error: {str(e)}"}), 500


@app.route("/api/verify-signature", methods=["POST"])
def api_verify_signature():
    """
    Verify an uploaded file with its .sig signature and corresponding public key.
    Calculates SHA-256 hash and verifies RSA-PSS signature.
    """
    try:
        if "file" not in request.files:
            return jsonify({"success": False, "error": "Target file to verify is missing."}), 400

        file_obj = request.files["file"]
        if not file_obj.filename:
            return jsonify({"success": False, "error": "No file selected."}), 400

        # Signature input (file or text)
        signature_bytes = b""
        if "signature" in request.files and request.files["signature"].filename:
            signature_bytes = request.files["signature"].read()
        elif "signature_text" in request.form:
            sig_text = request.form["signature_text"].strip()
            # Try base64 decoding if given text
            try:
                signature_bytes = base64.b64decode(sig_text)
            except Exception:
                try:
                    signature_bytes = bytes.fromhex(sig_text)
                except Exception:
                    signature_bytes = sig_text.encode("utf-8")

        if not signature_bytes:
            return jsonify({"success": False, "error": "Signature (.sig) file or data is missing."}), 400

        # Public key input (file or text)
        public_key_pem = b""
        if "public_key" in request.files and request.files["public_key"].filename:
            public_key_pem = request.files["public_key"].read()
        elif "public_key_text" in request.form:
            public_key_pem = request.form["public_key_text"].encode("utf-8")

        if not public_key_pem or not public_key_pem.strip():
            return jsonify({"success": False, "error": "Public key (.pem) is missing."}), 400

        # 1. Compute SHA-256 of candidate file
        t0 = time.perf_counter()
        hex_hash, digest_bytes = calculate_sha256_stream(file_obj.stream)
        hashing_time_ms = (time.perf_counter() - t0) * 1000

        # 2. Verify signature
        t_ver_0 = time.perf_counter()
        is_valid = verify_digest(public_key_pem, signature_bytes, digest_bytes)
        verification_time_ms = (time.perf_counter() - t_ver_0) * 1000

        file_obj.seek(0, os.SEEK_END)
        file_size = file_obj.tell()

        if is_valid:
            status_message = "Signature Valid — File Integrity Verified"
            explanation = "The cryptographic signature matches the file content and public key exactly. No unauthorized changes or tampering detected."
        else:
            status_message = "Signature Invalid — File May Have Been Modified"
            explanation = "Cryptographic verification failed. Either the file content was modified after signing, the wrong public key was provided, or the signature file is invalid."

        return jsonify({
            "success": True,
            "valid": is_valid,
            "filename": secure_filename(file_obj.filename) or "verified_file",
            "file_size": file_size,
            "sha256_hash": hex_hash,
            "status_message": status_message,
            "explanation": explanation,
            "hashing_time_ms": round(hashing_time_ms, 2),
            "verification_time_ms": round(verification_time_ms, 2),
            "total_time_ms": round(hashing_time_ms + verification_time_ms, 2)
        })

    except ValueError as ve:
        return jsonify({"success": False, "error": str(ve)}), 400
    except Exception as e:
        return jsonify({"success": False, "error": f"Verification error: {str(e)}"}), 500


@app.route("/api/security-test", methods=["POST"])
def api_security_test():
    """
    Module 3 Security Tests:
    Supports both automated presets and custom user-provided code for interactive tampering!
    Test 1: File Tampering (Code signed, modified, verified -> fails)
    Test 2: Wrong Public Key (Code signed with Key A, verified with Key B -> fails)
    Uses REAL cryptographic operations.
    """
    try:
        data = request.get_json(silent=True) or {}
        test_type = data.get("test_type", "all")

        # Support user-entered custom code or use default sample
        user_orig = data.get("original_code")
        if user_orig and str(user_orig).strip():
            original_code = str(user_orig).encode("utf-8")
        else:
            original_code = b'# CodeShield Sample Script\ndef calculate_discount(price, discount):\n    return price * (1 - discount)\n\nprint("Price with discount:", calculate_discount(100, 0.15))\n'

        user_tamp = data.get("tampered_code")
        if user_tamp and str(user_tamp).strip():
            tampered_code = str(user_tamp).encode("utf-8")
        else:
            tampered_code = original_code + b'# Injected line: unauthorized price override\ndef calculate_discount(price, discount):\n    return 0.0\n'

        # Generate Key Pair A
        priv_a, pub_a = generate_rsa_key_pair(None)
        orig_hex, orig_digest = calculate_sha256_stream(original_code)
        orig_sig = sign_digest(priv_a, None, orig_digest)

        # Baseline: Original file verification with Key A
        baseline_valid = verify_digest(pub_a, orig_sig, orig_digest)

        results = {
            "baseline": {
                "name": "Original File Integrity Check",
                "code": original_code.decode("utf-8", errors="replace"),
                "hash": orig_hex,
                "valid": baseline_valid,
                "status": "Valid" if baseline_valid else "Invalid"
            }
        }

        # Test 1: Tampering
        if test_type in ["tampering", "interactive", "all"]:
            tamp_hex, tamp_digest = calculate_sha256_stream(tampered_code)
            tamper_valid = verify_digest(pub_a, orig_sig, tamp_digest)

            # Check if bytes are actually different
            is_identical = (original_code == tampered_code)

            if is_identical:
                explanation = "The code was not modified; therefore, the SHA-256 digest remained identical and verification succeeded. Edit any character in the modified box to trigger a tampering failure!"
            else:
                explanation = "The signature verification failed because altering code changes the cryptographic SHA-256 digest entirely (Avalanche Effect). The system detected this modification strictly through byte-level cryptographic integrity verification, not antivirus scanning."

            results["tampering_test"] = {
                "name": "Test 1: File Tampering Detection",
                "original_code": original_code.decode("utf-8", errors="replace"),
                "original_hash": orig_hex,
                "tampered_code": tampered_code.decode("utf-8", errors="replace"),
                "tampered_hash": tamp_hex,
                "is_identical": is_identical,
                "valid": tamper_valid,
                "status": "Valid" if tamper_valid else "Invalid",
                "signature_preview": orig_sig.hex()[:64] + "...",
                "explanation": explanation
            }

        # Test 2: Wrong Public Key
        if test_type in ["wrong_key", "all"]:
            # Generate second distinct key pair B
            _, pub_b = generate_rsa_key_pair(None)
            wrong_key_valid = verify_digest(pub_b, orig_sig, orig_digest)

            results["wrong_key_test"] = {
                "name": "Test 2: Wrong Public Key Verification",
                "key_a_preview": pub_a.decode("utf-8")[:120] + "...",
                "key_b_preview": pub_b.decode("utf-8")[:120] + "...",
                "file_hash": orig_hex,
                "valid": wrong_key_valid,
                "status": "Valid" if wrong_key_valid else "Invalid",
                "explanation": "Verification failed because the digital signature was created using Private Key A, which mathematically corresponds ONLY to Public Key A. Attempting to verify with Public Key B fails the RSA-PSS mathematical proof, proving the authenticity and non-repudiation of the signer."
            }

        # Table summary
        results["summary_table"] = [
            {"test": "Original file with matching Public Key", "result": "Valid", "badge": "success"},
            {"test": "Modified / Tampered file with original Signature", "result": "Invalid", "badge": "danger"},
            {"test": "Original file with Wrong Public Key", "result": "Invalid", "badge": "danger"}
        ]

        return jsonify({"success": True, "results": results})

    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route("/api/performance-benchmark", methods=["POST", "GET"])
def api_performance_benchmark():
    """
    Module 4: Performance Analysis
    Measures:
    - RSA key generation time
    - SHA-256 hashing time
    - Digital signature generation time
    - Signature verification time
    - Startup verification overhead on safe predefined demo program (repeated runs)
    Generates Matplotlib bar chart comparing hashing, signing, and verification.
    """
    try:
        # 1. Measure RSA 2048 Key Generation Time
        t0 = time.perf_counter()
        priv_pem, pub_pem = generate_rsa_key_pair(None)
        key_gen_ms = (time.perf_counter() - t0) * 1000

        # 2. Measure SHA-256 Hashing Time on a 256 KB test buffer
        sample_payload = b"CodeShield Secure Integrity Check Payload: " * 6000  # ~258 KB
        t0 = time.perf_counter()
        hex_hash, digest_bytes = calculate_sha256_stream(sample_payload)
        hash_ms = (time.perf_counter() - t0) * 1000

        # 3. Measure RSA-PSS Digital Signature Generation Time
        t0 = time.perf_counter()
        sig_bytes = sign_digest(priv_pem, None, digest_bytes)
        sign_ms = (time.perf_counter() - t0) * 1000

        # 4. Measure Signature Verification Time
        t0 = time.perf_counter()
        is_valid = verify_digest(pub_pem, sig_bytes, digest_bytes)
        verify_ms = (time.perf_counter() - t0) * 1000

        if not is_valid:
            raise ValueError("Sanity check failed during benchmark.")

        # 5. Measure Application Startup Overhead on predefined safe demo program
        # Read the predefined safe script
        if not os.path.exists(DEMO_SCRIPT_PATH):
            raise FileNotFoundError(f"Safe demo script not found at {DEMO_SCRIPT_PATH}")

        with open(DEMO_SCRIPT_PATH, "rb") as f:
            demo_content = f.read()

        _, demo_digest = calculate_sha256_stream(demo_content)
        demo_sig = sign_digest(priv_pem, None, demo_digest)

        # Run repeated measurements (5 iterations each)
        RUNS = 5
        normal_times = []
        verified_times = []

        for _ in range(RUNS):
            # Benchmark normal startup (direct subprocess launch without shell=True)
            t_start = time.perf_counter()
            res_normal = subprocess.run(
                [sys.executable, DEMO_SCRIPT_PATH],
                capture_output=True,
                text=True,
                shell=False
            )
            t_end = time.perf_counter()
            normal_times.append((t_end - t_start) * 1000)

        for _ in range(RUNS):
            # Benchmark verified startup (verify signature before launch)
            t_start = time.perf_counter()
            # Step A: Hash & Verify
            _, current_digest = calculate_sha256_stream(demo_content)
            ver_ok = verify_digest(pub_pem, demo_sig, current_digest)
            if not ver_ok:
                raise RuntimeError("Integrity verification failed for safe demo script.")
            # Step B: Launch only after verified
            res_ver = subprocess.run(
                [sys.executable, DEMO_SCRIPT_PATH],
                capture_output=True,
                text=True,
                shell=False
            )
            t_end = time.perf_counter()
            verified_times.append((t_end - t_start) * 1000)

        avg_normal_ms = sum(normal_times) / len(normal_times)
        avg_verified_ms = sum(verified_times) / len(verified_times)
        avg_overhead_ms = max(0.0, avg_verified_ms - avg_normal_ms)
        overhead_percent = (avg_overhead_ms / avg_normal_ms * 100) if avg_normal_ms > 0 else 0.0

        # 6. Generate Matplotlib Bar Chart
        fig, ax = plt.subplots(figsize=(7.5, 4.2), facecolor="#101b35")
        ax.set_facecolor("#070c18")

        operations = ["SHA-256 Hashing\n(256 KB)", "RSA-PSS Signing\n(2048-bit)", "RSA-PSS Verification\n(2048-bit)"]
        op_times = [hash_ms, sign_ms, verify_ms]
        colors = ["#38bdf8", "#818cf8", "#34d399"]

        bars = ax.bar(operations, op_times, color=colors, width=0.45, edgecolor="#36508d", linewidth=1.2)

        # Label bars with value in ms
        for bar, t_val in zip(bars, op_times):
            height = bar.get_height()
            ax.annotate(
                f"{t_val:.3f} ms",
                xy=(bar.get_x() + bar.get_width() / 2, height),
                xytext=(0, 5),
                textcoords="offset points",
                ha="center",
                va="bottom",
                color="#ffffff",
                fontsize=11,
                fontweight="bold"
            )

        ax.tick_params(colors="#e2e8f0", labelsize=11)
        ax.set_ylabel("Execution Time (milliseconds)", color="#ffffff", fontsize=11, fontweight="bold")
        ax.set_title("CodeShield Cryptographic Latency Breakdown", color="#ffffff", fontsize=13, fontweight="bold", pad=15)

        for spine in ax.spines.values():
            spine.set_color("#223561")

        ax.grid(axis="y", linestyle="--", alpha=0.3, color="#8b949e")
        # Ensure head space for annotations
        max_h = max(op_times) if op_times else 1.0
        ax.set_ylim(0, max_h * 1.3)

        plt.tight_layout()
        chart_buffer = io.BytesIO()
        plt.savefig(chart_buffer, format="png", dpi=140, facecolor=fig.get_facecolor(), edgecolor="none")
        plt.close(fig)
        chart_buffer.seek(0)
        chart_base64 = base64.b64encode(chart_buffer.read()).decode("utf-8")

        return jsonify({
            "success": True,
            "metrics": {
                "key_gen_ms": round(key_gen_ms, 2),
                "hash_ms": round(hash_ms, 3),
                "sign_ms": round(sign_ms, 3),
                "verify_ms": round(verify_ms, 3),
                "payload_size_kb": round(len(sample_payload) / 1024, 1),
                "iterations": RUNS,
                "avg_normal_ms": round(avg_normal_ms, 2),
                "avg_verified_ms": round(avg_verified_ms, 2),
                "avg_overhead_ms": round(avg_overhead_ms, 2),
                "overhead_percent": round(overhead_percent, 1)
            },
            "chart_base64": chart_base64
        })

    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


if __name__ == "__main__":
    print("=" * 60)
    print("CodeShield - Secure Code Integrity Verification Server")
    print("Running at: http://127.0.0.1:5000")
    print("=" * 60)
    app.run(host="127.0.0.1", port=5000, debug=True)
