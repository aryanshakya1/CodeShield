"""
CodeShield - Comprehensive Unit and Integration Test Suite
Validates:
1. Core Cryptographic Primitives (RSA-2048, RSA-PSS, SHA-256)
2. Streaming Hashing & Key Decryption with Passwords
3. Tamper Detection & Public Key Mismatches
4. Flask Web Endpoints & API Integration
5. Performance Benchmark & Startup Overhead Execution
"""

import unittest
import io
import json
import hashlib
from crypto_utils import (
    generate_rsa_key_pair,
    calculate_sha256_stream,
    sign_digest,
    verify_digest,
    load_private_key_safely,
    load_public_key_safely
)
from app import app


class TestCryptoPrimitives(unittest.TestCase):

    def setUp(self):
        self.password = "StrongPassword#2026"
        self.priv_pem, self.pub_pem = generate_rsa_key_pair(self.password)
        self.unenc_priv, self.unenc_pub = generate_rsa_key_pair(None)
        self.sample_code = b'print("CodeShield Secure Script")\n'

    def test_key_generation_and_loading(self):
        """Test RSA-2048 key generation and PKCS#8 loading."""
        self.assertIn(b"BEGIN", self.priv_pem)
        self.assertIn(b"BEGIN PUBLIC KEY", self.pub_pem)

        priv = load_private_key_safely(self.priv_pem, self.password)
        self.assertIsNotNone(priv)
        pub = load_public_key_safely(self.pub_pem)
        self.assertIsNotNone(pub)

    def test_wrong_password_failure(self):
        """Test decryption fails with wrong password."""
        with self.assertRaises(ValueError):
            load_private_key_safely(self.priv_pem, "IncorrectPass")

    def test_sha256_streaming(self):
        """Test stream-based SHA-256 calculation."""
        stream = io.BytesIO(self.sample_code)
        hex_digest, raw_digest = calculate_sha256_stream(stream)
        self.assertEqual(hex_digest, hashlib.sha256(self.sample_code).hexdigest())
        self.assertEqual(raw_digest, hashlib.sha256(self.sample_code).digest())

    def test_sign_and_verify_success(self):
        """Test signing and successful verification."""
        _, digest = calculate_sha256_stream(self.sample_code)
        sig = sign_digest(self.priv_pem, self.password, digest)
        self.assertEqual(len(sig), 256)  # 2048-bit RSA = 256 bytes

        valid = verify_digest(self.pub_pem, sig, digest)
        self.assertTrue(valid)

    def test_tampering_fails(self):
        """Test that modified content fails verification."""
        _, orig_digest = calculate_sha256_stream(self.sample_code)
        sig = sign_digest(self.priv_pem, self.password, orig_digest)

        modified_code = self.sample_code + b'# Injected line\n'
        _, mod_digest = calculate_sha256_stream(modified_code)

        valid = verify_digest(self.pub_pem, sig, mod_digest)
        self.assertFalse(valid)

    def test_wrong_public_key_fails(self):
        """Test that signature fails with another public key."""
        _, digest = calculate_sha256_stream(self.sample_code)
        sig = sign_digest(self.priv_pem, self.password, digest)

        _, other_pub = generate_rsa_key_pair(None)
        valid = verify_digest(other_pub, sig, digest)
        self.assertFalse(valid)


class TestFlaskEndpoints(unittest.TestCase):

    def setUp(self):
        app.config["TESTING"] = True
        self.client = app.test_client()

    def test_page_routes(self):
        """Verify all HTML pages render successfully."""
        routes = ["/", "/sign", "/verify", "/security", "/performance"]
        for route in routes:
            res = self.client.get(route)
            self.assertEqual(res.status_code, 200, f"Failed for route {route}")
            self.assertIn(b"CodeShield", res.data)

    def test_api_generate_keys(self):
        """Verify API key pair generation."""
        res = self.client.post("/api/generate-keys", json={"password": "TestPassword123"})
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertTrue(data["success"])
        self.assertTrue(data["encrypted"])
        self.assertIn("BEGIN", data["private_key"])
        self.assertIn("BEGIN PUBLIC KEY", data["public_key"])

    def test_api_sign_and_verify_flow(self):
        """Test full API sign -> verify flow with both intact and modified files."""
        # 1. Generate keys
        keygen_res = self.client.post("/api/generate-keys", json={"password": "MySecretPass!"})
        keygen_data = keygen_res.get_json()
        priv_pem = keygen_data["private_key"]
        pub_pem = keygen_data["public_key"]

        # 2. Sign file
        file_content = b'print("Safe Production Code")\n'
        sign_payload = {
            "file": (io.BytesIO(file_content), "script.py"),
            "private_key_text": priv_pem,
            "password": "MySecretPass!"
        }
        sign_res = self.client.post("/api/sign-file", data=sign_payload, content_type="multipart/form-data")
        self.assertEqual(sign_res.status_code, 200)
        sign_data = sign_res.get_json()
        self.assertTrue(sign_data["success"])
        sig_base64 = sign_data["signature_base64"]

        # 3. Verify intact file
        verify_payload_valid = {
            "file": (io.BytesIO(file_content), "script.py"),
            "signature_text": sig_base64,
            "public_key_text": pub_pem
        }
        ver_res = self.client.post("/api/verify-signature", data=verify_payload_valid, content_type="multipart/form-data")
        self.assertEqual(ver_res.status_code, 200)
        ver_data = ver_res.get_json()
        self.assertTrue(ver_data["success"])
        self.assertTrue(ver_data["valid"])
        self.assertIn("Verified", ver_data["status_message"])

        # 4. Verify modified file (tampered)
        tampered_content = file_content + b'# Unauthorized modification\n'
        verify_payload_invalid = {
            "file": (io.BytesIO(tampered_content), "script.py"),
            "signature_text": sig_base64,
            "public_key_text": pub_pem
        }
        ver_tamper_res = self.client.post("/api/verify-signature", data=verify_payload_invalid, content_type="multipart/form-data")
        self.assertEqual(ver_tamper_res.status_code, 200)
        ver_tamper_data = ver_tamper_res.get_json()
        self.assertTrue(ver_tamper_data["success"])
        self.assertFalse(ver_tamper_data["valid"])
        self.assertIn("Invalid", ver_tamper_data["status_message"])

    def test_api_security_tests(self):
        """Verify the security test demonstration API."""
        res = self.client.post("/api/security-test", json={"test_type": "all"})
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertTrue(data["success"])
        self.assertIn("tampering_test", data["results"])
        self.assertIn("wrong_key_test", data["results"])
        self.assertFalse(data["results"]["tampering_test"]["valid"])
        self.assertFalse(data["results"]["wrong_key_test"]["valid"])
        self.assertEqual(len(data["results"]["summary_table"]), 3)

    def test_api_performance_benchmark(self):
        """Verify the performance benchmark API."""
        res = self.client.post("/api/performance-benchmark")
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertTrue(data["success"])
        self.assertIn("metrics", data)
        self.assertIn("chart_base64", data)
        self.assertGreater(data["metrics"]["avg_normal_ms"], 0)


if __name__ == "__main__":
    unittest.main()
