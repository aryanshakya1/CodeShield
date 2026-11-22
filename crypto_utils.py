"""
CodeShield - Cryptographic Utility Module
Provides real cryptographic implementations for:
- RSA 2048-bit key pair generation (with optional password encryption)
- SHA-256 streaming hashing
- RSA-PSS digital signing with MGF1 (SHA-256)
- RSA-PSS digital signature verification
"""

import io
import hashlib
import time
from typing import Tuple, Optional
from cryptography.hazmat.primitives.asymmetric import rsa, padding, utils
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.exceptions import InvalidSignature


def generate_rsa_key_pair(password: Optional[str] = None) -> Tuple[bytes, bytes]:
    """
    Generate an RSA 2048-bit key pair.
    Returns:
        (private_key_pem_bytes, public_key_pem_bytes)
    If password is provided, private key is encrypted using PKCS8 with BestAvailableEncryption.
    """
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )

    if password and password.strip():
        encryption_algorithm = serialization.BestAvailableEncryption(password.strip().encode("utf-8"))
    else:
        encryption_algorithm = serialization.NoEncryption()

    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=encryption_algorithm
    )

    public_key = private_key.public_key()
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    return private_pem, public_pem


def calculate_sha256_stream(stream_or_bytes, chunk_size: int = 65536) -> Tuple[str, bytes]:
    """
    Calculate SHA-256 digest via streaming chunks.
    Accepts a file-like stream or raw bytes.
    Returns:
        (hex_digest_string, raw_digest_bytes)
    """
    hasher = hashlib.sha256()

    if isinstance(stream_or_bytes, (bytes, bytearray)):
        hasher.update(stream_or_bytes)
    elif hasattr(stream_or_bytes, "read"):
        # Handle file-like objects
        if hasattr(stream_or_bytes, "seek"):
            stream_or_bytes.seek(0)
        while True:
            chunk = stream_or_bytes.read(chunk_size)
            if not chunk:
                break
            if isinstance(chunk, str):
                chunk = chunk.encode("utf-8")
            hasher.update(chunk)
    else:
        raise ValueError("Unsupported data source for SHA-256 calculation.")

    digest_bytes = hasher.digest()
    hex_digest = hasher.hexdigest()
    return hex_digest, digest_bytes


def load_private_key_safely(private_key_pem: bytes, password: Optional[str] = None):
    """
    Safely load a private key from PEM bytes.
    Raises user-friendly ValueError on decryption or format failure.
    """
    if not private_key_pem or not private_key_pem.strip():
        raise ValueError("Private key data is empty.")

    pw_bytes = password.strip().encode("utf-8") if password and password.strip() else None

    try:
        return serialization.load_pem_private_key(private_key_pem, password=pw_bytes)
    except TypeError as e:
        # Key is encrypted but no password provided, or vice versa
        raise ValueError("Password is required for encrypted private key.") from e
    except ValueError as e:
        # Invalid password or invalid PEM format
        err_msg = str(e).lower()
        if "bad decrypt" in err_msg or "mac check failed" in err_msg:
            raise ValueError("Incorrect password for private key.") from e
        raise ValueError("Invalid private key PEM format or incorrect password.") from e
    except Exception as e:
        raise ValueError(f"Failed to load private key: {str(e)}") from e


def load_public_key_safely(public_key_pem: bytes):
    """
    Safely load a public key from PEM bytes.
    Raises user-friendly ValueError on format failure.
    """
    if not public_key_pem or not public_key_pem.strip():
        raise ValueError("Public key data is empty.")

    try:
        return serialization.load_pem_public_key(public_key_pem)
    except Exception as e:
        raise ValueError("Invalid public key format. Please provide a valid PEM public key.") from e


def sign_digest(private_key_pem: bytes, password: Optional[str], digest_bytes: bytes) -> bytes:
    """
    Sign a 32-byte SHA-256 digest using RSA-PSS padding and MGF1(SHA-256).
    Returns raw signature bytes (256 bytes for RSA-2048).
    """
    if len(digest_bytes) != 32:
        raise ValueError("Digest must be exactly 32 bytes for SHA-256.")

    private_key = load_private_key_safely(private_key_pem, password)

    if not isinstance(private_key, rsa.RSAPrivateKey):
        raise ValueError("Only RSA private keys are supported.")

    signature = private_key.sign(
        digest_bytes,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        utils.Prehashed(hashes.SHA256())
    )
    return signature


def verify_digest(public_key_pem: bytes, signature_bytes: bytes, digest_bytes: bytes) -> bool:
    """
    Verify an RSA-PSS digital signature against a 32-byte SHA-256 digest.
    Returns:
        True if signature is valid.
        False if invalid (e.g. tampering or mismatch).
    Raises ValueError for invalid key or signature formatting.
    """
    if len(digest_bytes) != 32:
        raise ValueError("Digest must be exactly 32 bytes for SHA-256.")

    public_key = load_public_key_safely(public_key_pem)

    if not isinstance(public_key, rsa.RSAPublicKey):
        raise ValueError("Only RSA public keys are supported.")

    if not signature_bytes or len(signature_bytes) == 0:
        raise ValueError("Signature file is empty.")

    # Try raw binary first; if base64 or hex encoded, attempt decoding
    sig = signature_bytes
    if len(sig) != 256:
        # Check if it was encoded in hex or base64
        try:
            import base64
            decoded = base64.b64decode(sig, validate=True)
            if len(decoded) == 256:
                sig = decoded
        except Exception:
            try:
                decoded = bytes.fromhex(sig.decode("utf-8").strip())
                if len(decoded) == 256:
                    sig = decoded
            except Exception:
                pass

    try:
        public_key.verify(
            sig,
            digest_bytes,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            utils.Prehashed(hashes.SHA256())
        )
        return True
    except InvalidSignature:
        return False
    except Exception as e:
        raise ValueError(f"Malformed signature structure: {str(e)}") from e
