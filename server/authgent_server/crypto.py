"""Cryptographic utilities — HKDF key derivation, AES-256-GCM encryption."""

import os

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


def derive_subkey(master: bytes, purpose: str, length: int = 32) -> bytes:
    """Derive a purpose-specific key from the master secret using HKDF (RFC 5869)."""
    return HKDF(
        algorithm=SHA256(),
        length=length,
        info=f"authgent-{purpose}".encode(),
        salt=None,
    ).derive(master)


def encrypt_private_key(pem_data: str, kek: bytes) -> str:
    """Encrypt a PEM private key with AES-256-GCM. Returns nonce:ciphertext (hex)."""
    aesgcm = AESGCM(kek)
    nonce = os.urandom(12)
    ciphertext = aesgcm.encrypt(nonce, pem_data.encode(), None)
    return nonce.hex() + ":" + ciphertext.hex()


def decrypt_private_key(encrypted: str, kek: bytes) -> str:
    """Decrypt a PEM private key from nonce:ciphertext (hex) format."""
    nonce_hex, ct_hex = encrypted.split(":", 1)
    aesgcm = AESGCM(kek)
    plaintext = aesgcm.decrypt(bytes.fromhex(nonce_hex), bytes.fromhex(ct_hex), None)
    return plaintext.decode()
