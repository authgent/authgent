"""Tests for crypto.py — HKDF key derivation, AES-256-GCM encrypt/decrypt."""

from authgent_server.crypto import decrypt_private_key, derive_subkey, encrypt_private_key


class TestDeriveSubkey:
    """HKDF subkey derivation tests."""

    def test_deterministic_output(self):
        """Same master + purpose always produces same subkey."""
        master = b"test-master-key-for-unit-tests"
        k1 = derive_subkey(master, "signing")
        k2 = derive_subkey(master, "signing")
        assert k1 == k2

    def test_different_purposes_produce_different_keys(self):
        """Different purposes derive different subkeys from the same master."""
        master = b"shared-master"
        k_sign = derive_subkey(master, "signing")
        k_encrypt = derive_subkey(master, "encryption")
        k_hmac = derive_subkey(master, "hmac")
        assert k_sign != k_encrypt
        assert k_sign != k_hmac
        assert k_encrypt != k_hmac

    def test_different_masters_produce_different_keys(self):
        """Different master secrets derive different subkeys for the same purpose."""
        k1 = derive_subkey(b"master-one", "signing")
        k2 = derive_subkey(b"master-two", "signing")
        assert k1 != k2

    def test_default_length_is_32_bytes(self):
        """Default subkey length is 32 bytes (256 bits)."""
        key = derive_subkey(b"master", "test")
        assert len(key) == 32

    def test_custom_length(self):
        """Can derive keys of custom length."""
        k16 = derive_subkey(b"master", "test", length=16)
        k64 = derive_subkey(b"master", "test", length=64)
        assert len(k16) == 16
        assert len(k64) == 64


class TestEncryptDecryptPrivateKey:
    """AES-256-GCM round-trip tests for private key encryption at rest."""

    def test_round_trip(self):
        """Encrypt then decrypt produces the original plaintext."""
        kek = derive_subkey(b"master-secret", "key-encryption")
        original_pem = "-----BEGIN EC PRIVATE KEY-----\nMHQCAQEEI...\n-----END EC PRIVATE KEY-----"

        encrypted = encrypt_private_key(original_pem, kek)
        decrypted = decrypt_private_key(encrypted, kek)
        assert decrypted == original_pem

    def test_encrypted_format_is_nonce_colon_ciphertext_hex(self):
        """Encrypted output is 'nonce_hex:ciphertext_hex'."""
        kek = derive_subkey(b"master", "kek")
        encrypted = encrypt_private_key("test-data", kek)

        parts = encrypted.split(":")
        assert len(parts) == 2
        nonce_hex, ct_hex = parts
        # Nonce is 12 bytes = 24 hex chars
        assert len(nonce_hex) == 24
        # Ciphertext is at least as long as plaintext + 16-byte GCM tag
        assert len(bytes.fromhex(ct_hex)) >= len("test-data") + 16

    def test_different_encryptions_produce_different_ciphertexts(self):
        """Each encryption uses a random nonce, so ciphertexts differ."""
        kek = derive_subkey(b"master", "kek")
        e1 = encrypt_private_key("same-plaintext", kek)
        e2 = encrypt_private_key("same-plaintext", kek)
        assert e1 != e2  # random nonce

        # But both decrypt to the same value
        assert decrypt_private_key(e1, kek) == "same-plaintext"
        assert decrypt_private_key(e2, kek) == "same-plaintext"

    def test_wrong_kek_fails_decryption(self):
        """Decrypting with wrong key raises an error (GCM tag mismatch)."""
        kek1 = derive_subkey(b"correct-master", "kek")
        kek2 = derive_subkey(b"wrong-master", "kek")
        encrypted = encrypt_private_key("secret", kek1)

        import pytest

        with pytest.raises(Exception):  # cryptography raises InvalidTag
            decrypt_private_key(encrypted, kek2)

    def test_tampered_ciphertext_fails(self):
        """Modifying ciphertext causes GCM authentication failure."""
        kek = derive_subkey(b"master", "kek")
        encrypted = encrypt_private_key("secret", kek)
        nonce_hex, ct_hex = encrypted.split(":")

        # Flip a byte in ciphertext
        ct_bytes = bytearray(bytes.fromhex(ct_hex))
        ct_bytes[0] ^= 0xFF
        tampered = nonce_hex + ":" + ct_bytes.hex()

        import pytest

        with pytest.raises(Exception):
            decrypt_private_key(tampered, kek)

    def test_large_key_round_trip(self):
        """Works with realistic PEM key sizes (~300 bytes)."""
        kek = derive_subkey(b"master-production", "kek")
        # Simulate a realistic EC private key PEM
        large_pem = (
            "-----BEGIN EC PRIVATE KEY-----\n" + ("A" * 300) + "\n-----END EC PRIVATE KEY-----"
        )
        encrypted = encrypt_private_key(large_pem, kek)
        assert decrypt_private_key(encrypted, kek) == large_pem
