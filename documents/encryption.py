"""
SentinelVault — Fernet Encryption Utilities
Implements Encryption at Rest for the CIA Triad (Confidentiality).

All files are encrypted with Fernet (AES-128-CBC + HMAC-SHA256) before
being saved to disk. The encryption key is loaded exclusively from the
FERNET_KEY environment variable — never from the database or source code.

Usage:
    from documents.encryption import encrypt_file, decrypt_file

    encrypted = encrypt_file(raw_bytes)
    decrypted = decrypt_file(encrypted)
"""

import logging

from cryptography.fernet import Fernet, InvalidToken
from django.conf import settings

logger = logging.getLogger('sentinelvault')


def _get_fernet() -> Fernet:
    """
    Instantiate a Fernet cipher using the key from settings.
    Raises a clear error if the key is missing or malformed.
    """
    key = settings.FERNET_KEY
    if not key:
        raise ValueError(
            "FERNET_KEY is not configured. Set it in your environment variables. "
            "Generate with: python -c \"from cryptography.fernet import Fernet; "
            "print(Fernet.generate_key().decode())\""
        )
    try:
        return Fernet(key.encode() if isinstance(key, str) else key)
    except Exception as e:
        raise ValueError(f"Invalid FERNET_KEY format: {e}")


def encrypt_file(file_bytes: bytes) -> bytes:
    """
    Encrypt raw file bytes using Fernet symmetric encryption.

    Args:
        file_bytes: The original, unencrypted file content.

    Returns:
        The encrypted byte string (Fernet token).

    Raises:
        ValueError: If FERNET_KEY is not configured or is invalid.
    """
    if not isinstance(file_bytes, bytes):
        raise TypeError("file_bytes must be bytes, not {}".format(type(file_bytes).__name__))

    fernet = _get_fernet()
    encrypted = fernet.encrypt(file_bytes)

    logger.info(
        f"ENCRYPTION: File encrypted successfully "
        f"({len(file_bytes)} bytes → {len(encrypted)} bytes)"
    )

    return encrypted


def decrypt_file(encrypted_bytes: bytes) -> bytes:
    """
    Decrypt a Fernet-encrypted byte string back to the original file content.

    Args:
        encrypted_bytes: The Fernet-encrypted file content.

    Returns:
        The original, decrypted file bytes.

    Raises:
        ValueError: If FERNET_KEY is not configured or is invalid.
        cryptography.fernet.InvalidToken: If the data was tampered with or
            the wrong key is used.
    """
    if not isinstance(encrypted_bytes, bytes):
        raise TypeError(
            "encrypted_bytes must be bytes, not {}".format(type(encrypted_bytes).__name__)
        )

    fernet = _get_fernet()

    try:
        decrypted = fernet.decrypt(encrypted_bytes)
    except InvalidToken:
        logger.critical(
            "DECRYPTION_FAILURE: InvalidToken — file may be tampered with "
            "or the encryption key has changed."
        )
        raise

    logger.info(
        f"DECRYPTION: File decrypted successfully "
        f"({len(encrypted_bytes)} bytes → {len(decrypted)} bytes)"
    )

    return decrypted
