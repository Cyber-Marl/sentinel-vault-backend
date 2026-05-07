"""
SentinelVault — SHA-256 File Hashing Utilities
Implements Data Integrity verification for the CIA Triad (Integrity).

Every uploaded file's SHA-256 hash is computed and stored alongside the document.
On download, the hash is recomputed and verified to detect tampering.

Usage:
    from documents.hashing import calculate_sha256, verify_integrity

    file_hash = calculate_sha256(file_bytes)
    is_valid  = verify_integrity(file_bytes, file_hash)
"""

import hashlib
import logging

logger = logging.getLogger('sentinelvault')


def calculate_sha256(file_bytes: bytes) -> str:
    """
    Compute the SHA-256 hash of a file's content.

    Args:
        file_bytes: The raw file content as bytes.

    Returns:
        The hexadecimal SHA-256 digest string (64 characters).
    """
    if not isinstance(file_bytes, bytes):
        raise TypeError("file_bytes must be bytes, not {}".format(type(file_bytes).__name__))

    digest = hashlib.sha256(file_bytes).hexdigest()

    logger.debug(f"HASH_COMPUTED: SHA-256 = {digest[:16]}... ({len(file_bytes)} bytes)")

    return digest


def verify_integrity(file_bytes: bytes, expected_hash: str) -> bool:
    """
    Verify the integrity of a file by comparing its SHA-256 hash
    against the stored expected hash.

    Args:
        file_bytes: The file content to verify.
        expected_hash: The SHA-256 hex digest stored at upload time.

    Returns:
        True if the hashes match, False if the file has been tampered with.
    """
    computed_hash = calculate_sha256(file_bytes)
    is_valid = computed_hash == expected_hash

    if is_valid:
        logger.info(f"INTEGRITY_CHECK: PASSED — hash matches ({computed_hash[:16]}...)")
    else:
        logger.critical(
            f"INTEGRITY_CHECK: FAILED — hash mismatch! "
            f"Expected: {expected_hash[:16]}..., "
            f"Computed: {computed_hash[:16]}..."
        )

    return is_valid
