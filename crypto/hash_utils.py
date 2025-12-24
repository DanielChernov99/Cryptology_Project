import hashlib

def hash_bytes(data: bytes) -> bytes:
    """
    Compute SHA-256 hash of input data.
    """
    return hashlib.sha256(data).digest()

def hash_to_int(data: bytes) -> int:
    """
    Hash data and convert to integer (used in DSA).
    """
    return int.from_bytes(hash_bytes(data), byteorder="big")
