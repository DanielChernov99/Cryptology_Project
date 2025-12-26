import hashlib


def str_to_bytes(text: str) -> bytes:
    """
    Convert string to bytes using UTF-8 encoding.
    """
    return text.encode("utf-8")

def bytes_to_str(data: bytes) -> str:
    """
    Convert bytes to string using UTF-8 decoding.
    """
    return data.decode("utf-8")

def bytes_to_hex(data: bytes) -> str:
    """
    Convert bytes to hex string (for display/logging).
    """
    return data.hex()

def hex_to_bytes(hex_str: str) -> bytes:
    """
    Convert hex string back to bytes.
    """
    return bytes.fromhex(hex_str)

def bytes_to_int(data: bytes) -> int:
    """
    Convert bytes to an integer (Big Endian).
    Essential for ECDH and DSA which perform math operations on large numbers.
    """
    return int.from_bytes(data, byteorder="big")

def int_to_bytes(value: int, length: int = None) -> bytes:
    """
    Convert integer to bytes (Big Endian).
    
    Args:
        value: The integer to convert.
        length: The fixed length of the output bytes (optional but recommended for Block Ciphers).
    
    Note: If length is not provided, it calculates the minimum bytes needed.
    """
    if length:
        return value.to_bytes(length, byteorder="big")
    
    # Calculate minimum length needed dynamically
    needed_bytes = (value.bit_length() + 7) // 8
    return value.to_bytes(needed_bytes, byteorder="big")

def generate_iv(block_size: int) -> bytes:
    """
    Generate a cryptographically secure random IV.
    """
    return os.urandom(block_size)

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
