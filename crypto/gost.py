import os
from utils import generate_iv

# ======================================================
# GOST 28147-89 Parameters
# ======================================================

BLOCK_SIZE = 8  # 64 bits

# Standard Test S-Box (RFC 5830 style / CryptoPro)
S_BOX = [
    [4,10,9,2,13,8,0,14,6,11,1,12,7,15,5,3],
    [14,11,4,12,6,13,15,10,2,3,8,1,0,7,5,9],
    [5,8,1,13,10,3,4,2,14,15,12,7,6,0,9,11],
    [7,13,10,1,0,8,9,15,14,4,6,12,11,2,5,3],
    [6,12,7,1,5,15,13,8,4,10,9,14,0,3,11,2],
    [4,11,10,0,7,2,1,13,3,6,8,5,9,12,15,14],
    [13,11,4,1,3,15,5,9,0,10,14,7,6,8,2,12],
    [1,15,13,0,5,7,10,4,9,2,3,14,6,11,8,12],
]

# ======================================================
# Helper Functions
# ======================================================

def _xor_bytes(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))

def _pad(data: bytes) -> bytes:
    # PKCS#7 Padding
    padding_len = BLOCK_SIZE - (len(data) % BLOCK_SIZE)
    return data + bytes([padding_len] * padding_len)

def _unpad(data: bytes) -> bytes:
    # PKCS#7 Unpadding
    if not data:
        raise ValueError("Data is empty")
    padding_len = data[-1]
    if padding_len < 1 or padding_len > BLOCK_SIZE:
        raise ValueError("Invalid padding length")
    if data[-padding_len:] != bytes([padding_len] * padding_len):
        raise ValueError("Invalid padding bytes")
    return data[:-padding_len]

def _split_blocks(data: bytes):
    return [data[i:i + BLOCK_SIZE] for i in range(0, len(data), BLOCK_SIZE)]

# ======================================================
# GOST Core Cipher
# ======================================================

def _f_function(right: int, subkey: int) -> int:
    # Modular addition 2^32
    x = (right + subkey) % (2**32)

    # S-Box Substitution
    result = 0
    for i in range(8):
        nibble = (x >> (4 * i)) & 0xF
        result |= S_BOX[i][nibble] << (4 * i)

    # Rotate Left 11
    return ((result << 11) | (result >> (32 - 11))) & 0xFFFFFFFF

def _round(left: int, right: int, subkey: int):
    # Feistel Step: New_Right = Old_Left XOR f(Old_Right, K)
    # New_Left = Old_Right
    return right, left ^ _f_function(right, subkey)

def _generate_subkeys(key: bytes):
    # Split 256-bit key into 8 32-bit integers (Little Endian)
    return [
        int.from_bytes(key[i*4:(i+1)*4], "little")
        for i in range(8)
    ]

def _encrypt_block(block: bytes, subkeys):
    left = int.from_bytes(block[:4], "little")
    right = int.from_bytes(block[4:], "little")

    # Rounds 1-24: Keys 0..7 (3 times)
    for i in range(24):
        left, right = _round(left, right, subkeys[i % 8])

    # Rounds 25-32: Keys 7..0 (1 time, reversed)
    for i in range(8):
        left, right = _round(left, right, subkeys[7 - i])

    # Output: Right || Left
    return (
        right.to_bytes(4, "little") +
        left.to_bytes(4, "little")
    )

def _decrypt_block(block: bytes, subkeys):
    left = int.from_bytes(block[:4], "little")
    right = int.from_bytes(block[4:], "little")

    # Rounds 1-8: Keys 0..7 (1 time)
    for i in range(8):
        left, right = _round(left, right, subkeys[i])

    # Rounds 9-32: Keys 7..0 (3 times, reversed)
    for i in range(24):
        left, right = _round(left, right, subkeys[(7 - i) % 8])

    # Output: Right || Left
    return (
        right.to_bytes(4, "little") +
        left.to_bytes(4, "little")
    )

# ======================================================
# Public API: CBC Mode (Adjusted for Main.py)
# ======================================================

def encrypt_cbc(plaintext: bytes, key: bytes, iv: bytes) -> bytes:
    """
    Encrypts data using GOST in CBC mode.
    Arguments:
      plaintext: The data to encrypt.
      key: 32 bytes (256 bits) session key.
      iv: 8 bytes (64 bits) initialization vector.
    Returns:
      ciphertext (bytes)
    """
    if len(key) != 32:
        raise ValueError("GOST key must be 256 bits")
    if len(iv) != BLOCK_SIZE:
        raise ValueError("IV must be 64 bits")

    subkeys = _generate_subkeys(key)
    padded = _pad(plaintext)
    blocks = _split_blocks(padded)

    ciphertext = b""
    prev = iv

    for block in blocks:
        # CBC: XOR with previous ciphertext (or IV) BEFORE encryption
        block_input = _xor_bytes(block, prev)
        encrypted_block = _encrypt_block(block_input, subkeys)
        
        ciphertext += encrypted_block
        prev = encrypted_block

    return ciphertext

def decrypt_cbc(ciphertext: bytes, key: bytes, iv: bytes) -> bytes:
    """
    Decrypts data using GOST in CBC mode.
    """
    if len(key) != 32:
        raise ValueError("GOST key must be 256 bits")
    if len(iv) != BLOCK_SIZE:
        raise ValueError("IV must be 64 bits")

    subkeys = _generate_subkeys(key)
    blocks = _split_blocks(ciphertext)

    plaintext = b""
    prev = iv

    for block in blocks:
        # CBC: Decrypt, THEN XOR with previous ciphertext (or IV)
        decrypted_block = _decrypt_block(block, subkeys)
        plaintext_block = _xor_bytes(decrypted_block, prev)
        
        plaintext += plaintext_block
        prev = block

    return _unpad(plaintext)