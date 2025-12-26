import os
from crypto.hash_utils import hash_to_int

# ======================================================
# DSA Parameters (Standard-sized, academic friendly)
# ======================================================
# These parameters are for educational purposes.
# In real systems, p is usually 2048 bits and q is 256 bits.

P = int(
    "86F1E3C7E5A9F7A5C2D8F5E4D1C9B7A3"
    "F1E2D3C4B5A6978877665544332211",
    16
)

Q = int(
    "996F967F6C8E388D9E28D01E205FBA957A5698B1",
    16
)

G = pow(2, (P - 1) // Q, P)

# ======================================================
# Key Generation
# ======================================================

def generate_keys():
    """
    Generate a DSA private/public key pair.

    Returns:
        private_key (x), public_key (y)
    """
    while True:
        x = int.from_bytes(os.urandom(32), "big") % Q
        if 1 <= x < Q:
            break

    y = pow(G, x, P)
    return x, y

# ======================================================
# DSA Signature
# ======================================================

def sign_message(private_key: int, message: bytes) -> tuple[int, int]:
    """
    Sign a message using classic DSA.

    Args:
        private_key: DSA private key (x).
        message: Message to sign (bytes).

    Returns:
        (r, s): DSA signature.
    """
    z = hash_to_int(message) % Q

    while True:
        k = int.from_bytes(os.urandom(32), "big") % Q
        if k == 0:
            continue

        r = pow(G, k, P) % Q
        if r == 0:
            continue

        k_inv = pow(k, Q - 2, Q)
        s = (k_inv * (z + private_key * r)) % Q

        if s != 0:
            return r, s

# ======================================================
# DSA Verification
# ======================================================

def verify_signature(public_key: int, message: bytes, signature: tuple[int, int]) -> bool:
    """
    Verify a DSA signature.

    Args:
        public_key: DSA public key (y).
        message: Original message (bytes).
        signature: (r, s)

    Returns:
        True if valid, False otherwise.
    """
    try:
        r, s = signature
    except (TypeError, ValueError):
        return False

    if not (1 <= r < Q and 1 <= s < Q):
        return False

    z = hash_to_int(message) % Q

    w = pow(s, Q - 2, Q)
    u1 = (z * w) % Q
    u2 = (r * w) % Q

    v = (pow(G, u1, P) * pow(public_key, u2, P)) % P
    v = v % Q

    return v == r

# ======================================================
# Self Test
# ======================================================

if __name__ == "__main__":
    priv, pub = generate_keys()

    msg = b"Pay 100 ILS to Bob"
    sig = sign_message(priv, msg)

    assert verify_signature(pub, msg, sig)
    assert not verify_signature(pub, b"Pay 200 ILS to Bob", sig)

    print("DSA test passed successfully")
