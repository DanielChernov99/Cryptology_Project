import os
from crypto.ecdh import (
    G,
    ORDER,
    _scalar_mult,
    _point_add,
    _is_on_curve,
    POINT_INFINITY
)
from crypto.hash_utils import hash_to_int


# ======================================================
# ECDSA - Elliptic Curve Digital Signature Algorithm
# ======================================================

def sign_message(private_key: int, message: bytes) -> tuple[int, int]:
    """
    Sign a message using ECDSA.

    Args:
        private_key: Signer's private key (int).
        message: Message to sign (bytes).

    Returns:
        (r, s): ECDSA signature.
    """
    # Hash message and reduce modulo curve order
    z = hash_to_int(message) % ORDER

    while True:
        # Generate nonce k such that 1 <= k < ORDER
        k = int.from_bytes(os.urandom(32), "big") % ORDER
        if k == 0:
            continue

        # Compute R = k * G
        R = _scalar_mult(k, G)
        if R is POINT_INFINITY:
            continue

        r = R[0] % ORDER
        if r == 0:
            continue

        # Compute s = k^-1 * (z + r * d) mod ORDER
        k_inv = pow(k, ORDER - 2, ORDER)
        s = (k_inv * (z + r * private_key)) % ORDER

        if s != 0:
            return r, s


def verify_signature(public_key_point, message: bytes, signature: tuple[int, int]) -> bool:
    """
    Verify an ECDSA signature.

    Args:
        public_key_point: Signer's public key (EC point).
        message: Original message (bytes).
        signature: (r, s) tuple.

    Returns:
        True if signature is valid, False otherwise.
    """
    try:
        r, s = signature
    except (TypeError, ValueError):
        return False

    # Validate signature range
    if not (1 <= r < ORDER and 1 <= s < ORDER):
        return False

    # Validate public key
    if public_key_point is POINT_INFINITY:
        return False

    if not _is_on_curve(public_key_point):
        return False

    # Hash message
    z = hash_to_int(message) % ORDER

    # Compute w = s^-1 mod ORDER
    w = pow(s, ORDER - 2, ORDER)

    # Compute u1, u2
    u1 = (z * w) % ORDER
    u2 = (r * w) % ORDER

    # Compute P = u1*G + u2*Q
    p1 = _scalar_mult(u1, G)
    p2 = _scalar_mult(u2, public_key_point)
    P = _point_add(p1, p2)

    if P is POINT_INFINITY:
        return False

    # Signature valid if x-coordinate matches r
    return (P[0] % ORDER) == r


# ======================================================
# Self Test
# ======================================================

if __name__ == "__main__":
    from crypto.ecdh import generate_keys

    priv, pub = generate_keys()
    msg = b"Pay 100 ILS to Bob"

    sig = sign_message(priv, msg)

    assert verify_signature(pub, msg, sig)
    assert not verify_signature(pub, b"Pay 200 ILS to Bob", sig)

    print("ECDSA test passed successfully")
