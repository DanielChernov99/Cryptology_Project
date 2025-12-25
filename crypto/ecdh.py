import os
from utils.encoding import int_to_bytes
from crypto.hash_utils import hash_bytes


# --- Curve Parameters (secp256k1 - Bitcoin's Curve) ---
# y^2 = x^3 + 7 over F256-bit prime field
P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
A = 0
B = 7
G_X = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
G_Y = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
ORDER = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

G = (G_X, G_Y)
POINT_INFINITY = None

def _is_on_curve(point):
    """
    Check whether a point lies on the elliptic curve.
    """
    if point is POINT_INFINITY:
        return True

    x, y = point
    return (y * y - (x * x * x + A * x + B)) % P == 0

def _point_add(p1, p2):
    """
    Add two points on the elliptic curve.
    """
    if p1 is POINT_INFINITY:
        return p2
    if p2 is POINT_INFINITY:
        return p1

    x1, y1 = p1
    x2, y2 = p2

    # P + (-P) = infinity
    if x1 == x2 and (y1 + y2) % P == 0:
        return POINT_INFINITY

    # Point doubling
    if p1 == p2:
        inv = pow(2 * y1, P - 2, P)
        slope = (3 * x1 * x1 + A) * inv
    else:
        # Point addition
        inv = pow(x2 - x1, P - 2, P)
        slope = (y2 - y1) * inv

    slope %= P

    x3 = (slope * slope - x1 - x2) % P
    y3 = (slope * (x1 - x3) - y1) % P

    return (x3, y3)

def _scalar_mult(k, point):
    """
    Scalar multiplication using the double-and-add algorithm.
    """
    if k % ORDER == 0 or point is POINT_INFINITY:
        return POINT_INFINITY

    result = POINT_INFINITY
    addend = point

    while k > 0:
        if k & 1:
            result = _point_add(result, addend)
        addend = _point_add(addend, addend)
        k >>= 1

    return result


# --- Public API ---

def generate_keys():
    """
    Generate an ECDH private/public key pair.

    Returns:
        private_key (int)
        public_key (tuple[int, int])
    """
    while True:
        private_key = int.from_bytes(os.urandom(32), "big") % ORDER
        if private_key != 0:
            break

    public_key = _scalar_mult(private_key, G)

    if not _is_on_curve(public_key):
        raise ValueError("Generated public key is not on the curve")

    return private_key, public_key

def compute_shared_secret(my_private_key, other_public_key):
    """
    Compute ECDH shared secret and derive a symmetric key using hashing.

    Returns:
        symmetric_key (bytes)
    """
    if not _is_on_curve(other_public_key):
        raise ValueError("Invalid public key received")

    shared_point = _scalar_mult(my_private_key, other_public_key)

    if shared_point is POINT_INFINITY:
        raise ValueError("Invalid shared secret (point at infinity)")

    x_coord = shared_point[0]
    x_bytes = int_to_bytes(x_coord, 32)

    # Key Derivation Function (KDF) to insure uniform randomness and proper key length
    return hash_bytes(x_bytes)