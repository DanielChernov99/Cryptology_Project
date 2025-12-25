import os
from utils.encoding import int_to_bytes

# --- Curve Parameters (secp256k1 - Bitcoin's Curve) ---
# y^2 = x^3 + 7 over F256-bit prime field
P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
A = 0
B = 7
G_X = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
G_Y = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
ORDER = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

G = (G_X, G_Y)

def _point_add(p1, p2):
    """Adds two points on the elliptic curve."""
    if p1 is None: return p2
    if p2 is None: return p1
    
    x1, y1 = p1
    x2, y2 = p2
    
    if x1 == x2 and y1 != y2:
        return None 
    
    if x1 == x2:
        # Point Doubling
        inv = pow(2 * y1, P - 2, P)
        m = (3 * x1 * x1 + A) * inv
    else:
        # Point Addition
        inv = pow(x1 - x2, P - 2, P)
        m = (y1 - y2) * inv
        
    m = m % P
    x3 = (m * m - x1 - x2) % P
    y3 = (m * (x1 - x3) - y1) % P
    return (x3, y3)

def _scalar_mult(k, point):
    """Double-and-Add algorithm for scalar multiplication."""
    current = point
    result = None
    
    for bit in bin(k)[2:][::-1]:
        if bit == '1':
            result = _point_add(result, current)
        current = _point_add(current, current)
        
    return result

# --- Public API ---

def generate_keys():
    """
    Generates a private key (int) and a public key (tuple x,y).
    """
    # 1. Generate random private key in range [1, ORDER-1]
    private_key_bytes = os.urandom(32)
    private_key_int = int.from_bytes(private_key_bytes, 'big') % ORDER
    
    # 2. Calculate Public Key (Q = d * G)
    public_key_point = _scalar_mult(private_key_int, G)
    
    return private_key_int, public_key_point

def compute_shared_secret(my_private_key, other_public_key):
    """
    Derives the shared secret using ECDH.
    Returns the X coordinate of the shared point as bytes.
    """
    shared_point = _scalar_mult(my_private_key, other_public_key)
    
    if shared_point is None:
        raise ValueError("Invalid Shared Secret (Point at Infinity)")
    return int_to_bytes(shared_point[0], 32)