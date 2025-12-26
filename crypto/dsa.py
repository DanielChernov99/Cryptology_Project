import os
from hashlib import sha256
from crypto.elliptic_curve import G, ORDER, POINT_INFINITY, is_on_curve, point_add, scalar_mult

def hash_to_int(message: bytes) -> int:
    return int.from_bytes(sha256(message).digest(), "big")

def mod_inv(a: int, n: int) -> int:
    t, newt = 0, 1
    r, newr = n, a
    while newr != 0:
        quotient = r // newr
        t, newt = newt, t - quotient * newt
        r, newr = newr, r - quotient * newr
    if r > 1:
        raise ValueError("a is not invertible")
    if t < 0:
        t += n
    return t

def generate_keys():
    while True:
        private_key = int.from_bytes(os.urandom(32), "big") % ORDER
        if private_key != 0:
            break
    public_key = scalar_mult(private_key, G)
    return private_key, public_key

def sign_message(private_key: int, message: bytes):
    z = hash_to_int(message) % ORDER
    while True:
        k = int.from_bytes(os.urandom(32), "big") % ORDER
        if k == 0:
            continue
        R = scalar_mult(k, G)
        r = R[0] % ORDER
        if r == 0:
            continue
        k_inv = mod_inv(k, ORDER)
        s = (k_inv * (z + r * private_key)) % ORDER
        if s != 0:
            return (r, s)

def verify_signature(public_key, message: bytes, signature):
    try:
        r, s = signature
    except Exception:
        return False
    if not (1 <= r < ORDER and 1 <= s < ORDER):
        return False
    z = hash_to_int(message) % ORDER
    w = mod_inv(s, ORDER)
    u1 = (z * w) % ORDER
    u2 = (r * w) % ORDER
    point = point_add(scalar_mult(u1, G), scalar_mult(u2, public_key))
    if point is POINT_INFINITY:
        return False
    v = point[0] % ORDER
    return v == r

if __name__ == "__main__":
    priv, pub = generate_keys()
    print("Private Key:", priv)
    print("Public Key:", pub)

    msg = b"Hello ECDSA"
    sig = sign_message(priv, msg)
    print("Signature:", sig)

    print("Valid?", verify_signature(pub, msg, sig))
