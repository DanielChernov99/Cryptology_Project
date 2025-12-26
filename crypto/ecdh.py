import os
from crypto.elliptic_curve import G, ORDER, POINT_INFINITY, is_on_curve, scalar_mult
from utils import int_to_bytes
from utils import hash_bytes

def generate_keys():
    while True:
        private_key = int.from_bytes(os.urandom(32), "big") % ORDER
        if private_key != 0:
            break
    public_key = scalar_mult(private_key, G)
    return private_key, public_key

def compute_shared_secret(my_private_key, other_public_key):
    if not is_on_curve(other_public_key):
        raise ValueError("Invalid public key received")
    shared_point = scalar_mult(my_private_key, other_public_key)
    if shared_point is POINT_INFINITY:
        raise ValueError("Invalid shared secret (point at infinity)")
    x_coord = shared_point[0]
    x_bytes = int_to_bytes(x_coord, 32)
    return hash_bytes(x_bytes)

if __name__ == "__main__":
    priv1, pub1 = generate_keys()
    priv2, pub2 = generate_keys()
    secret1 = compute_shared_secret(priv1, pub2)
    secret2 = compute_shared_secret(priv2, pub1)
    print("Shared secrets equal:", secret1 == secret2)
