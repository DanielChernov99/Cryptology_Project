import os
import sys

# Adjust paths (in case running not as a module)
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from crypto.elliptic_curve import scalar_mult, POINT_INFINITY, is_on_curve
from crypto.gost import encrypt_cbc, decrypt_cbc
from utils import hash_bytes, int_to_bytes, generate_iv,str_to_bytes,bytes_to_str
from crypto.ecdh import generate_keys 

# === Important Addition: Import signature functions ===
# (Assumption: You saved the DSA code in crypto/dsa.py)
from crypto.dsa import sign_message, verify_signature

# ===============================
# Step 1: ECDH + DSA Key Generation
# ===============================

print("=== 1. Key Generation ===")

# ALICE
# Alice uses the same private key for both shared secret and signing
alice_priv, alice_pub = generate_keys()
print("Alice Private Key:", alice_priv)
print("Alice Public Key:", alice_pub)

# BOB
bob_priv, bob_pub = generate_keys()
print("Bob Private Key:", bob_priv)
print("Bob Public Key:", bob_pub)

# ===============================
# Step 2: Shared Secret Generation (ECDH)
# ===============================

def compute_shared_secret(my_private, other_public):
    if not is_on_curve(other_public):
        raise ValueError("Invalid public key")
    shared_point = scalar_mult(my_private, other_public)
    if shared_point is POINT_INFINITY:
        raise ValueError("Point at infinity!")
    x_bytes = int_to_bytes(shared_point[0], 32)
    return hash_bytes(x_bytes)

alice_secret = compute_shared_secret(alice_priv, bob_pub)
bob_secret = compute_shared_secret(bob_priv, alice_pub)

print("\n=== 2. Key Exchange (ECDH) ===")
print("Alice Shared Secret:", alice_secret.hex())
print("Bob Shared Secret  :", bob_secret.hex())
print("Secrets match?     :", alice_secret == bob_secret)

# ===============================
# Step 3: Sign + Encrypt (Alice Sends)
# ===============================

print("\n=== 3. Alice Sends Message (Sign -> Encrypt) ===")
message = str_to_bytes("Pay me 100 NIS")
print("Original Message:", bytes_to_str(message))

# A. Digital Signature (DSA)
# Alice signs with her *private* key
signature = sign_message(alice_priv, message)
print(f"Signature generated: {signature}")

# B. Encryption (GOST)
# Alice encrypts with the *shared* key
iv = generate_iv(8)  # 8 bytes random IV
ciphertext = encrypt_cbc(message, alice_secret, iv)
print("Ciphertext (hex):", ciphertext.hex())

# ===============================
# Step 4: Decrypt + Verify (Bob Receives)
# ===============================

print("\n=== 4. Bob Receives Message (Decrypt -> Verify) ===")

# A. Decrypt the message
# Bob uses the *shared* key
decrypted = decrypt_cbc(ciphertext, bob_secret, iv)
print("Decrypted Message:", bytes_to_str(decrypted))

# B. Verify Signature
# Bob uses Alice's *public* key to verify it's her
is_valid = verify_signature(alice_pub, decrypted, signature)

if is_valid:
    print(">>> SUCCESS: Signature verified! Message is authentically from Alice.")
else:
    print(">>> ERROR: Invalid signature! Message might be fake.")