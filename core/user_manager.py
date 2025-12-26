import json
import os
import hashlib
from crypto.ecdh import generate_keys as gen_ecdh
from crypto.dsa import generate_keys as gen_dsa
from crypto.gost import encrypt_cbc, decrypt_cbc
from utils import bytes_to_hex, hex_to_bytes, int_to_bytes, bytes_to_int, str_to_bytes, bytes_to_str

DATA_DIR = "data"
USERS_FILE = os.path.join(DATA_DIR, "users.json")

class UserManager:
    def __init__(self):
        if not os.path.exists(DATA_DIR):
            os.makedirs(DATA_DIR)
        self.users = self._load_users()

    def _load_users(self):
        if not os.path.exists(USERS_FILE):
            return {}
        try:
            with open(USERS_FILE, "r") as f:
                return json.load(f)
        except:
            return {}

    def _save_users(self):
        with open(USERS_FILE, "w") as f:
            json.dump(self.users, f, indent=4)

    def _derive_key_from_password(self, password: str) -> bytes:
        """Creates a 32-byte key from the password for encrypting the private keys locally."""
        return hashlib.sha256(str_to_bytes(password)).digest()

    def register(self, username, password):
        if username in self.users:
            return False, "Username already exists."

        # 1. Generate new keys for the user
        dsa_priv, dsa_pub = gen_dsa()
        ecdh_priv, ecdh_pub = gen_ecdh()

        # 2. Encrypt private keys using the user's password (so we don't save them raw)
        pwd_key = self._derive_key_from_password(password)
        # Use a zero IV for local key storage simplicity (or random and store it)
        iv = bytes(8) 
        
        # We need to serialize private keys to bytes before encrypting
        dsa_priv_bytes = int_to_bytes(dsa_priv)
        ecdh_priv_bytes = int_to_bytes(ecdh_priv)

        # Encrypt
        enc_dsa_priv = encrypt_cbc(dsa_priv_bytes, pwd_key, iv)
        enc_ecdh_priv = encrypt_cbc(ecdh_priv_bytes, pwd_key, iv)

        # 3. Save public data and encrypted private data
        self.users[username] = {
            "dsa_public": dsa_pub,   # Tuple (G, Y, etc) or just public point/value
            "ecdh_public": ecdh_pub, # Point (x, y)
            "enc_dsa_priv": bytes_to_hex(enc_dsa_priv),
            "enc_ecdh_priv": bytes_to_hex(enc_ecdh_priv)
        }
        self._save_users()
        return True, "Registration successful."

    def login(self, username, password):
        if username not in self.users:
            return None, "User not found."

        user_data = self.users[username]
        pwd_key = self._derive_key_from_password(password)
        iv = bytes(8)

        try:
            # Attempt to decrypt private keys
            enc_dsa = hex_to_bytes(user_data["enc_dsa_priv"])
            enc_ecdh = hex_to_bytes(user_data["enc_ecdh_priv"])

            dsa_priv_bytes = decrypt_cbc(enc_dsa, pwd_key, iv)
            ecdh_priv_bytes = decrypt_cbc(enc_ecdh, pwd_key, iv)

            # Convert back to int
            dsa_priv = bytes_to_int(dsa_priv_bytes)
            ecdh_priv = bytes_to_int(ecdh_priv_bytes)
            
            # If successful, return a User session object (dict or class)
            # This object stays in memory only while the program runs
            active_user = {
                "username": username,
                "dsa_priv": dsa_priv,
                "dsa_pub": user_data["dsa_public"],
                "ecdh_priv": ecdh_priv,
                "ecdh_pub": user_data["ecdh_public"]
            }
            return active_user, "Login successful."
            
        except Exception as e:
            return None, "Incorrect password or corrupted data."

    def get_public_keys(self, username):
        """Returns the public keys of a target user (for sending them a message)."""
        if username not in self.users:
            return None
        return {
            "dsa": self.users[username]["dsa_public"],
            "ecdh": self.users[username]["ecdh_public"]
        }