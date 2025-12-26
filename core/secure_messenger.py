import os
import json
import time
from crypto.ecdh import compute_shared_secret
from crypto.dsa import sign_message, verify_signature
from crypto.gost import encrypt_cbc, decrypt_cbc
from utils import generate_iv, str_to_bytes, bytes_to_str, bytes_to_hex, hex_to_bytes

MESSAGES_DIR = os.path.join("data", "messages")

class SecureMessenger:
    def __init__(self, user_manager):
        self.user_manager = user_manager
        if not os.path.exists(MESSAGES_DIR):
            os.makedirs(MESSAGES_DIR)

    def send_message(self, sender_user, recipient_name, message_text):
        # 1. Get recipient public keys
        recipient_keys = self.user_manager.get_public_keys(recipient_name)
        if not recipient_keys:
            return False, "Recipient not found."

        # 2. Compute Shared Secret (ECDH)
        # Using Sender's Private + Recipient's Public
        try:
            shared_secret = compute_shared_secret(sender_user["ecdh_priv"], recipient_keys["ecdh"])
        except ValueError as e:
            return False, f"Key Exchange Error: {e}"

        # 3. Sign the message (DSA)
        # Using Sender's Private DSA Key
        msg_bytes = str_to_bytes(message_text)
        signature = sign_message(sender_user["dsa_priv"], msg_bytes)

        # 4. Encrypt the message (GOST)
        # Using the Shared Secret
        iv = generate_iv(8)
        ciphertext = encrypt_cbc(msg_bytes, shared_secret, iv)

        # 5. Package the message
        # We need to send: IV, Ciphertext, Signature
        packet = {
            "sender": sender_user["username"],
            "recipient": recipient_name,
            "timestamp": time.time(),
            "iv": bytes_to_hex(iv),
            "ciphertext": bytes_to_hex(ciphertext),
            "signature": signature # Tuple (r, s)
        }

        # 6. Save to file (Simulating network send)
        filename = f"{recipient_name}_{int(time.time())}.msg"
        filepath = os.path.join(MESSAGES_DIR, filename)
        
        with open(filepath, "w") as f:
            json.dump(packet, f)

        return True, "Message sent securely."

    def check_inbox(self, active_user):
        """Reads all messages destined for the active user."""
        messages = []
        
        # Scan directory for files
        for filename in os.listdir(MESSAGES_DIR):
            if not filename.endswith(".msg"):
                continue
            
            filepath = os.path.join(MESSAGES_DIR, filename)
            try:
                with open(filepath, "r") as f:
                    packet = json.load(f)
            except:
                continue

            # Check if this message is for me
            if packet.get("recipient") != active_user["username"]:
                continue

            # === Process the Message ===
            sender_name = packet["sender"]
            
            # 1. Get Sender's Public Keys (for verification and ECDH)
            sender_keys = self.user_manager.get_public_keys(sender_name)
            if not sender_keys:
                messages.append({"sender": sender_name, "error": "Unknown sender"})
                continue

            # 2. Compute Shared Secret (ECDH) to decrypt
            # Using My Private + Sender's Public
            try:
                shared_secret = compute_shared_secret(active_user["ecdh_priv"], sender_keys["ecdh"])
            except:
                messages.append({"sender": sender_name, "error": "ECDH Failed"})
                continue

            # 3. Decrypt (GOST)
            iv = hex_to_bytes(packet["iv"])
            ciphertext = hex_to_bytes(packet["ciphertext"])
            try:
                decrypted_bytes = decrypt_cbc(ciphertext, shared_secret, iv)
            except:
                messages.append({"sender": sender_name, "error": "Decryption Failed"})
                continue

            # 4. Verify Signature (DSA)
            # Using Sender's DSA Public Key
            signature = tuple(packet["signature"]) # Convert list back to tuple
            is_valid = verify_signature(sender_keys["dsa"], decrypted_bytes, signature)

            status = "Verified" if is_valid else "FAKE/TAMPERED"
            
            messages.append({
                "sender": sender_name,
                "timestamp": packet["timestamp"],
                "content": bytes_to_str(decrypted_bytes),
                "status": status
            })

        return messages