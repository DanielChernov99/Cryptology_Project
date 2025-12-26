import os
import json
import time
from crypto.ecdh import compute_shared_secret
from crypto.dsa import sign_message, verify_signature
from crypto.gost import encrypt_cbc, decrypt_cbc
from utils import generate_iv, str_to_bytes, bytes_to_str, bytes_to_hex, hex_to_bytes

MESSAGES_DIR = os.path.join("data", "messages")

class SecureMessenger:
    def __init__(self, user_manager, debug_callback=None):
        """
        Initialize the Secure Messenger.
        :param user_manager: Reference to the UserManager (to look up public keys).
        :param debug_callback: A function to call for logging events (used by the GUI Monitor).
        """
        self.user_manager = user_manager
        self.debug_callback = debug_callback
        
        if not os.path.exists(MESSAGES_DIR):
            os.makedirs(MESSAGES_DIR)

    def _log(self, title, details):
        """Helper function to send logs to the monitor if a callback is set."""
        if self.debug_callback:
            self.debug_callback(title, details)

    def send_message(self, sender_user, recipient_name, message_text):
        self._log("SEND PROCESS START", f"Initiating secure message from '{sender_user['username']}' to '{recipient_name}'.")

        # 1. Get recipient public keys
        recipient_keys = self.user_manager.get_public_keys(recipient_name)
        if not recipient_keys:
            self._log("ERROR", f"Recipient '{recipient_name}' not found in database.")
            return False, "Recipient not found."

        # 2. Compute Shared Secret (ECDH)
        # Using Sender's Private + Recipient's Public
        self._log("ECDH KEY EXCHANGE", 
                  f"Sender Private: [HIDDEN]\n"
                  f"Recipient Public: {recipient_keys['ecdh']}\n"
                  f"Calculating shared secret point...")
        
        try:
            shared_secret = compute_shared_secret(sender_user["ecdh_priv"], recipient_keys["ecdh"])
            self._log("SHARED SECRET DERIVED", f"Shared Secret (SHA-256 of Point X): {shared_secret.hex().upper()}")
        except ValueError as e:
            self._log("ECDH ERROR", str(e))
            return False, f"Key Exchange Error: {e}"

        # 3. Sign the message (DSA)
        # Using Sender's Private DSA Key
        msg_bytes = str_to_bytes(message_text)
        self._log("DIGITAL SIGNATURE (DSA)", f"Signing message hash with '{sender_user['username']}' Private Key...")
        
        signature = sign_message(sender_user["dsa_priv"], msg_bytes)
        self._log("SIGNATURE GENERATED", f"Signature (r, s): {signature}")

        # 4. Encrypt the message (GOST)
        # Using the Shared Secret
        self._log("ENCRYPTION (GOST)", "Generating random IV and encrypting message using CBC mode...")
        iv = generate_iv(8)
        ciphertext = encrypt_cbc(msg_bytes, shared_secret, iv)
        
        self._log("ENCRYPTION COMPLETE", f"IV: {bytes_to_hex(iv)}\nCiphertext: {bytes_to_hex(ciphertext)}")

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
            
        self._log("NETWORK SIMULATION", f"Message packet saved to '{filename}'.")

        return True, "Message sent securely."

    def check_inbox(self, active_user):
        """Reads all messages destined for the active user."""
        messages = []
        found_count = 0
        
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

            found_count += 1
            sender_name = packet["sender"]
            
            # self._log("INBOX CHECK", f"Processing message from '{sender_name}'...")

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
            
            # Only log detailed crypto steps for new/unread messages if you want to avoid spam,
            # but for this demo, we can log the verification result.
            if is_valid:
                pass 
                # self._log("VERIFICATION SUCCESS", f"Message from {sender_name} verified successfully.")
            else:
                self._log("SECURITY WARNING", f"Invalid signature detected from {sender_name}!")

            messages.append({
                "sender": sender_name,
                "timestamp": packet["timestamp"],
                "content": bytes_to_str(decrypted_bytes),
                "status": status
            })

        if found_count > 0:
             # self._log("INBOX REFRESH", f"Found {found_count} messages for user.")
             pass

        return messages