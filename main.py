import sys
import os

# Add the current directory to sys.path to ensure imports work correctly
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from core.user_manager import UserManager
from core.secure_messenger import SecureMessenger

def main():
    # --- Initialize the engine (The same logic can be used for GUI later) ---
    user_manager = UserManager()
    messenger = SecureMessenger(user_manager)
    
    current_user = None # Variable to store the currently logged-in user

    print("=== Cryptology Project: Secure Data Exchange ===")

    while True:
        # State 1: User not logged in (Entry Menu)
        if not current_user:
            print("\n--- Main Menu ---")
            print("1. Register")
            print("2. Login")
            print("3. Exit")
            choice = input("Select option: ")

            if choice == '1':
                u = input("Choose Username: ")
                p = input("Choose Password: ")
                # Call the core logic
                success, msg = user_manager.register(u, p)
                print(f"Result: {msg}")

            elif choice == '2':
                u = input("Username: ")
                p = input("Password: ")
                # Call logic - returns user object if successful
                user_obj, msg = user_manager.login(u, p)
                if user_obj:
                    current_user = user_obj
                    print(f"Welcome back, {u}!")
                else:
                    print(f"Error: {msg}")
            
            elif choice == '3':
                print("Goodbye.")
                break

        # State 2: User logged in (Action Menu)
        else:
            print(f"\n--- User: {current_user['username']} ---")
            print("1. Send Message")
            print("2. Check Inbox")
            print("3. Logout")
            choice = input("Select option: ")

            if choice == '1':
                recipient = input("To (Username): ")
                content = input("Message: ")
                # Cryptographic operations happen internally; Main doesn't need to know details
                success, msg = messenger.send_message(current_user, recipient, content)
                if success:
                    print(f"[SUCCESS] {msg}")
                else:
                    print(f"[ERROR] {msg}")

            elif choice == '2':
                # Receive a list of message objects, not raw text
                messages = messenger.check_inbox(current_user)
                if not messages:
                    print("No new messages.")
                else:
                    print(f"\nYou have {len(messages)} messages:")
                    for m in messages:
                        print("-" * 30)
                        print(f"From: {m['sender']}")
                        print(f"Time: {m['timestamp']}")
                        print(f"Status: {m['status']}") # Verified / Fake
                        print(f"Content: {m['content']}")
                        print("-" * 30)
            
            elif choice == '3':
                current_user = None
                print("Logged out.")

if __name__ == "__main__":
    main()