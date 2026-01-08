import sys
import os

# Add parent directory to path to import core modules
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.user_manager import UserManager
from core.secure_messenger import SecureMessenger

class CLIController:
    def __init__(self):
        # Define a callback to print logs to the console
        def log_printer(title, details):
            print(f"\n[LOG] === {title} ===")
            print(details)
            print("-" * 40)

        # Initialize Core Logic with the logger callback
        # This connects the print messages to the core logic events
        self.user_manager = UserManager(debug_callback=log_printer)
        self.messenger = SecureMessenger(self.user_manager, debug_callback=log_printer)
        self.current_user = None

    def run(self):
        print("=== Cryptology Project: CLI Mode ===")

        while True:
            if not self.current_user:
                self._show_login_menu()
            else:
                self._show_user_menu()

    def _show_login_menu(self):
        print("\n--- Main Menu ---")
        print("1. Register")
        print("2. Login")
        print("3. Exit")
        choice = input("Select option: ")

        if choice == '1':
            u = input("Choose Username: ")
            p = input("Choose Password: ")
            success, msg = self.user_manager.register(u, p)
            print(f"Result: {msg}")

        elif choice == '2':
            u = input("Username: ")
            p = input("Password: ")
            user_obj, msg = self.user_manager.login(u, p)
            if user_obj:
                self.current_user = user_obj
                print(f"Welcome back, {u}!")
            else:
                print(f"Error: {msg}")
        
        elif choice == '3':
            print("Goodbye.")
            sys.exit()

    def _show_user_menu(self):
        print(f"\n--- User: {self.current_user['username']} ---")
        print("1. Send Message")
        print("2. Check Inbox")
        print("3. Logout")
        choice = input("Select option: ")

        if choice == '1':
            recipient = input("To (Username): ")
            content = input("Message: ")
            # The log_printer will handle printing the encryption details during this call
            success, msg = self.messenger.send_message(self.current_user, recipient, content)
            if success:
                print(f"[SUCCESS] {msg}")
            else:
                print(f"[ERROR] {msg}")

        elif choice == '2':
            # The log_printer will handle printing the decryption details during this call
            messages = self.messenger.check_inbox(self.current_user)
            if not messages:
                print("No new messages.")
            else:
                print(f"\nYou have {len(messages)} messages:")
                for m in messages:
                    print("-" * 30)
                    print(f"From: {m['sender']}")
                    print(f"Time: {m['timestamp']}")
                    print(f"Status: {m['status']}")
                    print(f"Content: {m['content']}")
                    print("-" * 30)
        
        elif choice == '3':
            self.current_user = None
            print("Logged out.")