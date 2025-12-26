from secure_system import SecureMessengerSystem

def main():
    system = SecureMessengerSystem()

    while True:
        print("\n--- SYSTEM MENU ---")
        if system.current_user:
            print(f"User: {system.current_user.username}")
            print("1. Send Message")
            print("2. Inbox")
            print("3. Logout")
        else:
            print("1. Register")
            print("2. Login")
            print("3. Exit")

        choice = input(">> ")

        if not system.current_user:
            if choice == "1":
                u = input("User: ")
                p = input("Pass: ")
                print(system.register(u, p))
            elif choice == "2":
                u = input("User: ")
                p = input("Pass: ")
                print(system.login(u, p))
            elif choice == "3":
                break
        else:
            if choice == "1":
                to = input("To: ")
                msg = input("Message: ")
                print(system.send_message(to, msg))
            elif choice == "2":
                inbox = system.read_inbox()
                print(f"\nYou have {len(inbox)} messages:")
                for m in inbox:
                    print(f"[*] From {m['sender']} [{m['status']}]: {m['text']}")
            elif choice == "3":
                print(system.logout())

if __name__ == "__main__":
    main()