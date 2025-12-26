import sys

def main():
    print("=== Cryptology Project Launcher ===")
    print("1. Run CLI Mode")
    print("2. Run GUI Mode")
    
    choice = input("Select mode (1/2): ")

    if choice == '1':
        from controllers.cli_controller import CLIController
        app = CLIController()
        app.run()
        
    elif choice == '2':
        try:
            from gui.app import CryptologyGUI
            app = CryptologyGUI()
            app.run()
        except ImportError as e:
            print(f"[ERROR] Could not load GUI: {e}")
            print("Ensure tkinter is installed (standard in Python).")
    
    else:
        print("Invalid selection.")

if __name__ == "__main__":
    main()