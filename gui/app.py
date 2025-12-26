import tkinter as tk
from core.user_manager import UserManager
from core.secure_messenger import SecureMessenger
from gui.auth_frame import AuthFrame
from gui.chat_frame import ChatFrame
from gui.monitor_window import MonitorWindow 

class CryptologyGUI(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Crypto Project - Secure Messenger")
        self.geometry("600x500")

        # --- 1. Setup Monitor Window (Hidden by default) ---
        self.monitor = MonitorWindow(self)
        self.monitor.withdraw() # Hide initially

        # Define the callback function that Core will use to log events
        def on_core_log(title, data):
            self.monitor.log_event(title, data)

        # --- 2. Initialize Core Logic with Logger ---
        self.user_manager = UserManager(debug_callback=on_core_log)
        self.messenger = SecureMessenger(self.user_manager, debug_callback=on_core_log)

        # --- 3. Setup Main UI Container ---
        self.container = tk.Frame(self)
        self.container.pack(fill="both", expand=True)

        self.frames = {}

        # Initialize Frames
        self.frames["Auth"] = AuthFrame(self.container, self)
        self.frames["Chat"] = ChatFrame(self.container, self)

        self.frames["Auth"].grid(row=0, column=0, sticky="nsew")
        self.frames["Chat"].grid(row=0, column=0, sticky="nsew")

        # --- 4. Create Menu ---
        self.create_menu()

        # Show initial screen
        self.show_frame("Auth")

    def create_menu(self):
        menubar = tk.Menu(self)
        
        # Debug Menu
        debug_menu = tk.Menu(menubar, tearoff=0)
        debug_menu.add_command(label="Show Workflow Monitor", command=self.show_monitor)
        menubar.add_cascade(label="Debug", menu=debug_menu)
        
        self.config(menu=menubar)

    def show_monitor(self):
        self.monitor.deiconify() # Show the window
        self.monitor.lift()      # Bring to front

    def show_frame(self, page_name):
        frame = self.frames[page_name]
        frame.tkraise()

    def on_login_success(self, user_obj):
        # Pass user data to chat frame
        self.frames["Chat"].set_user(user_obj)
        self.show_frame("Chat")

    def logout(self):
        self.show_frame("Auth")

    def run(self):
        self.mainloop()