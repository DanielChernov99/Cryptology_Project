import tkinter as tk
from core.user_manager import UserManager
from core.secure_messenger import SecureMessenger
from gui.auth_frame import AuthFrame
from gui.chat_frame import ChatFrame

class CryptologyGUI(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Crypto Project - Secure Messenger")
        self.geometry("600x500")

        # Initialize Core Logic
        self.user_manager = UserManager()
        self.messenger = SecureMessenger(self.user_manager)

        # Container for screens
        self.container = tk.Frame(self)
        self.container.pack(fill="both", expand=True)

        # Dictionary to hold frames
        self.frames = {}

        # Initialize Frames
        self.frames["Auth"] = AuthFrame(self.container, self)
        self.frames["Chat"] = ChatFrame(self.container, self)

        self.frames["Auth"].grid(row=0, column=0, sticky="nsew")
        self.frames["Chat"].grid(row=0, column=0, sticky="nsew")

        # Show initial screen
        self.show_frame("Auth")

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