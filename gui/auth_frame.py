import tkinter as tk
from tkinter import messagebox

class AuthFrame(tk.Frame):
    def __init__(self, parent, controller):
        super().__init__(parent)
        self.controller = controller # Reference to the main App class
        
        # UI Elements
        tk.Label(self, text="Secure Messenger Login", font=("Arial", 16)).pack(pady=20)
        
        tk.Label(self, text="Username:").pack()
        self.entry_user = tk.Entry(self)
        self.entry_user.pack()

        tk.Label(self, text="Password:").pack()
        self.entry_pass = tk.Entry(self, show="*")
        self.entry_pass.pack()

        # Buttons
        btn_frame = tk.Frame(self)
        btn_frame.pack(pady=20)
        
        tk.Button(btn_frame, text="Login", command=self.do_login, width=10).pack(side=tk.LEFT, padx=5)
        tk.Button(btn_frame, text="Register", command=self.do_register, width=10).pack(side=tk.LEFT, padx=5)

    def do_login(self):
        u = self.entry_user.get()
        p = self.entry_pass.get()
        
        # Access logic through the controller (app.py)
        user_obj, msg = self.controller.user_manager.login(u, p)
        
        if user_obj:
            messagebox.showinfo("Success", "Login Successful!")
            self.controller.on_login_success(user_obj)
        else:
            messagebox.showerror("Error", msg)

    def do_register(self):
        u = self.entry_user.get()
        p = self.entry_pass.get()
        
        if not u or not p:
            messagebox.showwarning("Warning", "Fields cannot be empty")
            return

        success, msg = self.controller.user_manager.register(u, p)
        if success:
            messagebox.showinfo("Success", msg)
        else:
            messagebox.showerror("Error", msg)