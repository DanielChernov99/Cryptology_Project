import tkinter as tk
from tkinter import messagebox, scrolledtext

class ChatFrame(tk.Frame):
    def __init__(self, parent, controller):
        super().__init__(parent)
        self.controller = controller
        
        # Header
        self.lbl_welcome = tk.Label(self, text="Welcome", font=("Arial", 14))
        self.lbl_welcome.pack(pady=10)

        # Actions Frame (Refresh / Logout)
        top_frame = tk.Frame(self)
        top_frame.pack(fill=tk.X, padx=10)
        tk.Button(top_frame, text="Refresh Inbox", command=self.load_messages).pack(side=tk.LEFT)
        tk.Button(top_frame, text="Logout", command=self.controller.logout).pack(side=tk.RIGHT)

        # Messages Area
        tk.Label(self, text="Inbox:").pack(anchor=tk.W, padx=10, pady=(10,0))
        self.txt_display = scrolledtext.ScrolledText(self, height=10, state='disabled')
        self.txt_display.pack(padx=10, pady=5, fill=tk.BOTH, expand=True)

        # Send Area
        send_frame = tk.Frame(self, bd=1, relief=tk.SUNKEN)
        send_frame.pack(fill=tk.X, padx=10, pady=10)
        
        tk.Label(send_frame, text="To:").pack(side=tk.LEFT, padx=5)
        self.entry_recipient = tk.Entry(send_frame, width=15)
        self.entry_recipient.pack(side=tk.LEFT, padx=5)
        
        tk.Label(send_frame, text="Msg:").pack(side=tk.LEFT, padx=5)
        self.entry_msg = tk.Entry(send_frame)
        self.entry_msg.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)
        
        tk.Button(send_frame, text="Send", command=self.send_msg).pack(side=tk.LEFT, padx=5)

    def set_user(self, user_obj):
        self.current_user = user_obj
        self.lbl_welcome.config(text=f"User: {user_obj['username']}")
        self.load_messages()

    def load_messages(self):
        # Clear display
        self.txt_display.config(state='normal')
        self.txt_display.delete(1.0, tk.END)
        
        # Fetch from core logic
        msgs = self.controller.messenger.check_inbox(self.current_user)
        
        if not msgs:
            self.txt_display.insert(tk.END, "No messages.\n")
        else:
            for m in msgs:
                display_str = f"From: {m['sender']} | {m['status']}\nContent: {m['content']}\n{'-'*30}\n"
                self.txt_display.insert(tk.END, display_str)
        
        self.txt_display.config(state='disabled')

    def send_msg(self):
        recipient = self.entry_recipient.get()
        content = self.entry_msg.get()
        
        if not recipient or not content:
            return

        success, msg = self.controller.messenger.send_message(self.current_user, recipient, content)
        
        if success:
            messagebox.showinfo("Sent", msg)
            self.entry_msg.delete(0, tk.END)
        else:
            messagebox.showerror("Error", msg)