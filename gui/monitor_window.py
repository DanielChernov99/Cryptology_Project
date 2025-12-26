import tkinter as tk
from tkinter import scrolledtext
import datetime

class MonitorWindow(tk.Toplevel):
    def __init__(self, parent):
        super().__init__(parent)
        self.title("Cryptographic Workflow Monitor")
        self.geometry("500x600")
        
        # Make sure checking this window doesn't close the main app, just hides it
        self.protocol("WM_DELETE_WINDOW", self.withdraw)

        tk.Label(self, text="Real-Time Cryptographic Operations", 
                 font=("Courier New", 12, "bold"), bg="black", fg="#00ff00").pack(fill=tk.X)

        # Scrolled Text Area for logs
        self.log_area = scrolledtext.ScrolledText(self, state='disabled', bg="black", fg="#00ff00", font=("Consolas", 10))
        self.log_area.pack(expand=True, fill=tk.BOTH)

    def log_event(self, title, details):
        """Adds a new event to the monitor window."""
        timestamp = datetime.datetime.now().strftime("%H:%M:%S")
        
        self.log_area.config(state='normal')
        
        # Insert Header
        self.log_area.insert(tk.END, f"\n[{timestamp}] === {title} ===\n", "header")
        
        # Insert Details
        self.log_area.insert(tk.END, f"{details}\n", "body")
        self.log_area.insert(tk.END, "-"*40 + "\n", "separator")
        
        # Auto-scroll to bottom
        self.log_area.see(tk.END)
        self.log_area.config(state='disabled')
        
        # Styling tags
        self.log_area.tag_config("header", foreground="cyan", font=("Consolas", 10, "bold"))
        self.log_area.tag_config("body", foreground="#00ff00")
        self.log_area.tag_config("separator", foreground="gray")