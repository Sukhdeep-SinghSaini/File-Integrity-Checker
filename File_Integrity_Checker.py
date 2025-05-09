# Importing required libraries for GUI, file handling, hashing, and monitoring
import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext
import threading
import hashlib
import os
import json
import time
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

# File to store the original hash values of files
HASH_RECORD_FILE = "file_hashes.json"

# 🔐 Function to calculate SHA-256 hash of a file to detect any changes
def calculate_file_hash(file_path):
    hasher = hashlib.sha256()
    try:
        with open(file_path, 'rb') as f:
            # Read the file in chunks to avoid memory issues with large files
            while chunk := f.read(8192):
                hasher.update(chunk)
        return hasher.hexdigest()
    except:
        # If file can't be accessed (e.g., deleted), return None
        return None

# Load stored hash values from the JSON record file
def load_hashes():
    if not os.path.exists(HASH_RECORD_FILE):
        return {}
    with open(HASH_RECORD_FILE, 'r') as f:
        return json.load(f)

# Save updated hash values back to the JSON record file
def save_hashes(hashes):
    with open(HASH_RECORD_FILE, 'w') as f:
        json.dump(hashes, f, indent=2)

# 🧠 File event handler class using watchdog to respond to file system changes
class ChangeHandler(FileSystemEventHandler):
    def __init__(self, log_callback):
        self.hashes = load_hashes()
        self.log_callback = log_callback

    # Update hash value of a file if it was modified or created
    def update_hash(self, path):
        if os.path.isfile(path):
            new_hash = calculate_file_hash(path)
            if new_hash:
                self.hashes[path] = new_hash
                self.log_callback(f"🔄 MODIFIED → {os.path.basename(path)}", "yellow")
                save_hashes(self.hashes)

    # Watchdog calls this when a file is modified
    def on_modified(self, event):
        self.update_hash(event.src_path)

    # Watchdog calls this when a file is created
    def on_created(self, event):
        self.update_hash(event.src_path)
        self.log_callback(f"✨ CREATED → {os.path.basename(event.src_path)}", "lime")

    # Watchdog calls this when a file is deleted
    def on_deleted(self, event):
        if event.src_path in self.hashes:
            del self.hashes[event.src_path]
            save_hashes(self.hashes)
            self.log_callback(f"❌ DELETED → {os.path.basename(event.src_path)}", "red")

# 💻 Main GUI Application Class
class RGBFileMonitorApp:
    def __init__(self, root):
        self.root = root
        self.root.title("🌈 File Integrity Checker")  # Set window title
        self.root.geometry("850x550")  # Set window size
        self.root.configure(bg="#222222")  # Set background color
        self.directory = tk.StringVar()  # Variable to hold selected folder path
        self.monitoring = False
        self.observer = None
        self.animation_running = False

        # Set up the UI components
        self.build_ui()

    # 🧱 Create and place all GUI components
    def build_ui(self):
        # Title label at the top
        self.title_label = tk.Label(self.root, text="🌈 File Integrity Checker", font=("Helvetica Neue", 20, "bold"),
                                    bg="#222222", fg="#FFFFFF")
        self.title_label.pack(pady=10)

        # Row for folder selection
        top_frame = tk.Frame(self.root, bg="#222222")
        top_frame.pack(pady=10)

        tk.Label(top_frame, text="Folder:", font=("Helvetica Neue", 11), fg="white", bg="#222222").pack(side=tk.LEFT, padx=5)
        tk.Entry(top_frame, textvariable=self.directory, width=50, font=("Helvetica Neue", 11)).pack(side=tk.LEFT, padx=5)
        tk.Button(top_frame, text="Browse", bg="#444444", fg="white", font=("Helvetica Neue", 10),
                  command=self.browse_folder, activebackground="#666666", relief="flat").pack(side=tk.LEFT)

        # Control buttons (Start, Stop, Clear)
        btn_frame = tk.Frame(self.root, bg="#222222")
        btn_frame.pack(pady=20)

        self.start_btn = self.create_darker_button(btn_frame, "▶ START", "#007502", self.start_monitoring)
        self.start_btn.grid(row=0, column=0, padx=15)

        self.stop_btn = self.create_darker_button(btn_frame, "⏹ STOP", "#AB0000", self.stop_monitoring, state=tk.DISABLED)
        self.stop_btn.grid(row=0, column=1, padx=15)

        self.clear_btn = self.create_darker_button(btn_frame, "🧹 CLEAR", "#808080", self.clear_log)
        self.clear_btn.grid(row=0, column=2, padx=15)

        # Status label showing monitoring state
        self.status = tk.Label(self.root, text="⛔ STATUS: Not Monitoring", font=("Helvetica Neue", 10, "italic"),
                               bg="#222222", fg="gray")
        self.status.pack(anchor="w", padx=20, pady=(0, 5))

        # Scrollable text area for logs
        self.log_box = scrolledtext.ScrolledText(self.root, wrap=tk.WORD, height=20, font=("Helvetica Neue", 10),
                                                 bg="#333333", fg="white", insertbackground="white")
        self.log_box.pack(fill=tk.BOTH, padx=20, pady=10, expand=True)

    # 🕹️ Helper to create a button with hover effect
    def create_darker_button(self, parent, text, color, command, state=tk.NORMAL):
        button = tk.Button(parent, text=text, font=("Helvetica Neue", 12, "bold"), bg=color, fg="white", command=command,
                           state=state, relief="flat", width=15, height=2)
        button.bind("<Enter>", lambda e: self.on_hover(button, color))
        button.bind("<Leave>", lambda e: self.on_leave(button, color))
        return button

    # Mouse hover: darken the button color
    def on_hover(self, button, color):
        darker_color = self.darken_color(color)
        button.config(bg=darker_color)

    # Mouse leave: restore original button color
    def on_leave(self, button, color):
        button.config(bg=color)

    # Convert color hex code to a darker shade
    def darken_color(self, color):
        r = int(color[1:3], 16)
        g = int(color[3:5], 16)
        b = int(color[5:7], 16)
        r = max(r - 30, 0)
        g = max(g - 30, 0)
        b = max(b - 30, 0)
        return f"#{r:02x}{g:02x}{b:02x}"

    # Open a dialog to browse and select a folder
    def browse_folder(self):
        folder = filedialog.askdirectory()
        if folder:
            self.directory.set(folder)

    # Log a message with timestamp and optional color
    def log(self, message, color="white"):
        timestamp = time.strftime("%H:%M:%S")
        self.log_box.insert(tk.END, f"[{timestamp}] {message}\n")
        self.log_box.tag_add(color, "end-2l", "end-1l")
        self.log_box.tag_config(color, foreground=color)
        self.fade_in_log()
        self.log_box.see(tk.END)

    # Begin fade-in animation for new log entries
    def fade_in_log(self):
        if not self.animation_running:
            self.animation_running = True
            for i in range(10):
                self.root.after(i * 100, lambda i=i: self.update_log_opacity(i))
            self.root.after(1000, lambda: self.reset_log_opacity())

    # Change log entry text color to simulate fading
    def update_log_opacity(self, index):
        self.log_box.tag_config("faded", foreground=f"#{index * 10}{index * 10}{index * 10}")
        self.log_box.tag_add("faded", "end-2l", "end-1l")

    # Restore log color after fade animation
    def reset_log_opacity(self):
        self.animation_running = False
        self.log_box.tag_remove("faded", "1.0", "end")

    # Clear all log messages
    def clear_log(self):
        self.log_box.delete(1.0, tk.END)

    # 🔍 Start folder monitoring using watchdog
    def start_monitoring(self):
        path = self.directory.get()
        if not os.path.isdir(path):
            messagebox.showerror("Error", "Please choose a valid folder.")
            return

        self.handler = ChangeHandler(self.log)
        self.observer = Observer()
        self.observer.schedule(self.handler, path, recursive=True)
        self.observer.start()
        self.monitoring = True
        self.status.config(text="✅ STATUS: Monitoring", fg="#00FF7F")
        self.log(f"🟢 Monitoring started on: {path}", "cyan")

        self.start_btn.config(state=tk.DISABLED)
        self.stop_btn.config(state=tk.NORMAL)

        # Run monitoring loop in background thread
        threading.Thread(target=self.monitor_thread, daemon=True).start()

    # ⛔ Stop monitoring process and clean up
    def stop_monitoring(self):
        if self.monitoring:
            self.observer.stop()
            self.observer.join()
            self.monitoring = False
            self.status.config(text="⛔ STATUS: Not Monitoring", fg="gray")
            self.log("🔴 Monitoring stopped.", "red")

        self.start_btn.config(state=tk.NORMAL)
        self.stop_btn.config(state=tk.DISABLED)

    # Keep the monitor alive until monitoring is turned off
    def monitor_thread(self):
        while self.monitoring:
            time.sleep(1)

    # Gracefully shut down the app when window is closed
    def on_close(self):
        self.stop_monitoring()
        self.root.destroy()

# 🔥 Launch the GUI application
if __name__ == "__main__":
    root = tk.Tk()
    app = RGBFileMonitorApp(root)
    root.protocol("WM_DELETE_WINDOW", app.on_close)
    root.mainloop()
