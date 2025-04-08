import tkinter as tk
from tkinter import simpledialog, scrolledtext, messagebox, font
import subprocess
import os
import threading
import queue
import re

# --- Styling constants for a modern look ---
BG_COLOR = "#ECE5DD"         # Overall background color
CHAT_BG_COLOR = "#FFFFFF"     # Chat display background
CHAT_FG_COLOR = "#303030"     # Chat text color
SENT_BG_COLOR = "#DCF8C6"     # Background for sent messages (light green)
ACCENT_COLOR = "#075E54"      # Accent color (for Send button)
FONT_FAMILY = "Helvetica"
FONT_SIZE = 12

# --- Regular expressions to filter out unwanted CLI output ---
FILTER_PATTERNS = [
    re.compile(r"^Menu:"), 
    re.compile(r"^Enter server"), 
    re.compile(r"^Enter your username:"), 
    re.compile(r"^Choice:"), 
    re.compile(r"Encrypted AES key hex:"), 
    re.compile(r"Decrypted AES key \(hex\):"),
    re.compile(r"^\[Info\] Sent to client:")
]

# --- ClientWindow class ---
class ClientWindow:
    def __init__(self, root, username, server_ip, port):
        self.root = root
        self.username = username
        self.server_ip = server_ip
        self.port = port
        self.process = None
        self.output_queue = queue.Queue()
        self.setup_gui()
        self.start_client()
        self.root.after(100, self.process_output)

    def setup_gui(self):
        self.root.title(f"Secure Messenger - {self.username}")
        self.root.geometry("600x500")
        self.root.configure(bg=BG_COLOR)
        self.custom_font = font.Font(family=FONT_FAMILY, size=FONT_SIZE)

        # Chat display (read-only)
        self.chat_area = scrolledtext.ScrolledText(
            self.root, wrap=tk.WORD, state=tk.DISABLED,
            font=self.custom_font, bg=CHAT_BG_COLOR,
            fg=CHAT_FG_COLOR, relief=tk.FLAT, bd=0
        )
        self.chat_area.pack(padx=10, pady=10, fill=tk.BOTH, expand=True)

        # Input frame
        self.input_frame = tk.Frame(self.root, bg=BG_COLOR)
        self.input_frame.pack(padx=10, pady=5, fill=tk.X)

        self.message_entry = tk.Entry(
            self.input_frame, font=self.custom_font, bg="white", fg="black", relief=tk.FLAT
        )
        self.message_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0,5))
        self.message_entry.bind("<Return>", lambda event: self.send_message())

        self.send_button = tk.Button(
            self.input_frame, text="Send", font=self.custom_font,
            bg=ACCENT_COLOR, fg="white", relief=tk.FLAT, command=self.send_message
        )
        self.send_button.pack(side=tk.RIGHT)

    def start_client(self):
        # Launch the CLI client (ClientApp) as a subprocess.
        client_path = os.path.join(os.path.dirname(__file__), "ClientApp")
        if not os.path.isfile(client_path):
            messagebox.showerror("Error", f"ClientApp not found at {client_path}")
            self.root.destroy()
            return

        try:
            self.process = subprocess.Popen(
                [client_path],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1
            )
        except Exception as e:
            messagebox.showerror("Error", f"Failed to start ClientApp: {e}")
            self.root.destroy()
            return

        # Send initial connection info (server IP, port, username)
        # (Each line must end with a newline exactly as expected.)
        init_data = f"{self.server_ip}\n{self.port}\n{self.username}\n"
        self._write_to_client(init_data)

        # Start threads to read output from stdout and stderr.
        threading.Thread(target=self.read_stdout, daemon=True).start()
        threading.Thread(target=self.read_stderr, daemon=True).start()

    def _write_to_client(self, text):
        try:
            if self.process and self.process.stdin:
                self.process.stdin.write(text)
                self.process.stdin.flush()
        except Exception as e:
            self.output_queue.put(f"[Error] Failed to write to client: {e}")

    def send_message(self):
        message = self.message_entry.get().strip()
        if not message:
            return
        # Ask for recipients via a simple dialog.
        recipients = simpledialog.askstring("Recipients", 
                                            "Enter comma-separated recipients:", 
                                            initialvalue="satya", parent=self.root)
        if not recipients:
            return

        # According to the CLI protocol, send:
        # 1 (send message menu choice), then recipients line, then message line.
        input_sequence = f"1\n{recipients}\n{message}\n"
        self._write_to_client(input_sequence)
        # Display sent message in the chat area, aligned to the right.
        self._append_output(f"You: {message}", sent=True)
        self.message_entry.delete(0, tk.END)

    def read_stdout(self):
        while True:
            try:
                line = self.process.stdout.readline()
                if line:
                    self.output_queue.put(line.strip())
                else:
                    break
            except Exception as e:
                self.output_queue.put(f"[Error] stdout read error: {e}")
                break

    def read_stderr(self):
        while True:
            try:
                line = self.process.stderr.readline()
                if line:
                    self.output_queue.put(f"[Error] {line.strip()}")
                else:
                    break
            except Exception as e:
                self.output_queue.put(f"[Error] stderr read error: {e}")
                break

    def process_output(self):
        while not self.output_queue.empty():
            line = self.output_queue.get()
            # Filter out unwanted CLI output (e.g., menu prompts, debug hex output).
            if any(pattern.search(line) for pattern in FILTER_PATTERNS):
                continue
            self._append_output(line)
        self.root.after(100, self.process_output)

    def _append_output(self, text, sent=False):
        self.chat_area.configure(state=tk.NORMAL)
        if sent:
            # Align sent messages to the right (simulate with padding spaces)
            self.chat_area.insert(tk.END, f"{' ' * 30}{text}\n")
        else:
            self.chat_area.insert(tk.END, text + "\n")
        self.chat_area.configure(state=tk.DISABLED)
        self.chat_area.see(tk.END)

# --- MainApplication: Launch multiple client windows ---
class MainApplication:
    def __init__(self):
        self.root = tk.Tk()
        self.root.withdraw()  # Hide the main window while setting up.
        self.setup_clients()

    def setup_clients(self):
        # Ask how many clients (for a two-member chat, use 2).
        num_clients = simpledialog.askinteger("Clients", 
                                               "Enter number of clients to launch (1-2):", 
                                               parent=self.root, minvalue=1, maxvalue=2)
        if not num_clients:
            messagebox.showerror("Error", "At least one client must be specified!")
            self.root.destroy()
            return

        self.client_windows = []
        for i in range(num_clients):
            server_ip = simpledialog.askstring("Server Setup", f"Client {i+1} - Enter server IP:", 
                                               initialvalue="127.0.0.1", parent=self.root)
            port = simpledialog.askstring("Server Setup", f"Client {i+1} - Enter server port:", 
                                          initialvalue="4444", parent=self.root)
            username = simpledialog.askstring("User Setup", f"Client {i+1} - Enter your username:", parent=self.root)
            if not server_ip or not port or not username:
                messagebox.showerror("Error", "All fields are required for each client!")
                continue
            window = tk.Toplevel()
            # Position each window with an offset.
            window.geometry(f"600x500+{100 + (i * 50)}+{100 + (i * 50)}")
            ClientWindow(window, username, server_ip, port)
            self.client_windows.append(window)
        self.root.mainloop()

if __name__ == "__main__":
    MainApplication()
