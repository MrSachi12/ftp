import os
import socket
import threading
import customtkinter as ctk
from pyftpdlib.authorizers import DummyAuthorizer
from pyftpdlib.handlers import FTPHandler
from pyftpdlib.servers import FTPServer
import logging
import sys

# Is function ko use karke pyftpdlib ka color support issue fix karte hain
def _dummy_stderr_supports_color(*args, **kwargs):
    return False

# Pyftpdlib ke log.py module me dummy function ko assign kar rahe hain
import pyftpdlib.log
pyftpdlib.log._stderr_supports_color = _dummy_stderr_supports_color

# Custom log handler class jo log console pe output dikhaega
class CustomLogHandler(logging.Handler):
    def __init__(self, log_console):
        super().__init__()
        self.log_console = log_console

    def emit(self, record):
        log_entry = self.format(record)
        self.log_console.configure(state='normal')
        self.log_console.insert('end', log_entry + '\n')
        self.log_console.configure(state='disabled')

class FTPServerGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("FTP Server GUI")
        self.default_geometry = "600x500"  # Default size set kar diya
        self.user_geometry = "400x300"     # User frame ke liye size
        self.root.geometry(self.default_geometry)  # Initial size set kar rahe hain
        self.root.minsize(500, 350)    # Minimum size set kar diya
        self.root.resizable(True, True)  # Resize allow karna hai

        self.server_thread = None
        self.server_running = False
        self.port = None
        self.users = []
        self.server = None

        # Sidebar banate hain navigation ke liye
        self.sidebar = ctk.CTkFrame(self.root, width=150, corner_radius=0)
        self.sidebar.pack(side="left", fill="y")

        # Navigation buttons
        self.address_button = ctk.CTkButton(self.sidebar, text="Address", command=self.show_address_frame)
        self.address_button.pack(pady=10, padx=10, fill="x")

        self.user_button = ctk.CTkButton(self.sidebar, text="Users", command=self.show_user_frame)
        self.user_button.pack(pady=10, padx=10, fill="x")

        # Frames banate hain
        self.address_frame = ctk.CTkFrame(self.root)
        self.user_frame = ctk.CTkFrame(self.root)

        self.create_address_frame()
        self.create_user_frame()

        # By default address frame dikhate hain
        self.show_address_frame()

        # Logging setup kar rahe hain
        self.setup_logging()

    def create_address_frame(self):
        local_ip = self.get_local_ip()

        frame = ctk.CTkFrame(self.address_frame)
        frame.pack(padx=15, pady=15, fill="both", expand=True)

        ip_container = ctk.CTkFrame(frame, border_width=1, border_color="gray")
        ip_container.pack(pady=10, padx=10, fill="x", expand=True)

        ctk.CTkLabel(ip_container, text=f"Local IP Address: {local_ip}", font=("Arial", 16, "bold")).pack(pady=10, padx=10)

        ctk.CTkLabel(frame, text="Port:", font=("Arial", 12, "bold")).pack(pady=5, padx=10, anchor="w")
        self.port_entry = ctk.CTkEntry(frame)
        self.port_entry.pack(pady=5, padx=10, fill="x")

        button_frame = ctk.CTkFrame(frame)
        button_frame.pack(pady=10, padx=10)

        self.start_button = ctk.CTkButton(button_frame, text="Start Server", command=self.start_server)
        self.start_button.pack(side="left", padx=5)

        self.stop_button = ctk.CTkButton(button_frame, text="Stop Server", command=self.stop_server)
        self.stop_button.pack(side="left", padx=5)

        # Log console set kar rahe hain
        self.log_console = ctk.CTkTextbox(frame, wrap="word", font=("Arial", 13, "bold"), state="disabled")  # Font size set to 16 and bold
        self.log_console.pack(pady=10, padx=10, fill="both", expand=True)

    def create_user_frame(self):
        frame = ctk.CTkFrame(self.user_frame)
        frame.pack(padx=15, pady=15, fill="both", expand=True)

        self.add_user_button = ctk.CTkButton(frame, text="Add User", command=self.open_add_user_window)
        self.add_user_button.pack(pady=10)

        self.add_anonymous_button = ctk.CTkButton(frame, text="Add Anonymous User", command=self.open_add_anonymous_user_window)
        self.add_anonymous_button.pack(pady=10)

    def show_address_frame(self):
        self.user_frame.pack_forget()
        self.address_frame.pack(fill="both", expand=True)
        self.root.geometry(self.default_geometry)  # Default size pe wapas set karte hain

    def show_user_frame(self):
        self.address_frame.pack_forget()
        self.user_frame.pack(fill="both", expand=True)
        self.root.geometry(self.user_geometry) # User frame ke size pe resize karte hain

    def get_local_ip(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.connect(("8.8.8.8", 80))
            local_ip = s.getsockname()[0]
        finally:
            s.close()
        return local_ip

    def log(self, message):
        self.log_console.configure(state='normal')
        self.log_console.insert('end', message + '\n')
        self.log_console.configure(state='disabled')

    def setup_logging(self):
        # Logging setup karte hain
        self.logger = logging.getLogger('pyftpdlib')
        self.logger.setLevel(logging.INFO)  # INFO level logs hi show karenge
        self.logger.addHandler(CustomLogHandler(self.log_console))

    def open_add_user_window(self):
        self.user_window = ctk.CTkToplevel(self.root)
        self.user_window.title("Add User")

        frame = ctk.CTkFrame(self.user_window)
        frame.pack(padx=15, pady=15, fill="both", expand=True)

        ctk.CTkLabel(frame, text="Username:", font=("Arial", 12, "bold")).grid(row=0, column=0, pady=10, padx=10, sticky="w")
        self.username_entry = ctk.CTkEntry(frame)
        self.username_entry.grid(row=0, column=1, pady=10, padx=10, sticky="ew")

        ctk.CTkLabel(frame, text="Password:", font=("Arial", 12, "bold")).grid(row=1, column=0, pady=10, padx=10, sticky="w")
        self.password_entry = ctk.CTkEntry(frame, show='*')
        self.password_entry.grid(row=1, column=1, pady=10, padx=10, sticky="ew")

        ctk.CTkLabel(frame, text="Home Directory:", font=("Arial", 12, "bold")).grid(row=2, column=0, pady=10, padx=10, sticky="w")
        self.home_dir_entry = ctk.CTkEntry(frame)
        self.home_dir_entry.grid(row=2, column=1, pady=10, padx=10, sticky="ew")

        self.perms_vars = {
            "Read": ctk.BooleanVar(),
            "Write": ctk.BooleanVar(),
            "Append": ctk.BooleanVar(),
            "Delete": ctk.BooleanVar(),
            "Rename": ctk.BooleanVar(),
            "List": ctk.BooleanVar(),
            "Create Directory": ctk.BooleanVar()
        }

        row = 4
        for perm in self.perms_vars:
            ctk.CTkCheckBox(frame, text=perm, variable=self.perms_vars[perm]).grid(row=row, column=0, pady=5, padx=10, sticky="w")
            row += 1

        self.add_user_button = ctk.CTkButton(frame, text="Add User", command=self.add_user)
        self.add_user_button.grid(row=row, column=0, columnspan=2, pady=10, padx=10)

        frame.grid_columnconfigure(1, weight=1)

    def add_user(self):
        username = self.username_entry.get()
        password = self.password_entry.get()
        home_dir = self.home_dir_entry.get()

        if not username or not password or not home_dir:
            self.log("Sabhi fields bharna zaroori hai.")
            return

        perm_str = ''.join([code for perm, code in zip(self.perms_vars.values(), "rwadelm") if perm.get()])
        self.users.append((username, password, home_dir, perm_str))
        if hasattr(self, 'user_window') and self.user_window.winfo_exists():
            self.user_window.destroy()
        self.log(f"User '{username}' added with home directory '{home_dir}' aur permissions '{perm_str}'.")

    def open_add_anonymous_user_window(self):
        self.anon_window = ctk.CTkToplevel(self.root)
        self.anon_window.title("Add Anonymous User")

        frame = ctk.CTkFrame(self.anon_window)
        frame.pack(padx=15, pady=15, fill="both", expand=True)

        ctk.CTkLabel(frame, text="Home Directory:", font=("Arial", 12, "bold")).grid(row=0, column=0, pady=10, padx=10, sticky="w")
        self.anon_dir_entry = ctk.CTkEntry(frame)
        self.anon_dir_entry.grid(row=0, column=1, pady=10, padx=10, sticky="ew")

        self.anon_perms_vars = {
            "Read": ctk.BooleanVar(),
            "Write": ctk.BooleanVar(),
            "Append": ctk.BooleanVar(),
            "Delete": ctk.BooleanVar(),
            "Rename": ctk.BooleanVar(),
            "List": ctk.BooleanVar(),
            "Create Directory": ctk.BooleanVar()
        }

        row = 1
        for perm in self.anon_perms_vars:
            ctk.CTkCheckBox(frame, text=perm, variable=self.anon_perms_vars[perm]).grid(row=row, column=0, pady=5, padx=10, sticky="w")
            row += 1

        self.add_anon_button = ctk.CTkButton(frame, text="Add Anonymous User", command=self.add_anonymous_user)
        self.add_anon_button.grid(row=row, column=0, columnspan=2, pady=10, padx=10)

        frame.grid_columnconfigure(1, weight=1)

    def add_anonymous_user(self):
        home_dir = self.anon_dir_entry.get()

        if not home_dir:
            self.log("Home directory zaroori hai anonymous user add karne ke liye.")
            return

        perm_str = ''.join([code for perm, code in zip(self.anon_perms_vars.values(), "rwadelm") if perm.get()])
        self.users.append(("anonymous", "", home_dir, perm_str))
        if hasattr(self, 'anon_window') and self.anon_window.winfo_exists():
            self.anon_window.destroy()
        self.log(f"Anonymous user added with home directory '{home_dir}' aur permissions '{perm_str}'.")

    def start_server(self):
        if self.server_running:
            self.log("Server already chal raha hai.")
            return

        port = self.port_entry.get()
        if not port.isdigit():
            self.log("Port number invalid hai.")
            return

        self.port = int(port)
        authorizer = DummyAuthorizer()

        for user, password, home_dir, perm_str in self.users:
            authorizer.add_user(user, password, home_dir, perm_str)

        handler = FTPHandler
        handler.authorizer = authorizer

        self.server = FTPServer(("0.0.0.0", self.port), handler)

        self.server_thread = threading.Thread(target=self.server.serve_forever)
        self.server_thread.start()

        self.server_running = True
        self.log(f"Server port {self.port} pe start ho gaya.")

    def stop_server(self):
        if not self.server_running:
            self.log("Server run nahi kar raha hai.")
            return

        self.server.shutdown()
        self.server_thread.join()
        self.server_running = False
        self.log("Server stop ho gaya.")

if __name__ == "__main__":
    root = ctk.CTk()
    app = FTPServerGUI(root)
    root.mainloop()
