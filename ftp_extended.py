import os
import socket
from pyftpdlib.authorizers import DummyAuthorizer
from pyftpdlib.handlers import FTPHandler
from pyftpdlib.servers import FTPServer


def get_ip_address():
    """Retrieves the server's IP address."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(("8.8.8.8", 80))  # Connect to a public DNS server
    ip_address = s.getsockname()[0]
    s.close()
    return ip_address


def get_anonymous_dir():
    """Prompts user for anonymous home directory."""
    print("\n**Anonymous User Configuration**\n")
    anon_dir = input("Enter home directory for anonymous user (absolute path): ")
    return anon_dir


def get_user_input():
    """Prompts user for FTP user details and permissions."""
    users = []
    add_users = input("\nDo you want to add users? (yes/no): ").lower()
    if add_users == 'yes':
        num_users = int(input("Enter number of users to add: "))
        for _ in range(num_users):
            username = input("\nEnter username: ")
            password = input("Enter password: ")
            home_dir = input(f"\nEnter home directory for {username} (relative to current directory): ").replace('/', '\\')
            custom_perms = get_custom_permissions()
            users.append((username, password, home_dir, custom_perms))

    return users


def get_custom_permissions(is_anonymous=False):
    """Prompts user for individual permissions and builds a permission string."""
    permissions = {
        "read": "r",
        "write": "w",
        "append": "a",
        "delete": "d",
        "rename": "e",
        "list": "l",
        "create_dir": "m",
    }

    custom_perm_str = ""
    print(f"\nGranting permissions for {('Anonymous' if is_anonymous else 'User')}")
    for perm_name, perm_code in permissions.items():
        if input(f"Grant {perm_name} permission? (yes/no): ").lower() == 'yes':
            custom_perm_str += perm_code

    # Warn about write permissions for anonymous users
    if is_anonymous and "w" in custom_perm_str:
        print("\nWARNING: Granting write permissions to anonymous users can be a security risk.\n")

    return custom_perm_str


def start_ftp_server(ip_address, port, anonymous_dir, users):
    """Starts the FTP server with the specified user configurations."""
    authorizer = DummyAuthorizer()

    # Configure anonymous user with permission and home directory selection
    anon_permission = get_custom_permissions(is_anonymous=True)
    authorizer.add_anonymous(anonymous_dir, perm=anon_permission)

    # Add additional users with permission and home directory selection
    for username, password, home_dir, perms in users:
        # Ensure the home directory is relative to the current working directory
        full_home_dir = os.path.join(os.getcwd(), home_dir)
        authorizer.add_user(username, password, full_home_dir, perm=perms)

    handler = FTPHandler
    handler.authorizer = authorizer

    server = FTPServer((ip_address, port), handler)
    print(f"\nFTP server started on {ip_address}:{port}\n")
    server.serve_forever()


if __name__ == "__main__":
    ip_address = get_ip_address()
    port = int(input("Enter port (default 21): ") or 21)
    anonymous_dir = get_anonymous_dir()
    users = get_user_input()
    start_ftp_server(ip_address, port, anonymous_dir, users)
