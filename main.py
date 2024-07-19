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
    """Prompts user for anonymous user's home directory."""
    anonymous_dir = input("Enter home directory for anonymous user: ").replace('/','\\')
    return anonymous_dir

def get_user_input():
    """Prompts user for FTP user details."""
    users = []
    add_users = input("Do you want to add users? (yes/no): ").lower()
    if add_users == 'yes':
        num_users = int(input("Enter number of users to add: "))
        for _ in range(num_users):
            username = input("Enter username: ")
            password = input("Enter password: ")
            home_dir = input("Enter home directory for this user: ").replace('/','\\')
            permission = input("Enter permission (read-only/full): ").lower()
            perms = "elradfmw" if permission == "full" else "r"
            users.append((username, password, home_dir, perms))
    return users

def start_ftp_server(ip_address, port, anonymous_dir, users):
    """Starts the FTP server with the specified user configurations."""
    authorizer = DummyAuthorizer()
    
    # Configure anonymous user
    anon_permission = input("Enter permission for anonymous user (read-only/full): ").lower()
    anon_perms = "elradfmw" if anon_permission == "full" else "r"
    authorizer.add_anonymous(anonymous_dir, perm=anon_perms)

    # Add additional users
    for username, password, home_dir, perms in users:
        authorizer.add_user(username, password, home_dir, perm=perms)

    handler = FTPHandler
    handler.authorizer = authorizer

    server = FTPServer((ip_address, port), handler)
    print(f"FTP server started on {ip_address}:{port}")
    server.serve_forever()

if __name__ == "__main__":
    ip_address = get_ip_address()
    port = int(input("Enter port (default 21): ") or 21)
    anonymous_dir = get_anonymous_dir()
    users = get_user_input()
    start_ftp_server(ip_address, port, anonymous_dir, users)
