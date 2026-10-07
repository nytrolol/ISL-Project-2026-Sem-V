import os
import json
import time
import socket
import threading
import paramiko

SERVER_PORT = 2222
LOG_FILE = "ssh_attempts.jsonl"
HOST_KEY_FILE = "server_host_rsa.key"

# Registered legitimate system users
VALID_CREDENTIALS = {
    "admin": "SecureAdminPass!2026",
    "nikhil": "Manipal@2026",
    "suhani": "LabAuth#99",
    "abhimanyu": "ProjectSec$42"
}

# Generate host key if not present
if not os.path.exists(HOST_KEY_FILE):
    key = paramiko.RSAKey.generate(2048)
    key.write_private_key_file(HOST_KEY_FILE)

HOST_KEY = paramiko.RSAKey(filename=HOST_KEY_FILE)

BLOCKED_IPS = set()
lock = threading.Lock()

def log_event(event: dict):
    """Thread-safe append of structured auth attempts."""
    with lock:
        with open(LOG_FILE, "a") as f:
            f.write(json.dumps(event) + "\n")

class BasicSSHServer(paramiko.ServerInterface):
    def __init__(self, client_ip):
        self.client_ip = client_ip
        self.event = threading.Event()

    def check_auth_password(self, username, password):
        # 1. Intrusion Prevention enforcement check
        if self.client_ip in BLOCKED_IPS:
            event = {
                "timestamp": time.time(),
                "source_ip": self.client_ip,
                "username": username,
                "password_len": len(password),
                "status": "BLOCKED_DROPPED"
            }
            log_event(event)
            return paramiko.AUTH_FAILED

        # 2. Credential verification
        is_success = (VALID_CREDENTIALS.get(username) == password)
        status = "SUCCESS" if is_success else "FAILURE"

        event = {
            "timestamp": time.time(),
            "source_ip": self.client_ip,
            "username": username,
            "password_len": len(password),
            "status": status
        }
        log_event(event)

        if is_success:
            return paramiko.AUTH_SUCCESSFUL
        return paramiko.AUTH_FAILED

    def get_allowed_auths(self, username):
        return "password"

def get_blocked_ips():
    """Reads dynamically updated blocklist from the IDS dashboard."""
    if not os.path.exists("blocked_ips.txt"):
        return set()
    with open("blocked_ips.txt", "r") as f:
        return set(line.strip() for line in f if line.strip())

def handle_client(client_socket, client_addr):
    client_ip = client_addr[0]
    
    # Pre-handshake drop if blacklisted by the ML/Baseline IPS
    if client_ip in get_blocked_ips():
        # Log the dropped connection attempt
        log_event({
            "timestamp": time.time(),
            "source_ip": client_ip,
            "username": "NONE",
            "password_len": 0,
            "status": "BLOCKED_DROPPED"
        })
        client_socket.close()
        return

    transport = paramiko.Transport(client_socket)
    transport.add_server_key(HOST_KEY)
    server = BasicSSHServer(client_ip)

    try:
        transport.start_server(server=server)
        channel = transport.accept(20)
        if channel:
            channel.close()
    except Exception:
        pass
    finally:
        transport.close()

def run_server():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind(("0.0.0.0", SERVER_PORT))
    server_socket.listen(100)
    print(f"[*] Mock SSH Server listening on 0.0.0.0:{SERVER_PORT}...")

    while True:
        client_socket, client_addr = server_socket.accept()
        t = threading.Thread(target=handle_client, args=(client_socket, client_addr), daemon=True)
        t.start()

if __name__ == "__main__":
    if os.path.exists(LOG_FILE):
        os.remove(LOG_FILE)
    run_server()