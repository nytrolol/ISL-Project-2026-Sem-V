import socket
import time
import random
import threading
import paramiko

TARGET_HOST = "127.0.0.1"
TARGET_PORT = 2222

COMMON_USERNAMES = [
    "root", "admin", "ubuntu", "test", "user", "oracle", "guest", "pi",
    "support", "postgres", "mysql", "deploy", "git", "ftpuser", "nagios",
    "webmaster", "operator", "jenkins", "ansible", "hadoop", "service"
]

COMMON_PASSWORDS = [
    "123456", "password", "admin123", "root", "toor", "12345678", "qwerty",
    "letmein", "welcome", "pass1234", "master", "login", "iloveyou", "111111",
    "changeme", "server2024", "temp123", "access", "default", "123123"
]

def make_attempt(bind_ip: str, username: str, password: str):
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.bind((bind_ip, 0))
        sock.connect((TARGET_HOST, TARGET_PORT))
        client.connect(
            hostname=TARGET_HOST,
            port=TARGET_PORT,
            username=username,
            password=password,
            sock=sock,
            timeout=3,
            allow_agent=False,
            look_for_keys=False
        )
    except Exception:
        pass
    finally:
        client.close()
        sock.close()

def simulate_aggressive_burst():
    """Hydra/Medusa style rapid credential bursts from 127.0.0.2."""
    SRC_IP = "127.0.0.2"
    print(f"[+] Aggressive Brute-Force Bot Active on {SRC_IP}")
    while True:
        user = random.choice(COMMON_USERNAMES)
        pwd = random.choice(COMMON_PASSWORDS)
        make_attempt(SRC_IP, user, pwd)
        time.sleep(random.uniform(0.05, 0.25))

def simulate_low_and_slow():
    """Stealthy brute-force: 1 attempt every 4 to 7 seconds from 127.0.0.3."""
    SRC_IP = "127.0.0.3"
    print(f"[+] Low-and-Slow Stealth Bot Active on {SRC_IP}")
    while True:
        user = random.choice(["admin", "root", "nikhil"])
        pwd = random.choice(COMMON_PASSWORDS)
        make_attempt(SRC_IP, user, pwd)
        time.sleep(random.uniform(4.0, 7.0))

def simulate_legitimate_user():
    """Benign user authentications from 127.0.0.4 with natural delays."""
    SRC_IP = "127.0.0.4"
    print(f"[+] Legitimate User Active on {SRC_IP}")
    valid_users = ["nikhil", "suhani", "abhimanyu"]
    passwords = {
        "nikhil": "Manipal@2026",
        "suhani": "LabAuth#99",
        "abhimanyu": "ProjectSec$42"
    }

    while True:
        user = random.choice(valid_users)
        pwd = passwords[user] if random.random() < 0.90 else (passwords[user] + "1")
        make_attempt(SRC_IP, user, pwd)
        time.sleep(random.uniform(5.0, 10.0))

if __name__ == "__main__":
    t1 = threading.Thread(target=simulate_aggressive_burst, daemon=True)
    t2 = threading.Thread(target=simulate_low_and_slow, daemon=True)
    t3 = threading.Thread(target=simulate_legitimate_user, daemon=True)

    t1.start()
    t2.start()
    t3.start()

    print("[*] All traffic streams initiated. Press Ctrl+C to stop.")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[*] Stopping traffic generators.")