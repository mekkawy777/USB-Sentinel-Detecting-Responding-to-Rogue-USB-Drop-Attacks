import json
import socket

SIEM_SERVER = "127.0.0.1"
SIEM_PORT = 514  # Syslog UDP

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

def send_to_siem(entry: dict):
    try:
        msg = json.dumps(entry).encode()
        sock.sendto(msg, (SIEM_SERVER, SIEM_PORT))
    except Exception:
        pass
