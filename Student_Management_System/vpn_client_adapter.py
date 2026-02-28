# vpn_client_adapter.py

import socket
import json

VPN_HOST = "127.0.0.1"
VPN_PORT = 5012

def check_access(jwt_token, path):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(2)
            sock.connect((VPN_HOST, VPN_PORT))

            request = {
                "jwt": jwt_token,
                "path": path
            }

            sock.sendall(json.dumps(request).encode())
            response = sock.recv(4096)

            return response.decode()

    except Exception:
        return "SESSION_TERMINATED: VPN_UNREACHABLE"
