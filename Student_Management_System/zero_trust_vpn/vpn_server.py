# zero_trust_vpn/vpn_server.py
# =========================
# Zero Trust Policy Server with RSA + AES Encryption
# =========================

import socket
import json
import jwt
import threading
import os
import sys
from dotenv import load_dotenv

# Add the zero_trust_vpn directory to sys.path
sys.path.insert(0, os.path.dirname(__file__))
from crypto_utils import decrypt_payload, load_private_key

load_dotenv()

HOST = "127.0.0.1"
PORT = 5012
JWT_SECRET = os.getenv("JWT_SECRET", "your_jwt_secret_key")

PRIVATE_KEY_PATH = os.path.join(os.path.dirname(__file__), "keys", "private.pem")

# Load RSA private key on startup
try:
    PRIVATE_KEY = load_private_key(PRIVATE_KEY_PATH)
    print(f"[VPN] RSA private key loaded from {PRIVATE_KEY_PATH}")
except FileNotFoundError:
    print(f"[VPN] ERROR: RSA private key not found at {PRIVATE_KEY_PATH}")
    print("[VPN] Run: python zero_trust_vpn/generate_keys.py")
    sys.exit(1)

try:
    from logger import log_event, log_suspicious, log_vpn_decision, log_error
except ImportError:
    def log_event(m): print(f"[LOG] {m}")
    def log_suspicious(u, m, d): print(f"[SUSPICIOUS] {u}: {m} | {d}")
    def log_vpn_decision(u, r, p, a, t): print(f"[VPN] {a} | {u} | {r} | {p} | trust:{t}")
    def log_error(m): print(f"[ERROR] {m}")

# In-memory trust store
trust_scores = {}

# Paths that are always allowed regardless of role
PUBLIC_PATHS = [
    "/logout",
    "/login",
    "/",
    "/static",
    "/restricted",
    "/request-admin-help",
    "/self-service-verify",
    "/confirm-recovery",
    "/public-request-help",
    "/verify_otp",
    "/dashboard",
]

# RBAC policy
POLICY = {
    "student": ["/student", "/dashboard"],
    "parent":  ["/parent",  "/dashboard"],
    "faculty": ["/faculty", "/dashboard"],
    "admin":   ["/admin",   "/faculty",  "/dashboard"],  # admin can access faculty routes too
}

BASE_TRUST = 100

# How many points to deduct per RBAC violation
RBAC_PENALTY = 5  # was 15 — too aggressive

# Trust threshold below which session is terminated
TERMINATE_THRESHOLD = 10  # was 40 — way too aggressive


def allowed(role, path):
    for allowed_path in POLICY.get(role, []):
        if path.startswith(allowed_path):
            return True
    return False


def handle_client(conn, addr):
    try:
        # Read all incoming bytes (encrypted payload)
        chunks = []
        while True:
            chunk = conn.recv(4096)
            if not chunk:
                break
            chunks.append(chunk)
            if len(chunk) < 4096:
                break
        wire_data = b"".join(chunks)

        if not wire_data:
            return

        # ─── RSA + AES Decrypt ───────────────────────────────────────────────
        try:
            plaintext = decrypt_payload(wire_data, PRIVATE_KEY)
            request_data = json.loads(plaintext)
        except Exception as e:
            print(f"[VPN] Decryption failed: {e}")
            conn.sendall(b"DECRYPT_ERROR")
            return

        jwt_token = request_data.get("jwt")
        path      = request_data.get("path")

        # ─── Verify JWT ─────────────────────────────────────────────────────
        try:
            payload = jwt.decode(jwt_token, JWT_SECRET, algorithms=["HS256"])
        except Exception as e:
            print(f"[VPN] JWT decode failed: {e}")
            conn.sendall(b"TOKEN_INVALID")
            return

        username = payload["sub"]
        role     = payload["role"]

        trust_scores.setdefault(username, BASE_TRUST)
        trust = trust_scores[username]

        # ─── Always allow public/utility paths ──────────────────────────────
        if any(path.startswith(p) for p in PUBLIC_PATHS):
            log_vpn_decision(username, role, path, "ALLOW_PUBLIC", trust)
            conn.sendall(f"ALLOWED:{path}".encode())
            return

        # ─── Low trust → terminate session ──────────────────────────────────
        if trust < TERMINATE_THRESHOLD:
            log_suspicious(username, "Trust critically low", f"Trust={trust}")
            conn.sendall(b"SESSION_TERMINATED_LOW_TRUST")
            return

        # ─── RBAC check ─────────────────────────────────────────────────────
        if not allowed(role, path):
            trust_scores[username] = max(0, trust_scores[username] - RBAC_PENALTY)
            trust = trust_scores[username]

            response = json.dumps({
                "action": "JWT_DOWNGRADED",
                "trust":  trust,
                "reason": "RBAC_VIOLATION",
            })

            log_suspicious(username, f"RBAC violation accessing {path}", f"Trust reduced to {trust}")
            log_vpn_decision(username, role, path, "DENY_RBAC", trust)
            conn.sendall(response.encode())
            return

        # ─── Allowed ────────────────────────────────────────────────────────
        log_vpn_decision(username, role, path, "ALLOW", trust)
        conn.sendall(f"ALLOWED:{path}".encode())

    except Exception as e:
        print(f"[VPN] Handler error: {e}")
    finally:
        conn.close()


print(f"[VPN] Zero Trust Policy Server (RSA+AES encrypted) running on {HOST}:{PORT}")

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((HOST, PORT))
    server.listen(50)

    while True:
        conn, addr = server.accept()
        threading.Thread(target=handle_client, args=(conn, addr), daemon=True).start()