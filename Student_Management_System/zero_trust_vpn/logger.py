# logger.py
import os
import time
import threading
import traceback

# =========================
# LOG DIRECTORY SETUP
# =========================
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
LOGS_DIR = os.path.join(BASE_DIR, "..", "logs")

os.makedirs(LOGS_DIR, exist_ok=True)

SESSION_LOG = os.path.join(LOGS_DIR, "session.log")
SECURITY_LOG = os.path.join(LOGS_DIR, "security.log")
ERROR_LOG = os.path.join(LOGS_DIR, "error.log")

# Thread lock to prevent race conditions
log_lock = threading.Lock()

# =========================
# INTERNAL WRITE FUNCTION
# =========================
def _write_log(filepath, message):
    with log_lock:
        with open(filepath, "a", encoding="utf-8") as f:
            f.write(message + "\n")
            f.flush()  # force write to disk


# =========================
# GENERAL EVENT LOG
# =========================
def log_event(username, action, status, reason=""):
    """
    Logs normal system activity:
    login, logout, access, trust changes, OTP, VPN decisions
    """
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
    msg = f"{timestamp} | USER={username} | ACTION={action} | STATUS={status} | REASON={reason}"
    _write_log(SESSION_LOG, msg)


# =========================
# SUSPICIOUS / SECURITY LOG
# =========================
def log_suspicious(username, reason, metadata=""):
    """
    Logs suspicious behavior:
    brute-force, RBAC violation, rate-limit, unusual behavior
    """
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
    msg = f"{timestamp} | USER={username} | ⚠ SUSPICIOUS | {reason} | {metadata}"
    _write_log(SECURITY_LOG, msg)


# =========================
# TRUST SCORE LOG
# =========================
def log_trust_change(username, old_score, new_score, reason):
    """
    Explicit trust score transitions
    """
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
    msg = (
        f"{timestamp} | USER={username} | TRUST_CHANGE | "
        f"{old_score} → {new_score} | REASON={reason}"
    )
    _write_log(SESSION_LOG, msg)


# =========================
# VPN / ZERO TRUST LOG
# =========================
def log_vpn_decision(username, role, path, decision, trust_score):
    """
    Logs Zero Trust VPN policy decisions
    """
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
    msg = (
        f"{timestamp} | USER={username} | ROLE={role} | PATH={path} | "
        f"DECISION={decision} | TRUST={trust_score}"
    )
    _write_log(SESSION_LOG, msg)


# =========================
# ERROR LOGGING
# =========================
def log_error(context, exc: Exception):
    """
    Logs uncaught exceptions with stack trace
    """
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
    trace = traceback.format_exc()
    msg = (
        f"{timestamp} | ❌ ERROR | CONTEXT={context}\n"
        f"{trace}\n"
        f"{'-'*60}"
    )
    _write_log(ERROR_LOG, msg)
