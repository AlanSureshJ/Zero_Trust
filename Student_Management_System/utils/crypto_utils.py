from Crypto.Cipher import AES
import base64

# This will be dynamically set during RSA key exchange
session_key = None


def set_session_key(key):
    """Store the session key for this connection."""
    global session_key
    session_key = key


def encrypt_message(message: str) -> bytes:
    """Encrypt message using the dynamic AES session key."""
    if session_key is None:
        raise ValueError("Session key not set! Cannot encrypt.")
    
    cipher = AES.new(session_key, AES.MODE_EAX)
    nonce = cipher.nonce
    ciphertext, tag = cipher.encrypt_and_digest(message.encode('utf-8'))
    return base64.b64encode(nonce + tag + ciphertext)


def decrypt_message(ciphertext_b64: bytes) -> str:
    """Decrypt message using the dynamic AES session key."""
    if session_key is None:
        raise ValueError("Session key not set! Cannot decrypt.")
    
    raw = base64.b64decode(ciphertext_b64)
    nonce = raw[:16]
    tag = raw[16:32]
    ciphertext = raw[32:]
    cipher = AES.new(session_key, AES.MODE_EAX, nonce=nonce)
    decrypted = cipher.decrypt_and_verify(ciphertext, tag)
    return decrypted.decode('utf-8')
