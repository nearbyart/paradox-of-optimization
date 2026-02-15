#!/usr/bin/env python3
"""
paradox_auth.py

Improvements over the original:
- Use `secrets` for strong, unpredictable nonces.
- Produce a canonical challenge format: "<base64url_nonce>.<timestamp>"
- Check challenge expiry (TTL) to prevent replay attacks.
- Keep signing/verification on the exact UTF-8 bytes of the canonical challenge string.
- Better error handling, type hints and inline docs.
- Small demonstration including a replay attack example.
"""

from dataclasses import dataclass
import base64
import hashlib
import hmac
import secrets
import time
from typing import Optional, Tuple


# --- Configuration & Storage (The "Pocket") ---
@dataclass
class CloudKeyStore:
    """Simulates the secure vault (the 'Honey' jar)."""
    api_admin_id: str
    _secret_key: bytes  # The 'Colored Piano Key'

    def get_secret(self) -> bytes:
        return self._secret_key


# --- Metrics Engine (The "Eye") ---
class AuthMetrics:
    def __init__(self):
        self.attempts = 0
        self.successes = 0

    def log_attempt(self, success: bool) -> None:
        self.attempts += 1
        if success:
            self.successes += 1

    def get_consistency_metrics(self) -> str:
        """Returns <con/con%> - The Stability of the Constraint."""
        if self.attempts == 0:
            return "0.00%"
        ratio = (self.successes / self.attempts) * 100
        return f"{ratio:.2f}%"


# --- The Logic (The Constraint) ---
class ReverseAuthenticator:
    """
    Challenge format (canonical): "<base64url_nonce>.<timestamp>"
    Package format returned by the user: "<challenge>.<hex_signature>"

    Verification does:
      - parse package
      - enforce challenge timestamp within TTL
      - compute HMAC-SHA256 over the UTF-8 bytes of the canonical challenge
      - use hmac.compare_digest for constant-time comparison
      - log metrics
    """

    def __init__(self, key_store: CloudKeyStore, ttl_seconds: int = 30):
        self.store = key_store
        self.metrics = AuthMetrics()
        self.ttl_seconds = ttl_seconds  # allowed age for a challenge

    @staticmethod
    def _b64url_encode_no_padding(data: bytes) -> str:
        """URL-safe base64 without padding (canonical representation)."""
        return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")

    @staticmethod
    def _b64url_decode_no_padding(data: str) -> bytes:
        """Decode base64url that may be missing padding."""
        padded = data + "=" * (-len(data) % 4)
        return base64.urlsafe_b64decode(padded.encode("ascii"))

    def generate_challenge(self) -> str:
        """Step 1: The Shake (Admin throws chaos). Returns canonical challenge string."""
        nonce = secrets.token_bytes(32)  # strong random nonce
        nonce_b64 = self._b64url_encode_no_padding(nonce)
        ts = int(time.time())
        return f"{nonce_b64}.{ts}"

    def user_sign_challenge(self, challenge: str, user_secret: bytes) -> str:
        """
        Step 2: The User Constraint (Wrapping chaos in the Key).
        Signs the exact UTF-8 bytes of `challenge` using HMAC-SHA256 and returns package.
        """
        message = challenge.encode("utf-8")
        signature = hmac.new(user_secret, message, hashlib.sha256).hexdigest()
        return f"{challenge}.{signature}"

    def verify_with_reason(self, received_package: str) -> Tuple[bool, str]:
        """More descriptive verifier that returns (is_valid, reason).
        Useful for logging and tests."""
        try:
            # Split only on the last '.' to allow challenge to contain a dot separator
            challenge, user_signature = received_package.rsplit(".", 1)
        except ValueError:
            self.metrics.log_attempt(False)
            return False, "malformed package (missing signature separator)"

        # parse challenge into nonce and timestamp
        try:
            nonce_b64, ts_str = challenge.rsplit(".", 1)
            ts = int(ts_str)
        except ValueError:
            self.metrics.log_attempt(False)
            return False, "malformed challenge (missing timestamp separator)"
        except Exception:
            self.metrics.log_attempt(False)
            return False, "invalid timestamp in challenge"

        # check timestamp age (replay protection)
        now = int(time.time())
        age = now - ts
        if age < 0:
            # future timestamp — reject
            self.metrics.log_attempt(False)
            return False, "challenge timestamp is in the future"
        if age > self.ttl_seconds:
            self.metrics.log_attempt(False)
            return False, f"challenge expired (age {age}s > ttl {self.ttl_seconds}s)"

        # optionally verify nonce decoding (ensure format)
        try:
            _nonce = self._b64url_decode_no_padding(nonce_b64)
            # Note: we don't store nonces here; in a production system you'd
            # want to record used nonces to prevent replays within the TTL window.
        except Exception:
            self.metrics.log_attempt(False)
            return False, "invalid base64url nonce"

        # compute local signature
        stored_secret = self.store.get_secret()
        local_signature = hmac.new(
            stored_secret, challenge.encode("utf-8"), hashlib.sha256
        ).hexdigest()

        is_valid = hmac.compare_digest(local_signature, user_signature)
        self.metrics.log_attempt(is_valid)
        if is_valid:
            return True, "ok"
        else:
            return False, "signature mismatch"

    def verify_reverse_process(self, received_package: str) -> bool:
        """Compatibility method: returns only boolean (old behavior)."""
        valid, _reason = self.verify_with_reason(received_package)
        return valid


# --- Execution Block / demo ---
if __name__ == "__main__":
    MASTER_KEY = b"Laith_Salman_Constraint_999"

    system = ReverseAuthenticator(CloudKeyStore("Admin_01", MASTER_KEY), ttl_seconds=10)
    print("--- PARADOX ENGINE ONLINE ---")

    # 1) Normal flow
    challenge = system.generate_challenge()
    print(f"System Challenge: {challenge}")

    response = system.user_sign_challenge(challenge, MASTER_KEY)
    valid = system.verify_reverse_process(response)
    print(f"Authentication Result (valid): {valid}")
    print(f"System Stability <con/con%>: {system.metrics.get_consistency_metrics()}")

    # 2) Invalid key
    bad_response = system.user_sign_challenge(challenge, b"wrong_key")
    valid_bad = system.verify_reverse_process(bad_response)
    print(f"Authentication Result (wrong key): {valid_bad}")
    print(f"System Stability <con/con%>: {system.metrics.get_consistency_metrics()}")

    # 3) Replay / expired challenge example
    # Simulate an old challenge by using a timestamp in the past
    old_nonce = secrets.token_bytes(16)
    old_nonce_b64 = ReverseAuthenticator._b64url_encode_no_padding(old_nonce)
    old_ts = int(time.time()) - 60  # 60s old, TTL is 10s in this demo
    old_challenge = f"{old_nonce_b64}.{old_ts}"
    old_resp = system.user_sign_challenge(old_challenge, MASTER_KEY)
    valid_old = system.verify_reverse_process(old_resp)
    print(f"Authentication Result (replay/expired): {valid_old}")
    print(f"System Stability <con/con%>: {system.metrics.get_consistency_metrics()}")
