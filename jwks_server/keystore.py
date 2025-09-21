# jwks_server/keystore.py
"""
KeyStore: in-memory RSA key generation and retrieval.
Each key has:
 - kid: uuid4 string
 - private_key: cryptography RSA private key
 - expiry: datetime
"""

from dataclasses import dataclass
from datetime import datetime
import threading
import uuid
from typing import List, Optional
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

from .utils import base64url_encode_int


@dataclass
class KeyPair:
    kid: str
    private_key: rsa.RSAPrivateKey
    expiry: datetime


class KeyStore:
    def __init__(self):
        self._lock = threading.RLock()
        self._keys: List[KeyPair] = []

    def generate_key(self, expiry):
        """Generate a 2048-bit RSA key with the given expiry (datetime)."""
        priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        kp = KeyPair(kid=str(uuid.uuid4()), private_key=priv, expiry=expiry)
        with self._lock:
            self._keys.append(kp)
        return kp

    def get_unexpired(self, now=None):
        """Return list of KeyPair with expiry > now."""
        from datetime import datetime
        now = now or datetime.utcnow()
        with self._lock:
            return [k for k in self._keys if k.expiry > now]

    def get_expired(self, now=None):
        from datetime import datetime
        now = now or datetime.utcnow()
        with self._lock:
            return [k for k in self._keys if k.expiry <= now]

    def find_signing_key(self, want_expired: bool = False, now=None) -> Optional[KeyPair]:
        """
        If want_expired==True, return the first expired key (deterministic by insertion order).
        Otherwise return the soonest-expiring unexpired key.
        """
        now = now or __import__("datetime").datetime.utcnow()
        with self._lock:
            if want_expired:
                expired = [k for k in self._keys if k.expiry <= now]
                return expired[0] if expired else None
            unexp = [k for k in self._keys if k.expiry > now]
            if not unexp:
                return None
            # pick soonest-expiring
            unexp.sort(key=lambda x: x.expiry)
            return unexp[0]

    def jwks(self, now=None):
        """
        Return a JWKS dict (per RFC) containing only unexpired public keys.
        Each key contains kty, kid, use, alg, n, e, and a custom 'exp' (unix) to help tests.
        """
        now = now or __import__("datetime").datetime.utcnow()
        out = {"keys": []}
        with self._lock:
            for k in self._keys:
                if k.expiry <= now:
                    continue
                pub = k.private_key.public_key()
                numbers = pub.public_numbers()
                n_b64 = base64url_encode_int(numbers.n)
                e_b64 = base64url_encode_int(numbers.e)
                out["keys"].append({
                    "kty": "RSA",
                    "use": "sig",
                    "alg": "RS256",
                    "kid": k.kid,
                    "n": n_b64,
                    "e": e_b64,
                    "exp": int(k.expiry.timestamp()),  # custom field for tests / visibility
                })
        return out

    def private_key_pem(self, kp: KeyPair) -> bytes:
        """Return private key in PEM format for PyJWT signing."""
        return kp.private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )