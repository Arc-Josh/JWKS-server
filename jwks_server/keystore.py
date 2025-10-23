# jwks_server/keystore.py
"""
KeyStore: SQLite-backed RSA key generation and retrieval.
Each key has:
 - kid: integer (database primary key)
 - private_key: cryptography RSA private key (serialized to PEM in DB)
 - expiry: datetime (stored as unix timestamp in DB)
"""

from dataclasses import dataclass
from datetime import datetime
import threading
from typing import List, Optional
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

from .utils import base64url_encode_int
from .database import DatabaseManager


@dataclass
class KeyPair:
    kid: int  # Changed from str to int to match database schema
    private_key: rsa.RSAPrivateKey
    expiry: datetime


class KeyStore:
    def __init__(self, db_file: str = "totally_not_my_privateKeys.db"):
        self._lock = threading.RLock()
        self._db = DatabaseManager(db_file)

    def generate_key(self, expiry: datetime) -> KeyPair:
        """Generate a 2048-bit RSA key with the given expiry and save to database."""
        with self._lock:
            # Generate the private key
            priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
            
            # Serialize to PEM format for database storage
            key_pem = priv.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            )
            
            # Save to database and get the assigned kid
            kid = self._db.save_key(key_pem, int(expiry.timestamp()))
            
            # Return KeyPair object
            return KeyPair(kid=kid, private_key=priv, expiry=expiry)

    def _load_key_from_db(self, kid: int, key_pem: bytes, expiry_timestamp: int) -> KeyPair:
        """Load a private key from PEM bytes and create KeyPair object."""
        private_key = serialization.load_pem_private_key(
            key_pem, password=None
        )
        expiry = datetime.fromtimestamp(expiry_timestamp)
        return KeyPair(kid=kid, private_key=private_key, expiry=expiry)

    def get_unexpired(self, now: datetime = None) -> List[KeyPair]:
        """Return list of KeyPair with expiry > now."""
        now = now or datetime.utcnow()
        with self._lock:
            keys_data = self._db.get_valid_keys(int(now.timestamp()))
            return [self._load_key_from_db(kid, key_pem, exp) 
                   for kid, key_pem, exp in keys_data]

    def get_expired(self, now: datetime = None) -> List[KeyPair]:
        """Return list of KeyPair with expiry <= now."""
        now = now or datetime.utcnow()
        with self._lock:
            keys_data = self._db.get_expired_keys(int(now.timestamp()))
            return [self._load_key_from_db(kid, key_pem, exp) 
                   for kid, key_pem, exp in keys_data]

    def find_signing_key(self, want_expired: bool = False, now: datetime = None) -> Optional[KeyPair]:
        """
        If want_expired==True, return the first expired key (deterministic by kid order).
        Otherwise return the soonest-expiring unexpired key.
        """
        now = now or datetime.utcnow()
        with self._lock:
            if want_expired:
                expired_data = self._db.get_expired_keys(int(now.timestamp()))
                if expired_data:
                    kid, key_pem, exp = expired_data[0]  # First expired key
                    return self._load_key_from_db(kid, key_pem, exp)
                return None
            
            valid_data = self._db.get_valid_keys(int(now.timestamp()))
            if valid_data:
                kid, key_pem, exp = valid_data[0]  # First valid key (ordered by exp ASC)
                return self._load_key_from_db(kid, key_pem, exp)
            return None

    def jwks(self, now: datetime = None) -> dict:
        """
        Return a JWKS dict (per RFC) containing only unexpired public keys.
        Each key contains kty, kid, use, alg, n, e, and a custom 'exp' (unix) to help tests.
        """
        now = now or datetime.utcnow()
        out = {"keys": []}
        
        with self._lock:
            keys_data = self._db.get_valid_keys(int(now.timestamp()))
            
            for kid, key_pem, exp in keys_data:
                # Load the private key and extract public key
                private_key = serialization.load_pem_private_key(key_pem, password=None)
                pub = private_key.public_key()
                numbers = pub.public_numbers()
                
                # Encode RSA public key components
                n_b64 = base64url_encode_int(numbers.n)
                e_b64 = base64url_encode_int(numbers.e)
                
                out["keys"].append({
                    "kty": "RSA",
                    "use": "sig",
                    "alg": "RS256",
                    "kid": str(kid),  # Convert to string for JSON compatibility
                    "n": n_b64,
                    "e": e_b64,
                    "exp": exp,  # Unix timestamp
                })
        return out

    def private_key_pem(self, kp: KeyPair) -> bytes:
        """Return private key in PEM format for PyJWT signing."""
        return kp.private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )