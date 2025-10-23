# tests/test_app.py
import json
import base64
import tempfile
import os
from datetime import datetime, timedelta
import time

import jwt
from jwks_server import keystore
from jwks_server.keystore import KeyStore
from jwks_server.app import app
from jwks_server.utils import base64url_encode_int
from jwks_server.database import DatabaseManager
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
import pytest

def b64url_decode(s: str) -> bytes:
    rem = len(s) % 4
    if rem:
        s += "=" * (4 - rem)
    return base64.urlsafe_b64decode(s.encode("ascii"))

def fetch_jwks(client):
    rv = client.get("/.well-known/jwks.json")
    assert rv.status_code == 200
    return rv.get_json()

def fetch_jwks_legacy(client):
    rv = client.get("/jwks")
    assert rv.status_code == 200
    return rv.get_json()

def jwt_payload(token):
    parts = token.split(".")
    assert len(parts) >= 2
    payload_bytes = b64url_decode(parts[1])
    return json.loads(payload_bytes.decode("utf-8"))

def jwt_header(token):
    parts = token.split(".")
    hdr_bytes = b64url_decode(parts[0])
    return json.loads(hdr_bytes.decode("utf-8"))

def build_public_key_from_jwk(j):
    # j has "n" and "e" base64url
    n = int.from_bytes(base64.urlsafe_b64decode(j["n"] + "=="), "big")
    e = int.from_bytes(base64.urlsafe_b64decode(j["e"] + "=="), "big")
    pubnum = rsa.RSAPublicNumbers(e, n)
    pubkey = pubnum.public_key()
    return pubkey

# JWKS Tests
def test_jwks_only_unexpired(client):
    jwks = fetch_jwks(client)
    assert "keys" in jwks
    assert len(jwks["keys"]) > 0
    now = int(datetime.utcnow().timestamp())
    for k in jwks["keys"]:
        assert k["exp"] > now  # custom 'exp' field included

def test_jwks_legacy_endpoint(client):
    jwks = fetch_jwks_legacy(client)
    assert "keys" in jwks
    assert len(jwks["keys"]) > 0

def test_jwks_structure(client):
    jwks = fetch_jwks(client)
    for key in jwks["keys"]:
        assert "kty" in key and key["kty"] == "RSA"
        assert "use" in key and key["use"] == "sig"
        assert "alg" in key and key["alg"] == "RS256"
        assert "kid" in key
        assert "n" in key
        assert "e" in key
        assert "exp" in key

# Auth Tests
def test_auth_returns_valid_nonexpired_jwt(client):
    # POST /auth
    rv = client.post("/auth")
    assert rv.status_code == 200
    body = rv.get_json()
    assert "token" in body
    token = body["token"]

    # header should contain kid
    hdr = jwt_header(token)
    kid = hdr.get("kid")
    assert kid is not None

    # jwks should contain this kid
    jwks = fetch_jwks(client)
    found = False
    for k in jwks["keys"]:
        if k["kid"] == kid:
            found = True
            pub = build_public_key_from_jwk(k)
            # verify signature with PyJWT
            pub_pem = pub.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            decoded = jwt.decode(token, pub_pem, algorithms=["RS256"])
            assert decoded["sub"] == "fake-user-1"
            break
    assert found, "kid from token not present in jwks"

def test_auth_expired_param_signs_with_expired_key_not_in_jwks(client):
    rv = client.post("/auth?expired=1")
    assert rv.status_code == 200
    body = rv.get_json()
    token = body["token"]
    hdr = jwt_header(token)
    kid = hdr.get("kid")
    # jwks should not have this kid (expired keys are not in jwks)
    jwks = fetch_jwks(client)
    assert all(k["kid"] != kid for k in jwks["keys"])

    # payload exp should be in the past
    payload = jwt_payload(token)
    assert payload["exp"] < int(datetime.utcnow().timestamp())

def test_auth_json_payload_valid_credentials(client):
    """Test JSON authentication with valid credentials"""
    payload = {"username": "userABC", "password": "password123"}
    rv = client.post("/auth", json=payload, content_type='application/json')
    assert rv.status_code == 200
    body = rv.get_json()
    assert "token" in body

def test_auth_json_payload_invalid_credentials(client):
    """Test JSON authentication with invalid credentials"""
    payload = {"username": "wrong", "password": "wrong"}
    rv = client.post("/auth", json=payload, content_type='application/json')
    assert rv.status_code == 401

def test_auth_malformed_json(client):
    """Test auth endpoint with malformed JSON"""
    rv = client.post("/auth", data="invalid json", content_type='application/json')
    assert rv.status_code == 400

def test_auth_no_signing_key_available(app, client):
    """Test auth when no signing keys are available"""
    # Clear all keys from database
    with app.app_context():
        app.store._db._init_database()  # Reset database
    
    rv = client.post("/auth")
    assert rv.status_code == 500

# Database Tests
def test_database_operations():
    """Test database operations directly"""
    # Create temporary database
    db_fd, db_path = tempfile.mkstemp()
    
    try:
        db = DatabaseManager(db_path)
        
        # Test key saving
        test_key = b"test_key_pem_data"
        exp_time = int(datetime.utcnow().timestamp()) + 3600
        
        kid = db.save_key(test_key, exp_time)
        assert kid is not None
        
        # Test key retrieval
        valid_keys = db.get_valid_keys(int(datetime.utcnow().timestamp()))
        assert len(valid_keys) == 1
        assert valid_keys[0][0] == kid
        assert valid_keys[0][1] == test_key
        
        # Test expired keys
        expired_keys = db.get_expired_keys(int(datetime.utcnow().timestamp()) + 7200)
        assert len(expired_keys) == 1
        
        # Test get by ID
        key_data = db.get_key_by_id(kid)
        assert key_data is not None
        assert key_data[1] == test_key
        
    finally:
        os.close(db_fd)
        os.unlink(db_path)

# KeyStore Tests
def test_keystore_operations():
    """Test KeyStore operations"""
    # Create temporary database
    db_fd, db_path = tempfile.mkstemp()
    
    try:
        store = KeyStore(db_path)
        now = datetime.utcnow()
        
        # Test key generation
        valid_key = store.generate_key(now + timedelta(hours=1))
        expired_key = store.generate_key(now - timedelta(hours=1))
        
        assert valid_key.kid is not None
        assert expired_key.kid is not None
        
        # Test get unexpired
        unexpired = store.get_unexpired(now)
        assert len(unexpired) == 1
        assert unexpired[0].kid == valid_key.kid
        
        # Test get expired
        expired = store.get_expired(now)
        assert len(expired) == 1
        assert expired[0].kid == expired_key.kid
        
        # Test find signing key
        signing_key = store.find_signing_key(want_expired=False, now=now)
        assert signing_key is not None
        assert signing_key.kid == valid_key.kid
        
        expired_signing_key = store.find_signing_key(want_expired=True, now=now)
        assert expired_signing_key is not None
        assert expired_signing_key.kid == expired_key.kid
        
        # Test JWKS generation
        jwks = store.jwks(now)
        assert "keys" in jwks
        assert len(jwks["keys"]) == 1
        
        # Test private key PEM
        pem = store.private_key_pem(valid_key)
        assert b"BEGIN PRIVATE KEY" in pem
        
    finally:
        os.close(db_fd)
        os.unlink(db_path)

# Utils Tests
def test_base64url_encode_int():
    """Test base64url integer encoding"""
    from jwks_server.utils import base64url_encode_int
    
    # Test small number
    result = base64url_encode_int(123)
    assert isinstance(result, str)
    assert len(result) > 0
    
    # Test large number (RSA modulus size)
    large_num = 2**2048 - 1
    result = base64url_encode_int(large_num)
    assert isinstance(result, str)
    assert len(result) > 0

# Error Handling Tests
def test_database_edge_cases():
    """Test database edge cases"""
    db_fd, db_path = tempfile.mkstemp()
    
    try:
        db = DatabaseManager(db_path)
        
        # Test get key by non-existent ID
        result = db.get_key_by_id(999999)
        assert result is None
        
        # Test cleanup expired keys
        past_time = int(datetime.utcnow().timestamp()) - 3600
        deleted_count = db.cleanup_expired_keys(past_time)
        assert deleted_count >= 0
        
    finally:
        os.close(db_fd)
        os.unlink(db_path)

def test_keystore_no_keys_available():
    """Test KeyStore when no keys are available"""
    db_fd, db_path = tempfile.mkstemp()
    
    try:
        store = KeyStore(db_path)
        now = datetime.utcnow()
        
        # Test finding signing key when none exist
        signing_key = store.find_signing_key(want_expired=False, now=now)
        assert signing_key is None
        
        expired_signing_key = store.find_signing_key(want_expired=True, now=now)
        assert expired_signing_key is None
        
        # Test JWKS with no keys
        jwks = store.jwks(now)
        assert jwks["keys"] == []
        
    finally:
        os.close(db_fd)
        os.unlink(db_path)
