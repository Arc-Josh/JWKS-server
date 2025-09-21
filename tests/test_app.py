# tests/test_app.py
import json
import base64
from datetime import datetime, timedelta
import time

import jwt
from jwks_server import keystore
from jwks_server.keystore import KeyStore
from jwks_server.app import app
from jwks_server.utils import base64url_encode_int
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
import pytest

# helper to decode base64url-encoded JWT parts safely
def b64url_decode(s: str) -> bytes:
    rem = len(s) % 4
    if rem:
        s += "=" * (4 - rem)
    return base64.urlsafe_b64decode(s.encode("ascii"))

def fetch_jwks(client):
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

def test_jwks_only_unexpired(client):
    # The app's store already has keys, but to be sure we can simply query and assert all exp > now
    jwks = fetch_jwks(client)
    assert "keys" in jwks
    assert len(jwks["keys"]) > 0
    now = int(datetime.utcnow().timestamp())
    for k in jwks["keys"]:
        assert k["exp"] > now  # custom 'exp' field included

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
