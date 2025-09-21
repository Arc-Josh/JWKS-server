# jwks_server/app.py
"""
Flask application exposing:
 - GET /jwks  -> returns JWKS (only unexpired keys)
 - POST /auth -> issues JWT signed with an unexpired key; ?expired=1 signs with expired key
"""

from flask import Flask, jsonify, request, abort
from datetime import datetime, timedelta
import time
import jwt  # PyJWT
from .keystore import KeyStore
from .utils import base64url_encode_int

app = Flask(__name__)
store = KeyStore()

# Initialize some sample keys on startup
now = datetime.utcnow()
# one expired
store.generate_key(now - timedelta(hours=2))
# two valid
store.generate_key(now + timedelta(hours=2))
store.generate_key(now + timedelta(days=1))


@app.route("/jwks", methods=["GET"])
def jwks():
    """Return JWKS JSON with only unexpired public keys."""
    return jsonify(store.jwks())


@app.route("/auth", methods=["POST"])
def auth():
    """
    Return a signed JWT.
    If query parameter 'expired' is present (e.g., /auth?expired=1), the server signs with an expired key and
    sets the token exp to that expired key expiry (in the past).
    Otherwise it signs with a non-expired key and token exp is min(key_expiry, now+1h).
    """
    now = datetime.utcnow()
    want_expired = "expired" in request.args and request.args.get("expired") != ""

    kp = store.find_signing_key(want_expired=want_expired, now=now)
    if kp is None:
        abort(500, description="no signing key available")

    # Decide token expiry
    if want_expired:
        token_exp = kp.expiry
    else:
        one_hour = now + timedelta(hours=1)
        token_exp = kp.expiry if kp.expiry < one_hour else one_hour

    payload = {
        "sub": "fake-user-1",
        "iat": int(now.timestamp()),
        "exp": int(token_exp.timestamp()),
    }

    headers = {"kid": kp.kid}
    # serialize private key to PEM (PyJWT supports PEM bytes)
    priv_pem = store.private_key_pem(kp)
    token = jwt.encode(payload, priv_pem, algorithm="RS256", headers=headers)

    return jsonify({"token": token, "kid": kp.kid})
