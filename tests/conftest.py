# tests/conftest.py
import pytest
from jwks_server.app import app as flask_app
from jwks_server.keystore import KeyStore
from datetime import datetime, timedelta

@pytest.fixture
def client():
    """Flask test client using the app that's configured with a default store."""
    # Use flask_app.test_client()
    with flask_app.test_client() as c:
        yield c
