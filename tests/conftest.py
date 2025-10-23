# tests/conftest.py
import pytest
import tempfile
import os
from jwks_server.app import app as flask_app
from jwks_server.keystore import KeyStore
from datetime import datetime, timedelta

@pytest.fixture
def app():
    """Create application for testing with temporary database."""
    # Create a temporary database file for testing
    db_fd, db_path = tempfile.mkstemp()
    
    # Configure app for testing
    flask_app.config['TESTING'] = True
    flask_app.config['DATABASE'] = db_path
    
    # Create new KeyStore with temporary database
    flask_app.store = KeyStore(db_file=db_path)
    
    # Initialize test keys
    now = datetime.utcnow()
    flask_app.store.generate_key(now - timedelta(hours=2))  # expired
    flask_app.store.generate_key(now + timedelta(hours=2))  # valid
    flask_app.store.generate_key(now + timedelta(days=1))   # valid
    
    yield flask_app
    
    # Cleanup
    os.close(db_fd)
    os.unlink(db_path)

@pytest.fixture
def client(app):
    """Flask test client using the app that's configured with a test database."""
    return app.test_client()
