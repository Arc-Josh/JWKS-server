# test_standalone.py
"""
Standalone tests that don't rely on Flask test client
Tests the core functionality to achieve higher coverage
"""
import tempfile
import os
import pytest
from datetime import datetime, timedelta
from jwks_server.database import DatabaseManager
from jwks_server.keystore import KeyStore
from jwks_server.utils import base64url_encode_int

def test_database_module_complete():
    """Test all DatabaseManager methods"""
    with tempfile.NamedTemporaryFile(delete=False) as tmp:
        db_path = tmp.name
    
    try:
        # Test initialization
        db = DatabaseManager(db_path)
        
        # Test key saving
        test_key = b"-----BEGIN PRIVATE KEY-----\ntest_data\n-----END PRIVATE KEY-----"
        exp_time = int(datetime.utcnow().timestamp()) + 3600
        
        kid = db.save_key(test_key, exp_time)
        assert kid == 1  # First key should have ID 1
        
        # Test get_valid_keys
        valid_keys = db.get_valid_keys(int(datetime.utcnow().timestamp()))
        assert len(valid_keys) == 1
        assert valid_keys[0][0] == kid
        assert valid_keys[0][1] == test_key
        assert valid_keys[0][2] == exp_time
        
        # Test get_expired_keys (should be empty initially)
        expired_keys = db.get_expired_keys(int(datetime.utcnow().timestamp()))
        assert len(expired_keys) == 0
        
        # Add an expired key
        past_time = int(datetime.utcnow().timestamp()) - 3600
        expired_kid = db.save_key(b"expired_key", past_time)
        
        # Test get_expired_keys now
        expired_keys = db.get_expired_keys(int(datetime.utcnow().timestamp()))
        assert len(expired_keys) == 1
        assert expired_keys[0][0] == expired_kid
        
        # Test get_key_by_id
        key_data = db.get_key_by_id(kid)
        assert key_data is not None
        assert key_data[0] == kid
        assert key_data[1] == test_key
        assert key_data[2] == exp_time
        
        # Test get_key_by_id with non-existent ID
        missing_key = db.get_key_by_id(999999)
        assert missing_key is None
        
        # Test cleanup_expired_keys
        deleted_count = db.cleanup_expired_keys(int(datetime.utcnow().timestamp()))
        assert deleted_count == 1  # Should delete the expired key
        
        # Verify expired key was deleted
        expired_keys_after = db.get_expired_keys(int(datetime.utcnow().timestamp()))
        assert len(expired_keys_after) == 0
        
    finally:
        try:
            os.unlink(db_path)
        except (OSError, PermissionError):
            pass  # File might be locked on Windows

def test_keystore_module_complete():
    """Test all KeyStore methods"""
    with tempfile.NamedTemporaryFile(delete=False) as tmp:
        db_path = tmp.name
    
    try:
        store = KeyStore(db_path)
        now = datetime.utcnow()
        
        # Test key generation
        valid_key = store.generate_key(now + timedelta(hours=1))
        expired_key = store.generate_key(now - timedelta(hours=1))
        
        assert valid_key.kid is not None
        assert expired_key.kid is not None
        assert valid_key.private_key is not None
        assert expired_key.private_key is not None
        
        # Test get_unexpired
        unexpired = store.get_unexpired(now)
        assert len(unexpired) == 1
        assert unexpired[0].kid == valid_key.kid
        
        # Test get_expired
        expired = store.get_expired(now)
        assert len(expired) == 1
        assert expired[0].kid == expired_key.kid
        
        # Test find_signing_key (valid)
        signing_key = store.find_signing_key(want_expired=False, now=now)
        assert signing_key is not None
        assert signing_key.kid == valid_key.kid
        
        # Test find_signing_key (expired)
        expired_signing_key = store.find_signing_key(want_expired=True, now=now)
        assert expired_signing_key is not None
        assert expired_signing_key.kid == expired_key.kid
        
        # Test JWKS generation
        jwks = store.jwks(now)
        assert "keys" in jwks
        assert len(jwks["keys"]) == 1
        
        key_data = jwks["keys"][0]
        assert key_data["kty"] == "RSA"
        assert key_data["use"] == "sig"
        assert key_data["alg"] == "RS256"
        assert key_data["kid"] == str(valid_key.kid)
        assert "n" in key_data
        assert "e" in key_data
        assert "exp" in key_data
        
        # Test private_key_pem
        pem = store.private_key_pem(valid_key)
        assert b"BEGIN PRIVATE KEY" in pem
        assert b"END PRIVATE KEY" in pem
        
        # Test _load_key_from_db (private method but important)
        key_pem = store.private_key_pem(valid_key)
        loaded_key = store._load_key_from_db(
            valid_key.kid, 
            key_pem, 
            int(valid_key.expiry.timestamp())
        )
        assert loaded_key.kid == valid_key.kid
        assert loaded_key.expiry == valid_key.expiry
        
    finally:
        try:
            os.unlink(db_path)
        except (OSError, PermissionError):
            pass

def test_keystore_edge_cases():
    """Test KeyStore edge cases"""
    with tempfile.NamedTemporaryFile(delete=False) as tmp:
        db_path = tmp.name
    
    try:
        store = KeyStore(db_path)
        now = datetime.utcnow()
        
        # Test with no keys
        signing_key = store.find_signing_key(want_expired=False, now=now)
        assert signing_key is None
        
        expired_signing_key = store.find_signing_key(want_expired=True, now=now)
        assert expired_signing_key is None
        
        # Test JWKS with no keys
        jwks = store.jwks(now)
        assert jwks["keys"] == []
        
        # Test get methods with no keys
        unexpired = store.get_unexpired(now)
        assert len(unexpired) == 0
        
        expired = store.get_expired(now)
        assert len(expired) == 0
        
    finally:
        try:
            os.unlink(db_path)
        except (OSError, PermissionError):
            pass

def test_utils_module_complete():
    """Test all utility functions"""
    # Test small integers
    result = base64url_encode_int(123)
    assert isinstance(result, str)
    assert len(result) > 0
    
    # Test zero
    result = base64url_encode_int(0)
    assert result == "AA"
    
    # Test large RSA modulus (2048-bit)
    large_num = 2**2048 - 1
    result = base64url_encode_int(large_num)
    assert isinstance(result, str)
    assert len(result) > 340  # Should be quite long for 2048-bit number
    
    # Test typical RSA exponent
    result = base64url_encode_int(65537)
    assert isinstance(result, str)
    assert result == "AQAB"  # This is the standard encoding for 65537

def test_app_imports():
    """Test that app modules can be imported without issues"""
    from jwks_server import app, keystore, database, utils
    
    # Test that the app has the expected routes
    assert app.app is not None
    assert hasattr(app, 'jwks')
    assert hasattr(app, 'jwks_legacy')
    assert hasattr(app, 'auth')

if __name__ == "__main__":
    # Run tests manually for demonstration
    print("Running standalone tests for higher coverage...")
    
    test_database_module_complete()
    print("✅ Database module tests passed")
    
    test_keystore_module_complete()
    print("✅ KeyStore module tests passed")
    
    test_keystore_edge_cases()
    print("✅ KeyStore edge cases passed")
    
    test_utils_module_complete()
    print("✅ Utils module tests passed")
    
    test_app_imports()
    print("✅ App import tests passed")
    
    print("\n🎉 All standalone tests passed!")
    print("These tests achieve near-100% coverage for core modules.")