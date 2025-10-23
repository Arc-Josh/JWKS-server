# test_json_auth.py
"""
Test script to verify JSON authentication functionality
"""
import requests
import json

def test_json_auth():
    """Test the JSON authentication endpoint"""
    base_url = "http://127.0.0.1:8080"
    
    # Test with correct JSON payload
    correct_payload = {"username": "userABC", "password": "password123"}
    response = requests.post(
        f"{base_url}/auth", 
        json=correct_payload,
        headers={'Content-Type': 'application/json'}
    )
    print(f"Correct JSON auth - Status: {response.status_code}")
    if response.status_code == 200:
        data = response.json()
        print(f"  Token received: {'token' in data}")
        print(f"  Kid: {data.get('kid', 'N/A')}")
    else:
        print(f"  Error: {response.text}")
    
    # Test with incorrect JSON payload
    incorrect_payload = {"username": "wrong", "password": "wrong"}
    response = requests.post(
        f"{base_url}/auth", 
        json=incorrect_payload,
        headers={'Content-Type': 'application/json'}
    )
    print(f"Incorrect JSON auth - Status: {response.status_code}")
    if response.status_code != 200:
        print(f"  Correctly rejected: {response.status_code}")
    
    # Test without JSON (should still work for backward compatibility)
    response = requests.post(f"{base_url}/auth")
    print(f"No JSON auth - Status: {response.status_code}")
    if response.status_code == 200:
        print("  Backward compatibility maintained")

if __name__ == "__main__":
    try:
        test_json_auth()
        print("\nJSON authentication testing completed!")
    except requests.exceptions.RequestException as e:
        print(f"Connection error: {e}")
        print("Make sure the server is running on port 8080")