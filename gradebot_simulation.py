# gradebot_simulation.py
"""
Simulates the Gradebot test client to test Project 2 requirements
"""
import requests
import json
import sqlite3
import os
from datetime import datetime

def print_rubric_table():
    """Print a rubric table similar to what Gradebot would show"""
    print("=" * 80)
    print("GRADEBOT TEST RESULTS - PROJECT 2")
    print("=" * 80)
    print(f"{'Requirement':<50} {'Points':<10} {'Status':<10}")
    print("-" * 80)
    
    results = []
    total_points = 0
    max_points = 0
    
    # Test 1: Database file exists with correct name
    max_points += 10
    if os.path.exists("totally_not_my_privateKeys.db"):
        results.append(("Database file 'totally_not_my_privateKeys.db' exists", 10, "PASS"))
        total_points += 10
    else:
        results.append(("Database file 'totally_not_my_privateKeys.db' exists", 0, "FAIL"))
    
    # Test 2: Database schema is correct
    max_points += 15
    try:
        conn = sqlite3.connect("totally_not_my_privateKeys.db")
        cursor = conn.execute("PRAGMA table_info(keys)")
        columns = cursor.fetchall()
        conn.close()
        
        expected_columns = ['kid', 'key', 'exp']
        found_columns = [col[1] for col in columns]
        
        if all(col in found_columns for col in expected_columns):
            results.append(("Database schema is correct", 15, "PASS"))
            total_points += 15
        else:
            results.append(("Database schema is correct", 0, "FAIL"))
    except Exception:
        results.append(("Database schema is correct", 0, "FAIL"))
    
    # Test 3: JWKS endpoint returns valid JSON
    max_points += 15
    try:
        response = requests.get("http://127.0.0.1:8080/.well-known/jwks.json", timeout=5)
        if response.status_code == 200:
            jwks_data = response.json()
            if "keys" in jwks_data and len(jwks_data["keys"]) > 0:
                results.append(("JWKS endpoint returns valid JSON", 15, "PASS"))
                total_points += 15
            else:
                results.append(("JWKS endpoint returns valid JSON", 0, "FAIL"))
        else:
            results.append(("JWKS endpoint returns valid JSON", 0, "FAIL"))
    except Exception:
        results.append(("JWKS endpoint returns valid JSON", 0, "FAIL"))
    
    # Test 4: Auth endpoint returns JWT
    max_points += 15
    try:
        response = requests.post("http://127.0.0.1:8080/auth", timeout=5)
        if response.status_code == 200:
            auth_data = response.json()
            if "token" in auth_data:
                results.append(("Auth endpoint returns JWT", 15, "PASS"))
                total_points += 15
            else:
                results.append(("Auth endpoint returns JWT", 0, "FAIL"))
        else:
            results.append(("Auth endpoint returns JWT", 0, "FAIL"))
    except Exception:
        results.append(("Auth endpoint returns JWT", 0, "FAIL"))
    
    # Test 5: Expired parameter works
    max_points += 15
    try:
        response = requests.post("http://127.0.0.1:8080/auth?expired=1", timeout=5)
        if response.status_code == 200:
            auth_data = response.json()
            if "token" in auth_data:
                results.append(("Expired parameter functionality", 15, "PASS"))
                total_points += 15
            else:
                results.append(("Expired parameter functionality", 0, "FAIL"))
        else:
            results.append(("Expired parameter functionality", 0, "FAIL"))
    except Exception:
        results.append(("Expired parameter functionality", 0, "FAIL"))
    
    # Test 6: JSON authentication
    max_points += 15
    try:
        json_payload = {"username": "userABC", "password": "password123"}
        response = requests.post(
            "http://127.0.0.1:8080/auth", 
            json=json_payload,
            headers={'Content-Type': 'application/json'},
            timeout=5
        )
        if response.status_code == 200:
            results.append(("JSON authentication support", 15, "PASS"))
            total_points += 15
        else:
            results.append(("JSON authentication support", 0, "FAIL"))
    except Exception:
        results.append(("JSON authentication support", 0, "FAIL"))
    
    # Test 7: Keys persist across restarts (check database)
    max_points += 15
    try:
        conn = sqlite3.connect("totally_not_my_privateKeys.db")
        cursor = conn.execute("SELECT COUNT(*) FROM keys")
        count = cursor.fetchone()[0]
        conn.close()
        
        if count > 0:
            results.append(("Keys persist in database", 15, "PASS"))
            total_points += 15
        else:
            results.append(("Keys persist in database", 0, "FAIL"))
    except Exception:
        results.append(("Keys persist in database", 0, "FAIL"))
    
    # Print results
    for requirement, points, status in results:
        print(f"{requirement:<50} {points:<10} {status:<10}")
    
    print("-" * 80)
    print(f"{'TOTAL SCORE':<50} {total_points}/{max_points:<10}")
    print(f"{'PERCENTAGE':<50} {(total_points/max_points)*100:.1f}%")
    print("=" * 80)
    
    return total_points, max_points

if __name__ == "__main__":
    print("Starting Gradebot Simulation for Project 2")
    print("Make sure your server is running on http://127.0.0.1:8080")
    print()
    
    try:
        total, max_total = print_rubric_table()
        print(f"\nProject 2 Grade: {(total/max_total)*100:.1f}%")
        
        if total == max_total:
            print("🎉 EXCELLENT! All tests passed!")
        elif total >= max_total * 0.8:
            print("✅ GOOD! Most tests passed!")
        else:
            print("⚠️  Some tests failed. Check your implementation.")
            
    except Exception as e:
        print(f"Error running tests: {e}")
        print("Make sure your server is running on port 8080")