#!/usr/bin/env python3
"""
Enhanced Gradebot Client for Project 2
Displays a detailed rubric table and tests all requirements
"""
import requests
import json
import sqlite3
import os
import sys
from datetime import datetime
from typing import Tuple, List
import base64
import jwt as pyjwt
from tabulate import tabulate
from colorama import init, Fore, Back, Style

# Initialize colorama for Windows
init(autoreset=True)

class GradebotClient:
    def __init__(self, base_url="http://127.0.0.1:8080"):
        self.base_url = base_url
        self.results = []
        self.total_points = 0
        self.max_points = 0

    def add_test(self, name: str, points: int, test_func, description: str = ""):
        """Add a test to the rubric"""
        self.max_points += points
        try:
            passed = test_func()
            if passed:
                self.total_points += points
                status = f"{Fore.GREEN}PASS ✓{Style.RESET_ALL}"
                points_earned = points
            else:
                status = f"{Fore.RED}FAIL ✗{Style.RESET_ALL}"
                points_earned = 0
        except Exception as e:
            status = f"{Fore.RED}ERROR ✗{Style.RESET_ALL}"
            points_earned = 0
            description += f" (Error: {str(e)[:50]}...)"

        self.results.append([name, f"{points_earned}/{points}", status, description])

    def test_database_file_exists(self) -> bool:
        """Test if the database file exists with correct name"""
        return os.path.exists("totally_not_my_privateKeys.db")

    def test_database_schema(self) -> bool:
        """Test if database schema is correct"""
        try:
            conn = sqlite3.connect("totally_not_my_privateKeys.db")
            cursor = conn.execute("PRAGMA table_info(keys)")
            columns = cursor.fetchall()
            conn.close()
            
            expected_columns = ['kid', 'key', 'exp']
            found_columns = [col[1] for col in columns]
            
            # Check if all expected columns exist
            return all(col in found_columns for col in expected_columns)
        except Exception:
            return False

    def test_database_has_keys(self) -> bool:
        """Test if database contains keys"""
        try:
            conn = sqlite3.connect("totally_not_my_privateKeys.db")
            cursor = conn.execute("SELECT COUNT(*) FROM keys")
            count = cursor.fetchone()[0]
            conn.close()
            return count > 0
        except Exception:
            return False

    def test_jwks_endpoint(self) -> bool:
        """Test JWKS endpoint returns valid JSON"""
        try:
            response = requests.get(f"{self.base_url}/.well-known/jwks.json", timeout=5)
            if response.status_code != 200:
                return False
            
            jwks_data = response.json()
            return "keys" in jwks_data and len(jwks_data["keys"]) > 0
        except Exception:
            return False

    def test_jwks_structure(self) -> bool:
        """Test JWKS structure is correct"""
        try:
            response = requests.get(f"{self.base_url}/.well-known/jwks.json", timeout=5)
            jwks_data = response.json()
            
            for key in jwks_data["keys"]:
                required_fields = ["kty", "use", "alg", "kid", "n", "e", "exp"]
                if not all(field in key for field in required_fields):
                    return False
                if key["kty"] != "RSA" or key["use"] != "sig" or key["alg"] != "RS256":
                    return False
            return True
        except Exception:
            return False

    def test_auth_endpoint(self) -> bool:
        """Test auth endpoint returns JWT"""
        try:
            response = requests.post(f"{self.base_url}/auth", timeout=5)
            if response.status_code != 200:
                return False
            
            auth_data = response.json()
            return "token" in auth_data and "kid" in auth_data
        except Exception:
            return False

    def test_jwt_validity(self) -> bool:
        """Test JWT token is valid and properly formed"""
        try:
            response = requests.post(f"{self.base_url}/auth", timeout=5)
            auth_data = response.json()
            token = auth_data["token"]
            
            # Check token structure
            parts = token.split(".")
            if len(parts) != 3:
                return False
            
            # Decode header and payload (without verification for testing)
            header = json.loads(base64.urlsafe_b64decode(parts[0] + "=="))
            payload = json.loads(base64.urlsafe_b64decode(parts[1] + "=="))
            
            # Check required claims
            required_claims = ["sub", "iat", "exp"]
            return all(claim in payload for claim in required_claims)
        except Exception:
            return False

    def test_expired_functionality(self) -> bool:
        """Test expired parameter functionality"""
        try:
            response = requests.post(f"{self.base_url}/auth?expired=1", timeout=5)
            if response.status_code != 200:
                return False
            
            auth_data = response.json()
            if "token" not in auth_data:
                return False
            
            # Decode payload to check expiration
            token = auth_data["token"]
            parts = token.split(".")
            payload = json.loads(base64.urlsafe_b64decode(parts[1] + "=="))
            
            # Token should be expired (exp < now)
            return payload["exp"] < int(datetime.utcnow().timestamp())
        except Exception:
            return False

    def test_json_authentication(self) -> bool:
        """Test JSON authentication support"""
        try:
            json_payload = {"username": "userABC", "password": "password123"}
            response = requests.post(
                f"{self.base_url}/auth", 
                json=json_payload,
                headers={'Content-Type': 'application/json'},
                timeout=5
            )
            return response.status_code == 200 and "token" in response.json()
        except Exception:
            return False

    def test_json_auth_rejection(self) -> bool:
        """Test JSON authentication rejects invalid credentials"""
        try:
            json_payload = {"username": "wrong", "password": "wrong"}
            response = requests.post(
                f"{self.base_url}/auth", 
                json=json_payload,
                headers={'Content-Type': 'application/json'},
                timeout=5
            )
            return response.status_code == 401
        except Exception:
            return False

    def test_server_running(self) -> bool:
        """Test if server is running on correct port"""
        try:
            response = requests.get(f"{self.base_url}/.well-known/jwks.json", timeout=2)
            return response.status_code == 200
        except Exception:
            return False

    def run_tests(self):
        """Run all tests and generate rubric"""
        print(f"{Fore.CYAN}{Style.BRIGHT}{'='*80}")
        print(f"CSCE 3550 - PROJECT 2 GRADEBOT CLIENT")
        print(f"{'='*80}{Style.RESET_ALL}")
        print(f"Testing server at: {self.base_url}")
        print(f"Database file: totally_not_my_privateKeys.db")
        print()

        # Define all tests with points
        tests = [
            ("Server Accessibility", 5, self.test_server_running, 
             "Server responds on port 8080"),
            
            ("Database File Exists", 10, self.test_database_file_exists,
             "File 'totally_not_my_privateKeys.db' present"),
            
            ("Database Schema", 15, self.test_database_schema,
             "Correct table schema (kid, key, exp)"),
            
            ("Database Contains Keys", 10, self.test_database_has_keys,
             "Keys are persisted in database"),
            
            ("JWKS Endpoint", 15, self.test_jwks_endpoint,
             "/.well-known/jwks.json returns valid JSON"),
            
            ("JWKS Structure", 10, self.test_jwks_structure,
             "JWKS contains proper RSA key format"),
            
            ("Auth Endpoint", 15, self.test_auth_endpoint,
             "/auth returns JWT token"),
            
            ("JWT Validity", 10, self.test_jwt_validity,
             "JWT has proper structure and claims"),
            
            ("Expired Functionality", 15, self.test_expired_functionality,
             "?expired=1 returns expired token"),
            
            ("JSON Authentication", 10, self.test_json_authentication,
             "Accepts JSON auth payload"),
            
            ("Auth Security", 5, self.test_json_auth_rejection,
             "Rejects invalid credentials")
        ]

        # Run all tests
        for name, points, test_func, description in tests:
            self.add_test(name, points, test_func, description)

        # Display results
        self.display_rubric()

    def display_rubric(self):
        """Display the rubric table with results"""
        print(f"{Fore.YELLOW}{Style.BRIGHT}RUBRIC AND TEST RESULTS{Style.RESET_ALL}")
        print("─" * 80)
        
        headers = ["Test Case", "Points", "Status", "Description"]
        
        # Create colored table
        colored_results = []
        for row in self.results:
            colored_results.append(row)
        
        print(tabulate(colored_results, headers=headers, tablefmt="grid", maxcolwidths=[25, 8, 10, 35]))
        
        # Summary
        percentage = (self.total_points / self.max_points) * 100 if self.max_points > 0 else 0
        
        print()
        print(f"{Style.BRIGHT}{'='*80}")
        print(f"FINAL GRADE: {self.total_points}/{self.max_points} ({percentage:.1f}%)")
        
        if percentage >= 95:
            print(f"{Fore.GREEN}{Style.BRIGHT}🎉 EXCELLENT! Outstanding work!{Style.RESET_ALL}")
        elif percentage >= 85:
            print(f"{Fore.CYAN}{Style.BRIGHT}✅ VERY GOOD! Well done!{Style.RESET_ALL}")
        elif percentage >= 70:
            print(f"{Fore.YELLOW}{Style.BRIGHT}⚠️  GOOD! Some improvements needed.{Style.RESET_ALL}")
        else:
            print(f"{Fore.RED}{Style.BRIGHT}❌ NEEDS WORK! Please review requirements.{Style.RESET_ALL}")
        
        print(f"{'='*80}{Style.RESET_ALL}")
        
        # Additional info
        if os.path.exists("totally_not_my_privateKeys.db"):
            size = os.path.getsize("totally_not_my_privateKeys.db")
            print(f"\n{Fore.CYAN}Database Info:{Style.RESET_ALL}")
            print(f"  File size: {size:,} bytes")
            
            try:
                conn = sqlite3.connect("totally_not_my_privateKeys.db")
                cursor = conn.execute("SELECT COUNT(*) FROM keys")
                count = cursor.fetchone()[0]
                print(f"  Total keys: {count}")
                
                now = int(datetime.utcnow().timestamp())
                cursor = conn.execute("SELECT COUNT(*) FROM keys WHERE exp > ?", (now,))
                valid = cursor.fetchone()[0]
                cursor = conn.execute("SELECT COUNT(*) FROM keys WHERE exp <= ?", (now,))
                expired = cursor.fetchone()[0]
                print(f"  Valid keys: {valid}")
                print(f"  Expired keys: {expired}")
                conn.close()
            except Exception as e:
                print(f"  Error reading database: {e}")

def main():
    """Main function"""
    print(f"{Fore.CYAN}Starting Project 2 Gradebot Client...{Style.RESET_ALL}")
    
    # Check if server is likely running
    try:
        response = requests.get("http://127.0.0.1:8080/.well-known/jwks.json", timeout=2)
    except:
        print(f"{Fore.RED}⚠️  Warning: Server doesn't appear to be running on port 8080{Style.RESET_ALL}")
        print("Please start your server with: python -m flask --app jwks_server.app run --port 8080")
        print()
    
    client = GradebotClient()
    client.run_tests()

if __name__ == "__main__":
    # Install required packages if not available
    try:
        import tabulate
        import colorama
    except ImportError:
        print("Installing required packages...")
        import subprocess
        import sys
        subprocess.check_call([sys.executable, "-m", "pip", "install", "tabulate", "colorama"])
        import tabulate
        import colorama
    
    main()