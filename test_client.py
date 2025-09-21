# test_client.py
"""
Simple test client that POSTs to /auth with no body.
Run this while the server is listening on localhost:8080.
"""
import requests

def main():
    r = requests.post("http://127.0.0.1:8080/auth")
    print("status:", r.status_code)
    print(r.text)

if __name__ == "__main__":
    main()
