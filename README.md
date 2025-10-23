# JWKS Server
# ojd0011

## Features

- **SQLite Database Storage**: Persistent key storage with secure parameterized queries
- **JWKS Endpoint**: Serves unexpired public keys in standard JWKS format
- **JWT Authentication**: Issues signed JSON Web Tokens with RSA keys
- **Key Expiration**: Supports expired key functionality for testing
- **JSON Authentication**: Accepts JSON credentials for authentication
- **Security**: Protection against SQL injection attacks

## Requirements

- Python 3.8+
- Flask
- cryptography
- sqlite3 (included with Python)

## Installation

1. Clone the repository:
   ```bash
   git clone <repository-url>
   cd JWKS-server-main
   ```

2. Create and activate a virtual environment:
   ```bash
   python -m venv .venv
   .venv\Scripts\activate  # Windows
   source .venv/bin/activate  # Linux/Mac
   ```

3. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

## Running the Server

Start the JWKS server on port 8080:

```bash
python -m flask --app jwks_server.app run --port 8080
```

The server will be available at `http://127.0.0.1:8080`

## API Endpoints

### GET /.well-known/jwks.json
Returns unexpired public keys in JWKS format.

**Response:**
```json
{
  "keys": [
    {
      "kty": "RSA",
      "use": "sig",
      "kid": "1",
      "n": "...",
      "e": "AQAB"
    }
  ]
}
```

### POST /auth
Issues a signed JWT token. Supports both URL-encoded and JSON requests.

**JSON Request:**
```json
{
  "username": "userABC",
  "password": "password123"
}
```

**Response:**
```json
{
  "token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9..."
}
```

**Query Parameter:**
- `expired=true` - Use expired key for testing

## Database

The server uses SQLite database (`totally_not_my_privateKeys.db`) with the following schema:

```sql
CREATE TABLE keys(
    kid INTEGER PRIMARY KEY AUTOINCREMENT,
    key BLOB NOT NULL,
    exp INTEGER NOT NULL
);
```

## Testing

Run the test suite:

```bash
python -m pytest tests/ --cov=jwks_server --cov-report=term -v
```

## Project Structure

```
jwks_server/
├── __init__.py
├── app.py          # Flask application and routes
├── database.py     # SQLite database manager
├── keystore.py     # RSA key management
└── utils.py        # Utility functions
tests/
├── conftest.py     # Test configuration
└── test_app.py     # Application tests
```
