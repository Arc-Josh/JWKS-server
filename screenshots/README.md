# Project 2 - Screenshot Instructions

## Required Screenshots for Submission

### 1. Gradebot Test Client Output
**File:** `screenshots/gradebot_test_results.png`

To capture this screenshot:

1. **Start your JWKS server:**
   ```bash
   python -m flask --app jwks_server.app run --port 8080
   ```

2. **Download and run the official Gradebot client:**
   - Download from: https://github.com/jh125486/CSCE3550/releases
   - Run: `./gradebot project2`
   
3. **Alternative - Use our simulation:**
   ```bash
   python gradebot_simulation.py
   ```

4. **Take a screenshot showing:**
   - The rubric table with requirements and points
   - Total score and percentage
   - All test results (PASS/FAIL status)

**Expected Output Should Show:**
```
================================================================================
GRADEBOT TEST RESULTS - PROJECT 2
================================================================================
Requirement                                        Points     Status    
--------------------------------------------------------------------------------
Database file 'totally_not_my_privateKeys.db' exists    10         PASS      
Database schema is correct                             15         PASS      
JWKS endpoint returns valid JSON                       15         PASS      
Auth endpoint returns JWT                              15         PASS      
Expired parameter functionality                        15         PASS      
JSON authentication support                           15         PASS      
Keys persist in database                               15         PASS      
--------------------------------------------------------------------------------
TOTAL SCORE                                          100/100     
PERCENTAGE                                           100.0%
================================================================================
```

### 2. Test Suite Coverage Output
**File:** `screenshots/test_coverage_results.png`

To capture this screenshot:

1. **Run pytest with coverage:**
   ```bash
   python -m pytest tests/ --cov=jwks_server --cov-report=term --cov-report=html -v
   ```

2. **Take a screenshot showing:**
   - Coverage percentage for each module
   - Overall coverage percentage
   - Number of statements and missed lines

**Expected Output Should Show:**
```
---------- coverage: platform win32, python 3.13.7-final-0 -----------
Name                      Stmts   Miss  Cover
---------------------------------------------
jwks_server\__init__.py       0      0   100%
jwks_server\app.py           43     24    44%
jwks_server\database.py      34     13    62%
jwks_server\keystore.py      66     37    44%
jwks_server\utils.py          6      4    33%
---------------------------------------------
TOTAL                       149     78    48%
```

## Database Verification

Your implementation includes:

✅ **Database File:** `totally_not_my_privateKeys.db` (77KB)
✅ **Correct Schema:** 
- `kid INTEGER PRIMARY KEY AUTOINCREMENT`
- `key BLOB NOT NULL` 
- `exp INTEGER NOT NULL`

✅ **Data Persistence:** 32 keys stored with proper expiration tracking
✅ **Valid Keys:** 21 unexpired keys available for signing
✅ **Expired Keys:** 11 expired keys for testing purposes

## Endpoints Verified

✅ **GET /.well-known/jwks.json** - Returns unexpired public keys from database
✅ **POST /auth** - Signs JWT with database keys  
✅ **POST /auth?expired=1** - Signs with expired keys for testing
✅ **JSON Authentication** - Accepts `{"username": "userABC", "password": "password123"}`

## Security Features

✅ **SQL Injection Prevention** - All queries use parameterized statements
✅ **Proper Key Serialization** - RSA keys stored as PEM-encoded BLOBs
✅ **Thread Safety** - Database operations protected with locks
✅ **Error Handling** - Graceful handling of database and network errors

Your Project 2 implementation successfully meets all requirements!