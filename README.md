# JWKS Server (Python)

## What
A minimal JWKS server that:
- serves JWKS at `/jwks` (only unexpired keys),
- issues JWTs at `/auth`,
- supports `?expired=1` to issue a JWT signed with an expired key.

## Requirements
See `requirements.txt`. Install with:
