# One-time Secret for Railway

Self-hosted one-time secret sharing app built with Flask + PostgreSQL.

## Features
- One-time secret links
- Expiry / TTL
- Optional passphrase
- Encrypted secret storage
- URL fragment token (`/s#token`) so token is not sent in normal HTTP request logs

## Required environment variables
- DATABASE_URL
- MASTER_KEY
- ADMIN_TOKEN

## Optional environment variables
- APP_BASE_URL
- MAX_SECRET_LENGTH
- MAX_TTL_MINUTES

## Generate MASTER_KEY
```bash
python - <<'PY'
import base64, os
print(base64.urlsafe_b64encode(os.urandom(32)).decode())
PY
