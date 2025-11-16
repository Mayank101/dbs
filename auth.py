# auth_module.py - Complete authentication system
# Supports: Multiple API keys, Expiry, Rate limiting, HMAC verification, Twilio signature

import os
import json
import time
import hmac
import hashlib
import secrets
from typing import Dict, Any
from fastapi import Header, HTTPException

# Load environment variables
API_KEYS_FILE = os.getenv("API_KEYS_FILE", "api_keys.json")
ADMIN_API_KEY = os.getenv("ADMIN_API_KEY", "admin_key_change_me")
WHATSAPP_WEBHOOK_SECRET = os.getenv("WHATSAPP_WEBHOOK_SECRET")
RATE_LIMIT_CAPACITY = int(os.getenv("RATE_LIMIT_CAPACITY", "60"))
RATE_LIMIT_REFILL_PER_SEC = float(os.getenv("RATE_LIMIT_REFILL_PER_SEC", "1.0"))
TWILIO_AUTH_TOKEN = os.getenv("TWILIO_AUTH_TOKEN")

# In memory token buckets
token_buckets: Dict[str, Dict[str, Any]] = {}


# ---------------------------------------------
# API KEY STORAGE
# ---------------------------------------------

def load_api_keys():
    try:
        with open(API_KEYS_FILE, "r") as f:
            return json.load(f)
    except FileNotFoundError:
        return {}


def save_api_keys(data: Dict[str, Any]):
    with open(API_KEYS_FILE, "w") as f:
        json.dump(data, f, indent=2)


api_keys_store = load_api_keys()


def now_ts():
    return int(time.time())


def create_api_key_record(client_name: str, days_valid: int = 30):
    key = secrets.token_urlsafe(32)
    now = now_ts()
    expires = now + days_valid * 24 * 3600

    record = {
        "client_name": client_name,
        "created_at": now,
        "expires_at": expires,
        "rate_capacity": RATE_LIMIT_CAPACITY,
        "rate_refill_per_sec": RATE_LIMIT_REFILL_PER_SEC
    }

    api_keys_store[key] = record
    save_api_keys(api_keys_store)

    token_buckets[key] = {
        "tokens": RATE_LIMIT_CAPACITY,
        "last_refill": time.time(),
        "capacity": RATE_LIMIT_CAPACITY,
        "refill_per_sec": RATE_LIMIT_REFILL_PER_SEC
    }

    return key, record


def revoke_api_key(key: str):
    if key in api_keys_store:
        del api_keys_store[key]
        save_api_keys(api_keys_store)
    if key in token_buckets:
        del token_buckets[key]


# ---------------------------------------------
# RATE LIMITING
# ---------------------------------------------

def verify_rate_limit(key: str):
    record = api_keys_store.get(key)
    if not record:
        return False

    if now_ts() > record.get("expires_at", 0):
        return False

    bucket = token_buckets.setdefault(
        key,
        {
            "tokens": record["rate_capacity"],
            "last_refill": time.time(),
            "capacity": record["rate_capacity"],
            "refill_per_sec": record["rate_refill_per_sec"]
        }
    )

    now = time.time()
    elapsed = now - bucket["last_refill"]
    refill_amount = elapsed * bucket["refill_per_sec"]
    bucket["tokens"] = min(bucket["capacity"], bucket["tokens"] + refill_amount)
    bucket["last_refill"] = now

    if bucket["tokens"] >= 1:
        bucket["tokens"] -= 1
        return True

    return False


# ---------------------------------------------
# API KEY VALIDATION
# ---------------------------------------------
async def verify_api_key(x_api_key: str = Header(None)):
    if not x_api_key:
        raise HTTPException(status_code=401, detail="Missing API key")

    record = api_keys_store.get(x_api_key)
    if not record:
        raise HTTPException(status_code=401, detail="Invalid API key")

    if now_ts() > record.get("expires_at", 0):
        raise HTTPException(status_code=403, detail="API key expired")

    if not verify_rate_limit(x_api_key):
        raise HTTPException(status_code=429, detail="Rate limit exceeded")

    return record


# ---------------------------------------------
# ADMIN VALIDATION
# ---------------------------------------------
async def verify_admin(x_admin_api_key: str = Header(None)):
    if x_admin_api_key != ADMIN_API_KEY:
        raise HTTPException(status_code=401, detail="Invalid admin key")
    return True


# ---------------------------------------------
# ADMIN HANDLERS
# ---------------------------------------------

def admin_create_key(client_name: str, days_valid: int, admin_ok):
    return create_api_key_record(client_name, days_valid)


def admin_list_keys(admin_ok):
    return api_keys_store


def admin_revoke_key(key: str, admin_ok):
    revoke_api_key(key)
    return {"revoked": key}


# ---------------------------------------------
# HMAC VERIFICATION
# ---------------------------------------------

def verify_hmac_sha256(body: bytes, signature_header: str, secret: str):
    if not signature_header or not secret:
        return False

    try:
        if signature_header.startswith("sha256="):
            signature = signature_header.split("=", 1)[1]
        else:
            signature = signature_header

        computed = hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
        return hmac.compare_digest(computed, signature)
    except Exception:
        return False


# ---------------------------------------------
# TWILIO SIGNATURE VERIFICATION
# ---------------------------------------------

def verify_twilio_signature(url: str, params: dict, signature: str):
    if not TWILIO_AUTH_TOKEN:
        return False

    try:
        import base64
        combined = url
        for k in sorted(params.keys()):
            combined += str(params[k])

        mac = hmac.new(TWILIO_AUTH_TOKEN.encode(), combined.encode(), hashlib.sha1)
        expected = base64.b64encode(mac.digest()).decode()

        return hmac.compare_digest(expected, signature)
    except Exception:
        return False
