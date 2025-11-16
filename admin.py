from fastapi import APIRouter, Depends
from auth_module import (
    verify_admin,
    admin_create_key,
    admin_list_keys,
    admin_revoke_key
)

router = APIRouter()

@router.post("/create-key")
def create_key(client_name: str, days_valid: int = 30, admin_ok: bool = Depends(verify_admin)):
    key, record = admin_create_key(client_name, days_valid, admin_ok)
    return {
        "message": "API key created",
        "api_key": key,
        "record": record
    }

@router.get("/list-keys")
def list_keys(admin_ok: bool = Depends(verify_admin)):
    return {
        "message": "All API keys",
        "keys": admin_list_keys(admin_ok)
    }

@router.delete("/revoke-key")
def revoke_key(key: str, admin_ok: bool = Depends(verify_admin)):
    return {
        "message": "API key revoked",
        "key": admin_revoke_key(key, admin_ok)
    }
