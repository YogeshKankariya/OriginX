from fastapi import APIRouter, Header, HTTPException
from pydantic import BaseModel, Field

from app.config import settings
from app.services.claims_service import get_claim_history, insert_claim
from app.services.supabase_client import check_supabase_connection

router = APIRouter()


class ClaimRequest(BaseModel):
    claim_text: str = Field(min_length=1)


def _ensure_test_db_access(token: str | None) -> None:
    configured_token = settings.TEST_DB_API_TOKEN.strip()
    if not configured_token:
        return

    if token != configured_token:
        raise HTTPException(status_code=403, detail="Forbidden")


@router.get("/test-db/status")
def db_status(x_originx_admin_token: str | None = Header(default=None)) -> dict[str, str | bool]:
    _ensure_test_db_access(x_originx_admin_token)

    ok, message = check_supabase_connection()
    if not ok:
        raise HTTPException(status_code=503, detail=message)

    return {"connected": True, "message": message}


@router.post("/test-db")
def db_insert(payload: ClaimRequest, x_originx_admin_token: str | None = Header(default=None)) -> dict:
    _ensure_test_db_access(x_originx_admin_token)

    try:
        return insert_claim(payload.claim_text)
    except TimeoutError as exc:
        raise HTTPException(status_code=504, detail=str(exc)) from exc
    except RuntimeError as exc:
        raise HTTPException(status_code=500, detail="Database operation failed.") from exc
    except Exception as exc:
        raise HTTPException(status_code=500, detail="Unexpected server error.") from exc


@router.get("/test-db/history")
def db_history(claim_text: str, x_originx_admin_token: str | None = Header(default=None)) -> list[dict]:
    _ensure_test_db_access(x_originx_admin_token)

    try:
        return get_claim_history(claim_text)
    except TimeoutError as exc:
        raise HTTPException(status_code=504, detail=str(exc)) from exc
    except RuntimeError as exc:
        raise HTTPException(status_code=500, detail="Database operation failed.") from exc
    except Exception as exc:
        raise HTTPException(status_code=500, detail="Unexpected server error.") from exc
