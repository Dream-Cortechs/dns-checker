"""Écran « Sécurité email » : MX, SPF, DKIM, DMARC (rapide, synchrone)."""

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from . import services

router = APIRouter(prefix="/api/email", tags=["email"])


class EmailIn(BaseModel):
    domain: str = Field(min_length=1, max_length=253)
    selector: str = "default"


@router.post("/check")
def check(payload: EmailIn):
    try:
        return services.email_check(payload.domain, payload.selector)
    except services.InvalidInput as exc:
        raise HTTPException(status_code=400, detail=str(exc))
