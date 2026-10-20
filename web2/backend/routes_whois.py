"""Écran « WHOIS » (synchrone, 1 à 5 s selon le registre)."""

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from . import services

router = APIRouter(prefix="/api/whois", tags=["whois"])


class WhoisIn(BaseModel):
    domain: str = Field(min_length=1, max_length=253)


@router.post("/lookup")
def lookup(payload: WhoisIn):
    try:
        return services.whois(payload.domain)
    except services.InvalidInput as exc:
        raise HTTPException(status_code=400, detail=str(exc))
