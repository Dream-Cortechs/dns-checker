"""Écran « Enregistrements DNS » : interrogations directes (rapide, synchrone)."""

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from . import services

router = APIRouter(prefix="/api/dns", tags=["dns"])


class LookupIn(BaseModel):
    domain: str = Field(min_length=1, max_length=253)
    record_type: str = "A"
    resolver: str = ""


@router.post("/lookup")
def lookup(payload: LookupIn):
    try:
        return services.lookup(payload.domain, payload.record_type, payload.resolver)
    except services.InvalidInput as exc:
        raise HTTPException(status_code=400, detail=str(exc))
