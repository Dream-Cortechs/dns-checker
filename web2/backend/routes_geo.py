"""Écran « Géolocalisation » (synchrone : 1 appel ip-api par IP)."""

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from . import services

router = APIRouter(prefix="/api/geo", tags=["geo"])


class GeoIn(BaseModel):
    target: str = Field(min_length=1, max_length=253)


@router.post("/locate")
def locate(payload: GeoIn):
    try:
        return services.geo(payload.target)
    except services.InvalidInput as exc:
        raise HTTPException(status_code=400, detail=str(exc))
