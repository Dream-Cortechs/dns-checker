"""Écran « Blacklists » : 12 listes interrogées en parallèle (tâche de fond)."""

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from . import jobs, services
from .routes_common import started

router = APIRouter(prefix="/api/blacklist", tags=["blacklist"])


class BlacklistIn(BaseModel):
    target: str = Field(min_length=1, max_length=253)


@router.post("/run")
def run(payload: BlacklistIn):
    try:
        services.normalise_ip(payload.target)
        target = payload.target
    except services.InvalidInput:
        try:
            target = services.normalise_domain(payload.target)
        except services.InvalidInput as exc:
            raise HTTPException(status_code=400, detail=str(exc))
    job = jobs.submit("blacklist", lambda j: services.blacklist(j, target), label=target)
    return started(job)
