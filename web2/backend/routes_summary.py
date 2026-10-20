"""Écran « Vue d'ensemble » : scan complet en une tâche de fond."""

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from . import jobs, services
from .routes_common import started

router = APIRouter(prefix="/api/summary", tags=["summary"])


class SummaryIn(BaseModel):
    domain: str = Field(min_length=1, max_length=253)


@router.post("/run")
def run(payload: SummaryIn):
    try:
        domain = services.normalise_domain(payload.domain)
    except services.InvalidInput as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    job = jobs.submit("summary", lambda j: services.summary(j, domain), label=domain)
    return started(job)
