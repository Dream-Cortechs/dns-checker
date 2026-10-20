"""Écran « Propagation » : 24 résolveurs en parallèle (tâche de fond)."""

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from . import jobs, services
from .routes_common import started

router = APIRouter(prefix="/api/propagation", tags=["propagation"])


class PropagationIn(BaseModel):
    domain: str = Field(min_length=1, max_length=253)
    record_type: str = "A"


@router.post("/run")
def run(payload: PropagationIn):
    try:
        domain = services.normalise_domain(payload.domain)
    except services.InvalidInput as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    job = jobs.submit("propagation",
                      lambda j: services.propagation(j, domain, payload.record_type),
                      label=domain)
    return started(job)
