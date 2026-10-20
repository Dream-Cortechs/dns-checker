"""Écran « Audit sécurité » : DNSSEC, CAA, en-têtes HTTP, TLS (tâche de fond)."""

from typing import List, Optional

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from . import jobs, services
from .routes_common import started

router = APIRouter(prefix="/api/security", tags=["security"])


class SecurityIn(BaseModel):
    domain: str = Field(min_length=1, max_length=253)
    subdomains: Optional[List[str]] = None


@router.post("/run")
def run(payload: SecurityIn):
    try:
        domain = services.normalise_domain(payload.domain)
    except services.InvalidInput as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    job = jobs.submit("security",
                      lambda j: services.security(j, domain, payload.subdomains or []),
                      label=domain)
    return started(job)
