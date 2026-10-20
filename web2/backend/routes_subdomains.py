"""Écran « Sous-domaines » : crt.sh + brute-force (tâche de fond, 5 à 30 s)."""

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from . import jobs, services
from .routes_common import started

router = APIRouter(prefix="/api/subdomains", tags=["subdomains"])


class SubdomainsIn(BaseModel):
    domain: str = Field(min_length=1, max_length=253)
    bruteforce: bool = True
    crtsh: bool = True


@router.post("/run")
def run(payload: SubdomainsIn):
    try:
        domain = services.normalise_domain(payload.domain)
    except services.InvalidInput as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    if not payload.bruteforce and not payload.crtsh:
        raise HTTPException(status_code=400, detail="Choisissez au moins une méthode de découverte")
    job = jobs.submit("subdomains",
                      lambda j: services.subdomains(j, domain, payload.bruteforce, payload.crtsh),
                      label=domain)
    return started(job)
