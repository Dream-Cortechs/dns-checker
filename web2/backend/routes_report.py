"""Écran « Rapport PDF » : génération en tâche de fond, puis téléchargement."""

from fastapi import APIRouter, HTTPException
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field

from . import jobs, services
from .routes_common import started

router = APIRouter(prefix="/api/report", tags=["report"])


class ReportIn(BaseModel):
    domain: str = Field(min_length=1, max_length=253)
    ip: str = ""


@router.post("/run")
def run(payload: ReportIn):
    try:
        domain = services.normalise_domain(payload.domain)
    except services.InvalidInput as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    job = jobs.submit("report", lambda j: services.report(j, domain, payload.ip), label=domain)
    return started(job)


@router.get("/{token}/download")
def download(token: str):
    path = services.report_path(token)
    if path is None:
        raise HTTPException(status_code=404, detail="Rapport introuvable ou expiré")
    return FileResponse(str(path), media_type="application/pdf", filename=path.name)
