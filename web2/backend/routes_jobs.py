"""Suivi des tâches de fond (interrogé par le front toutes les 800 ms)."""

from fastapi import APIRouter

from .routes_common import job_state

router = APIRouter(prefix="/api/jobs", tags=["jobs"])


@router.get("/{job_id}")
def state(job_id: str):
    return job_state(job_id)
