"""Helpers partagés par les routeurs (réponses de tâches, erreurs)."""

from fastapi import HTTPException

from . import jobs


def started(job) -> dict:
    """Réponse immédiate d'une tâche de fond : le front suit /api/jobs/{id}."""
    return {"job_id": job.id, "status": job.status, "kind": job.kind,
            "poll": "/api/jobs/%s" % job.id}


def job_state(job_id: str) -> dict:
    job = jobs.get(job_id)
    if job is None:
        raise HTTPException(status_code=404, detail="Tâche inconnue ou expirée")
    return job.to_dict(with_result=True)
