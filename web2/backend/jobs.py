"""
Tâches de fond avec suivi de progression.

Pourquoi : la propagation (24 résolveurs), la découverte de sous-domaines, l'audit
de sécurité et le rapport PDF prennent de 5 s à 2 min. Exécutés dans la requête
HTTP, ils dépassent le délai du reverse proxy (ou du navigateur) et l'appelant
reçoit une page HTML d'erreur au lieu d'un JSON. On rend donc la main tout de
suite avec un identifiant de tâche, et le front interroge ``GET /api/jobs/{id}``
jusqu'à voir le résultat arriver.
"""

import threading
import time
import traceback
import uuid
from typing import Any, Callable, Dict, List, Optional

from . import settings

_lock = threading.Lock()
_jobs: Dict[str, "Job"] = {}
_order: List[str] = []


class Job:
    """Une tâche de fond : étapes, résultat, erreur éventuelle."""

    def __init__(self, kind: str, label: str = ""):
        self.id = uuid.uuid4().hex[:12]
        self.kind = kind
        self.label = label
        self.status = "running"          # running | done | error
        self.created = time.time()
        self.finished: Optional[float] = None
        self.steps: List[Dict[str, Any]] = []
        self.result: Any = None
        self.error: Optional[str] = None

    # -- progression -------------------------------------------------------
    def step(self, label: str, detail: str = "", status: str = "ok") -> None:
        with _lock:
            # Une étape annoncée « en cours » (running) est acquittée par l'étape
            # suivante : sans cela, la liste garde des points bleus « … » même
            # une fois la tâche terminée, ce qui laisse croire que ça tourne encore.
            for ancienne in self.steps:
                if ancienne["status"] == "running":
                    ancienne["status"] = "ok"
            self.steps.append({"label": label, "detail": detail, "status": status,
                               "ts": round(time.time() - self.created, 2)})

    def running(self, label: str, detail: str = "") -> None:
        self.step(label, detail, status="running")

    # -- sérialisation -----------------------------------------------------
    def to_dict(self, with_result: bool = False) -> Dict[str, Any]:
        data = {
            "id": self.id,
            "kind": self.kind,
            "label": self.label,
            "status": self.status,
            "created": self.created,
            "finished": self.finished,
            "elapsed": round((self.finished or time.time()) - self.created, 1),
            "steps": list(self.steps),
            "error": self.error,
        }
        if with_result:
            data["result"] = self.result
        return data


def submit(kind: str, fn: Callable[[Job], Any], label: str = "") -> Job:
    """Démarre ``fn(job)`` dans un fil isolé et renvoie la tâche créée."""
    job = Job(kind, label)
    with _lock:
        _jobs[job.id] = job
        _order.append(job.id)
        _prune_locked()

    def runner():
        try:
            job.result = fn(job)
            job.status = "done"
        except Exception as exc:  # on garde la trace pour le diagnostic
            job.error = "%s : %s" % (type(exc).__name__, exc)
            job.status = "error"
            job.steps.append({"label": "Erreur", "detail": traceback.format_exc()[-600:],
                              "status": "error", "ts": round(time.time() - job.created, 2)})
        finally:
            job.finished = time.time()

    threading.Thread(target=runner, name="job-%s-%s" % (kind, job.id), daemon=True).start()
    return job


def get(job_id: str) -> Optional[Job]:
    with _lock:
        return _jobs.get(job_id)


def _prune_locked() -> None:
    while len(_order) > settings.JOBS_KEEP:
        old = _order.pop(0)
        _jobs.pop(old, None)
