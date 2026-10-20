"""Santé et métadonnées (types d'enregistrements, résolveurs, blacklists)."""

from fastapi import APIRouter

from . import services, settings

router = APIRouter(prefix="/api", tags=["système"])


@router.get("/health")
def health():
    return {"status": "ok", "version": settings.VERSION}


@router.get("/meta")
def meta():
    return services.meta()
