"""
DNS Checker v2 — application FastAPI.

Un seul service : l'API sous /api/*, le front compilé (dist/) servi à la racine.
⚠️ Le repli SPA ne doit JAMAIS répondre pour /api/* : sinon une faute de frappe
d'URL ou un routeur non branché renvoie le HTML de la page avec un code 200, et
l'écran reste vide sans la moindre erreur (piège connu de la stack v2).
"""

from datetime import datetime

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse

from . import settings
from .routes_blacklist import router as blacklist_router
from .routes_dns import router as dns_router
from .routes_email import router as email_router
from .routes_geo import router as geo_router
from .routes_jobs import router as jobs_router
from .routes_meta import router as meta_router
from .routes_propagation import router as propagation_router
from .routes_report import router as report_router
from .routes_security import router as security_router
from .routes_subdomains import router as subdomains_router
from .routes_summary import router as summary_router
from .routes_whois import router as whois_router

ROUTERS = [
    meta_router,
    dns_router,
    email_router,
    whois_router,
    geo_router,
    blacklist_router,
    propagation_router,
    subdomains_router,
    security_router,
    report_router,
    summary_router,
    jobs_router,
]

app = FastAPI(
    title="DNS Checker Cortechs",
    version=settings.VERSION,
    docs_url="/api/docs",
    openapi_url="/api/openapi.json",
)

# Le front de développement tourne sur http://localhost:5173 (Vite).
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://127.0.0.1:5173"],
    allow_methods=["*"],
    allow_headers=["*"],
)

for router in ROUTERS:
    app.include_router(router)


@app.get("/api/build")
def build_info():
    dist = settings.FRONTEND_DIST
    assets = sorted((dist / "assets").glob("*.js")) if (dist / "assets").exists() else []
    return {
        "version": settings.VERSION,
        "front_built": (dist / "index.html").exists(),
        "front_assets": [a.name for a in assets],
        "server_time": datetime.now().isoformat(timespec="seconds"),
    }


@app.get("/{full_path:path}")
def spa(full_path: str):
    """Sert le front compilé, en refusant explicitement les chemins /api/*."""
    if full_path.startswith("api/") or full_path == "api":
        return JSONResponse({"detail": "Route API inconnue : /%s" % full_path}, status_code=404)

    dist = settings.FRONTEND_DIST
    if full_path:
        candidate = (dist / full_path).resolve()
        if str(candidate).startswith(str(dist.resolve())) and candidate.is_file():
            return FileResponse(str(candidate))

    index = dist / "index.html"
    if index.exists():
        return FileResponse(str(index), headers={"Cache-Control": "no-store, must-revalidate"})
    raise HTTPException(status_code=503, detail="Front non compilé : lancez npm run build")
