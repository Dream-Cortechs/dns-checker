"""Test de câblage : toute route déclarée répond du JSON, et /api/* inconnu ne renvoie jamais le HTML du front."""

import re
import sys
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from web2.backend.main import app  # noqa: E402

client = TestClient(app)

# Toutes les routes GET de l'API, sans paramètre dynamique
# FastAPI récent encapsule les routeurs inclus (_IncludedRouter) : app.routes n'est plus
# à plat, l'introspection donne des faux négatifs. La source de vérité est le schéma OpenAPI.
def api_paths():
    return client.get("/api/openapi.json").json()["paths"]


def api_get_paths():
    return sorted(p for p, ops in api_paths().items()
                  if "get" in ops and "{" not in p and p not in ("/api/docs", "/api/openapi.json"))


def test_meta_and_health():
    assert client.get("/api/health").json()["status"] == "ok"
    meta = client.get("/api/meta").json()
    assert "A" in meta["record_types"]
    assert len(meta["resolvers"]) >= 20
    assert len(meta["blacklists"]) == 12


@pytest.mark.parametrize("path", api_get_paths())
def test_get_routes_return_json(path):
    response = client.get(path)
    assert response.headers["content-type"].startswith("application/json"), (
        "la route %s a renvoyé %s" % (path, response.headers.get("content-type"))
    )


def test_unknown_api_is_json_404():
    response = client.get("/api/route-qui-nexiste-pas")
    assert response.status_code == 404
    assert response.headers["content-type"].startswith("application/json")
    assert "detail" in response.json()


def test_every_router_module_is_mounted():
    """Un fichier routes_*.py écrit mais non branché = écran muet : on le détecte par appel réel."""
    backend = ROOT / "web2" / "backend"
    modules = sorted({p.stem for p in backend.glob("routes_*.py")} - {"routes_common"})
    chemins = api_paths()
    manquants = []
    for module in modules:
        nom = module.replace("routes_", "")
        if not any(c.startswith("/api/" + nom) for c in chemins):
            manquants.append(module)
    assert not manquants, "routeurs non branchés : %s" % manquants
    # les écrans qui doivent exister
    for attendu in ("dns", "email", "whois", "geo", "blacklist", "propagation",
                    "subdomains", "security", "report", "summary", "jobs"):
        assert any(c.startswith("/api/" + attendu) for c in chemins), attendu


def test_bad_domain_is_400():
    for payload in ({"domain": "pas un domaine"}, {"domain": ""}, {"domain": "http://x"}):
        response = client.post("/api/dns/lookup", json=payload)
        assert response.status_code in (400, 422), payload


def test_job_inconnu():
    assert client.get("/api/jobs/inconnu123").status_code == 404


def test_report_token_invalide():
    assert client.get("/api/report/../etc/passwd/download").status_code in (404, 400)
