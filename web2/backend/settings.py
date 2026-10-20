"""Réglages de l'application DNS Checker v2 (Cortechs)."""

import os
from pathlib import Path

VERSION = "2.0.0"
APP_NAME = "DNS Checker"

BACKEND_DIR = Path(__file__).resolve().parent
WEB2_DIR = BACKEND_DIR.parent
ROOT_DIR = WEB2_DIR.parent
FRONTEND_DIST = WEB2_DIR / "frontend" / "dist"

# Données d'exécution (jamais dans le dépôt)
DATA_DIR = Path(os.environ.get("DNS_DATA_DIR", "/var/lib/dns-checker-v2"))
CACHE_DIR = DATA_DIR / "cache"
CACHE_DIR.mkdir(parents=True, exist_ok=True)

# Un rapport PDF reste téléchargeable N minutes après génération
REPORT_TTL_MINUTES = int(os.environ.get("DNS_REPORT_TTL_MINUTES", "60"))
# Nombre de rapports gardés sur disque
REPORT_KEEP = int(os.environ.get("DNS_REPORT_KEEP", "20"))

# Durées maximales des tâches de fond (secondes)
JOB_TIMEOUTS = {
    "propagation": 120,
    "subdomains": 180,
    "security": 240,
    "report": 300,
    "blacklist": 120,
}

# Nombre de jobs conservés en mémoire
JOBS_KEEP = 50
