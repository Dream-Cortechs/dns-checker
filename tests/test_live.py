"""Tests sur données réelles (réseau requis) — marqués « live », exclus par défaut en CI hors LAN."""

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from web2.backend import services  # noqa: E402

pytestmark = pytest.mark.live


def test_lookup_reel():
    res = services.lookup("cortechs.fr", "A")
    assert res["count"] >= 1
    assert res["error"] is None


def test_email_reel():
    res = services.email_check("cortechs.fr")
    assert res["mx"]["servers"]
    assert 0 <= res["score"] <= 4


class JobFactice:
    """Job minimal : la progression n'a pas d'importance ici."""
    def step(self, *args, **kwargs):
        pass

    def running(self, *args, **kwargs):
        pass


def test_security_details_sont_des_chaines():
    """Régression : un « detail » objet faisait planter l'écran Audit (React #31)."""
    res = services.security(JobFactice(), "cortechs.fr", [])
    for cle, critere in res["criteria"].items():
        assert isinstance(critere["detail"], str), "%s.detail = %r" % (cle, critere["detail"])


def test_whois_fr_reel():
    res = services.whois("cortechs.fr")
    assert res["registrar"], "WHOIS .fr vide : régression du correctif AFNIC"
    assert res["creation_date"]
