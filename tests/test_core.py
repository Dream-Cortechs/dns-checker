"""Tests unitaires du moteur : classification blacklist, WHOIS .fr, validation des entrées."""

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from core.blacklist import ERREUR, LISTEE, PROPRE, RESEAU, _classify  # noqa: E402
from core.whois_geo import _parse_whois_raw  # noqa: E402
from web2.backend.services import InvalidInput, normalise_domain, normalise_ip  # noqa: E402


def test_code_255_est_une_erreur_pas_un_listage():
    """La v1 comptait 127.255.255.254 comme « IP listée » : c'était un faux positif."""
    statut, detail = _classify("127.255.255.254", "cbl.abuseat.org")
    assert statut == ERREUR
    assert "pas un listage" in detail


def test_listage_individuel():
    statut, _ = _classify("127.0.0.4", "zen.spamhaus.org")
    assert statut == LISTEE


def test_uceprotect_niveau_reseau():
    statut, detail = _classify("127.0.0.2", "dnsbl-3.uceprotect.net")
    assert statut == RESEAU
    assert "/24" in detail


def test_parse_whois_afnic():
    brut = """domain:      cortechs.fr
status:      ACTIVE
holder:      CORTECHS
registrar:   IONOS SE
created:     2007-08-23T15:10:30Z
last-update: 2026-09-30T22:07:22Z
anniversary: 2027-08-23T15:10:30Z
nserver:     ns1108.ui-dns.de
nserver:     ns1108.ui-dns.com
"""
    info = _parse_whois_raw(brut, "cortechs.fr")
    assert info["registrar"] == "IONOS SE"
    assert info["holder"] == "CORTECHS"
    assert info["creation_date"].startswith("2007-08-23")
    assert info["expiration_date"].startswith("2027-08-23")
    assert len(info["name_servers"]) == 2


@pytest.mark.parametrize("entree,attendu", [
    ("cortechs.fr", "cortechs.fr"),
    ("  CORTECHS.FR  ", "cortechs.fr"),
    ("https://erp.cortechs.fr/saisie?x=1", "erp.cortechs.fr"),
    ("cortechs.fr.", "cortechs.fr"),
])
def test_normalise_domain(entree, attendu):
    assert normalise_domain(entree) == attendu


@pytest.mark.parametrize("entree", ["pas un domaine", "cortechs", "http://", "a..b.fr", "-x.fr"])
def test_domaines_refuses(entree):
    with pytest.raises(InvalidInput):
        normalise_domain(entree)


def test_ip():
    assert normalise_ip("217.160.0.200") == "217.160.0.200"
    with pytest.raises(InvalidInput):
        normalise_ip("999.1.1.1")
