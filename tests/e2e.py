"""
Recette de bout en bout du DNS Checker v2 (vrai navigateur, vraies données).

Lancement :
    .venv/bin/python tests/e2e.py [http://127.0.0.1:8507]

Vérifie, pour chaque écran : montage, action réelle, données affichées, absence
d'erreur JavaScript, absence de débordement horizontal, et enregistre une
capture dans docs/captures/. Sort en erreur (code 1) au premier défaut.
"""

import json
import pathlib
import sys
import time
import urllib.request

from playwright.sync_api import sync_playwright

URL = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:8507"
CHROME = "/root/.cache/ms-playwright/chromium-1234/chrome-linux64/chrome"
CAPTURES = pathlib.Path(__file__).resolve().parents[1] / "docs" / "captures"
CAPTURES.mkdir(parents=True, exist_ok=True)

DOMAINE = "cortechs.fr"
resultats = []
erreurs_js = []


def verifier(nom: str, condition: bool, detail: str = ""):
    resultats.append((nom, bool(condition), detail))
    print(("  OK   " if condition else "  ECHEC") + " " + nom + ((" — " + detail) if detail else ""))


def attendre(page, selecteur: str, secondes: int = 180):
    page.wait_for_selector(selecteur, timeout=secondes * 1000, state="visible")


def mesures(page):
    """Quatre mesures du design system : tokens, contraste, débordement, barres."""
    js = """() => {
      const s = getComputedStyle(document.documentElement);
      const tokens = ['--navy','--blue','--txt','--muted','--field']
        .map(k => s.getPropertyValue(k).trim());
      const lbl = document.querySelector('.kpi-lbl') || document.querySelector('.muted');
      return {
        tokens,
        couleurTexte: lbl ? getComputedStyle(lbl).color : null,
        fond: getComputedStyle(document.body).backgroundColor,
        largeur: [document.documentElement.scrollWidth, window.innerWidth],
      };
    }"""
    return page.evaluate(js)


def main():
    with sync_playwright() as pilote:
        navigateur = pilote.chromium.launch(executable_path=CHROME, args=["--no-sandbox"])
        page = navigateur.new_page(viewport={"width": 1440, "height": 1000})

        page.on("console", lambda m: erreurs_js.append(m.text) if m.type == "error" else None)
        page.on("pageerror", lambda e: erreurs_js.append(str(e)))

        def ouvrir(chemin: str, selecteur_pret: str):
            page.goto(URL + chemin)
            attendre(page, selecteur_pret, 30)

        def capture(nom: str):
            page.screenshot(path=str(CAPTURES / nom), full_page=False)

        # ── 1. Vue d'ensemble ────────────────────────────────────────────────
        print("\n[1/10] Vue d'ensemble")
        ouvrir("/", ".navi")
        page.fill("input.domaine", DOMAINE)
        page.click(".btn.primary")
        attendre(page, ".charge", 240)
        kpis = page.locator(".kpi-num").all_inner_texts()
        verifier("KPI affichés", len(kpis) == 6, " | ".join(kpis))
        verifier("points à corriger listés", page.locator(".finding").count() > 0,
                 page.locator(".finding b").first.inner_text() if page.locator(".finding").count() else "aucun")
        verifier("aucune étape restée « en cours »",
                 page.locator(".dot.run").count() == 0, "points bleus : %d" % page.locator(".dot.run").count())
        capture("01-vue-ensemble.png")

        m = mesures(page)
        verifier("tokens de thème non vides", all(m["tokens"]), str(m["tokens"]))
        verifier("pas de débordement horizontal", m["largeur"][0] <= m["largeur"][1] + 1,
                 "%s > %s" % tuple(m["largeur"]))

        # ── 2. Thème clair ───────────────────────────────────────────────────
        print("\n[2/10] Thème clair")
        page.click(".theme-toggle")
        time.sleep(0.4)
        theme = page.evaluate("document.documentElement.getAttribute('data-theme')")
        verifier("bascule en thème clair", theme == "light", str(theme))
        m_clair = mesures(page)
        verifier("tokens non vides en clair", all(m_clair["tokens"]), str(m_clair["tokens"]))
        verifier("fond clair effectif", m_clair["fond"] != m["fond"], "%s → %s" % (m["fond"], m_clair["fond"]))
        capture("02-vue-ensemble-clair.png")
        page.click(".theme-toggle")

        # ── 3. Enregistrements DNS ───────────────────────────────────────────
        print("\n[3/10] Enregistrements DNS")
        ouvrir("/dns", "h2")
        page.fill("input.search", DOMAINE)
        page.click(".btn.primary")
        attendre(page, ".tbl tbody tr")
        lignes = page.locator(".tbl tbody tr").count()
        verifier("enregistrements affichés", lignes >= 1, page.locator(".tbl tbody tr").first.inner_text())
        capture("03-enregistrements.png")

        # ── 4. Propagation ───────────────────────────────────────────────────
        print("\n[4/10] Propagation")
        ouvrir("/propagation", "h2")
        page.fill("input.search", DOMAINE)
        page.click(".btn.primary")
        attendre(page, ".tbl tbody tr", 240)
        page.wait_for_function("document.querySelectorAll('.tbl tbody tr').length >= 20", timeout=240000)
        lignes = page.locator(".tbl tbody tr").count()
        verifier("24 résolveurs testés", lignes == 24, "%d lignes" % lignes)
        verifier("consensus affiché", page.locator(".kpi-num").nth(1).inner_text() != "—",
                 page.locator(".kpi-num").nth(1).inner_text())
        capture("04-propagation.png")

        # ── 5. Sécurité email ────────────────────────────────────────────────
        print("\n[5/10] Sécurité email")
        ouvrir("/email", "h2")
        page.fill("input.search", DOMAINE)
        page.click(".btn.primary")
        attendre(page, ".charge")
        score = page.locator(".charge").inner_text()
        verifier("score email calculé", "Score" in score, score)
        verifier("4 critères affichés", page.locator(".cards .card").count() >= 4)
        capture("05-email.png")

        # ── 6. Blacklists ────────────────────────────────────────────────────
        print("\n[6/10] Blacklists")
        ouvrir("/blacklists", "h2")
        page.fill("input.search", "217.160.0.200")
        page.click(".btn.primary")
        attendre(page, ".tbl tbody tr", 180)
        page.wait_for_function("document.querySelectorAll('.tbl tbody tr').length >= 12", timeout=180000)
        lignes = page.locator(".tbl tbody tr").count()
        verifier("12 listes interrogées", lignes == 12, "%d lignes" % lignes)
        texte = page.locator(".tbl tbody").inner_text()
        verifier("un code 127.255.255.x n'est jamais présenté comme un listage",
                 "127.255.255" not in texte or "Requête refusée" in texte)
        capture("06-blacklists.png")

        # ── 7. WHOIS ─────────────────────────────────────────────────────────
        print("\n[7/10] WHOIS")
        ouvrir("/whois", "h2")
        page.fill("input.search", DOMAINE)
        page.click(".btn.primary")
        attendre(page, ".ck-row")
        texte = page.locator(".content").inner_text()
        verifier("registraire récupéré (.fr)", "IONOS" in texte,
                 page.locator(".ck-row").first.inner_text())
        verifier("date de création affichée", "2007" in texte)
        capture("07-whois.png")

        # ── 8. Géo IP ────────────────────────────────────────────────────────
        print("\n[8/10] Géolocalisation")
        ouvrir("/geo", "h2")
        page.fill("input.search", DOMAINE)
        page.click(".btn.primary")
        attendre(page, ".tbl tbody tr")
        verifier("adresse localisée", page.locator(".tbl tbody tr").count() >= 1,
                 page.locator(".tbl tbody tr").first.inner_text())
        capture("08-geo.png")

        # ── 9. Sous-domaines + audit sécurité ────────────────────────────────
        print("\n[9/10] Sous-domaines")
        ouvrir("/sous-domaines", "h2")
        page.fill("input.search", DOMAINE)
        page.click(".btn.primary")
        attendre(page, ".tbl tbody tr", 240)
        page.wait_for_function("document.querySelectorAll('.tbl tbody tr').length >= 5", timeout=240000)
        lignes = page.locator(".tbl tbody tr").count()
        verifier("sous-domaines découverts", lignes >= 5, "%d lignes" % lignes)
        capture("09-sous-domaines.png")

        print("\n[10/10] Audit de sécurité")
        ouvrir("/securite", "h2")
        page.fill("input.search", DOMAINE)
        page.click(".btn.primary")
        attendre(page, ".charge", 240)
        verifier("score d'audit affiché", "Score" in page.locator(".charge").inner_text(),
                 page.locator(".charge").inner_text())
        lignes = page.locator(".tbl tbody tr").count()
        verifier("certificats TLS listés", lignes >= 1, "%d hôte(s)" % lignes)
        premiere = page.locator(".tbl tbody").inner_text()
        verifier("émetteur du certificat renseigné", "—" not in premiere.split("\n")[0],
                 premiere.split("\n")[0])
        capture("10-securite.png")

        # ── Rapport PDF ──────────────────────────────────────────────────────
        print("\n[BONUS] Rapport PDF")
        ouvrir("/rapport", "h2")
        page.fill("input.search", DOMAINE)
        page.click(".btn.primary")
        attendre(page, "a.btn.primary", 300)
        href = page.locator("a.btn.primary").get_attribute("href")
        verifier("lien de téléchargement fourni", bool(href and href.startswith("/api/report/")), str(href))
        capture("11-rapport.png")
        if href:
            contenu = urllib.request.urlopen(URL + href, timeout=30).read()
            verifier("PDF réellement téléchargeable", contenu[:4] == b"%PDF",
                     "%d octets" % len(contenu))

        verifier("aucune erreur JavaScript", not erreurs_js, " || ".join(erreurs_js[:5]))
        navigateur.close()

    total = len(resultats)
    echecs = [r for r in resultats if not r[1]]
    print("\n" + "=" * 60)
    print("RECETTE : %d vérifications, %d échec(s)" % (total, len(echecs)))
    for nom, _, detail in echecs:
        print("  - " + nom + " : " + detail)
    print("Captures : %s" % CAPTURES)
    return 1 if echecs else 0


if __name__ == "__main__":
    sys.exit(main())
