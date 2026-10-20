# Journal des modifications

## 2.0.0 — 20/10/2026

Première version web de la stack v2 (FastAPI + React) du DNS Checker.
La v1 Streamlit reste en service sur le port 8506 jusqu'à validation.

### Ajouté
- 9 écrans : vue d'ensemble, enregistrements, propagation, sécurité email, blacklists,
  WHOIS, géolocalisation, sous-domaines, audit de sécurité + rapport PDF.
- Tâches de fond avec suivi de progression (propagation, sous-domaines, audit, PDF) :
  plus de requête longue qui se fait couper par le proxy.
- Vue d'ensemble en un seul scan : synthèse chiffrée et liste des points à corriger
  classés par gravité.
- Thème sombre par défaut + thème clair mémorisé, charte Cortechs.
- Tests : 23 tests unitaires/câblage, 3 tests sur données réelles, recette
  navigateur de 10 écrans (`tests/e2e.py`).

### Corrigé (défauts de la v1)
- **Blacklists** : un code de retour `127.255.255.x` (requête refusée par la liste)
  était compté comme un listage. Les listages au niveau /24 ou AS (UCEPROTECT L2/L3)
  sont désormais distingués d'un listage de l'IP elle-même.
- **Certificats TLS** : la connexion était ouverte sans vérification, donc `getpeercert()`
  renvoyait un dictionnaire vide — émetteur, sujet et dates restaient vides pour tous
  les hôtes. La validation est faite d'abord, avec repli explicite.
- **WHOIS** : le binaire `whois` et `python-whois` ne gèrent pas les `.fr` (résultat vide).
  Client TCP port 43 avec motifs AFNIC : titulaire, dates, serveurs de noms.
