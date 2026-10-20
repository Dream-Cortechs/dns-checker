# Déploiement du DNS Checker v2

## Cible
- Conteneur **CT 115** (`dns-checker`, 192.168.17.35), à côté de la v1 Streamlit.
- v1 : port **8506** (service `dns-checker.service`) — inchangée.
- v2 : port **8507** (service `dns-checker-v2.service`).
- Accès : **LAN uniquement** en HTTP, sans authentification (choix validé).
  Le port 8507 est ouvert à `192.168.17.0/24` dans UFW.

## Prérequis
Le port 22 de CT 115 est **filtré** : le déploiement passe par Proxmox
(`pct push` / `pct exec` sur 192.168.17.3) et non par SSH direct.

## Procédure
```bash
./deploy.sh            # tests + build + envoi sur CT 115 + redémarrage du service
./deploy.sh --sans-tests   # déploiement rapide (à éviter)
```

Le script refuse de déployer si un test échoue, puis vérifie que le code
réellement installé est celui du dépôt (empreinte du build) — un HTTP 200 ne
prouve rien à lui seul.

## Retour arrière
La v1 n'est pas touchée. En cas de problème : `systemctl stop dns-checker-v2`
sur CT 115 et l'outil reste accessible sur http://192.168.17.35:8506.
