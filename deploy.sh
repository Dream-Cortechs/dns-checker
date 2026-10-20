#!/usr/bin/env bash
# Déploiement DNS Checker v2 sur CT 115 (Proxmox PROX-INTERNE), port 8507.
# - refuse de déployer si un test échoue
# - reconstruit le front sur Tack (le CT n'a pas Node)
# - recrée le venv sur le CT (un venv transféré par tar est corrompu)
# - vérifie le service ET le code réellement déployé
set -euo pipefail

PROX="192.168.17.3"
PROX_PASS="Adamnoeelias#172001"
CTID=115
APP_DIR="/opt/dns-checker-v2"
PORT=8507
PROJ="$(cd "$(dirname "$0")" && pwd)"
SKIP_TESTS=0
[ "${1:-}" = "--sans-tests" ] && SKIP_TESTS=1

prox() { sshpass -p "$PROX_PASS" ssh -o PreferredAuthentications=password -o PubkeyAuthentication=no \
         -o StrictHostKeyChecking=no -o ConnectTimeout=10 root@"$PROX" "$@"; }

echo "== 1. Tests =="
if [ "$SKIP_TESTS" -eq 0 ]; then
  "$PROJ/.venv/bin/python" -m pytest "$PROJ/tests" -q
else
  echo "   (ignorés à la demande)"
fi

echo "== 2. Build du front =="
cd "$PROJ/web2/frontend"
npm run build >/dev/null
test -f dist/index.html || { echo "build front absent"; exit 1; }
EMPREINTE=$(sha256sum dist/assets/*.js | awk '{print $1}')

echo "== 3. Archive =="
cd "$PROJ"
TAR=/tmp/dns-checker-v2-$(date +%H%M%S).tar.gz
tar czf "$TAR" core web2/backend web2/frontend/dist web2/requirements.txt \
    VERSION CHANGELOG.md deploy.sh systemd tests 2>/dev/null
echo "   $TAR ($(du -h "$TAR" | cut -f1))"

echo "== 4. Transfert vers Proxmox puis CT $CTID =="
sshpass -p "$PROX_PASS" scp -o PreferredAuthentications=password -o PubkeyAuthentication=no \
        -o StrictHostKeyChecking=no "$TAR" root@"$PROX":/tmp/
prox "pct push $CTID /tmp/$(basename "$TAR") /tmp/$(basename "$TAR")"

echo "== 5. Installation dans $APP_DIR =="
prox "pct exec $CTID -- bash -c 'set -e
  mkdir -p $APP_DIR /var/lib/dns-checker-v2/cache
  tar xzf /tmp/$(basename "$TAR") -C $APP_DIR
  find $APP_DIR -name __pycache__ -type d -exec rm -rf {} + 2>/dev/null || true
  cd $APP_DIR
  [ -d .venv ] || python3 -m venv .venv
  .venv/bin/pip -q install --upgrade pip
  .venv/bin/pip -q install -r web2/requirements.txt
'"

echo "== 6. Service systemd =="
prox "pct exec $CTID -- bash -c 'cp $APP_DIR/systemd/dns-checker-v2.service /etc/systemd/system/ && systemctl daemon-reload && systemctl enable --now dns-checker-v2 && systemctl restart dns-checker-v2'"

echo "== 7. Pare-feu (LAN seul) =="
prox "pct exec $CTID -- bash -c 'ufw status | grep -q "$PORT" || ufw allow from 192.168.17.0/24 to any port $PORT proto tcp'"

echo "== 8. Vérifications =="
sleep 3
prox "pct exec $CTID -- bash -c 'systemctl is-active dns-checker-v2; curl -s -o /dev/null -w "health %{http_code}\n" http://127.0.0.1:$PORT/api/health; curl -s http://127.0.0.1:$PORT/api/build'"
echo
echo "Empreinte JS déployée (doit correspondre) : $EMPREINTE"
prox "pct exec $CTID -- bash -c 'sha256sum $APP_DIR/web2/frontend/dist/assets/*.js'"
echo
echo "URL : http://192.168.17.35:$PORT"
