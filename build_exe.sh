#!/bin/bash
# DNS CHECKER — Build Linux standalone
echo "============================================="
echo " DNS CHECKER — Build Linux"
echo " Cortechs © 2026"
echo "============================================="

echo "[1/4] Installation des dépendances..."
pip install --quiet dnspython pyinstaller

echo "[2/4] Build PyInstaller..."
pyinstaller --clean --onefile --noconsole --name "dns-checker" \
  --add-data "static:static" \
  dns_checker.py

echo "[3/4] Copie du binaire..."
if [ -f "dist/dns-checker" ]; then
    cp dist/dns-checker ./dns-checker
    chmod +x ./dns-checker
    echo "[OK] dns-checker créé !"
else
    echo "[ERREUR] Le build a échoué."
    exit 1
fi

echo "[4/4] Nettoyage..."
rm -rf build dist dns-checker.spec

echo "============================================="
echo " BUILD TERMINÉ !"
echo " Exécutable : ./dns-checker"
echo "============================================="
