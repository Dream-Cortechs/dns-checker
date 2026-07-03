# DNS CHECKER — Diagnostic DNS Complet

🔍 **Équivalent self-hosted de whatsmydns.net + MXToolbox**

Application desktop de diagnostic DNS avec interface moderne dark mode.

## Fonctionnalités

| Onglet | Description |
|---|---|
| 🔍 **DNS Lookup** | Recherche d'enregistrements DNS (A, AAAA, MX, CNAME, TXT, NS, SOA, PTR, SRV, CAA) via résolveur système ou personnalisé |
| 🌍 **Propagation** | Vérification multi-résolveurs mondiale (27 résolveurs publics) — équivalent whatsmydns.net |
| 📧 **Sécurité Email** | Analyse SPF, DKIM, DMARC, MX avec score de sécurité — équivalent MXToolbox |
| 🚫 **Blacklists** | Vérification IP contre 12 DNSBL (Spamhaus, Barracuda, SpamCop, SORBS...) |

## Installation

```bash
pip install dnspython
python dns_checker.py
```

## Build .exe (Windows)

```bat
build_exe.bat
```

## Build standalone (Linux)

```bash
chmod +x build_exe.sh
./build_exe.sh
```

## Résolveurs globaux (Propagation)

27 résolveurs DNS publics répartis mondialement :
Google, Cloudflare, Quad9, OpenDNS, Level3, Verisign, Comodo, Yandex, AdGuard, DNS.WATCH, Freenom, AliDNS, SafeDNS, OpenNIC, et plus.

## Blacklists DNS vérifiées

12 DNSBL : Spamhaus ZEN, Barracuda, SpamCop, SORBS, SURBL, CBL (AbuseAt), UCEPROTECT L1/L2/L3, PSBL, JustSpam, WPBL.

## Tech stack

- Python 3.10+
- tkinter (GUI native, zéro dépendance UI)
- dnspython (requêtes DNS)
- PyInstaller (build .exe standalone)

---

**Cortechs © 2026** — Thème sombre #0a1628 / #c9a94e
