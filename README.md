# 🛠️ Arsenal d'outils — Pentest & Bug Bounty

**by 12akHack**

Boîte à outils personnelle en **Python pur** (marche partout : Windows, Linux, Exegol/Kali).
Chaque outil affiche son propre guide si tu le lances **sans argument** (ex: `python reconx.py`).

> ## ⚠️ AVERTISSEMENT LÉGAL
> Ces outils sont fournis **à des fins éducatives et de test de sécurité autorisé uniquement**.
> Ne les utilise **que** sur des systèmes qui t'appartiennent ou pour lesquels tu as une
> **autorisation écrite explicite** (labs, CTF, HTB/THM/VulnHub, programmes de bug bounty en scope).
> Toute utilisation non autorisée est **illégale** et relève de ta seule responsabilité.
> L'auteur décline toute responsabilité en cas de mauvais usage. **Voir [DISCLAIMER.md](DISCLAIMER.md).**

```
outils/
├── reconx.py          → scanner réseau (HTB / TryHackMe / VulnHub)
├── web_enum.py        → énumération web (SecLists + ffuf)
└── bunty/             → arsenal bug bounty
    ├── recon.py       → énumération de sous-domaines
    ├── hunt.py        → orchestrateur (relie tous les outils)
    ├── apifinder.py   → découverte & énumération d'API
    ├── jsleaks.py     → secrets + endpoints dans les fichiers JS
    └── takeover.py    → détection de subdomain takeover
```

---

## 🧭 QUAND utiliser quoi (décision rapide)

```
Tu as une IP / un réseau ?     →  reconx.py
Tu as une URL web ?            →  web_enum.py   (+ jsleaks.py s'il y a des .js)
Tu as un domaine (bug bounty)?→  recon.py → (hunt.py) → takeover.py
Tu as repéré une API ?         →  apifinder.py
```

| Outil | Quand le sortir |
|---|---|
| **reconx.py** | Tu as une **IP/réseau** → ports, OS, services (CTF, VulnHub, lab) |
| **web_enum.py** | Tu as une **URL web** → répertoires/fichiers cachés |
| **recon.py** | Bug bounty, **1re étape** → lister les sous-domaines |
| **hunt.py** | Bug bounty → **tout automatiser** (subs→live→urls→vulns) |
| **apifinder.py** | Tu as une **API** (`api.`, `/api`, swagger) → l'énumérer |
| **jsleaks.py** | Un site a des **`.js`** → secrets + endpoints cachés |
| **takeover.py** | Une **liste de sous-domaines** → vérifier les takeover |

---

## 🎯 SITUATION 1 — Box HTB / TryHackMe (une machine via VPN)

```bash
# 1. Scan réseau complet de la box (ports, OS, services, versions)
python reconx.py 10.10.10.5 -A

# 2. SI un port web est ouvert (80, 443, 8080...) → énumération web
python web_enum.py http://10.10.10.5 -o rapport
```
**Logique :** `reconx.py` d'abord (il dit quels services tournent) → `web_enum.py` si web.
Sur VPN HTB (latence), ajoute `--timeout 2`.

---

## 🖥️ SITUATION 2 — VulnHub (VM locale, IP inconnue)

```bash
# 1. Trouver l'IP de ta VM (repérée [VM VirtualBox] grâce à sa MAC)
sudo python reconx.py auto --fast

# 2. Scan complet de la VM trouvée
sudo python reconx.py 192.168.56.101 --full -A -o rapport

# 3. SI web → énumération
python web_enum.py http://192.168.56.101
```
`sudo` requis pour l'ARP (couche 2) et la détection d'OS.

---

## 💰 SITUATION 3 — Bug Bounty (un domaine, scope large)

> ⚠️ **Avant tout** : lis le scope. Recon **passif** d'abord. **Pas de scan brut**
> si les règles l'interdisent. Vérifie que le programme est **ACTIF** (pas en pause).

```bash
cd bunty/

# ÉTAPE 1 — Recon passif (non-invasif, ne touche pas leurs serveurs)
python recon.py cible.com
#   → sous-domaines. FILTRE selon le scope autorisé.

# ÉTAPE 2 — Pipeline complet (SEULEMENT si actif + autorisé)
python hunt.py cible.com --deep -o results
#   → subs → hôtes vivants → URLs → vulns, tout enchaîné

# ÉTAPE 3 — Subdomain takeover (sur les subs trouvés)
python takeover.py -l results/cible.com/subdomains.txt -o results/cible.com/takeover

# ÉTAPE 4 — Si une API → énumération API
python apifinder.py https://api.cible.com --fuzz

# ÉTAPE 5 — Sur les sites vivants → secrets dans les JS
grep '\.js' results/cible.com/urls.txt | python jsleaks.py

# ÉTAPE 6 — Énumération de contenu d'un site précis
python web_enum.py https://cible.com
```

---

## 📖 Exemple complet par outil

### reconx.py
```bash
sudo python reconx.py auto --fast                       # trouver les hôtes actifs
sudo python reconx.py 192.168.56.101 --full -A -o rapport   # scan total d'une cible
```

### web_enum.py
```bash
python web_enum.py http://10.10.10.5 -o rapport         # CTF : fingerprint + dirs (agressif)
python web_enum.py http://10.10.10.5 --deep             # large + récursif
python web_enum.py https://cible.com --bb               # bug bounty : throttle + vérif anti-faux-positif
```
**Modes :** `--ctf` (défaut, rapide/agressif) vs `--bb` (prudent : threads réduits, délai,
double-vérification de chaque trouvaille, backoff auto sur 429/503). Détecte aussi le **WAF/CDN**
(Cloudflare, Akamai, Imperva…) et **calibre le soft-404** (empreinte de contenu) pour ne pas
remonter de faux positifs. Détection PHP active + wordlist `common.txt` toujours jouée.

### recon.py (bunty)
```bash
python recon.py cible.com                               # passif seulement
python recon.py cible.com --http -o resultats           # + sonde HTTP + rapports
```

### hunt.py (bunty)
```bash
python hunt.py cible.com --deep -o results              # pipeline complet
python hunt.py cible.com --passive-only                 # juste subs + live
```

### apifinder.py (bunty)
```bash
python apifinder.py https://api.cible.com --fuzz -o rapport_api
```

### jsleaks.py (bunty)
```bash
python jsleaks.py https://cible.com -o rapport_js
grep '\.js' results/cible.com/urls.txt | python jsleaks.py
```

### takeover.py (bunty)
```bash
python takeover.py -l results/cible.com/subdomains.txt -o takeover
```

---

## ⚠️ Règles d'or (à ne JAMAIS oublier)

1. **Autorisation avant chaque scan actif.** HTB/THM/VulnHub = OK (fait pour ça).
   Bug bounty = uniquement dans le scope, programme **actif**, pas en pause.
2. **Bug bounty : recon passif d'abord**, filtre le scope, évite les scans bruts
   si interdits. Un sous-domaine hors périmètre (ex: infra mail) reste **interdit**
   même s'il matche le wildcard.
3. **Vérifie les findings avant de reporter** (secrets JS, takeover "à vérifier" =
   souvent des faux positifs). Un scanner trouve les mêmes bugs que tout le monde
   → **doublons**. Le vrai argent est dans le **test manuel** (logique métier,
   IDOR entre 2 comptes, chaînage).
4. Sur **Exegol/Kali**, installe les vrais outils (`subfinder httpx nuclei ffuf
   gau katana dnspython`) → les scripts les utilisent **automatiquement**.

---

## 🔧 Dépendances (optionnelles)

Tout marche en Python pur. Pour la pleine puissance sur Kali/Exegol :
```bash
# outils recon/bb
subfinder assetfinder amass httpx naabu katana gau waybackurls nuclei ffuf
# python
pip install scapy dnspython
# wordlists
apt install seclists      # -> /usr/share/seclists
```
