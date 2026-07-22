# bunty — arsenal web (bug bounty / CTF)

Outils Python purs (aucune dépendance obligatoire) qui **pilotent les vrais outils**
(ffuf, subfinder, nuclei, katana…) quand ils sont présents, et **retombent sur un
moteur natif** sinon. Un seul principe : on n'ré-écrit pas les références, on les
**orchestre** et on comble les trous.

> [!] Usage **LÉGAL uniquement** : labs, CTF, ou cible explicitement autorisée.
> Reste **strictement** dans le scope du programme.

---

## `auto.py` — l'orchestrateur tout-en-un ⭐

Une seule commande sur une URL/IP → **tout s'enchaîne, étape par étape** :

```bash
python auto.py http://10.10.10.10
python auto.py 10.10.10.10 --fuzz
python auto.py cible.com --recon -H "X-HackerOne-Research: pseudo"
```

Ce qu'il fait :
0. **Scan des ports web** (natif) — trouve tous les services HTTP (80, 443, **5000**, 3000, 8080…).
1. **web_enum** par service — content discovery (dirs/fichiers, SecLists).
2. **jsleaks** par service — endpoints + secrets dans le JS.
3. **apifinder** par service — API, versions **cachées**, GraphQL, actuator, **LFI**, **console Werkzeug**, auto-loot des flags.
   *(option `--recon` = sous-domaines d'abord)*

À la fin : un **RECAP agrégé** (LFI, flags, PIN Werkzeug, console, secrets détectés).

---

## Les briques

| Outil | Rôle |
|-------|------|
| **recon.py** | Sous-domaines : 8 sources passives + brute DNS + sonde HTTP, détection WAF. |
| **hunt.py** | Pipeline bug bounty : subfinder→httpx→naabu→katana/gau→jsleaks→nuclei (repli pur-python). |
| **apifinder.py** | Découverte API : schémas swagger/openapi, **versions cachées (pivot v1/v0)**, GraphQL introspection, actuator, fuite DTO, **LFI (show/file/path…) + traversal**, **console Werkzeug** + auto-loot. |
| **jsleaks.py** | Parse les `.js` : endpoints (chunks lazy-load Vite/webpack), secrets, config runtime, sinks DOM XSS, source maps. |
| **takeover.py** | Subdomain takeover : 31 services (GitHub Pages, S3, Heroku, Azure…). |

### apifinder — nouveautés (leçon *Bookstore*)
La faille était sur `/api/**v1**/resources/books?**show**=…` alors que la doc annonçait
`v2`. apifinder gère maintenant :
- **pivot de version** : documente `v2` → teste automatiquement `v0`/`v1`/`v3`/`v4` du même chemin ;
- **fuzz des paramètres LFI** (`show`, `file`, `path`, `page`, `doc`, `view`…) avec payloads de traversal, détection `/etc/passwd` ;
- **auto-loot** après LFI : lit `/etc/passwd` → homes → `user.txt`, `.bash_history`, code source (repère le **flag** et le **PIN Werkzeug**) ;
- **détection console Werkzeug** `/console` (+ extraction du `SECRET`) → piste RCE.

```bash
python apifinder.py http://10.10.10.10:5000            # LFI + console actifs par défaut
python apifinder.py http://api.cible.com --fuzz --dto  # + fuzz routes + fuite DTO
python apifinder.py http://10.10.10.10:5000 --no-lfi   # désactiver LFI/console
```
