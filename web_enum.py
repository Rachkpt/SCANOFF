#!/usr/bin/env python3
"""
web_enum.py - Enumeration web automatique et intelligente
=========================================================
Usage :  python web_enum.py http://target        (et tout se passe tout seul)

Ce qu'il fait, de A a Z :
  1. Fingerprint : serveur, techno (PHP/ASP/JSP), CMS (WordPress/Joomla/Drupal),
     API/REST, cookies, titre, generator, robots.txt, sitemap.xml
  2. Choisit AUTOMATIQUEMENT les bonnes wordlists SecLists (Discovery/Web-Content)
     et les bonnes extensions selon la techno detectee
  3. Verifie les fichiers sensibles (.git, .env, backups, config...)
  4. Content discovery progressif :
        quick hits  ->  repertoires medium  ->  fichiers + extensions  ->
        wordlist CMS/API dediee  ->  (--deep) large + recursif
  5. Rapport clair a l'ecran + export .txt / .json / .html

Moteur : pilote 'ffuf' s'il est installe (rapide, fiable), sinon moteur
Python natif de secours. Wordlists : SecLists uniquement.

Legal uniquement : HTB, TryHackMe, VulnHub, bug bounty autorise, tes labs.
"""

import argparse
import os
import sys
import re
import ssl
import json
import time
import random
import string
import shutil
import hashlib
import subprocess
import http.client
import html as html_mod
from urllib.parse import urlparse, urljoin
from concurrent.futures import ThreadPoolExecutor, as_completed

# ----------------------------------------------------------------------
class C:
    G = "\033[92m"; Y = "\033[93m"; R = "\033[91m"; B = "\033[94m"
    CY = "\033[96m"; GR = "\033[90m"; BD = "\033[1m"; X = "\033[0m"
if os.name == "nt":
    try:
        import ctypes
        k = ctypes.windll.kernel32
        k.SetConsoleMode(k.GetStdHandle(-11), 7)
    except Exception:
        for a in ("G", "Y", "R", "B", "CY", "GR", "BD", "X"):
            setattr(C, a, "")

def log(m): print(m)

UA = "Mozilla/5.0 (X11; Linux x86_64) web_enum/1.0"

# ----------------------------------------------------------------------
# Emplacements possibles de SecLists
# ----------------------------------------------------------------------
SECLISTS_DIRS = [
    "/usr/share/seclists", "/usr/share/wordlists/seclists",
    "/usr/share/wordlists/SecLists", "/opt/seclists", "/opt/SecLists",
    "/usr/share/SecLists", os.path.expanduser("~/seclists"),
    os.path.expanduser("~/SecLists"),
]
WC = "Discovery/Web-Content"   # la partie qui nous interesse

# ----------------------------------------------------------------------
# Extensions par techno (chaines a ajouter au mot, avec le point)
# ----------------------------------------------------------------------
EXTS = {
    "php": [".php", ".phtml", ".phps", ".php~", ".php.bak", ".php.swp",
            ".inc", ".bak", ".old", ".txt", ".zip", ".tar.gz", "~"],
    "asp": [".asp", ".aspx", ".asmx", ".ashx", ".config", ".bak", ".old",
            ".txt", ".zip"],
    "jsp": [".jsp", ".jspx", ".do", ".action", ".bak", ".old", ".txt", ".zip"],
    "generic": [".html", ".txt", ".bak", ".old", ".zip", ".json", ".xml",
                ".conf", ".sql", ".tar.gz", "~"],
}

# Fichiers sensibles verifies systematiquement (rapide, natif)
JUICY = [
    ".git/HEAD", ".git/config", ".gitignore", ".env", ".env.bak", ".env.example",
    ".htaccess", ".htpasswd", "web.config", "config.php.bak", "config.php~",
    "wp-config.php.bak", "wp-config.php~", "configuration.php.bak",
    "backup.zip", "backup.tar.gz", "backup.sql", "db.sql", "database.sql",
    "dump.sql", "www.zip", "site.zip", "phpinfo.php", "info.php", "test.php",
    "composer.json", "package.json", ".DS_Store", ".svn/entries",
    ".idea/workspace.xml", "server-status", "robots.txt", "sitemap.xml",
    "readme.html", "license.txt", "id_rsa", "credentials.txt", ".vscode/sftp.json",
]

# Wordlists candidates par CMS (premiere existante utilisee)
CMS_WL = {
    "wordpress": ["CMS/wordpress.fuzz.txt", "CMS/wp-plugins.fuzz.txt",
                  "CMS/wordpress-plugins.fuzz.txt", "CMS/wp-themes.fuzz.txt"],
    "joomla":    ["CMS/Joomla.txt", "CMS/joomla.fuzz.txt", "CMS/joomla-plugins.fuzz.txt"],
    "drupal":    ["CMS/Drupal.txt", "CMS/drupal.txt", "CMS/Drupal_files.txt"],
}
API_WL = ["api/api-endpoints.txt", "api/common-api-endpoints-mazen160.txt",
          "api/objects.txt", "api/api-endpoints-res.txt"]

# ----------------------------------------------------------------------
# Signatures WAF/CDN : (nom, [indices en-tetes], [indices dans le corps])
# ----------------------------------------------------------------------
WAF_SIGNS = [
    ("Cloudflare",   ["cf-ray", "cf-cache-status", "cf-mitigated", "__cfduid",
                      "server:cloudflare"], ["attention required", "cloudflare"]),
    ("Akamai",       ["akamaighost", "x-akamai", "aka-cdn"], ["akamai"]),
    ("Sucuri",       ["x-sucuri-id", "x-sucuri-cache", "server:sucuri"], ["sucuri"]),
    ("Imperva/Incapsula", ["x-iinfo", "incap_ses", "visid_incap", "x-cdn:incapsula"],
                     ["incapsula", "powered by imperva"]),
    ("AWS WAF/ELB",  ["x-amzn-requestid", "x-amz-cf-id", "awselb", "x-amz-apigw-id"],
                     ["<title>403 forbidden</title>"]),
    ("F5 BIG-IP/ASM",["bigipserver", "ts01", "x-waf-status", "server:big-ip"],
                     ["the requested url was rejected"]),
    ("Barracuda",    ["barra_counter_session", "barracuda"], ["barracuda"]),
    ("ModSecurity",  ["mod_security", "server:mod_security"],
                     ["mod_security", "not acceptable", "this error was generated by mod_security"]),
    ("Wordfence",    ["wordfence"], ["generated by wordfence", "your access to this site has been limited"]),
    ("Fastly",       ["x-served-by", "x-fastly", "server:fastly"], []),
]

def detect_waf(headers, body=""):
    """Renvoie la liste des WAF/CDN reperes dans les en-tetes/corps."""
    h = " ".join("%s:%s" % (k, v) for k, v in headers.items()).lower()
    b = (body or "").lower()
    hits = []
    for name, hdr_keys, body_keys in WAF_SIGNS:
        if any(k in h for k in hdr_keys) or any(k in b for k in body_keys):
            hits.append(name)
    return hits

# ----------------------------------------------------------------------
# HTTP (http.client, sans suivre les redirections -> on voit 301/302/403)
# ----------------------------------------------------------------------
def fetch(url, method="GET", timeout=8, max_body=45000):
    try:
        u = urlparse(url)
        host = u.hostname
        if not host:
            return None
        port = u.port or (443 if u.scheme == "https" else 80)
        path = (u.path or "/") + (("?" + u.query) if u.query else "")
        if u.scheme == "https":
            conn = http.client.HTTPSConnection(host, port, timeout=timeout,
                                               context=ssl._create_unverified_context())
        else:
            conn = http.client.HTTPConnection(host, port, timeout=timeout)
        conn.request(method, path, headers={"User-Agent": UA, "Accept": "*/*"})
        r = conn.getresponse()
        body = r.read(max_body)
        hdrs = {k.lower(): v for k, v in r.getheaders()}
        status, loc = r.status, r.getheader("Location")
        conn.close()
        cl = hdrs.get("content-length")
        length = int(cl) if (cl and cl.isdigit()) else len(body)
        return {"status": status, "headers": hdrs, "body": body,
                "location": loc, "length": length}
    except Exception:
        return None

def normalize_url(target):
    """Ajoute le schema si absent et renvoie une base qui repond."""
    if not re.match(r"^https?://", target, re.I):
        for scheme in ("http://", "https://"):
            r = fetch(scheme + target, timeout=6)
            if r:
                return scheme + target.rstrip("/")
        return "http://" + target.rstrip("/")
    return target.rstrip("/")

# ----------------------------------------------------------------------
# Fingerprint
# ----------------------------------------------------------------------
def fingerprint(base):
    fp = {"server": "", "powered": "", "techno": set(), "cms": None,
          "api": False, "title": "", "generator": "", "cookies": [],
          "notes": [], "status": None, "waf": []}
    r = fetch(base + "/", timeout=8)
    if not r:
        return fp, None
    fp["status"] = r["status"]
    h, body = r["headers"], r["body"].decode("utf-8", "ignore")
    low = body.lower()

    # WAF / CDN (utile surtout en bug bounty : explique les 403 en serie)
    fp["waf"] = detect_waf(h, body)

    fp["server"] = h.get("server", "")
    fp["powered"] = h.get("x-powered-by", "")
    if h.get("x-aspnet-version") or "asp.net" in fp["powered"].lower():
        fp["techno"].add("asp")
    if "php" in fp["powered"].lower() or "php" in fp["server"].lower():
        fp["techno"].add("php")

    # Cookies -> techno
    sc = h.get("set-cookie", "")
    fp["cookies"] = [c.split("=")[0].strip() for c in sc.split(",") if "=" in c][:6]
    cl = sc.lower()
    if "phpsessid" in cl: fp["techno"].add("php")
    if "asp.net" in cl or "aspsession" in cl: fp["techno"].add("asp")
    if "jsessionid" in cl: fp["techno"].add("jsp")
    if "wordpress" in cl or "wp-settings" in cl: fp["cms"] = "wordpress"
    if "laravel_session" in cl: fp["notes"].append("Laravel (PHP)"); fp["techno"].add("php")
    if "ci_session" in cl: fp["notes"].append("CodeIgniter (PHP)"); fp["techno"].add("php")
    if "csrftoken" in cl or "django" in cl: fp["notes"].append("Django (Python)")

    # Titre + generator
    m = re.search(r"<title[^>]*>(.*?)</title>", body, re.I | re.S)
    if m: fp["title"] = re.sub(r"\s+", " ", m.group(1)).strip()[:80]
    m = re.search(r'name=["\']generator["\'][^>]*content=["\']([^"\']+)', body, re.I)
    if m: fp["generator"] = m.group(1).strip()[:80]

    # Signaux CMS dans le corps
    if "wp-content" in low or "wp-includes" in low or "/wp-json" in low:
        fp["cms"] = "wordpress"
    elif "joomla" in low or "/media/jui/" in low or "com_content" in low:
        fp["cms"] = "joomla"
    elif "drupal" in low or "sites/default/files" in low or "/core/misc/drupal" in low:
        fp["cms"] = "drupal"
    gen = fp["generator"].lower()
    if "wordpress" in gen: fp["cms"] = "wordpress"
    elif "joomla" in gen: fp["cms"] = "joomla"
    elif "drupal" in gen: fp["cms"] = "drupal"
    if fp["cms"] == "wordpress":
        fp["techno"].add("php")

    # API ? (JSON en reponse, ou /api present)
    ct = h.get("content-type", "")
    if "application/json" in ct or low.strip().startswith("{"):
        fp["api"] = True
    for p in ("/api", "/api/v1", "/graphql", "/rest", "/swagger.json",
              "/api-docs", "/openapi.json"):
        rr = fetch(base + p, timeout=5)
        if rr and rr["status"] in (200, 301, 302, 401, 403):
            fp["api"] = True
            fp["notes"].append(f"endpoint API : {p} ({rr['status']})")
            break

    # robots.txt / sitemap.xml (contiennent souvent des chemins caches)
    rob = fetch(base + "/robots.txt", timeout=5)
    if rob and rob["status"] == 200 and b"llow" in rob["body"]:
        paths = re.findall(r"(?:Dis)?[Aa]llow:\s*(\S+)", rob["body"].decode("utf-8", "ignore"))
        fp["notes"].append(f"robots.txt : {len(paths)} chemin(s) -> " +
                           ", ".join(sorted(set(paths))[:8]))
    sm = fetch(base + "/sitemap.xml", timeout=5)
    if sm and sm["status"] == 200:
        fp["notes"].append("sitemap.xml present")

    # Detection ACTIVE de la techno si le passif n'a rien trouve.
    # (Cas classique VulnHub/HTB : page d'accueil statique, Apache nu, mais
    #  le site est en PHP -> il faut sonder pour ne pas rater les *.php.)
    if not fp["techno"]:
        detect_techno_active(base, fp)

    return fp, r

def detect_techno_active(base, fp, timeout=6):
    """Sonde le serveur pour deviner la techno quand les en-tetes sont muets."""
    # 1) Reference : une page inexistante (pour comparer les statuts)
    rnd = "".join(random.choice(string.ascii_lowercase) for _ in range(12))
    ref = fetch(base + "/" + rnd + ".xyz", timeout=timeout)
    ref_st = ref["status"] if ref else 404

    # 2) Sondes par techno : si le statut differe du "404 de reference",
    #    c'est que le serveur sait interpreter cette extension.
    probes = [
        ("php", ["index.php", "index.phps", "info.php"]),
        ("asp", ["index.asp", "index.aspx", "default.aspx"]),
        ("jsp", ["index.jsp", "index.do", "index.action"]),
    ]
    for tech, paths in probes:
        for p in paths:
            r = fetch(base + "/" + p, timeout=timeout)
            if not r:
                continue
            st = r["status"]
            # 200/301/302/500 = la ressource ou le moteur repond
            # 403 sur .phps/.php = handler configure (PHP present)
            if st in (200, 301, 302, 500) or (st == 403 and st != ref_st):
                fp["techno"].add(tech)
                fp["notes"].append(f"techno active : /{p} -> {st}")
                break
        if tech in fp["techno"]:
            break

def print_fingerprint(base, fp):
    log(f"\n{C.CY}{C.BD}{'='*68}{C.X}")
    log(f"{C.CY}{C.BD}  CIBLE : {base}{C.X}")
    log(f"{C.CY}{C.BD}{'='*68}{C.X}")
    if fp["status"]: log(f"  {C.Y}Statut / :{C.X} {fp['status']}")
    if fp["title"]:  log(f"  {C.Y}Titre :{C.X} {fp['title']}")
    if fp["server"]: log(f"  {C.Y}Serveur :{C.X} {fp['server']}")
    if fp["powered"]:log(f"  {C.Y}X-Powered-By :{C.X} {fp['powered']}")
    if fp["generator"]:log(f"  {C.Y}Generator :{C.X} {fp['generator']}")
    if fp["techno"]: log(f"  {C.Y}Techno :{C.X} {C.G}{', '.join(sorted(fp['techno']))}{C.X}")
    if fp["cms"]:    log(f"  {C.Y}CMS :{C.X} {C.G}{fp['cms']}{C.X}")
    if fp["api"]:    log(f"  {C.Y}API/REST :{C.X} {C.G}detectee{C.X}")
    if fp["waf"]:    log(f"  {C.Y}WAF/CDN :{C.X} {C.R}{', '.join(fp['waf'])}{C.X}")
    if fp["cookies"]:log(f"  {C.Y}Cookies :{C.X} {', '.join(fp['cookies'])}")
    for n in fp["notes"]:
        log(f"  {C.GR}- {n}{C.X}")

# ----------------------------------------------------------------------
# SecLists : localisation + resolution de wordlists
# ----------------------------------------------------------------------
def find_seclists(override=None):
    cands = ([override] if override else []) + SECLISTS_DIRS
    for d in cands:
        if d and os.path.isdir(os.path.join(d, WC)):
            return d
        if d and os.path.isdir(os.path.join(d, "Discovery")):
            return d
    return None

def wl(seclists, *names):
    """Renvoie le premier chemin existant parmi les noms donnes (sous Web-Content)."""
    for name in names:
        p = os.path.join(seclists, WC, name)
        if os.path.isfile(p):
            return p
    return None

# ----------------------------------------------------------------------
# Construction de la strategie (les etapes de scan)
# ----------------------------------------------------------------------
def build_plan(seclists, fp, args):
    # extensions
    if args.ext:
        exts = ["." + e.lstrip(".") if e != "~" else "~" for e in args.ext.split(",")]
    else:
        exts = []
        for t in ("php", "asp", "jsp"):
            if t in fp["techno"]:
                exts += EXTS[t]
        if not exts:
            # Techno inconnue -> on ne se limite PAS au generique : PHP est de
            # loin la techno la plus courante (VulnHub/HTB), donc on teste .php
            # en plus du generique pour ne pas rater les endpoints PHP.
            exts = EXTS["php"] + EXTS["generic"]
        # on ajoute toujours quelques backups generiques
        for e in (".bak", ".old", ".zip", "~"):
            if e not in exts:
                exts.append(e)
    exts = list(dict.fromkeys(exts))  # dedoublonne en gardant l'ordre

    steps = []
    seen_wl = set()
    def add(label, path, ext=None, extra=None):
        # on ne rajoute pas deux fois exactement la meme (wordlist + extensions)
        key = (path, tuple(ext or ()))
        if path and key not in seen_wl:
            seen_wl.add(key)
            steps.append({"label": label, "wordlist": path,
                          "exts": ext, "extra": extra or []})

    # 1) quick hits (rapide, souvent gagnant)
    add("Quick hits", wl(seclists, "quickhits.txt"))
    # 2) common.txt : la reference incontournable -> TOUJOURS lancee, avec ext.
    #    (elle attrape des chemins que raft rate, et inversement)
    add("Common (dirs + fichiers + ext)", wl(seclists, "common.txt"), ext=exts)
    # 3) repertoires medium (raft) - liste differente de common, complementaire
    add("Repertoires (medium)",
        wl(seclists, "raft-medium-directories.txt", "directory-list-2.3-medium.txt"))
    # 4) fichiers + extensions (raft)
    add("Fichiers + extensions (medium)",
        wl(seclists, "raft-medium-files.txt"), ext=exts)
    # 5) CMS dedie
    if fp["cms"] and fp["cms"] in CMS_WL:
        add(f"CMS {fp['cms']}", wl(seclists, *CMS_WL[fp["cms"]]))
    # 6) API dedie
    if fp["api"]:
        add("API endpoints", wl(seclists, *API_WL))
    # 7) deep : mots + large + recursif (lourd -> uniquement en --deep)
    if args.deep:
        add("Mots + extensions (medium)",
            wl(seclists, "raft-medium-words.txt"), ext=exts)
        add("Large repertoires (recursif)",
            wl(seclists, "raft-large-directories.txt", "directory-list-2.3-big.txt"),
            extra=["-recursion", "-recursion-depth", str(args.depth)])
        add("Large fichiers + extensions",
            wl(seclists, "raft-large-files.txt"), ext=exts)
    return steps, exts

# ----------------------------------------------------------------------
# Moteur ffuf
# ----------------------------------------------------------------------
def has_ffuf():
    return shutil.which("ffuf") is not None

def run_ffuf(base, step, args):
    findings = []
    out = os.path.join(args._tmp, "ffuf_%d.json" % int(time.time() * 1000))
    cmd = ["ffuf", "-u", base + "/FUZZ", "-w", step["wordlist"],
           "-t", str(args.threads), "-ac", "-s", "-noninteractive",
           "-mc", args.match, "-o", out, "-of", "json",
           "-timeout", str(int(args.timeout))]
    if step["exts"]:
        cmd += ["-e", ",".join(step["exts"])]
    if args.filter_size:
        cmd += ["-fs", args.filter_size]
    if args.delay:                     # throttle (mode bb) : pause entre requetes
        cmd += ["-p", str(args.delay)]
    cmd += step["extra"]
    try:
        subprocess.run(cmd, capture_output=True, timeout=args.max_time)
        if os.path.isfile(out):
            data = json.load(open(out, encoding="utf-8"))
            for it in data.get("results", []):
                findings.append({"url": it.get("url"), "status": it.get("status"),
                                 "length": it.get("length"), "words": it.get("words"),
                                 "lines": it.get("lines")})
            os.remove(out)
    except subprocess.TimeoutExpired:
        log(f"{C.Y}    (etape trop longue, on passe a la suite){C.X}")
    except Exception as e:
        log(f"{C.R}    ffuf erreur : {e}{C.X}")
    return findings

# ----------------------------------------------------------------------
# Moteur natif (secours si ffuf absent)
# ----------------------------------------------------------------------
def load_words(path, cap=40000):
    words = []
    try:
        with open(path, encoding="utf-8", errors="ignore") as f:
            for line in f:
                w = line.strip()
                if w and not w.startswith("#"):
                    words.append(w.lstrip("/"))
                    if len(words) >= cap:
                        break
    except Exception:
        pass
    return words

def _sig(r, reflected=""):
    """Signature d'une reponse en neutralisant le chemin reflete dans le corps.
    -> (status, taille_normalisee, hash_md5_du_corps). Deux 'page introuvable'
    qui ne different que par le chemin affiche auront la MEME signature."""
    body = r["body"]
    if isinstance(body, bytes):
        body = body.decode("utf-8", "ignore")
    if reflected:
        body = body.replace(reflected, "").replace(reflected.rstrip("/"), "")
    body = re.sub(r"\s+", " ", body).strip()
    h = hashlib.md5(body.encode("utf-8", "ignore")).hexdigest()
    return (r["status"], len(body), h)

def calibrate(base, exts, timeout):
    """Apprend a quoi ressemble une reponse 'introuvable' (soft-404) et
    detecte le wildcard (serveur qui repond 200 a n'importe quoi).
    Renvoie un dict de reference passe ensuite a is_softnotfound()."""
    sigs, lengths, statuses = set(), set(), set()
    ok200 = 0
    # on sonde sans extension + avec les extensions les plus courantes du plan
    probe_exts = [""]
    for e in (".php", ".html", ".aspx", ".jsp"):
        if e in exts and e not in probe_exts:
            probe_exts.append(e)
    for _ in range(3):
        token = "".join(random.choice(string.ascii_lowercase + string.digits)
                        for _ in range(18))
        for e in probe_exts:
            path = token + e
            r = fetch(base + "/" + path, timeout=timeout, max_body=12000)
            if not r:
                continue
            s = _sig(r, path)
            sigs.add(s); lengths.add(s[1]); statuses.add(r["status"])
            if r["status"] == 200:
                ok200 += 1
    return {"sigs": sigs, "lengths": lengths, "statuses": statuses,
            "wildcard": ok200 >= 2}

def is_softnotfound(r, cal, reflected):
    """True si la reponse ressemble a une 'page introuvable' apprise = faux positif."""
    s = _sig(r, reflected)
    if s in cal["sigs"]:                       # meme corps exact -> soft-404
        return True
    if r["status"] in cal["statuses"]:         # meme statut + taille tres proche
        for ln in cal["lengths"]:
            if abs(s[1] - ln) <= 24:
                return True
    return False

def run_native(base, step, args, cal, blocked):
    words = load_words(step["wordlist"])
    exts = step["exts"] or [""]
    candidates = []
    for w in words:
        for e in exts:
            candidates.append(w + e if e else w)
    findings, seen = [], set()
    ok_codes = set(int(x) for x in args.match.split(","))

    def check(path):
        if args.delay:
            time.sleep(args.delay)
        r = fetch(base + "/" + path, timeout=args.timeout, max_body=12000)
        if not r:
            return None
        st, ln = r["status"], r["length"]
        # rate-limit / blocage : on recule (backoff) et on compte
        if st in (429, 503):
            blocked["n"] += 1
            time.sleep(1.5 if args.mode == "bb" else 0.3)
            return None
        if st not in ok_codes:
            return None
        if is_softnotfound(r, cal, path):      # ressemble au soft-404 appris
            return None
        # double verification (mode bb / --verify) : on rejoue et on compare
        if args.verify:
            r2 = fetch(base + "/" + path, timeout=args.timeout, max_body=12000)
            if not r2 or r2["status"] != st or is_softnotfound(r2, cal, path):
                return None
        return {"url": base + "/" + path, "status": st, "length": ln,
                "words": None, "lines": None}

    with ThreadPoolExecutor(max_workers=args.threads) as ex:
        futs = [ex.submit(check, c) for c in candidates]
        for fu in as_completed(futs):
            r = fu.result()
            if r and r["url"] not in seen:
                seen.add(r["url"]); findings.append(r)
    return findings

# ----------------------------------------------------------------------
# Fichiers sensibles (toujours, natif, rapide)
# ----------------------------------------------------------------------
def check_juicy(base, args):
    hits = []
    def check(p):
        r = fetch(base + "/" + p, timeout=args.timeout, max_body=2048)
        if r and r["status"] in (200, 301, 302, 401, 403):
            return {"path": p, "status": r["status"], "length": r["length"]}
    with ThreadPoolExecutor(max_workers=min(30, len(JUICY))) as ex:
        for fu in as_completed([ex.submit(check, p) for p in JUICY]):
            r = fu.result()
            if r:
                hits.append(r)
    return sorted(hits, key=lambda x: x["path"])

# ----------------------------------------------------------------------
# Affichage / export
# ----------------------------------------------------------------------
def color_status(st):
    if st in (200, 204): return C.G
    if st in (301, 302, 307, 308): return C.CY
    if st in (401, 403): return C.Y
    if st >= 500: return C.R
    return C.GR

def print_findings(findings):
    if not findings:
        log(f"  {C.GR}(rien){C.X}")
        return
    for f in sorted(findings, key=lambda x: (x["status"], x["url"])):
        extra = ""
        if f.get("length") is not None:
            extra = f"{C.GR}[{f['length']} o]{C.X}"
        path = urlparse(f["url"]).path or "/"
        log(f"    {color_status(f['status'])}{f['status']}{C.X}  {path:<40} {extra}")

def save_reports(base, fp, juicy, findings, out):
    b = out.rsplit(".", 1)[0]
    data = {"target": base, "fingerprint": {k: (list(v) if isinstance(v, set) else v)
                                            for k, v in fp.items() if k != "body"},
            "juicy": juicy, "findings": findings}
    with open(b + ".json", "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
    with open(b + ".txt", "w", encoding="utf-8") as f:
        f.write(f"# web_enum - {base}\n\n[Fingerprint]\n")
        for k in ("server", "powered", "techno", "cms", "api", "title", "generator"):
            v = fp.get(k)
            if v: f.write(f"  {k}: {list(v) if isinstance(v, set) else v}\n")
        f.write("\n[Fichiers sensibles]\n")
        for j in juicy: f.write(f"  {j['status']}  /{j['path']}  [{j['length']} o]\n")
        f.write("\n[Decouvertes]\n")
        for it in sorted(findings, key=lambda x: (x["status"], x["url"])):
            f.write(f"  {it['status']}  {it['url']}  [{it.get('length')} o]\n")
    # HTML
    def rows(items, isjuicy=False):
        out = []
        for it in sorted(items, key=lambda x: (x["status"], x.get("url", x.get("path", "")))):
            url = it.get("url") or (base + "/" + it["path"])
            out.append(f"<tr><td class=s{it['status']//100}>{it['status']}</td>"
                       f"<td><a href='{html_mod.escape(url)}'>{html_mod.escape(url)}</a></td>"
                       f"<td>{it.get('length','')}</td></tr>")
        return "".join(out) or "<tr><td colspan=3 class=g>(rien)</td></tr>"
    doc = f"""<!doctype html><meta charset=utf-8><title>web_enum {html_mod.escape(base)}</title>
<style>body{{font-family:monospace;background:#0d1117;color:#c9d1d9;padding:20px}}
h1,h2{{color:#58a6ff}}table{{border-collapse:collapse;width:100%;margin-bottom:24px}}
td,th{{border:1px solid #30363d;padding:6px 10px;text-align:left}}
a{{color:#79c0ff}}.g{{color:#8b949e}}.s2{{color:#3fb950;font-weight:bold}}
.s3{{color:#58a6ff}}.s4{{color:#d29922}}.s5{{color:#f85149}}</style>
<h1>web_enum - {html_mod.escape(base)}</h1>
<p class=g>{time.strftime('%Y-%m-%d %H:%M')} | serveur: {html_mod.escape(fp.get('server',''))}
 | techno: {html_mod.escape(', '.join(sorted(fp['techno'])))} | cms: {fp.get('cms') or '-'}</p>
<h2>Fichiers sensibles</h2><table><tr><th>Code</th><th>URL</th><th>Taille</th></tr>{rows(juicy, True)}</table>
<h2>Decouvertes ({len(findings)})</h2><table><tr><th>Code</th><th>URL</th><th>Taille</th></tr>{rows(findings)}</table>"""
    with open(b + ".html", "w", encoding="utf-8") as f:
        f.write(doc)
    log(f"\n{C.G}[+] Rapports : {b}.txt / {b}.json / {b}.html{C.X}")

# ----------------------------------------------------------------------
BANNER = f"""{C.CY}{C.BD}
  web_enum  -  enumeration web automatique{C.X}
{C.GR}  fingerprint -> wordlists SecLists auto -> content discovery{C.X}
{C.Y}  by 12akHack{C.GR}  -  outil de securite offensive{C.X}
{C.R}  [!] Usage LEGAL uniquement : labs / CTF / cible explicitement autorisee.{C.X}
"""

def main():
    p = argparse.ArgumentParser(
        description="web_enum.py - enumeration web automatique (SecLists + ffuf)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
------------------------------------------------------------------------
 GUIDE
------------------------------------------------------------------------
 Le plus simple (tout est automatique) :
    python web_enum.py http://target
    python web_enum.py target.htb              # schema http/https auto

 Bug bounty (cible reelle : prudent, throttle, verifie chaque trouvaille) :
    python web_enum.py https://target.com --bb

 Scan profond (large + recursif) :
    python web_enum.py http://target --deep

 Forcer des extensions / un rapport :
    python web_enum.py http://target -e php,bak,txt,zip -o rapport

 Si SecLists n'est pas trouve tout seul :
    python web_enum.py http://target --seclists /usr/share/seclists

 Ce que fait l'outil :
   1. fingerprint (serveur, PHP/ASP/JSP, WordPress/Joomla/Drupal, API, robots)
   2. choisit les bonnes wordlists SecLists/Discovery/Web-Content + extensions
   3. verifie les fichiers sensibles (.git .env backups config...)
   4. content discovery progressif (quickhits -> medium -> CMS/API -> [--deep] large)
 Moteur : ffuf si dispo (rapide), sinon moteur Python natif.

 EXEMPLE COMPLET (une box HTB avec un site web) :
    python web_enum.py http://10.10.10.5 -o rapport
        # -> fingerprint (PHP/WordPress/...), fichiers sensibles (.git .env),
        #    puis quickhits -> medium -> CMS/API, rapport txt/json/html
    # Si peu de resultats, va plus loin :
    python web_enum.py http://10.10.10.5 --deep
        # -> ajoute raft-large + recursif (plus long, ne rate rien)
------------------------------------------------------------------------
""")
    p.add_argument("url", nargs="?", help="URL cible (http://... ou juste le domaine)")
    p.add_argument("-m", "--mode", choices=["ctf", "bb"], default="ctf",
                   help="ctf = agressif/rapide (defaut) ; bb = bug bounty (prudent, throttle, verifie)")
    p.add_argument("--bb", dest="mode", action="store_const", const="bb",
                   help="Raccourci pour --mode bb (bug bounty)")
    p.add_argument("--deep", action="store_true", help="Ajoute large + recursif (plus long)")
    p.add_argument("--depth", type=int, default=2, help="Profondeur de recursion (defaut 2)")
    p.add_argument("-e", "--ext", help="Forcer les extensions (ex: php,bak,txt,zip)")
    p.add_argument("-t", "--threads", type=int, default=None,
                   help="Threads (defaut : 45 en ctf, 8 en bb)")
    p.add_argument("--delay", type=float, default=None,
                   help="Pause entre requetes en s (defaut : 0 en ctf, 0.15 en bb)")
    p.add_argument("--verify", action="store_true",
                   help="Rejoue chaque trouvaille pour eliminer les faux positifs (auto en bb)")
    p.add_argument("--timeout", type=float, default=8, help="Timeout par requete (defaut 8)")
    p.add_argument("--max-time", type=int, default=900, help="Temps max par etape en s (defaut 900)")
    p.add_argument("--match", default="200,204,301,302,307,401,403,405,500",
                   help="Codes HTTP interessants")
    p.add_argument("--filter-size", help="Filtrer une taille de reponse (ffuf -fs)")
    p.add_argument("--seclists", help="Chemin de SecLists si non trouve automatiquement")
    p.add_argument("--engine", choices=["auto", "ffuf", "native"], default="auto")
    p.add_argument("--no-juicy", action="store_true", help="Ne pas verifier les fichiers sensibles")
    p.add_argument("-o", "--output", help="Nom de base des rapports (.txt .json .html)")
    args = p.parse_args()

    # Reglages selon le mode (ctf = puissant/rapide, bb = prudent/fiable).
    # On ne remplit que ce que l'utilisateur n'a pas force explicitement.
    if args.mode == "bb":
        if args.threads is None: args.threads = 8
        if args.delay is None:   args.delay = 0.15
        args.verify = True                       # zero faux positif en bug bounty
    else:                                        # ctf
        if args.threads is None: args.threads = 45
        if args.delay is None:   args.delay = 0.0

    print(BANNER)
    if not args.url:
        p.print_help()
        sys.exit(0)

    import tempfile
    args._tmp = tempfile.gettempdir()

    base = normalize_url(args.url)
    fp, root = fingerprint(base)
    if root is None:
        log(f"{C.R}[!] Cible injoignable : {base}. Verifie l'URL / le VPN.{C.X}")
        sys.exit(1)
    print_fingerprint(base, fp)

    # Conseils selon le contexte
    log(f"\n{C.GR}[i] Mode : {C.X}"
        f"{(C.R + 'BUG BOUNTY (prudent : throttle + verification)') if args.mode=='bb' else (C.G + 'CTF (agressif/rapide)')}{C.X}")
    if fp["waf"] and args.mode != "bb":
        log(f"{C.Y}[!] WAF/CDN detecte ({', '.join(fp['waf'])}). "
            f"En cible reelle, lance plutot avec --bb pour eviter le ban.{C.X}")

    # Moteur
    use_ffuf = (args.engine == "ffuf") or (args.engine == "auto" and has_ffuf())
    if args.engine == "ffuf" and not has_ffuf():
        log(f"{C.R}[!] ffuf demande mais absent -> moteur natif.{C.X}"); use_ffuf = False
    engine = "ffuf" if use_ffuf else "natif"

    # SecLists
    seclists = find_seclists(args.seclists)
    if not seclists:
        log(f"\n{C.R}[!] SecLists introuvable.{C.X} Installe-le "
            f"(apt install seclists) ou precise --seclists /chemin/vers/seclists")
        log(f"{C.GR}    (le fingerprint et les fichiers sensibles ont quand meme tourne ci-dessus){C.X}")
        seclists = None

    all_findings, juicy = [], []
    start = time.time()

    # Fichiers sensibles
    if not args.no_juicy:
        log(f"\n{C.B}{C.BD}[*] Fichiers sensibles...{C.X}")
        juicy = check_juicy(base, args)
        if juicy:
            for j in juicy:
                log(f"    {color_status(j['status'])}{j['status']}{C.X}  "
                    f"/{j['path']:<30} {C.GR}[{j['length']} o]{C.X}")
        else:
            log(f"  {C.GR}(rien){C.X}")

    # Content discovery
    if seclists:
        steps, exts = build_plan(seclists, fp, args)
        log(f"\n{C.GR}[i] Moteur : {engine} | SecLists : {seclists} | "
            f"extensions : {','.join(exts)}{C.X}")
        if not steps:
            log(f"{C.R}[!] Aucune wordlist SecLists trouvee dans {WC}.{C.X}")
        cal = calibrate(base, exts, args.timeout) if not use_ffuf else None
        if cal and cal["wildcard"]:
            log(f"{C.Y}[!] Wildcard detecte : le serveur repond '200' a n'importe "
                f"quel chemin. Le filtre anti-faux-positifs est actif, mais mefie-toi "
                f"des resultats (compare bien les tailles).{C.X}")
        blocked = {"n": 0}
        for i, step in enumerate(steps, 1):
            log(f"\n{C.B}{C.BD}[*] Etape {i}/{len(steps)} : {step['label']}{C.X} "
                f"{C.GR}({os.path.basename(step['wordlist'])}"
                f"{' +ext' if step['exts'] else ''}){C.X}")
            if use_ffuf:
                res = run_ffuf(base, step, args)
            else:
                res = run_native(base, step, args, cal, blocked)
            # dedoublonnage inter-etapes
            known = {f["url"] for f in all_findings}
            new = [r for r in res if r["url"] not in known]
            all_findings += new
            print_findings(new)
        if blocked["n"]:
            log(f"\n{C.Y}[!] {blocked['n']} reponse(s) 429/503 (rate-limit/blocage). "
                f"{'Ralentis encore : --threads 3 --delay 0.5' if args.mode=='bb' else 'Passe en --bb pour throttler automatiquement.'}{C.X}")

    # Recap
    log(f"\n{C.B}{C.BD}{'='*68}{C.X}")
    log(f"{C.B}{C.BD}  RECAP : {len(juicy)} fichier(s) sensible(s), "
        f"{len(all_findings)} decouverte(s){C.X}")
    log(f"{C.B}{C.BD}{'='*68}{C.X}")
    interesting = [f for f in all_findings if f["status"] in (200, 401, 403)]
    for f in sorted(interesting, key=lambda x: x["status"])[:40]:
        log(f"  {color_status(f['status'])}{f['status']}{C.X}  {f['url']}")
    log(f"\n{C.GR}Termine en {time.time()-start:.1f}s{C.X}")

    if args.output:
        save_reports(base, fp, juicy, all_findings, args.output)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        log(f"\n{C.R}[!] Interrompu.{C.X}")
