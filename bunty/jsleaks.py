#!/usr/bin/env python3
"""
jsleaks.py - Extraction d'endpoints & secrets dans les fichiers JS
==================================================================
Les fichiers JavaScript cote client fuient enormement : chemins d'API
internes, endpoints non documentes, et parfois des CLES/TOKENS oublies.

Ce que fait l'outil :
  1. Recupere les .js (crawl de la page, OU liste -l, OU un .js direct, OU stdin)
  2. Extrait les ENDPOINTS references dans le code (facon LinkFinder)
  3. Extrait les SECRETS : cles Google/AWS/GitHub/Stripe, JWT, cles privees,
     tokens Slack/Twilio/SendGrid, Authorization Bearer... (facon SecretFinder)
  4. Signale les endpoints "interessants" (api, admin, token, upload, internal...)

Usage :
    python jsleaks.py https://target.com                 # crawl la page pour les JS
    python jsleaks.py https://target.com/static/app.js   # un seul JS
    python jsleaks.py -l js_urls.txt -o rapport          # une liste de JS
    cat urls.txt | python jsleaks.py                      # depuis un pipe (hunt.py)

[!] Bug bounty AUTORISE uniquement : reste STRICTEMENT dans le scope du programme.
"""

import argparse
import json
import os
import re
import ssl
import sys
import time
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
UA = "Mozilla/5.0 (X11; Linux x86_64) jsleaks/1.0"

# ----------------------------------------------------------------------
# HTTP GET (suit les redirections, pour les JS sur CDN)
# ----------------------------------------------------------------------
def fetch(url, timeout=12, max_body=5_000_000, redirects=3):
    for _ in range(redirects + 1):
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
            conn.request("GET", path, headers={"User-Agent": UA, "Accept": "*/*"})
            r = conn.getresponse()
            if r.status in (301, 302, 303, 307, 308):
                loc = r.getheader("Location")
                conn.close()
                if not loc:
                    return None
                url = urljoin(url, loc)
                continue
            body = r.read(max_body)
            hdrs = {k.lower(): v for k, v in r.getheaders()}
            conn.close()
            return {"status": r.status, "headers": hdrs, "body": body,
                    "text": body.decode("utf-8", "ignore")}
        except Exception:
            return None
    return None

# ----------------------------------------------------------------------
# Regex endpoints (LinkFinder) + secrets (SecretFinder)
# ----------------------------------------------------------------------
LINKFINDER = re.compile(r"""
  (?:"|'|`)
  (
    ((?:[a-zA-Z]{1,10}://|//)[^"'`/]{1,}\.[a-zA-Z]{2,}[^"'`]{0,})           |
    ((?:/|\.\./|\./)[^"'`><,;|*()%$^/\\\[\]][^"'`><,;|()]{1,})              |
    ([a-zA-Z0-9_\-/]{1,}/[a-zA-Z0-9_\-/]{1,}\.(?:[a-zA-Z]{1,4}|action)(?:[?#][^"'`]{0,}|)) |
    ([a-zA-Z0-9_\-]{1,}\.(?:php|asp|aspx|jsp|json|action|html|js|txt|xml)(?:[?#][^"'`]{0,}|))
  )
  (?:"|'|`)
""", re.VERBOSE)

SECRETS = {
    "Google API Key":      r"AIza[0-9A-Za-z\-_]{35}",
    "AWS Access Key":      r"A[SK]IA[0-9A-Z]{16}",
    "AWS Secret (ctx)":    r"(?i)aws.{0,20}['\"][0-9a-zA-Z/+]{40}['\"]",
    "Amazon MWS":          r"amzn\.mws\.[0-9a-f-]{36}",
    "Slack Token":         r"xox[baprs]-[0-9a-zA-Z-]{10,48}",
    "Slack Webhook":       r"https://hooks\.slack\.com/services/[A-Za-z0-9+/]{30,}",
    "GitHub Token":        r"gh[pousr]_[0-9A-Za-z]{36,}",
    "Stripe Secret Key":   r"[sr]k_live_[0-9a-zA-Z]{24}",
    "Stripe Public Key":   r"pk_live_[0-9a-zA-Z]{24}",
    "Google OAuth Token":  r"ya29\.[0-9A-Za-z\-_]{20,}",
    "JWT":                 r"eyJ[A-Za-z0-9_\-]{8,}\.eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}",
    "Private Key":         r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----",
    "Firebase DB":         r"[a-z0-9.-]+\.firebaseio\.com",
    "Google reCAPTCHA":    r"6L[0-9A-Za-z_-]{38}",
    "Mailgun Key":         r"key-[0-9a-zA-Z]{32}",
    "Twilio SID":          r"AC[a-z0-9]{32}",
    "SendGrid Key":        r"SG\.[0-9A-Za-z\-_]{22}\.[0-9A-Za-z\-_]{43}",
    "Facebook Token":      r"EAACEdEose0cBA[0-9A-Za-z]+",
    "Authorization Bearer":r"[Bb]earer\s+[0-9A-Za-z\-._~+/]{20,}",
    "Generic API Key":     r"(?i)(?:api[_-]?key|apikey|access[_-]?token|secret[_-]?key|client[_-]?secret|auth[_-]?token)['\"\s:=]{1,4}['\"]([0-9a-zA-Z\-_]{16,64})['\"]",
    "Generic Secret (ctx)":r"(?i)(?:secret|passwd|password|pwd)['\"\s:=]{1,4}['\"]([^'\"]{6,45})['\"]",
}
SECRETS = {k: re.compile(v) for k, v in SECRETS.items()}

# endpoints "interessants" a mettre en avant
INTERESTING = ("api", "admin", "token", "auth", "internal", "secret", "key",
               "upload", "graphql", "swagger", "openapi", "debug", "config",
               "password", "user", "account", "private", "v1", "v2", "v3",
               "oauth", "callback", "redirect", "webhook", ".json")

def analyze_js(url, text):
    endpoints, secrets = set(), []
    for m in LINKFINDER.finditer(text):
        ep = m.group(1).strip()
        if 1 < len(ep) < 250 and not ep.startswith(("data:", "text/", "image/")):
            endpoints.add(ep)
    for name, rx in SECRETS.items():
        for m in rx.finditer(text):
            frag = m.group(0)
            start = max(0, m.start() - 25)
            ctx = text[start:m.end() + 15].replace("\n", " ").strip()
            secrets.append({"type": name, "match": frag[:80], "context": ctx[:120],
                            "js": url})
    return endpoints, secrets

# ----------------------------------------------------------------------
# Collecte des URLs JS
# ----------------------------------------------------------------------
def extract_js_from_html(base_url, text):
    js = set()
    for m in re.finditer(r"""<script[^>]+src\s*=\s*['\"]([^'\"]+)['\"]""", text, re.I):
        js.add(urljoin(base_url, m.group(1)))
    # aussi les .js references en dur dans le HTML/inline
    for m in re.finditer(r"""['\"]([^'\"]+?\.js(?:\?[^'\"]*)?)['\"]""", text):
        js.add(urljoin(base_url, m.group(1)))
    return {u for u in js if urlparse(u).path.endswith(".js") or ".js?" in u}

def gather_targets(args):
    """Renvoie (js_urls, inline_pages) selon le mode d'entree."""
    js_urls = set()
    # stdin (pipe)
    if not sys.stdin.isatty() and not args.target and not args.list:
        for line in sys.stdin:
            u = line.strip()
            if u:
                js_urls.add(u)
        return js_urls
    # liste de fichiers
    if args.list:
        try:
            with open(args.list, encoding="utf-8", errors="ignore") as f:
                for line in f:
                    u = line.strip()
                    if u and not u.startswith("#"):
                        js_urls.add(u)
        except Exception as e:
            log(f"{C.R}[!] Liste illisible : {e}{C.X}")
        return js_urls
    # cible unique
    t = args.target
    if t.endswith(".js") or ".js?" in t:
        js_urls.add(t)
    else:
        log(f"{C.GR}[i] Crawl de la page pour trouver les JS...{C.X}")
        r = fetch(t, timeout=args.timeout)
        if r:
            found = extract_js_from_html(t, r["text"])
            log(f"{C.G}[+] {len(found)} fichier(s) JS trouve(s) dans la page.{C.X}")
            js_urls |= found
            # on analyse aussi le HTML inline (scripts inline)
            args._inline_html = r["text"]
            args._inline_url = t
        else:
            log(f"{C.R}[!] Page injoignable : {t}{C.X}")
    return js_urls

# ----------------------------------------------------------------------
def color_secret(name):
    hot = ("AWS", "Private Key", "Stripe", "GitHub", "Slack Token",
           "Google API", "SendGrid", "Twilio", "OAuth")
    return C.R if any(h in name for h in hot) else C.Y

def main():
    p = argparse.ArgumentParser(
        description="jsleaks.py - endpoints & secrets dans les fichiers JS",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
------------------------------------------------------------------------
 GUIDE
------------------------------------------------------------------------
 Crawl une page et analyse tous ses JS :
    python jsleaks.py https://target.com

 Analyse un seul fichier JS :
    python jsleaks.py https://target.com/static/app.js

 Analyse une liste de JS (ex: filtree depuis hunt.py) + rapport :
    python jsleaks.py -l js_urls.txt -o rapport

 Depuis un pipe (chaine avec d'autres outils) :
    grep '\\.js' results/target/urls.txt | python jsleaks.py

 EXEMPLE COMPLET (fouiller les JS d'un site) :
    python jsleaks.py https://cible.com -o rapport_js
        # -> telecharge tous les .js de la page et extrait secrets (cles API,
        #    tokens, JWT) + endpoints caches (api, admin, internal...)
    # Ou en masse depuis hunt.py :
    grep '\\.js' results/cible.com/urls.txt | python jsleaks.py
    # Attention: verifie chaque secret avant de reporter (faux positifs frequents).

 [!] Reste STRICTEMENT dans le scope autorise du programme.
------------------------------------------------------------------------
""")
    p.add_argument("target", nargs="?", help="URL de page ou fichier .js")
    p.add_argument("-l", "--list", help="Fichier contenant des URLs de JS")
    p.add_argument("-t", "--threads", type=int, default=20, help="Threads (defaut 20)")
    p.add_argument("--timeout", type=float, default=12, help="Timeout par JS (defaut 12)")
    p.add_argument("--all-endpoints", action="store_true",
                   help="Afficher TOUS les endpoints (sinon seulement les interessants)")
    p.add_argument("-o", "--output", help="Nom de base du rapport (.txt .json .html)")
    args = p.parse_args()

    print(f"{C.CY}{C.BD}\n  jsleaks.py  -  endpoints & secrets dans les JS{C.X}")
    print(f"{C.Y}  by 12akHack{C.GR}  -  outil de securite offensive{C.X}")
    print(f"{C.R}  [!] Bug bounty AUTORISE uniquement : reste STRICTEMENT dans le scope.{C.X}\n")
    args._inline_html = None; args._inline_url = None

    if not args.target and not args.list and sys.stdin.isatty():
        p.print_help(); sys.exit(0)

    js_urls = gather_targets(args)
    if not js_urls and not args._inline_html:
        log(f"{C.R}[!] Aucun JS a analyser.{C.X}"); sys.exit(0)

    log(f"\n{C.B}{C.BD}[*] Analyse de {len(js_urls)} fichier(s) JS...{C.X}")
    start = time.time()
    all_endpoints, all_secrets, per_js = {}, [], {}

    def work(u):
        r = fetch(u, timeout=args.timeout)
        if not r or r["status"] != 200:
            return u, set(), []
        return (u, *analyze_js(u, r["text"]))

    with ThreadPoolExecutor(max_workers=args.threads) as ex:
        for fu in as_completed([ex.submit(work, u) for u in js_urls]):
            u, eps, secs = fu.result()
            if eps or secs:
                per_js[u] = len(eps)
            for e in eps:
                all_endpoints.setdefault(e, set()).add(u)
            all_secrets += secs

    # scripts inline de la page
    if args._inline_html:
        eps, secs = analyze_js(args._inline_url + " (inline)", args._inline_html)
        for e in eps:
            all_endpoints.setdefault(e, set()).add("(inline HTML)")
        all_secrets += secs

    # --- SECRETS (le plus important) ---
    log(f"\n{C.R}{C.BD}{'='*66}{C.X}")
    log(f"{C.R}{C.BD}  SECRETS ({len(all_secrets)}){C.X}")
    log(f"{C.R}{C.BD}{'='*66}{C.X}")
    if all_secrets:
        seen = set()
        for s in all_secrets:
            key = (s["type"], s["match"])
            if key in seen:
                continue
            seen.add(key)
            log(f"  {color_secret(s['type'])}{C.BD}{s['type']}{C.X} : {s['match']}")
            log(f"    {C.GR}{s['context']}{C.X}")
            log(f"    {C.GR}dans : {s['js']}{C.X}")
    else:
        log(f"  {C.GR}(aucun secret detecte){C.X}")

    # --- ENDPOINTS ---
    interesting = {e: js for e, js in all_endpoints.items()
                   if any(t in e.lower() for t in INTERESTING)}
    show = all_endpoints if args.all_endpoints else interesting
    label = "TOUS LES ENDPOINTS" if args.all_endpoints else "ENDPOINTS INTERESSANTS"
    log(f"\n{C.CY}{C.BD}{'='*66}{C.X}")
    log(f"{C.CY}{C.BD}  {label} ({len(show)} / {len(all_endpoints)} au total){C.X}")
    log(f"{C.CY}{C.BD}{'='*66}{C.X}")
    for e in sorted(show):
        log(f"  {C.G}{e}{C.X}")
    if not args.all_endpoints and all_endpoints:
        log(f"  {C.GR}(+ {len(all_endpoints)-len(interesting)} autres, "
            f"--all-endpoints pour tout voir){C.X}")

    log(f"\n{C.GR}Analyse de {len(per_js)} JS utiles en {time.time()-start:.1f}s{C.X}")

    # export
    if args.output:
        b = args.output.rsplit(".", 1)[0]
        data = {"secrets": all_secrets,
                "endpoints": {e: sorted(js) for e, js in all_endpoints.items()},
                "interesting": sorted(interesting)}
        with open(b + ".json", "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
        with open(b + ".txt", "w", encoding="utf-8") as f:
            f.write("[SECRETS]\n")
            for s in all_secrets:
                f.write(f"  {s['type']}: {s['match']}  ({s['js']})\n")
            f.write("\n[ENDPOINTS INTERESSANTS]\n")
            for e in sorted(interesting):
                f.write(f"  {e}\n")
            f.write("\n[TOUS LES ENDPOINTS]\n")
            for e in sorted(all_endpoints):
                f.write(f"  {e}\n")
        log(f"{C.G}[+] Rapport : {b}.txt / {b}.json{C.X}")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        log(f"\n{C.R}[!] Interrompu.{C.X}")
