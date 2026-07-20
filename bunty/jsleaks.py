#!/usr/bin/env python3
"""
jsleaks.py - Extraction d'endpoints, secrets, config & sinks dans les JS
========================================================================
Les fichiers JavaScript cote client fuient enormement : chemins d'API
internes, endpoints non documentes, config runtime, et parfois des
CLES/TOKENS oublies.

Ce que fait l'outil :
  1. Recupere les .js (crawl de la page, OU liste -l, OU un .js direct, OU stdin)
  2. SUIT LES CHUNKS lazy-loaded (Vite/webpack : import("./x.js"), maps de chunk)
     -> les SPA modernes cachent toute la logique dans des chunks charges a la
        demande ; sans ca on ne voit que la coquille vide.
  3. Recupere la CONFIG RUNTIME (env.json, config.json, <link rel=preload as=fetch>)
     -> souvent l'archi backend complete (URLs d'API, client_id, pools...).
  4. Extrait les ENDPOINTS references (facon LinkFinder) + ceux construits en
     template literal (`${base}/begin-login`) et via .get()/.post()/fetch().
  5. Extrait les SECRETS : cles cloud/SaaS, JWT, cles privees, client_id OAuth,
     Cognito/Firebase/Supabase/Sentry/Algolia/Mapbox... (facon SecretFinder+).
  6. Detecte les SINKS DOM XSS (eval, innerHTML, document.write, postMessage...)
     avec une source contrôlable a proximite -> pistes XSS/CTF.
  7. Detecte les SOURCE MAPS (.js.map) -> code source original (--maps pour DL).

Usage :
    python jsleaks.py https://target.com                 # crawl + suit les chunks
    python jsleaks.py https://target.com/static/app.js   # un seul JS (+ ses chunks)
    python jsleaks.py -l js_urls.txt -o rapport          # une liste de JS
    cat urls.txt | python jsleaks.py                      # depuis un pipe (hunt.py)
    python jsleaks.py https://t.com -H "X-HackerOne-Research: user" --maps

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

# UA de navigateur reel : passe la plupart des filtres UA basiques (Cloudflare & co)
UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")
EXTRA_HEADERS = {}   # rempli par -H/--header (ex: X-HackerOne-Research)

# ----------------------------------------------------------------------
# HTTP GET (suit les redirections, pour les JS sur CDN)
# ----------------------------------------------------------------------
def fetch(url, timeout=12, max_body=8_000_000, redirects=4):
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
            h = {"User-Agent": UA, "Accept": "*/*"}
            h.update(EXTRA_HEADERS)
            conn.request("GET", path, headers=h)
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
                    "text": body.decode("utf-8", "ignore"), "url": url}
        except Exception:
            return None
    return None

# ----------------------------------------------------------------------
# Regex endpoints (LinkFinder) + secrets (SecretFinder+)
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

# endpoints construits dynamiquement : `${base}/begin-login`, .post("/x"), fetch(`...`)
TPL_PATH = re.compile(r"""[}`"'](/[a-zA-Z][a-zA-Z0-9_./{}$-]{2,80})(?=[`"'?)\\ ])""")
CALL_PATH = re.compile(r"""\.(?:get|post|put|patch|delete|request)\(\s*[`"']([^`"'\s)]{2,100})""", re.I)

SECRETS = {
    "Google API Key":      r"AIza[0-9A-Za-z\-_]{35}",
    "AWS Access Key":      r"A[SK]IA[0-9A-Z]{16}",
    "AWS Secret (ctx)":    r"(?i)aws.{0,20}['\"][0-9a-zA-Z/+]{40}['\"]",
    "Amazon MWS":          r"amzn\.mws\.[0-9a-f-]{36}",
    "AWS API Gateway":     r"[a-z0-9]{10}\.execute-api\.[a-z0-9-]+\.amazonaws\.com",
    "Slack Token":         r"xox[baprs]-[0-9a-zA-Z-]{10,48}",
    "Slack Webhook":       r"https://hooks\.slack\.com/services/[A-Za-z0-9+/]{30,}",
    "GitHub Token":        r"gh[pousr]_[0-9A-Za-z]{36,}",
    "Stripe Secret Key":   r"[sr]k_live_[0-9a-zA-Z]{24}",
    "Stripe Public Key":   r"pk_live_[0-9a-zA-Z]{24}",
    "Google OAuth Token":  r"ya29\.[0-9A-Za-z\-_]{20,}",
    "Google OAuth Client": r"[0-9]{10,}-[0-9a-z]{20,}\.apps\.googleusercontent\.com",
    "JWT":                 r"eyJ[A-Za-z0-9_\-]{8,}\.eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}",
    "Private Key":         r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----",
    "Firebase DB":         r"[a-z0-9.-]+\.firebaseio\.com",
    "Firebase apiKey":     r"(?i)apiKey['\"\s:=]{1,4}['\"]AIza[0-9A-Za-z\-_]{35}['\"]",
    "Supabase URL":        r"https://[a-z0-9]{20}\.supabase\.co",
    "Supabase anon key":   r"eyJ[A-Za-z0-9_\-]{20,}\.eyJ[A-Za-z0-9_\-]{40,}\.[A-Za-z0-9_\-]{20,}",
    "Sentry DSN":          r"https://[0-9a-f]{20,}@[a-z0-9.-]*sentry\.io/[0-9]+",
    "Algolia Key":         r"(?i)algolia.{0,20}['\"][0-9a-zA-Z]{32}['\"]",
    "Mapbox Token":        r"pk\.eyJ[0-9A-Za-z\-_.]{50,}",
    "AWS Cognito Pool":    r"[a-z0-9-]+_[0-9A-Za-z]{9,}",
    "Google reCAPTCHA":    r"6L[0-9A-Za-z_-]{38}",
    "Mailgun Key":         r"key-[0-9a-zA-Z]{32}",
    "Twilio SID":          r"AC[a-z0-9]{32}",
    "SendGrid Key":        r"SG\.[0-9A-Za-z\-_]{22}\.[0-9A-Za-z\-_]{43}",
    "Facebook Token":      r"EAACEdEose0cBA[0-9A-Za-z]+",
    "Authorization Bearer":r"[Bb]earer\s+[0-9A-Za-z\-._~+/]{20,}",
    "OAuth client_id":     r"(?i)client[_-]?id['\"\s:=]{1,4}['\"]([0-9a-zA-Z\-_]{8,64})['\"]",
    "Generic API Key":     r"(?i)(?:api[_-]?key|apikey|access[_-]?token|secret[_-]?key|client[_-]?secret|auth[_-]?token)['\"\s:=]{1,4}['\"]([0-9a-zA-Z\-_]{16,64})['\"]",
    "Generic Secret (ctx)":r"(?i)(?:secret|passwd|password|pwd)['\"\s:=]{1,4}['\"]([^'\"]{6,45})['\"]",
}
# 'AWS Cognito Pool' est bruyant -> on ne l'active qu'avec un mot-clef cognito autour
SECRETS = {k: re.compile(v) for k, v in SECRETS.items()}
NOISY = {"AWS Cognito Pool", "Supabase anon key"}   # exiges un contexte

# sinks DOM XSS + sources contrôlables (pour CTF / DOM XSS)
DOM_SINKS = re.compile(
    r"(\.innerHTML\s*=|\.outerHTML\s*=|insertAdjacentHTML\s*\(|document\.write(?:ln)?\s*\(|"
    r"\beval\s*\(|new\s+Function\s*\(|setTimeout\s*\(\s*[`\"']|setInterval\s*\(\s*[`\"']|"
    r"dangerouslySetInnerHTML|\.setAttribute\s*\(\s*[`\"']href|location\s*=|location\.href\s*=|"
    r"location\.replace\s*\(|\.src\s*=|jQuery\s*\(|\$\s*\(|\.html\s*\(|addEventListener\s*\(\s*[`\"']message)")
DOM_SOURCES = re.compile(
    r"location\.(?:hash|search|href|pathname)|document\.(?:URL|documentURI|referrer|cookie|baseURI)|"
    r"window\.name|\.postMessage|event\.data|URLSearchParams|\.getParameter|location\b")

# endpoints "interessants" a mettre en avant
INTERESTING = ("api", "admin", "token", "auth", "internal", "secret", "key",
               "upload", "graphql", "swagger", "openapi", "debug", "config",
               "password", "user", "account", "private", "v1", "v2", "v3",
               "oauth", "callback", "redirect", "webhook", "login", "logout",
               "par", "authorize", "verify", "otp", "session", "reset", ".json")

# fichiers de config runtime a tenter sur une page
CONFIG_PATHS = ("envs/env.json", "env.json", "config.json", "assets/config.json",
                "config/config.json", "appsettings.json", "runtime-config.json",
                "assets/env.json", "static/env.json", "manifest.json")

def analyze_js(url, text):
    endpoints, secrets, sinks = set(), [], []
    for m in LINKFINDER.finditer(text):
        ep = m.group(1).strip()
        if 1 < len(ep) < 250 and not ep.startswith(("data:", "text/", "image/")):
            endpoints.add(ep)
    for m in TPL_PATH.finditer(text):
        ep = m.group(1).strip()
        if 2 < len(ep) < 90:
            endpoints.add(ep)
    for m in CALL_PATH.finditer(text):
        ep = m.group(1).strip()
        if 2 < len(ep) < 100 and "/" in ep:
            endpoints.add(ep)
    for name, rx in SECRETS.items():
        for m in rx.finditer(text):
            frag = m.group(0)
            start = max(0, m.start() - 30)
            ctx = text[start:m.end() + 15].replace("\n", " ").strip()
            if name in NOISY and "cognito" not in ctx.lower() and "supabase" not in ctx.lower():
                continue
            secrets.append({"type": name, "match": frag[:80], "context": ctx[:130],
                            "js": url})
    # sinks DOM : on ne garde que si une source contrôlable est dans le meme fichier
    if DOM_SOURCES.search(text):
        for m in DOM_SINKS.finditer(text):
            start = max(0, m.start() - 60)
            ctx = text[start:m.end() + 60].replace("\n", " ").strip()
            if DOM_SOURCES.search(ctx):   # source + sink rapproches = plus credible
                sinks.append({"sink": m.group(1)[:40], "context": ctx[:150], "js": url})
    return endpoints, secrets, sinks

# ----------------------------------------------------------------------
# Suivi des chunks JS (Vite / webpack lazy-load)
# ----------------------------------------------------------------------
CHUNK_RX = [
    re.compile(r"""import\(\s*[`"']([^`"']+\.js)[`"']"""),           # import("./x.js")
    re.compile(r"""from\s*[`"']([^`"']+\.js)[`"']"""),                # from"./x.js"
    re.compile(r"""[`"']([\w./-]*assets/[\w./-]+\.js)[`"']"""),       # "assets/x-hash.js"
    re.compile(r"""[`"'](\.?/?[\w./-]*chunk[\w./-]*\.js)[`"']"""),    # "./chunk-x.js"
    re.compile(r"""[`"']([\w./-]+-[A-Za-z0-9_]{8}\.js)[`"']"""),      # vite hash "name-abcd1234.js"
]

def extract_child_js(js_url, text):
    """Trouve les URLs de chunks JS references dans un fichier JS deja recupere."""
    out = set()
    for rx in CHUNK_RX:
        for m in rx.finditer(text):
            ref = m.group(1)
            if ref.endswith(".js") and "node_modules" not in ref:
                out.add(urljoin(js_url, ref))
    return out

def find_source_map(js_url, text):
    m = re.search(r"//[#@]\s*sourceMappingURL=([^\s'\"]+)", text)
    if m and not m.group(1).startswith("data:"):
        return urljoin(js_url, m.group(1))
    return None

# ----------------------------------------------------------------------
# Collecte des URLs JS + config depuis une page HTML
# ----------------------------------------------------------------------
def extract_js_from_html(base_url, text):
    js = set()
    for m in re.finditer(r"""<script[^>]+src\s*=\s*['\"]([^'\"]+)['\"]""", text, re.I):
        js.add(urljoin(base_url, m.group(1)))
    for m in re.finditer(r"""['\"]([^'\"]+?\.js(?:\?[^'\"]*)?)['\"]""", text):
        js.add(urljoin(base_url, m.group(1)))
    return {u for u in js if urlparse(u).path.endswith(".js") or ".js?" in u}

def extract_config_urls(base_url, text):
    """Fichiers de config precharges : <link rel=preload as=fetch href=...>."""
    cfg = set()
    for m in re.finditer(r"""<link[^>]+href\s*=\s*['\"]([^'\"]+)['\"][^>]*>""", text, re.I):
        tag = m.group(0).lower()
        href = m.group(1)
        if ("as=\"fetch\"" in tag or "as=fetch" in tag or href.endswith(".json")):
            cfg.add(urljoin(base_url, href))
    return cfg

def gather_targets(args):
    """Renvoie (js_urls, config_urls) selon le mode d'entree."""
    js_urls, config_urls = set(), set()
    if not sys.stdin.isatty() and not args.target and not args.list:
        for line in sys.stdin:
            u = line.strip()
            if u:
                js_urls.add(u)
        return js_urls, config_urls
    if args.list:
        try:
            with open(args.list, encoding="utf-8", errors="ignore") as f:
                for line in f:
                    u = line.strip()
                    if u and not u.startswith("#"):
                        js_urls.add(u)
        except Exception as e:
            log(f"{C.R}[!] Liste illisible : {e}{C.X}")
        return js_urls, config_urls
    t = args.target
    if t.endswith(".js") or ".js?" in t:
        js_urls.add(t)
    else:
        log(f"{C.GR}[i] Crawl de la page pour trouver les JS + config...{C.X}")
        r = fetch(t, timeout=args.timeout)
        if r:
            found = extract_js_from_html(t, r["text"])
            log(f"{C.G}[+] {len(found)} fichier(s) JS dans la page.{C.X}")
            js_urls |= found
            config_urls |= extract_config_urls(t, r["text"])
            # + chemins de config classiques
            for cp in CONFIG_PATHS:
                config_urls.add(urljoin(t.rstrip("/") + "/", cp))
            args._inline_html = r["text"]
            args._inline_url = t
        else:
            log(f"{C.R}[!] Page injoignable : {t}{C.X}")
    return js_urls, config_urls

# ----------------------------------------------------------------------
def color_secret(name):
    hot = ("AWS", "Private Key", "Stripe", "GitHub", "Slack Token", "Supabase",
           "Google API", "SendGrid", "Twilio", "OAuth Token", "Sentry", "JWT")
    return C.R if any(h in name for h in hot) else C.Y

def main():
    p = argparse.ArgumentParser(
        description="jsleaks.py - endpoints, secrets, config & sinks dans les JS",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
------------------------------------------------------------------------
 GUIDE
------------------------------------------------------------------------
 Crawl une page, suit les chunks lazy-load, recupere la config :
    python jsleaks.py https://target.com

 Analyse un seul JS (et ses chunks importes) :
    python jsleaks.py https://target.com/assets/index-abc123.js

 Liste de JS (ex: filtree depuis hunt.py) + rapport :
    python jsleaks.py -l js_urls.txt -o rapport

 Avec header BB + telechargement des source maps :
    python jsleaks.py https://cible.com -H "X-HackerOne-Research: user" --maps

 Depuis un pipe :
    grep '\\.js' urls.txt | python jsleaks.py

 [!] Reste STRICTEMENT dans le scope autorise du programme.
------------------------------------------------------------------------
""")
    p.add_argument("target", nargs="?", help="URL de page ou fichier .js")
    p.add_argument("-l", "--list", help="Fichier contenant des URLs de JS")
    p.add_argument("-t", "--threads", type=int, default=20, help="Threads (defaut 20)")
    p.add_argument("--timeout", type=float, default=12, help="Timeout par JS (defaut 12)")
    p.add_argument("--depth", type=int, default=2,
                   help="Profondeur de suivi des chunks JS (defaut 2, 0=desactive)")
    p.add_argument("--max-files", type=int, default=80,
                   help="Nombre max de JS a recuperer (defaut 80)")
    p.add_argument("--maps", action="store_true",
                   help="Telecharger les source maps (.js.map) detectees")
    p.add_argument("-H", "--header", action="append", default=[],
                   help="Header custom 'Nom: valeur' (repetable, ex: X-HackerOne-Research)")
    p.add_argument("--all-endpoints", action="store_true",
                   help="Afficher TOUS les endpoints (sinon seulement les interessants)")
    p.add_argument("-o", "--output", help="Nom de base du rapport (.txt .json)")
    args = p.parse_args()

    print(f"{C.CY}{C.BD}\n  jsleaks.py  -  endpoints, secrets, config & sinks (JS){C.X}")
    print(f"{C.GR}  suit les chunks lazy-load + config runtime + sinks DOM XSS{C.X}")
    print(f"{C.Y}  by 12akHack{C.GR}  -  outil de securite offensive{C.X}")
    print(f"{C.R}  [!] Bug bounty AUTORISE uniquement : reste STRICTEMENT dans le scope.{C.X}\n")
    args._inline_html = None; args._inline_url = None

    for hv in args.header:
        if ":" in hv:
            k, v = hv.split(":", 1)
            EXTRA_HEADERS[k.strip()] = v.strip()

    if not args.target and not args.list and sys.stdin.isatty():
        p.print_help(); sys.exit(0)

    js_urls, config_urls = gather_targets(args)
    if not js_urls and not config_urls and not args._inline_html:
        log(f"{C.R}[!] Aucun JS a analyser.{C.X}"); sys.exit(0)

    start = time.time()
    all_endpoints, all_secrets, all_sinks, per_js = {}, [], [], {}
    source_maps = []
    seen = set()
    frontier = list(js_urls)
    fetched = 0

    def work(u):
        r = fetch(u, timeout=args.timeout)
        if not r or r["status"] != 200:
            return u, None
        return u, r

    # BFS sur le graphe de chunks
    depth = 0
    while frontier and fetched < args.max_files and depth <= max(0, args.depth):
        batch = [u for u in frontier if u not in seen][:args.max_files - fetched]
        for u in batch:
            seen.add(u)
        frontier = []
        if not batch:
            break
        log(f"\n{C.B}{C.BD}[*] Niveau {depth} : analyse de {len(batch)} JS...{C.X}")
        with ThreadPoolExecutor(max_workers=args.threads) as ex:
            for fu in as_completed([ex.submit(work, u) for u in batch]):
                u, r = fu.result()
                fetched += 1
                if not r:
                    continue
                eps, secs, sinks = analyze_js(u, r["text"])
                if eps or secs or sinks:
                    per_js[u] = len(eps)
                for e in eps:
                    all_endpoints.setdefault(e, set()).add(u)
                all_secrets += secs
                all_sinks += sinks
                sm = find_source_map(u, r["text"])
                if sm:
                    source_maps.append(sm)
                # chunks enfants (si on n'a pas atteint la profondeur max)
                if depth < args.depth:
                    for child in extract_child_js(u, r["text"]):
                        if child not in seen:
                            frontier.append(child)
        depth += 1

    # config runtime
    if config_urls:
        log(f"\n{C.B}{C.BD}[*] Config runtime ({len(config_urls)} candidats)...{C.X}")
        for cu in config_urls:
            r = fetch(cu, timeout=args.timeout)
            if r and r["status"] == 200 and r["body"][:1].strip() in (b"{", b"["):
                log(f"  {C.G}200{C.X} {cu}  {C.G}{C.BD}<- CONFIG !{C.X}")
                snippet = r["text"][:400].replace("\n", " ")
                log(f"    {C.GR}{snippet}{C.X}")
                eps, secs, _ = analyze_js(cu + " (config)", r["text"])
                for e in eps:
                    all_endpoints.setdefault(e, set()).add(cu)
                all_secrets += secs

    # source maps
    if source_maps:
        log(f"\n{C.CY}{C.BD}[*] Source maps detectees ({len(source_maps)}){C.X} "
            f"{C.GR}(code source original !){C.X}")
        for sm in sorted(set(source_maps)):
            tag = ""
            if args.maps:
                r = fetch(sm, timeout=args.timeout)
                if r and r["status"] == 200 and args.output:
                    fn = args.output.rsplit(".", 1)[0] + "_" + os.path.basename(urlparse(sm).path)
                    with open(fn, "w", encoding="utf-8") as f:
                        f.write(r["text"])
                    tag = f" {C.G}-> {fn}{C.X}"
                elif r and r["status"] == 200:
                    tag = f" {C.G}(200, dispo){C.X}"
            log(f"  {C.CY}{sm}{C.X}{tag}")

    # scripts inline de la page
    if args._inline_html:
        eps, secs, sinks = analyze_js(args._inline_url + " (inline)", args._inline_html)
        for e in eps:
            all_endpoints.setdefault(e, set()).add("(inline HTML)")
        all_secrets += secs
        all_sinks += sinks

    # --- SECRETS ---
    log(f"\n{C.R}{C.BD}{'='*66}{C.X}")
    log(f"{C.R}{C.BD}  SECRETS ({len(all_secrets)}){C.X}")
    log(f"{C.R}{C.BD}{'='*66}{C.X}")
    if all_secrets:
        seen_s = set()
        for s in all_secrets:
            key = (s["type"], s["match"])
            if key in seen_s:
                continue
            seen_s.add(key)
            log(f"  {color_secret(s['type'])}{C.BD}{s['type']}{C.X} : {s['match']}")
            log(f"    {C.GR}{s['context']}{C.X}")
            log(f"    {C.GR}dans : {s['js']}{C.X}")
    else:
        log(f"  {C.GR}(aucun secret detecte){C.X}")

    # --- SINKS DOM XSS ---
    if all_sinks:
        log(f"\n{C.Y}{C.BD}{'='*66}{C.X}")
        log(f"{C.Y}{C.BD}  SINKS DOM XSS ({len(all_sinks)}) - source+sink rapproches{C.X}")
        log(f"{C.Y}{C.BD}{'='*66}{C.X}")
        seen_k = set()
        for s in all_sinks:
            key = s["context"][:60]
            if key in seen_k:
                continue
            seen_k.add(key)
            log(f"  {C.Y}{s['sink']}{C.X}  {C.GR}{s['context']}{C.X}")

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

    log(f"\n{C.GR}{fetched} JS recuperes, {len(per_js)} utiles, "
        f"{len(source_maps)} source map(s) en {time.time()-start:.1f}s{C.X}")

    # export
    if args.output:
        b = args.output.rsplit(".", 1)[0]
        data = {"secrets": all_secrets,
                "sinks": all_sinks,
                "source_maps": sorted(set(source_maps)),
                "endpoints": {e: sorted(js) for e, js in all_endpoints.items()},
                "interesting": sorted(interesting)}
        with open(b + ".json", "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
        with open(b + ".txt", "w", encoding="utf-8") as f:
            f.write("[SECRETS]\n")
            for s in all_secrets:
                f.write(f"  {s['type']}: {s['match']}  ({s['js']})\n")
            f.write("\n[SINKS DOM XSS]\n")
            for s in all_sinks:
                f.write(f"  {s['sink']}  {s['context']}\n")
            f.write("\n[SOURCE MAPS]\n")
            for sm in sorted(set(source_maps)):
                f.write(f"  {sm}\n")
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
