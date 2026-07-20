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
from urllib.parse import urlparse
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
UA = "Mozilla/5.0 (X11; Linux x86_64) apifinder/1.0"

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
    p.add_argument("--fuzz", action="store_true", help="Activer le fuzzing des routes (SecLists)")
    p.add_argument("--seclists", help="Chemin de SecLists si non trouve")
    p.add_argument("-t", "--threads", type=int, default=40, help="Threads (defaut 40)")
    p.add_argument("--timeout", type=float, default=10, help="Timeout par requete (defaut 10)")
    p.add_argument("--max-time", type=int, default=600, help="Temps max fuzzing (defaut 600)")
    p.add_argument("-o", "--output", help="Nom de base du rapport (.txt .json)")
    args = p.parse_args()

    print(BANNER)
    if not args.url:
        p.print_help(); sys.exit(0)

    base = normalize(args.url)
    root = http_req(base + "/", timeout=args.timeout)
    if root is None:
        log(f"{C.R}[!] API injoignable : {base}{C.X}"); sys.exit(1)
    log(f"{C.CY}{C.BD}[*] Cible : {base}{C.X}  {C.GR}(/ -> {root['status']}, "
        f"{root['ctype'][:30]}){C.X}")
    start = time.time()

    data = {"target": base, "schemas": [], "endpoints": [], "versions": [],
            "graphql": [], "juicy": [], "fuzz": []}

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
    log(f"  Routes fuzz           : {len(data['fuzz'])}")
    log(f"\n{C.GR}Termine en {time.time()-start:.1f}s{C.X}")

    if args.output:
        save_report(base, data, args.output)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        log(f"\n{C.R}[!] Interrompu.{C.X}")
