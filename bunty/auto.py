#!/usr/bin/env python3
"""
auto.py - Orchestrateur web "tout-en-un" (bug bounty / CTF)
===========================================================
Une seule commande sur une URL ou une IP -> enchaine TOUT, etape par etape :

  0. Scan des ports web (natif)          -> quels services HTTP tournent
  1. web_enum.py   (par service)         -> content discovery (dirs/fichiers)
  2. jsleaks.py    (par service)         -> endpoints + secrets dans le JS
  3. apifinder.py  (par service)         -> API : schemas, versions CACHEES,
                                            GraphQL, actuator, LFI (show/file...),
                                            console Werkzeug, auto-loot des flags
  (option) recon.py (--recon, domaine)   -> sous-domaines

A la fin : un RECAP agrege (LFI, flags, PIN Werkzeug, console, secrets trouves).

Usage :
    python auto.py http://10.10.10.10
    python auto.py 10.10.10.10 --fuzz
    python auto.py cible.com --recon -H "X-HackerOne-Research: pseudo"

[!] Usage LEGAL uniquement : labs / CTF / cible explicitement autorisee.
"""
import argparse
import os
import re
import socket
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse

HERE = os.path.dirname(os.path.abspath(__file__))

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

# ports web courants (HTTP/HTTPS + frameworks : Flask 5000, node 3000, etc.)
WEB_PORTS = [80, 81, 443, 591, 3000, 3128, 5000, 7001, 8000, 8008, 8080,
             8081, 8088, 8443, 8888, 9000, 9090, 9200, 4200, 5601]
HTTPS_PORTS = {443, 8443, 9443, 4443}

def stage(n, title):
    print(f"\n{C.B}{C.BD}{'='*70}\n  ETAPE {n} — {title}\n{'='*70}{C.X}")

def sub(title):
    print(f"\n{C.CY}{C.BD}  >> {title}{C.X}")

# ----------------------------------------------------------------------
def parse_target(target):
    """Rend (host, forced_services). forced_services = [(scheme, port)] si URL."""
    forced = []
    host = target
    if re.match(r"^https?://", target, re.I):
        u = urlparse(target)
        host = u.hostname
        port = u.port or (443 if u.scheme == "https" else 80)
        forced.append((u.scheme, port))
    else:
        host = target.split("/")[0].split(":")[0]
    return host, forced

def scan_ports(host, ports, timeout=1.0):
    open_ = []
    def probe(p):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)
            if s.connect_ex((host, p)) == 0:
                s.close()
                return p
            s.close()
        except Exception:
            pass
        return None
    with ThreadPoolExecutor(max_workers=40) as ex:
        for fu in as_completed([ex.submit(probe, p) for p in ports]):
            r = fu.result()
            if r:
                open_.append(r)
    return sorted(open_)

def http_alive(scheme, host, port, timeout=4):
    """Confirme qu'un service HTTP repond (et renvoie le server header)."""
    import http.client, ssl
    try:
        if scheme == "https":
            conn = http.client.HTTPSConnection(host, port, timeout=timeout,
                                               context=ssl._create_unverified_context())
        else:
            conn = http.client.HTTPConnection(host, port, timeout=timeout)
        conn.request("GET", "/", headers={"User-Agent": "auto.py"})
        r = conn.getresponse()
        srv = r.getheader("Server", "")
        title = ""
        body = r.read(4096).decode("utf-8", "ignore")
        m = re.search(r"<title>([^<]{1,80})</title>", body, re.I)
        if m:
            title = m.group(1).strip()
        conn.close()
        return {"status": r.status, "server": srv, "title": title}
    except Exception:
        return None

# ----------------------------------------------------------------------
MARKERS = []   # collecte des findings importants pour le recap

def run_tool(script, tool_args, tag):
    """Lance un outil frere en streamant sa sortie + capte les findings cles."""
    path = os.path.join(HERE, script)
    if not os.path.isfile(path):
        print(f"{C.Y}    ({script} introuvable, saute){C.X}")
        return
    cmd = [sys.executable, path] + tool_args
    print(f"{C.GR}    $ {' '.join(cmd)}{C.X}")
    try:
        p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                             text=True, bufsize=1)
    except Exception as e:
        print(f"{C.R}    erreur lancement {script}: {e}{C.X}")
        return
    for line in p.stdout:
        sys.stdout.write(line)
        low = line.lower()
        if any(k in low for k in ("lfi !", "user flag", "pin werkzeug",
                                  "console werkzeug", ">>> ", "introspection active",
                                  "<- schema", "sensible", "secret =")):
            MARKERS.append(f"[{tag}] " + line.strip())
    p.wait()

# ----------------------------------------------------------------------
def pipeline_service(base, args):
    """Enchaine web_enum -> jsleaks -> apifinder sur un service HTTP."""
    hdr = []
    for h in args.header:
        hdr += ["-H", h]

    sub(f"1. Content discovery (web_enum) — {base}")
    we_script = "../web_enum.py" if os.path.isfile(os.path.join(HERE, "..", "web_enum.py")) else "web_enum.py"
    run_tool(we_script, [base, "-m", "ctf"], f"web_enum {base}")

    sub(f"2. Analyse JS (jsleaks) — {base}")
    run_tool("jsleaks.py", [base] + hdr, f"jsleaks {base}")

    sub(f"3. API + LFI + console Werkzeug (apifinder) — {base}")
    af = [base] + hdr
    if args.fuzz:
        af.append("--fuzz")
    if args.dto:
        af.append("--dto")
    run_tool("apifinder.py", af, f"apifinder {base}")

# ----------------------------------------------------------------------
BANNER = f"""{C.CY}{C.BD}
  auto.py  -  orchestrateur web tout-en-un{C.X}
{C.GR}  ports -> web_enum -> jsleaks -> apifinder (LFI + Werkzeug + flags){C.X}
{C.Y}  by 12akHack{C.GR}  -  outil de securite offensive{C.X}
{C.R}  [!] Usage LEGAL uniquement : labs / CTF / cible autorisee.{C.X}
"""

def main():
    p = argparse.ArgumentParser(
        description="auto.py - orchestrateur web tout-en-un (une URL -> tout)",
        formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("target", nargs="?", help="URL ou IP/host (http://10.10.10.10 ou 10.10.10.10)")
    p.add_argument("--recon", action="store_true",
                   help="Enum de sous-domaines (recon.py) — pour un domaine")
    p.add_argument("--fuzz", action="store_true", help="Activer le fuzzing des routes (apifinder)")
    p.add_argument("--dto", action="store_true", help="Fuite de schema DTO (apifinder)")
    p.add_argument("--ports", help="Ports web a scanner (ex: 80,5000,8080) sinon liste par defaut")
    p.add_argument("-H", "--header", action="append", default=[],
                   help="Header custom 'Nom: valeur' (repetable), propage aux outils")
    args = p.parse_args()

    print(BANNER)
    if not args.target:
        p.print_help(); sys.exit(0)

    host, forced = parse_target(args.target)
    t0 = time.time()

    # option : sous-domaines (domaine seulement)
    if args.recon and not re.match(r"^\d+\.\d+\.\d+\.\d+$", host):
        stage("R", f"Sous-domaines de {host} (recon.py)")
        hdr = []
        for h in args.header:
            hdr += ["-H", h]
        run_tool("recon.py", [host] + hdr, f"recon {host}")

    # ETAPE 0 : ports
    stage(0, f"Scan des ports web sur {host}")
    ports = ([int(x) for x in args.ports.split(",")] if args.ports else WEB_PORTS)
    print(f"{C.GR}  Sonde de {len(ports)} port(s)...{C.X}")
    open_ports = scan_ports(host, ports)
    if not open_ports:
        print(f"{C.R}  Aucun port web ouvert parmi la liste. "
              f"(essaie --ports ou un nmap -p- complet){C.X}")
    # services HTTP confirmes
    services = []
    seen = set()
    for scheme, port in forced:
        services.append((scheme, port)); seen.add(port)
    for port in open_ports:
        if port in seen:
            continue
        scheme = "https" if port in HTTPS_PORTS else "http"
        info = http_alive(scheme, host, port)
        if not info and scheme == "http":            # retente en https
            info = http_alive("https", host, port); scheme = "https" if info else scheme
        if info:
            services.append((scheme, port))
            print(f"    {C.G}{port}{C.X}  {scheme}  "
                  f"{C.GR}[{info['status']}] {info['server']}  {info['title']}{C.X}")
    if not services:
        print(f"{C.R}  Aucun service HTTP exploitable.{C.X}")
        sys.exit(1)

    # ETAPES 1-3 par service
    for i, (scheme, port) in enumerate(services, 1):
        base = f"{scheme}://{host}:{port}"
        stage(i, f"Pipeline web sur {base}")
        pipeline_service(base, args)

    # RECAP
    print(f"\n{C.B}{C.BD}{'='*70}\n  RECAP  {host}\n{'='*70}{C.X}")
    print(f"  Services web : " + ", ".join(f"{s}:{pt}" for s, pt in services))
    if MARKERS:
        print(f"\n  {C.R}{C.BD}Findings a regarder ({len(MARKERS)}) :{C.X}")
        for m in MARKERS:
            print(f"    {C.Y}- {m}{C.X}")
    else:
        print(f"  {C.GR}(pas de finding critique auto-detecte — verifie les sorties ci-dessus){C.X}")
    print(f"\n{C.GR}Termine en {time.time()-t0:.1f}s{C.X}")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{C.R}[!] Interrompu.{C.X}")
