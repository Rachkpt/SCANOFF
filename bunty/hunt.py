#!/usr/bin/env python3
"""
hunt.py - Orchestrateur de recon bug bounty
===========================================
Une seule commande, tout le pipeline s'enchaine :

  1. Sous-domaines   : subfinder + assetfinder (+ amass)   -> sinon recon.py (pur python)
  2. Hotes vivants   : httpx (statut/titre/tech)           -> sinon recon.py
  3. Ports           : naabu (top ports)                   -> sinon (saute)
  4. URLs / crawl    : gau + waybackurls + katana          -> sinon wayback natif
  5. Vulns connues   : nuclei                              -> sinon (saute)

Chaque etape ecrit ses resultats dans  results/<domaine>/ .
Les outils absents sont remplaces par une solution de secours quand possible.

Usage :
    python hunt.py example.com
    python hunt.py example.com --deep -o results
    python hunt.py example.com --no-nuclei --ports

[!] Bug bounty AUTORISE uniquement : reste STRICTEMENT dans le scope du programme.
"""

import argparse
import os
import sys
import shutil
import subprocess
import time

# import de recon.py (meme dossier) pour les solutions de secours
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
try:
    import recon as R
except Exception:
    R = None

# ----------------------------------------------------------------------
class C:
    G = "\033[92m"; Y = "\033[93m"; Rd = "\033[91m"; B = "\033[94m"
    CY = "\033[96m"; GR = "\033[90m"; BD = "\033[1m"; X = "\033[0m"
if os.name == "nt":
    try:
        import ctypes
        k = ctypes.windll.kernel32
        k.SetConsoleMode(k.GetStdHandle(-11), 7)
    except Exception:
        for a in ("G", "Y", "Rd", "B", "CY", "GR", "BD", "X"):
            setattr(C, a, "")

def log(m): print(m)
def have(tool): return shutil.which(tool) is not None

def stage(title):
    log(f"\n{C.B}{C.BD}{'='*66}{C.X}")
    log(f"{C.B}{C.BD}  {title}{C.X}")
    log(f"{C.B}{C.BD}{'='*66}{C.X}")

def read_lines(path):
    if not os.path.isfile(path):
        return []
    with open(path, encoding="utf-8", errors="ignore") as f:
        return [l.strip() for l in f if l.strip()]

def write_lines(path, items):
    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(items) + ("\n" if items else ""))

def merge_into(path, new_items):
    cur = set(read_lines(path))
    cur |= set(new_items)
    ordered = sorted(cur)
    write_lines(path, ordered)
    return ordered

def run(cmd, out_path=None, timeout=None, feed=None):
    """Lance une commande externe ; capture stdout dans out_path si donne.
    Renvoie (ok, lignes_stdout)."""
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True,
                              timeout=timeout, input=feed)
        lines = [l for l in proc.stdout.splitlines() if l.strip()]
        if out_path:
            write_lines(out_path, lines)
        return True, lines
    except subprocess.TimeoutExpired:
        log(f"{C.Y}    (timeout, on passe a la suite){C.X}")
        return False, []
    except Exception as e:
        log(f"{C.Rd}    erreur : {e}{C.X}")
        return False, []

# ----------------------------------------------------------------------
# 1. Sous-domaines
# ----------------------------------------------------------------------
def stage_subdomains(domain, outdir, args):
    stage("1. SOUS-DOMAINES")
    subs_file = os.path.join(outdir, "subdomains.txt")
    total = set([domain])
    used_tool = False

    if have("subfinder"):
        used_tool = True
        log(f"{C.GR}[i] subfinder...{C.X}")
        ok, lines = run(["subfinder", "-d", domain, "-silent", "-all"], timeout=600)
        total |= set(lines); log(f"    {C.G}subfinder : {len(lines)}{C.X}")
    if have("assetfinder"):
        used_tool = True
        log(f"{C.GR}[i] assetfinder...{C.X}")
        ok, lines = run(["assetfinder", "--subs-only", domain], timeout=300)
        keep = [l for l in lines if l.endswith(domain)]
        total |= set(keep); log(f"    {C.G}assetfinder : {len(keep)}{C.X}")
    if args.amass and have("amass"):
        used_tool = True
        log(f"{C.GR}[i] amass (passif, peut etre long)...{C.X}")
        ok, lines = run(["amass", "enum", "-passive", "-d", domain, "-silent"], timeout=1200)
        keep = [l for l in lines if l.endswith(domain)]
        total |= set(keep); log(f"    {C.G}amass : {len(keep)}{C.X}")

    if not used_tool:
        log(f"{C.Y}[i] Aucun outil de sous-domaines -> secours recon.py (sources passives){C.X}")
        if R:
            total |= R.passive_enum(domain)
        else:
            log(f"{C.Rd}[!] recon.py introuvable, etape limitee.{C.X}")

    if args.brute and R:
        total |= R.dns_brute(domain, args.brute, args.threads)

    ordered = sorted(total)
    write_lines(subs_file, ordered)
    log(f"\n{C.CY}{C.BD}[=] {len(ordered)} sous-domaine(s) -> {subs_file}{C.X}")
    return subs_file

# ----------------------------------------------------------------------
# 2. Hotes vivants
# ----------------------------------------------------------------------
def stage_live(subs_file, outdir, args):
    stage("2. HOTES VIVANTS")
    live_file = os.path.join(outdir, "live.txt")            # URLs vivantes (pour la suite)
    info_file = os.path.join(outdir, "live_info.txt")       # avec statut/titre/tech
    subs = read_lines(subs_file)

    if have("httpx"):
        log(f"{C.GR}[i] httpx sur {len(subs)} sous-domaine(s)...{C.X}")
        ok, lines = run(["httpx", "-l", subs_file, "-silent", "-status-code",
                         "-title", "-tech-detect", "-no-color"], timeout=900)
        write_lines(info_file, lines)
        urls = [l.split()[0] for l in lines if l.split()]
        write_lines(live_file, sorted(set(urls)))
        for l in lines[:60]:
            log(f"    {l}")
    else:
        log(f"{C.Y}[i] httpx absent -> secours recon.py (resolution + sonde HTTP){C.X}")
        if not R:
            log(f"{C.Rd}[!] recon.py introuvable, etape sautee.{C.X}")
            return live_file, info_file
        live = R.resolve_all(subs, args.threads)
        probes = R.probe_all(live, threads=min(40, args.threads), timeout=args.timeout)
        urls, info = [], []
        for p in probes:
            urls.append(p["url"])
            info.append(f"{p['url']} [{p['status']}] {p['title']} "
                        f"[{p['server']}] {'/'.join(p['techno'])}")
            log(f"    {R.color_status(p['status'])}{p['status']}{C.X} {p['url']}")
        write_lines(live_file, sorted(set(urls)))
        write_lines(info_file, info)

    log(f"\n{C.CY}{C.BD}[=] {len(read_lines(live_file))} hote(s) vivant(s) -> {live_file}{C.X}")
    return live_file, info_file

# ----------------------------------------------------------------------
# 3. Ports (optionnel)
# ----------------------------------------------------------------------
def stage_ports(subs_file, outdir, args):
    stage("3. PORTS (naabu)")
    ports_file = os.path.join(outdir, "ports.txt")
    if not have("naabu"):
        log(f"{C.Y}[i] naabu absent -> etape sautee "
            f"(utilise reconx.py pour scanner les ports){C.X}")
        return ports_file
    log(f"{C.GR}[i] naabu top ports...{C.X}")
    ok, lines = run(["naabu", "-l", subs_file, "-silent", "-top-ports", "100"], timeout=900)
    write_lines(ports_file, lines)
    for l in lines[:60]:
        log(f"    {l}")
    log(f"\n{C.CY}{C.BD}[=] {len(lines)} port(s) -> {ports_file}{C.X}")
    return ports_file

# ----------------------------------------------------------------------
# 4. URLs / crawl
# ----------------------------------------------------------------------
def native_wayback(domain):
    if not R:
        return []
    url = (f"http://web.archive.org/cdx/search/cdx?url=*.{domain}/*"
           f"&output=text&fl=original&collapse=urlkey&limit=20000")
    st, _, body = R.http_get(url, timeout=90)
    if st == 200:
        return [l for l in body.decode("utf-8", "ignore").splitlines() if l.strip()]
    return []

INTERESTING = (".js", ".json", ".xml", ".sql", ".bak", ".zip", ".env", ".config",
               "api", "admin", "graphql", "swagger", "openapi", "upload", "token",
               "redirect", "debug", "backup", "=", "?")

def stage_urls(domain, live_file, outdir, args):
    stage("4. URLs / CRAWL")
    urls_file = os.path.join(outdir, "urls.txt")
    juicy_file = os.path.join(outdir, "urls_interessantes.txt")
    all_urls = set()

    if have("gau"):
        log(f"{C.GR}[i] gau...{C.X}")
        ok, lines = run(["gau", "--subs", domain], timeout=600)
        all_urls |= set(lines); log(f"    {C.G}gau : {len(lines)}{C.X}")
    if have("waybackurls"):
        log(f"{C.GR}[i] waybackurls...{C.X}")
        ok, lines = run(["waybackurls", domain], timeout=600, feed=domain + "\n")
        all_urls |= set(lines); log(f"    {C.G}waybackurls : {len(lines)}{C.X}")
    if have("katana"):
        log(f"{C.GR}[i] katana (crawl live + JS)...{C.X}")
        ok, lines = run(["katana", "-list", live_file, "-silent", "-jc", "-d", "2"],
                        timeout=900)
        all_urls |= set(lines); log(f"    {C.G}katana : {len(lines)}{C.X}")

    if not (have("gau") or have("waybackurls") or have("katana")):
        log(f"{C.Y}[i] gau/waybackurls/katana absents -> secours wayback natif{C.X}")
        wb = native_wayback(domain)
        all_urls |= set(wb); log(f"    {C.G}wayback natif : {len(wb)}{C.X}")

    ordered = sorted(all_urls)
    write_lines(urls_file, ordered)
    juicy = sorted({u for u in ordered if any(t in u.lower() for t in INTERESTING)})
    write_lines(juicy_file, juicy)
    log(f"\n{C.CY}{C.BD}[=] {len(ordered)} URL(s) -> {urls_file}{C.X}")
    log(f"{C.CY}{C.BD}[=] {len(juicy)} URL(s) interessante(s) -> {juicy_file}{C.X}")
    for u in juicy[:25]:
        log(f"    {C.Y}{u}{C.X}")
    return urls_file, juicy_file

# ----------------------------------------------------------------------
# 5. Vulns (nuclei)
# ----------------------------------------------------------------------
def stage_nuclei(live_file, outdir, args):
    stage("5. VULNS (nuclei)")
    nuclei_file = os.path.join(outdir, "nuclei.txt")
    if not have("nuclei"):
        log(f"{C.Y}[i] nuclei absent -> etape sautee. "
            f"(installe-le : c'est l'outil BB incontournable){C.X}")
        return nuclei_file
    n = len(read_lines(live_file))
    sev = args.severity
    log(f"{C.GR}[i] nuclei | severite: {sev} | {n} cible(s) | "
        f"rate-limit {args.nuclei_rl}/s | timeout global {args.nuclei_timeout}s{C.X}")
    log(f"{C.GR}[i] nuclei peut durer plusieurs minutes (milliers de templates). "
        f"Ctrl+C = couper, les resultats partiels sont GARDES.{C.X}")
    cmd = ["nuclei", "-l", live_file, "-silent", "-severity", sev, "-no-color",
           "-rate-limit", str(args.nuclei_rl), "-c", str(args.nuclei_conc),
           "-timeout", "8", "-o", nuclei_file]
    lines, proc = [], None
    import threading
    try:
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                                stderr=subprocess.DEVNULL, text=True)
        watchdog = threading.Timer(args.nuclei_timeout, proc.kill)  # anti-blocage
        watchdog.start()
        for line in proc.stdout:
            line = line.strip()
            if line:
                lines.append(line)
                log(f"    {C.Rd}{line}{C.X}")
        proc.wait(timeout=10)
        watchdog.cancel()
    except KeyboardInterrupt:
        if proc:
            proc.kill()
        log(f"{C.Y}    (nuclei interrompu -> {len(lines)} resultat(s) gardes){C.X}")
    except Exception as e:
        log(f"{C.Rd}    nuclei: {e}{C.X}")
    if not lines:
        log(f"    {C.GR}(rien de detecte){C.X}")
    log(f"\n{C.CY}{C.BD}[=] {len(lines)} resultat(s) -> {nuclei_file}{C.X}")
    return nuclei_file

# ----------------------------------------------------------------------
BANNER = f"""{C.CY}{C.BD}
  hunt.py  -  orchestrateur de recon bug bounty{C.X}
{C.GR}  subfinder -> httpx -> naabu -> katana/gau -> nuclei  (repli pur-python){C.X}
{C.Y}  by 12akHack{C.GR}  -  outil de securite offensive{C.X}
{C.Rd}  [!] Bug bounty AUTORISE uniquement : reste STRICTEMENT dans le scope.{C.X}
"""

def main():
    p = argparse.ArgumentParser(
        description="hunt.py - orchestrateur de recon bug bounty",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
------------------------------------------------------------------------
 GUIDE
------------------------------------------------------------------------
 Pipeline complet en une commande :
    python hunt.py example.com

 Complet + ports + brute DNS + rapports dans un dossier :
    python hunt.py example.com --ports --deep -o results

 Choisir/sauter des etapes :
    python hunt.py example.com --no-nuclei            # sans nuclei
    python hunt.py example.com --passive-only         # juste sous-domaines + live
    python hunt.py example.com --severity medium,high,critical

 Chaque etape ecrit dans results/<domaine>/ :
   subdomains.txt  live.txt  live_info.txt  ports.txt
   urls.txt  urls_interessantes.txt  nuclei.txt

 Outils utilises s'ils sont installes, sinon repli sur recon.py (pur python).

 EXEMPLE COMPLET (bug bounty, programme ACTIF + autorise) :
    python hunt.py cible.com --deep -o results
        # -> subs -> hotes vivants -> ports -> URLs -> nuclei, tout enchaine
        #    Sortie dans results/cible.com/ (subdomains, live, urls, nuclei...)
    # Puis chaine sur les resultats :
    python takeover.py -l results/cible.com/subdomains.txt
    grep '\\.js' results/cible.com/urls.txt | python jsleaks.py

 /!\\ Reste STRICTEMENT dans le scope autorise du programme.
------------------------------------------------------------------------
""")
    p.add_argument("domain", nargs="?", help="Domaine racine (ex: example.com)")
    p.add_argument("--ports", action="store_true", help="Ajouter le scan de ports (naabu)")
    p.add_argument("--no-nuclei", action="store_true", help="Ne pas lancer nuclei")
    p.add_argument("--no-urls", action="store_true", help="Ne pas collecter les URLs")
    p.add_argument("--passive-only", action="store_true",
                   help="Seulement sous-domaines + hotes vivants")
    p.add_argument("--amass", action="store_true", help="Ajouter amass (plus complet, plus lent)")
    p.add_argument("--brute", metavar="WORDLIST", help="Bruteforce DNS (via recon.py)")
    p.add_argument("--deep", action="store_true", help="Mode complet (amass + ports + urls + nuclei)")
    p.add_argument("--severity", default="high,critical",
                   help="Severites nuclei (defaut high,critical - le reste = bruit/lent)")
    p.add_argument("--nuclei-timeout", type=int, default=900, help="Timeout global nuclei en s")
    p.add_argument("--nuclei-rl", type=int, default=50, help="Rate limit nuclei req/s")
    p.add_argument("--nuclei-conc", type=int, default=25, help="Concurrence nuclei")
    p.add_argument("-t", "--threads", type=int, default=100, help="Threads (repli python)")
    p.add_argument("--timeout", type=float, default=8, help="Timeout HTTP (repli python)")
    p.add_argument("-o", "--output", default="results", help="Dossier de sortie (defaut results/)")
    args = p.parse_args()

    print(BANNER)
    if not args.domain:
        p.print_help(); sys.exit(0)

    if args.deep:
        args.amass = True; args.ports = True

    import re
    domain = re.sub(r"^https?://", "", args.domain.strip().lower()).strip("/").split("/")[0]
    outdir = os.path.join(args.output, domain)
    os.makedirs(outdir, exist_ok=True)
    start = time.time()

    log(f"{C.GR}[i] Cible : {domain} | sortie : {outdir}/{C.X}")
    tools = [t for t in ("subfinder", "assetfinder", "amass", "httpx", "naabu",
                         "gau", "waybackurls", "katana", "nuclei") if have(t)]
    log(f"{C.GR}[i] Outils detectes : {', '.join(tools) if tools else 'aucun (repli pur-python)'}{C.X}")

    subs_file = stage_subdomains(domain, outdir, args)
    live_file, info_file = stage_live(subs_file, outdir, args)

    if not args.passive_only:
        if args.ports:
            stage_ports(subs_file, outdir, args)
        if not args.no_urls:
            stage_urls(domain, live_file, outdir, args)
        if not args.no_nuclei:
            stage_nuclei(live_file, outdir, args)

    # Recap
    stage("RECAP")
    for name, fn in (("Sous-domaines", "subdomains.txt"), ("Hotes vivants", "live.txt"),
                     ("Ports", "ports.txt"), ("URLs", "urls.txt"),
                     ("URLs interessantes", "urls_interessantes.txt"),
                     ("Vulns nuclei", "nuclei.txt")):
        path = os.path.join(outdir, fn)
        if os.path.isfile(path):
            n = len(read_lines(path))
            col = C.G if n else C.GR
            log(f"  {col}{name:<22}{C.X} {n:>6}   {C.GR}{path}{C.X}")
    log(f"\n{C.GR}Termine en {time.time()-start:.1f}s{C.X}")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        log(f"\n{C.Rd}[!] Interrompu.{C.X}")
