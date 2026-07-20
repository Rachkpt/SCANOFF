#!/usr/bin/env python3
"""
takeover.py - Detection de subdomain takeover (bug bounty)
==========================================================
Un "subdomain takeover" arrive quand un sous-domaine pointe (CNAME) vers un
service tiers (S3, GitHub Pages, Heroku, Azure, Shopify...) qui n'existe plus
ou n'a jamais ete reclame. Un attaquant peut alors reclamer la ressource et
prendre le controle du sous-domaine. Bug a fort impact, souvent paye.

Comment il detecte :
  1. Resout le CNAME du sous-domaine (dnspython si dispo, sinon socket)
  2. Recupere la reponse HTTP
  3. Croise : CNAME vers un service connu  +  empreinte d'erreur (page
     "NoSuchBucket", "There isn't a GitHub Pages site here", "No such app"...)
  4. Signale les CNAME orphelins (NXDOMAIN) vers un service = takeover probable

Entrees :
    python takeover.py sub.example.com
    python takeover.py -l subdomains.txt          (sortie de recon.py !)
    cat results/example.com/subdomains.txt | python takeover.py

[!] Bug bounty AUTORISE uniquement : ne reclame JAMAIS une ressource hors scope.
"""

import argparse
import json
import os
import re
import socket
import ssl
import sys
import time
import http.client
from urllib.parse import urljoin
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
UA = "Mozilla/5.0 (X11; Linux x86_64) takeover/1.0"

try:
    import dns.resolver
    HAS_DNS = True
except Exception:
    HAS_DNS = False

# ----------------------------------------------------------------------
# Base d'empreintes (d'apres can-i-take-over-xyz / subjack)
#   cname        : motifs de CNAME du service
#   fingerprint  : chaines presentes dans la page si la ressource est libre
#   vuln         : True = takeover confirme possible, False = cas limite
# ----------------------------------------------------------------------
FINGERPRINTS = [
    {"service": "GitHub Pages", "cname": ["github.io"],
     "fingerprint": ["There isn't a GitHub Pages site here.",
                     "For root URLs (like http://example.com/) you must provide an index.html file"],
     "vuln": True},
    {"service": "AWS/S3", "cname": ["s3.amazonaws.com", "s3-website", ".s3."],
     "fingerprint": ["The specified bucket does not exist", "NoSuchBucket"], "vuln": True},
    {"service": "Heroku", "cname": ["herokuapp.com", "herokudns.com", "herokussl.com"],
     "fingerprint": ["No such app", "herokucdn.com/error-pages/no-such-app.html"], "vuln": True},
    {"service": "Shopify", "cname": ["myshopify.com"],
     "fingerprint": ["Sorry, this shop is currently unavailable"], "vuln": False},
    {"service": "Fastly", "cname": ["fastly.net"],
     "fingerprint": ["Fastly error: unknown domain"], "vuln": False},
    {"service": "Ghost", "cname": ["ghost.io"],
     "fingerprint": ["The thing you were looking for is no longer here", "Domain error"], "vuln": True},
    {"service": "Pantheon", "cname": ["pantheonsite.io"],
     "fingerprint": ["The gods are wise, but do not know of the site which you seek"], "vuln": True},
    {"service": "Tumblr", "cname": ["domains.tumblr.com"],
     "fingerprint": ["Whatever you were looking for doesn't currently exist at this address",
                     "There's nothing here."], "vuln": True},
    {"service": "WordPress", "cname": ["wordpress.com"],
     "fingerprint": ["Do you want to register"], "vuln": False},
    {"service": "Bitbucket", "cname": ["bitbucket.io"],
     "fingerprint": ["Repository not found"], "vuln": True},
    {"service": "Zendesk", "cname": ["zendesk.com"],
     "fingerprint": ["Help Center Closed"], "vuln": False},
    {"service": "Surge.sh", "cname": ["surge.sh"],
     "fingerprint": ["project not found"], "vuln": True},
    {"service": "Webflow", "cname": ["proxy.webflow.com", "proxy-ssl.webflow.com"],
     "fingerprint": ["The page you are looking for doesn't exist or has been moved"], "vuln": True},
    {"service": "Readme.io", "cname": ["readme.io"],
     "fingerprint": ["Project doesnt exist... yet!"], "vuln": True},
    {"service": "HelpScout", "cname": ["helpscoutdocs.com"],
     "fingerprint": ["No settings were found for this company:"], "vuln": True},
    {"service": "Helpjuice", "cname": ["helpjuice.com"],
     "fingerprint": ["We could not find what you're looking for."], "vuln": True},
    {"service": "Aftership", "cname": ["aftership.com"],
     "fingerprint": ["Oops.</h2><p class=\"text-muted text-tight\">The page you're looking for doesn't exist."], "vuln": True},
    {"service": "Aha!", "cname": ["ideas.aha.io"],
     "fingerprint": ["There is no portal here ... sending you back to Aha!"], "vuln": True},
    {"service": "Bigcartel", "cname": ["bigcartel.com"],
     "fingerprint": ["<h1>Oops! We couldn&#8217;t find that page.</h1>"], "vuln": True},
    {"service": "Campaign Monitor", "cname": ["createsend.com"],
     "fingerprint": ["Trying to access your account?"], "vuln": False},
    {"service": "Feedpress", "cname": ["redirect.feedpress.me"],
     "fingerprint": ["The feed has not been found."], "vuln": True},
    {"service": "Ngrok", "cname": ["ngrok.io"],
     "fingerprint": ["Tunnel", "not found"], "vuln": True},
    {"service": "Strikingly", "cname": ["s.strikinglydns.com"],
     "fingerprint": ["But if you're looking to build your own website,"], "vuln": True},
    {"service": "Teamwork", "cname": ["teamwork.com"],
     "fingerprint": ["Oops - We didn't find your site."], "vuln": True},
    {"service": "Thinkific", "cname": ["thinkific.com"],
     "fingerprint": ["You may have mistyped the address or the page may have moved."], "vuln": True},
    {"service": "Intercom", "cname": ["custom.intercom.help"],
     "fingerprint": ["This page is reserved for artistic dogs.",
                     "Uh oh. That page doesn't exist."], "vuln": True},
    {"service": "JetBrains", "cname": ["myjetbrains.com"],
     "fingerprint": ["is not a registered InCloud YouTrack."], "vuln": True},
    {"service": "LaunchRock", "cname": ["launchrock.com"],
     "fingerprint": ["It looks like you may have taken a wrong turn somewhere."], "vuln": True},
    {"service": "Wishpond", "cname": ["wishpond.com"],
     "fingerprint": ["https://www.wishpond.com/404?"], "vuln": True},
    {"service": "Getresponse", "cname": [".gr8.com"],
     "fingerprint": ["With GetResponse Landing Pages, lead generation has never been easier"], "vuln": True},
    {"service": "Azure", "cname": ["azurewebsites.net", "cloudapp.net", "cloudapp.azure.com",
                                   "trafficmanager.net", "blob.core.windows.net", "azure-api.net",
                                   "azureedge.net", "azurecontainer.io", "azurecr.io"],
     "fingerprint": ["404 Web Site not found"], "vuln": True},
]

# ----------------------------------------------------------------------
# DNS : CNAME + resolution
# ----------------------------------------------------------------------
def get_cnames(host):
    cnames = []
    resolves = True
    nxdomain = False
    if HAS_DNS:
        try:
            ans = dns.resolver.resolve(host, "CNAME")
            cnames = [str(r.target).rstrip(".").lower() for r in ans]
        except dns.resolver.NXDOMAIN:
            nxdomain = True
        except Exception:
            pass
    # resolution A (et recup des alias si pas de dnspython)
    try:
        name, aliases, ips = socket.gethostbyname_ex(host)
        for a in aliases:
            a = a.rstrip(".").lower()
            if a != host.lower() and a not in cnames:
                cnames.append(a)
    except socket.gaierror as e:
        resolves = False
        if "not known" in str(e).lower() or getattr(e, "errno", None) in (11001, -2, -3, -5):
            nxdomain = True
    except Exception:
        resolves = False
    return cnames, resolves, nxdomain

# ----------------------------------------------------------------------
# HTTP
# ----------------------------------------------------------------------
def fetch(url, timeout=10, max_body=200000, redirects=2):
    for _ in range(redirects + 1):
        try:
            from urllib.parse import urlparse
            u = urlparse(url)
            host = u.hostname
            port = u.port or (443 if u.scheme == "https" else 80)
            path = (u.path or "/")
            if u.scheme == "https":
                conn = http.client.HTTPSConnection(host, port, timeout=timeout,
                                                   context=ssl._create_unverified_context())
            else:
                conn = http.client.HTTPConnection(host, port, timeout=timeout)
            conn.request("GET", path, headers={"User-Agent": UA, "Accept": "*/*"})
            r = conn.getresponse()
            if r.status in (301, 302, 303, 307, 308) and r.getheader("Location"):
                loc = r.getheader("Location"); conn.close()
                url = urljoin(url, loc); continue
            body = r.read(max_body).decode("utf-8", "ignore")
            conn.close()
            return body
        except Exception:
            return ""
    return ""

# ----------------------------------------------------------------------
# Analyse d'un sous-domaine
# ----------------------------------------------------------------------
def check_host(host, timeout):
    host = host.strip().lower()
    host = re.sub(r"^https?://", "", host).split("/")[0].split(":")[0]
    if not host:
        return None
    cnames, resolves, nxdomain = get_cnames(host)
    body = ""
    if resolves:
        body = fetch(f"http://{host}", timeout=timeout) or fetch(f"https://{host}", timeout=timeout)

    for svc in FINGERPRINTS:
        cname_hit = any(pat in c for c in cnames for pat in svc["cname"])
        fp_hit = body and all_present(body, svc["fingerprint"]) if body else False
        # 1) CNAME + empreinte -> takeover quasi certain
        if cname_hit and fp_hit:
            return {"host": host, "service": svc["service"], "cname": cnames,
                    "confidence": "HAUTE", "reason": "CNAME + empreinte",
                    "vuln": svc["vuln"]}
        # 2) empreinte seule -> probable
        if fp_hit and not cname_hit:
            return {"host": host, "service": svc["service"], "cname": cnames,
                    "confidence": "MOYENNE", "reason": "empreinte (CNAME non confirme)",
                    "vuln": svc["vuln"]}
        # 3) CNAME vers le service + domaine orphelin (NXDOMAIN) -> probable
        if cname_hit and nxdomain:
            return {"host": host, "service": svc["service"], "cname": cnames,
                    "confidence": "HAUTE", "reason": "CNAME orphelin (NXDOMAIN)",
                    "vuln": svc["vuln"]}
    return None

def all_present(body, fps):
    """True si AU MOINS une empreinte du service est presente."""
    return any(fp in body for fp in fps)

# ----------------------------------------------------------------------
# Entrees
# ----------------------------------------------------------------------
def gather(args):
    hosts = []
    if args.list:
        try:
            with open(args.list, encoding="utf-8", errors="ignore") as f:
                hosts = [l.strip() for l in f if l.strip() and not l.startswith("#")]
        except Exception as e:
            log(f"{C.R}[!] Liste illisible : {e}{C.X}")
    elif args.host:
        hosts = [args.host]
    elif not sys.stdin.isatty():
        hosts = [l.strip() for l in sys.stdin if l.strip()]
    return sorted(set(hosts))

def main():
    p = argparse.ArgumentParser(
        description="takeover.py - detection de subdomain takeover",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
------------------------------------------------------------------------
 GUIDE
------------------------------------------------------------------------
 Un seul sous-domaine :
    python takeover.py assets.example.com

 Une liste (la sortie de recon.py !) :
    python takeover.py -l results/example.com/subdomains.txt -o takeover

 Chaine directe depuis recon.py :
    python recon.py example.com | ...   (ou via le fichier subdomains.txt)
    cat subdomains.txt | python takeover.py

 Astuce : installe dnspython pour une detection CNAME plus fiable
          (pip install dnspython)

 EXEMPLE COMPLET (apres recon.py ou hunt.py) :
    python takeover.py -l results/cible.com/subdomains.txt -o takeover
        # -> teste chaque sous-domaine contre 31 services (S3, GitHub, Azure...)
        #    et signale [TAKEOVER PROBABLE] les CNAME orphelins/non reclames
    # Resultat: si "PROBABLE" -> verifie manuellement, puis reporte (fort impact).

 [!] Ne reclame JAMAIS une ressource hors scope. Signale, c'est tout.
------------------------------------------------------------------------
""")
    p.add_argument("host", nargs="?", help="Un sous-domaine a tester")
    p.add_argument("-l", "--list", help="Fichier de sous-domaines")
    p.add_argument("-t", "--threads", type=int, default=40, help="Threads (defaut 40)")
    p.add_argument("--timeout", type=float, default=10, help="Timeout HTTP (defaut 10)")
    p.add_argument("-o", "--output", help="Nom de base du rapport (.txt .json)")
    args = p.parse_args()

    print(f"{C.CY}{C.BD}\n  takeover.py  -  detection de subdomain takeover{C.X}")
    print(f"{C.Y}  by 12akHack{C.GR}  -  outil de securite offensive{C.X}")
    print(f"{C.R}  [!] Bug bounty AUTORISE uniquement : ne reclame JAMAIS hors scope.{C.X}")
    log(f"{C.GR}  {len(FINGERPRINTS)} services surveilles | dnspython : "
        f"{'oui' if HAS_DNS else 'non (socket)'}{C.X}\n")

    if not args.host and not args.list and sys.stdin.isatty():
        p.print_help(); sys.exit(0)

    hosts = gather(args)
    if not hosts:
        log(f"{C.R}[!] Aucun sous-domaine fourni.{C.X}"); sys.exit(0)

    log(f"{C.B}{C.BD}[*] Analyse de {len(hosts)} sous-domaine(s)...{C.X}")
    start = time.time()
    findings, done = [], [0]

    with ThreadPoolExecutor(max_workers=args.threads) as ex:
        futs = [ex.submit(check_host, h, args.timeout) for h in hosts]
        for fu in as_completed(futs):
            done[0] += 1
            if done[0] % 20 == 0 or done[0] == len(hosts):
                sys.stdout.write(f"\r{C.GR}    {done[0]}/{len(hosts)}{C.X}"); sys.stdout.flush()
            r = fu.result()
            if r:
                findings.append(r)
    print()

    log(f"\n{C.B}{C.BD}{'='*66}{C.X}")
    log(f"{C.B}{C.BD}  RESULTATS{C.X}")
    log(f"{C.B}{C.BD}{'='*66}{C.X}")
    if not findings:
        log(f"  {C.G}Aucun subdomain takeover detecte.{C.X}")
    for f in sorted(findings, key=lambda x: (not x["vuln"], x["host"])):
        col = C.R if f["vuln"] else C.Y
        badge = f"{C.R}{C.BD}[TAKEOVER PROBABLE]{C.X}" if f["vuln"] else f"{C.Y}[A VERIFIER]{C.X}"
        log(f"\n  {badge} {C.BD}{f['host']}{C.X}")
        log(f"    {col}Service :{C.X} {f['service']}  {C.GR}(confiance {f['confidence']}, {f['reason']}){C.X}")
        if f["cname"]:
            log(f"    {C.GR}CNAME : {', '.join(f['cname'])}{C.X}")

    vuln_n = sum(1 for f in findings if f["vuln"])
    log(f"\n{C.GR}Termine en {time.time()-start:.1f}s | "
        f"{len(findings)} signalement(s), dont {vuln_n} probable(s){C.X}")

    if args.output:
        b = args.output.rsplit(".", 1)[0]
        with open(b + ".json", "w", encoding="utf-8") as f:
            json.dump(findings, f, indent=2, ensure_ascii=False)
        with open(b + ".txt", "w", encoding="utf-8") as f:
            for it in findings:
                f.write(f"[{'PROBABLE' if it['vuln'] else 'A VERIFIER'}] {it['host']} "
                        f"-> {it['service']} ({it['confidence']}, {it['reason']}) "
                        f"CNAME={','.join(it['cname'])}\n")
        log(f"{C.G}[+] Rapport : {b}.txt / {b}.json{C.X}")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        log(f"\n{C.R}[!] Interrompu.{C.X}")
