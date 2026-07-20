#!/usr/bin/env python3
"""
recon.py - Enumeration de sous-domaines pour bug bounty
=======================================================
La fondation de toute recon BB : trouve un MAXIMUM de sous-domaines,
garde ceux qui vivent, et les fingerprint.

Sources PASSIVES (gratuites, sans cle API) interrogees en parallele :
  crt.sh, HackerTarget, CertSpotter, RapidDNS, AlienVault OTX, Anubis(jldc),
  ThreatCrowd, urlscan.io
Optionnel :
  --brute   bruteforce DNS avec une wordlist
  --http    sonde HTTP (statut, titre, serveur, techno) des sous-domaines vivants

Usage :
    python recon.py example.com
    python recon.py example.com --http -o resultats
    python recon.py example.com --brute /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt --http

[!] Bug bounty AUTORISE uniquement : reste STRICTEMENT dans le scope du programme.
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
import html as html_mod
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

# Signatures de pages de challenge / blocage WAF (un "403" ou "200" ici n'est
# PAS un vrai refus applicatif : c'est le WAF qui bloque notre requete non-navigateur)
WAF_SIGNS = (
    ("Just a moment", "Cloudflare (JS challenge)"),
    ("Attention Required! | Cloudflare", "Cloudflare (block)"),
    ("Enable JavaScript and cookies to continue", "Cloudflare (challenge)"),
    ("cf-browser-verification", "Cloudflare (challenge)"),
    ("challenge-platform", "Cloudflare (challenge)"),
    ("Checking if the site connection is secure", "Cloudflare (challenge)"),
    ("Request unsuccessful. Incapsula", "Imperva Incapsula"),
    ("_Incapsula_Resource", "Imperva Incapsula"),
    ("Access Denied", "Akamai/WAF"),
    ("Reference #", "Akamai (block)"),
    ("Pardon Our Interruption", "PerimeterX"),
    ("px-captcha", "PerimeterX"),
    ("<title>Just a moment...</title>", "Cloudflare (challenge)"),
)

def detect_waf(status, hdrs, text):
    """Renvoie une etiquette WAF si la reponse est un challenge/block, sinon ''."""
    if hdrs.get("cf-mitigated", "").lower() == "challenge":
        return "Cloudflare (cf-mitigated)"
    low = text[:4000]
    for sign, label in WAF_SIGNS:
        if sign in low:
            return label
    return ""

# ----------------------------------------------------------------------
# HTTP GET generique (via http.client, SSL non verifie)
# ----------------------------------------------------------------------
def http_get(url, timeout=15, max_body=3_000_000):
    try:
        u = urlparse(url)
        host = u.hostname
        port = u.port or (443 if u.scheme == "https" else 80)
        path = (u.path or "/") + (("?" + u.query) if u.query else "")
        if u.scheme == "https":
            conn = http.client.HTTPSConnection(host, port, timeout=timeout,
                                               context=ssl._create_unverified_context())
        else:
            conn = http.client.HTTPConnection(host, port, timeout=timeout)
        _h = {"User-Agent": UA, "Accept": "*/*"}
        _h.update(EXTRA_HEADERS)
        conn.request("GET", path, headers=_h)
        r = conn.getresponse()
        body = r.read(max_body)
        status = r.status
        hdrs = {k.lower(): v for k, v in r.getheaders()}
        conn.close()
        return status, hdrs, body
    except Exception:
        return None, {}, b""

def clean_sub(name, domain):
    name = name.strip().lower().lstrip(".").strip("*.")
    name = name.replace("https://", "").replace("http://", "").split("/")[0].split(":")[0]
    if name.endswith(domain) and re.match(r"^[a-z0-9._-]+$", name):
        return name
    return None

# ----------------------------------------------------------------------
# Sources passives
# ----------------------------------------------------------------------
def src_crtsh(domain):
    out = set()
    st, _, body = http_get(f"https://crt.sh/?q=%25.{quote(domain)}&output=json")
    if st == 200:
        try:
            for item in json.loads(body.decode("utf-8", "ignore")):
                for n in str(item.get("name_value", "")).split("\n"):
                    s = clean_sub(n, domain)
                    if s: out.add(s)
        except Exception:
            pass
    return out

def src_hackertarget(domain):
    out = set()
    st, _, body = http_get(f"https://api.hackertarget.com/hostsearch/?q={quote(domain)}")
    if st == 200:
        for line in body.decode("utf-8", "ignore").splitlines():
            s = clean_sub(line.split(",")[0], domain)
            if s: out.add(s)
    return out

def src_certspotter(domain):
    out = set()
    st, _, body = http_get(f"https://api.certspotter.com/v1/issuances?domain={quote(domain)}"
                           f"&include_subdomains=true&expand=dns_names")
    if st == 200:
        try:
            for item in json.loads(body.decode("utf-8", "ignore")):
                for n in item.get("dns_names", []):
                    s = clean_sub(n, domain)
                    if s: out.add(s)
        except Exception:
            pass
    return out

def src_rapiddns(domain):
    out = set()
    st, _, body = http_get(f"https://rapiddns.io/subdomain/{quote(domain)}?full=1")
    if st == 200:
        for m in re.findall(r"<td>([a-z0-9._-]+\." + re.escape(domain) + r")</td>",
                            body.decode("utf-8", "ignore"), re.I):
            s = clean_sub(m, domain)
            if s: out.add(s)
    return out

def src_otx(domain):
    out = set()
    st, _, body = http_get(f"https://otx.alienvault.com/api/v1/indicators/domain/"
                           f"{quote(domain)}/passive_dns")
    if st == 200:
        try:
            for item in json.loads(body.decode("utf-8", "ignore")).get("passive_dns", []):
                s = clean_sub(item.get("hostname", ""), domain)
                if s: out.add(s)
        except Exception:
            pass
    return out

def src_anubis(domain):
    out = set()
    st, _, body = http_get(f"https://jldc.me/anubis/subdomains/{quote(domain)}")
    if st == 200:
        try:
            for n in json.loads(body.decode("utf-8", "ignore")):
                s = clean_sub(n, domain)
                if s: out.add(s)
        except Exception:
            pass
    return out

def src_threatcrowd(domain):
    out = set()
    st, _, body = http_get(f"https://ci-www.threatcrowd.org/searchApi/v2/domain/report/"
                           f"?domain={quote(domain)}")
    if st == 200:
        try:
            for n in json.loads(body.decode("utf-8", "ignore")).get("subdomains", []):
                s = clean_sub(n, domain)
                if s: out.add(s)
        except Exception:
            pass
    return out

def src_urlscan(domain):
    out = set()
    st, _, body = http_get(f"https://urlscan.io/api/v1/search/?q=domain:{quote(domain)}&size=1000")
    if st == 200:
        try:
            for item in json.loads(body.decode("utf-8", "ignore")).get("results", []):
                page = item.get("page", {})
                s = clean_sub(page.get("domain", ""), domain)
                if s: out.add(s)
        except Exception:
            pass
    return out

SOURCES = {
    "crt.sh": src_crtsh, "HackerTarget": src_hackertarget,
    "CertSpotter": src_certspotter, "RapidDNS": src_rapiddns,
    "AlienVault": src_otx, "Anubis": src_anubis,
    "ThreatCrowd": src_threatcrowd, "urlscan.io": src_urlscan,
}

def passive_enum(domain):
    log(f"\n{C.B}{C.BD}[*] Sources passives ({len(SOURCES)})...{C.X}")
    found = set()
    with ThreadPoolExecutor(max_workers=len(SOURCES)) as ex:
        futs = {ex.submit(fn, domain): name for name, fn in SOURCES.items()}
        for fu in as_completed(futs):
            name = futs[fu]
            try:
                res = fu.result()
            except Exception:
                res = set()
            found |= res
            col = C.G if res else C.GR
            log(f"    {col}{name:<14}{C.X} {len(res)} sous-domaine(s)")
    return found

# ----------------------------------------------------------------------
# Bruteforce DNS
# ----------------------------------------------------------------------
def dns_brute(domain, wordlist, threads=100):
    words = []
    try:
        with open(wordlist, encoding="utf-8", errors="ignore") as f:
            for line in f:
                w = line.strip().lower()
                if w and not w.startswith("#"):
                    words.append(w)
    except Exception as e:
        log(f"{C.R}[!] Wordlist illisible : {e}{C.X}")
        return set()
    log(f"\n{C.B}{C.BD}[*] Bruteforce DNS ({len(words)} mots)...{C.X}")
    found, done = set(), [0]

    def check(w):
        host = f"{w}.{domain}"
        try:
            socket.gethostbyname(host)
            return host
        except Exception:
            return None

    with ThreadPoolExecutor(max_workers=threads) as ex:
        for fu in as_completed([ex.submit(check, w) for w in words]):
            done[0] += 1
            if done[0] % 200 == 0:
                sys.stdout.write(f"\r{C.GR}    {done[0]}/{len(words)}{C.X}"); sys.stdout.flush()
            r = fu.result()
            if r: found.add(r)
    print()
    log(f"{C.G}[+] Bruteforce : {len(found)} trouve(s).{C.X}")
    return found

# ----------------------------------------------------------------------
# Resolution
# ----------------------------------------------------------------------
def resolve_all(subs, threads=100):
    log(f"\n{C.B}{C.BD}[*] Resolution DNS ({len(subs)} sous-domaines)...{C.X}")
    live = {}

    def resolve(s):
        try:
            return s, socket.gethostbyname(s)
        except Exception:
            return s, None

    with ThreadPoolExecutor(max_workers=threads) as ex:
        for fu in as_completed([ex.submit(resolve, s) for s in subs]):
            s, ip = fu.result()
            if ip:
                live[s] = ip
    log(f"{C.G}[+] {len(live)} sous-domaine(s) resolvent.{C.X}")
    return live

# ----------------------------------------------------------------------
# Sonde HTTP + fingerprint
# ----------------------------------------------------------------------
def http_probe(sub, timeout=8):
    for scheme in ("https", "http"):
        st, hdrs, body = http_get(f"{scheme}://{sub}", timeout=timeout, max_body=60000)
        if st is None:
            continue
        text = body.decode("utf-8", "ignore")
        title = ""
        m = re.search(r"<title[^>]*>(.*?)</title>", text, re.I | re.S)
        if m:
            title = re.sub(r"\s+", " ", m.group(1)).strip()[:70]
        techno = []
        server = hdrs.get("server", "")
        powered = hdrs.get("x-powered-by", "")
        low = text.lower()
        if "wp-content" in low or "wordpress" in low: techno.append("WordPress")
        if "drupal" in low: techno.append("Drupal")
        if "joomla" in low: techno.append("Joomla")
        if "cloudflare" in server.lower(): techno.append("Cloudflare")
        waf = detect_waf(st, hdrs, text)
        cl = hdrs.get("content-length")
        return {"url": f"{scheme}://{sub}", "status": st, "title": title,
                "server": server, "powered": powered, "waf": waf,
                "techno": techno, "length": int(cl) if cl and cl.isdigit() else len(body)}
    return None

def probe_all(live, threads=40, timeout=8):
    log(f"\n{C.B}{C.BD}[*] Sonde HTTP ({len(live)} hotes)...{C.X}")
    results = []
    with ThreadPoolExecutor(max_workers=threads) as ex:
        futs = {ex.submit(http_probe, s, timeout): s for s in live}
        for fu in as_completed(futs):
            r = fu.result()
            if r:
                r["ip"] = live[futs[fu]]
                results.append(r)
    return sorted(results, key=lambda x: x["url"])

def color_status(st):
    if 200 <= st < 300: return C.G
    if 300 <= st < 400: return C.CY
    if 400 <= st < 500: return C.Y
    return C.R

# ----------------------------------------------------------------------
# Export
# ----------------------------------------------------------------------
def save_outputs(domain, live, probes, base):
    b = base.rsplit(".", 1)[0]
    with open(b + "_subs.txt", "w", encoding="utf-8") as f:
        f.write("\n".join(sorted(live)) + "\n")
    data = {"domain": domain, "count": len(live),
            "subdomains": [{"host": h, "ip": ip} for h, ip in sorted(live.items())],
            "http": probes}
    with open(b + ".json", "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
    if probes:
        rows = "".join(
            f"<tr><td class=s{p['status']//100}>{p['status']}</td>"
            f"<td><a href='{html_mod.escape(p['url'])}'>{html_mod.escape(p['url'])}</a></td>"
            f"<td>{p['ip']}</td><td>{html_mod.escape(p['title'])}</td>"
            f"<td>{html_mod.escape(p['server'])} {html_mod.escape(' '.join(p['techno']))}</td></tr>"
            for p in probes)
        doc = f"""<!doctype html><meta charset=utf-8><title>recon {html_mod.escape(domain)}</title>
<style>body{{font-family:monospace;background:#0d1117;color:#c9d1d9;padding:20px}}
h1{{color:#58a6ff}}table{{border-collapse:collapse;width:100%}}
td,th{{border:1px solid #30363d;padding:6px 10px;text-align:left}}a{{color:#79c0ff}}
.s2{{color:#3fb950;font-weight:bold}}.s3{{color:#58a6ff}}.s4{{color:#d29922}}.s5{{color:#f85149}}</style>
<h1>recon - {html_mod.escape(domain)} ({len(live)} sous-domaines, {len(probes)} vivants)</h1>
<table><tr><th>Code</th><th>URL</th><th>IP</th><th>Titre</th><th>Serveur/Techno</th></tr>{rows}</table>"""
        with open(b + ".html", "w", encoding="utf-8") as f:
            f.write(doc)
    log(f"\n{C.G}[+] Sauvegarde : {b}_subs.txt / {b}.json"
        f"{' / ' + b + '.html' if probes else ''}{C.X}")

# ----------------------------------------------------------------------
BANNER = f"""{C.CY}{C.BD}
  recon.py  -  enumeration de sous-domaines (bug bounty){C.X}
{C.GR}  8 sources passives + brute DNS + sonde HTTP{C.X}
{C.Y}  by 12akHack{C.GR}  -  outil de securite offensive{C.X}
{C.R}  [!] Bug bounty AUTORISE uniquement : reste STRICTEMENT dans le scope.{C.X}
"""

def main():
    p = argparse.ArgumentParser(
        description="recon.py - enumeration de sous-domaines pour bug bounty",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
------------------------------------------------------------------------
 GUIDE
------------------------------------------------------------------------
 Passif seulement (rapide, discret) :
    python recon.py example.com

 Passif + sonde HTTP (statut, titre, techno) + rapports :
    python recon.py example.com --http -o resultats

 Passif + bruteforce DNS + HTTP (couverture max) :
    python recon.py example.com --http \\
      --brute /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt

 EXEMPLE COMPLET (bug bounty, 1re etape) :
    python recon.py cible.com
        # -> passif seulement (OSINT, ne touche pas leurs serveurs).
        #    TU FILTRES selon le scope autorise avant d'aller plus loin.
    python recon.py cible.com --http -o resultats
        # -> + sonde HTTP (statut, titre, techno) + rapports
    # Ensuite: donne resultats_subs.txt a takeover.py et hunt.py.

 /!\\ Reste STRICTEMENT dans le scope autorise du programme bug bounty.
------------------------------------------------------------------------
""")
    p.add_argument("domain", nargs="?", help="Domaine racine (ex: example.com)")
    p.add_argument("--brute", metavar="WORDLIST", help="Bruteforce DNS avec cette wordlist")
    p.add_argument("--http", action="store_true", help="Sonder les sous-domaines vivants en HTTP")
    p.add_argument("--no-resolve", action="store_true", help="Ne pas resoudre (garder tout le passif brut)")
    p.add_argument("-t", "--threads", type=int, default=100, help="Threads DNS (defaut 100)")
    p.add_argument("--timeout", type=float, default=8, help="Timeout HTTP (defaut 8)")
    p.add_argument("-H", "--header", action="append", default=[],
                   help="Header custom 'Nom: valeur' (repetable, ex: X-HackerOne-Research)")
    p.add_argument("-o", "--output", help="Nom de base des rapports (.txt .json .html)")
    args = p.parse_args()

    print(BANNER)
    if not args.domain:
        p.print_help(); sys.exit(0)

    for hv in args.header:
        if ":" in hv:
            k, v = hv.split(":", 1)
            EXTRA_HEADERS[k.strip()] = v.strip()

    domain = args.domain.strip().lower().strip("/")
    domain = re.sub(r"^https?://", "", domain).split("/")[0]
    start = time.time()

    subs = passive_enum(domain)
    subs.add(domain)
    if args.brute:
        subs |= dns_brute(domain, args.brute, args.threads)
    log(f"\n{C.CY}{C.BD}[=] Total unique (passif+brute) : {len(subs)}{C.X}")

    if args.no_resolve:
        live = {s: "?" for s in subs}
    else:
        live = resolve_all(subs, args.threads)

    probes = []
    if args.http and live:
        probes = probe_all(live, threads=min(40, args.threads), timeout=args.timeout)
        log(f"\n{C.B}{C.BD}{'='*70}{C.X}")
        log(f"{C.B}{C.BD}  HOTES VIVANTS ({len(probes)}){C.X}")
        log(f"{C.B}{C.BD}{'='*70}{C.X}")
        n_waf = sum(1 for p in probes if p.get("waf"))
        for pr in probes:
            t = f"{C.GR}{pr['title']}{C.X}" if pr["title"] else ""
            tech = f" {C.CY}{'/'.join(pr['techno'])}{C.X}" if pr["techno"] else ""
            srv = f" {C.GR}[{pr['server']}]{C.X}" if pr["server"] else ""
            # un challenge WAF n'est pas un vrai statut applicatif -> on le signale
            waf = f" {C.R}{C.BD}[WAF: {pr['waf']}]{C.X}" if pr.get("waf") else ""
            log(f"  {color_status(pr['status'])}{pr['status']}{C.X} "
                f"{pr['url']:<45} {t}{srv}{tech}{waf}")
        if n_waf:
            log(f"\n{C.R}  [i] {n_waf} hote(s) derriere un challenge WAF : leur code "
                f"(403/503/200) n'est PAS le vrai statut applicatif.{C.X}")
            log(f"{C.GR}      -> a revisiter avec un navigateur reel (challenge JS) "
                f"ou via l'origine si elle fuite.{C.X}")
    else:
        log(f"\n{C.B}{C.BD}[=] Sous-domaines resolvant :{C.X}")
        for s in sorted(live):
            ipx = f" {C.GR}-> {live[s]}{C.X}" if live[s] != "?" else ""
            log(f"  {C.G}{s}{C.X}{ipx}")

    log(f"\n{C.GR}Termine en {time.time()-start:.1f}s | "
        f"{len(subs)} trouves, {len(live)} vivants{C.X}")

    if args.output:
        save_outputs(domain, live, probes, args.output)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        log(f"\n{C.R}[!] Interrompu.{C.X}")
