#!/usr/bin/env python3
"""
ReconX - Scanner d'enumeration reseau tout-en-un (moteur asyncio)
=================================================================
Trouve TOUS les hotes actifs d'un reseau et les enumere de A a Z :
  - Decouverte multi-methodes : ARP (couche 2) + ICMP + TCP ping
    -> ne rate aucun hote, meme ceux qui bloquent le ping / les ports
  - Auto-detection du reseau local (cible "auto") -> ideal VulnHub
  - Identification des VM (MAC : VMware / VirtualBox / QEMU / Hyper-V...)
  - Detection de l'OS (nmap si dispo, sinon TTL)
  - Scan TCP asyncio ultra-rapide + detection de VERSION des services
  - Scan UDP (DNS, SNMP, NTP, NetBIOS...)
  - Enumeration SMB / NetBIOS
  - Export JSON / HTML / TXT

Legal uniquement : HTB, TryHackMe, VulnHub, tes propres labs.

Exemples :
    python reconx.py auto                 (detecte et scanne ton reseau local)
    python reconx.py auto --fast          (juste : qui est actif ?)
    python reconx.py 192.168.56.0/24 -A
    python reconx.py 10.10.10.5 --full -A -o rapport
"""

import argparse
import asyncio
import ipaddress
import socket
import ssl
import struct
import subprocess
import sys
import time
import platform
import shutil
import re
import json
import html
from concurrent.futures import ThreadPoolExecutor

# ----------------------------------------------------------------------
# Couleurs
# ----------------------------------------------------------------------
class C:
    G = "\033[92m"; Y = "\033[93m"; R = "\033[91m"; B = "\033[94m"
    CY = "\033[96m"; GR = "\033[90m"; BD = "\033[1m"; X = "\033[0m"

if platform.system() == "Windows":
    try:
        import ctypes
        k = ctypes.windll.kernel32
        k.SetConsoleMode(k.GetStdHandle(-11), 7)
    except Exception:
        for a in ("G", "Y", "R", "B", "CY", "GR", "BD", "X"):
            setattr(C, a, "")

def log(m):
    print(m)

# scapy (ARP + SYN scan) -- optionnel
try:
    from scapy.all import (IP, TCP, Ether, ARP, srp, sr1,
                           conf as scapy_conf, get_if_list)
    scapy_conf.verb = 0
    SCAPY_OK = True
except Exception:
    SCAPY_OK = False

# ----------------------------------------------------------------------
# Ports & services
# ----------------------------------------------------------------------
COMMON_PORTS = [
    21, 22, 23, 25, 53, 80, 88, 110, 111, 135, 139, 143, 161, 389,
    443, 445, 464, 500, 512, 513, 514, 587, 593, 636, 873, 993, 995,
    1025, 1433, 1521, 1723, 2049, 2121, 3000, 3128, 3268, 3306, 3389,
    5000, 5060, 5432, 5900, 5985, 5986, 6379, 8000, 8008, 8080, 8081,
    8443, 8888, 9000, 9090, 9200, 10000, 27017, 49152, 49153, 49154,
]
TOP_PORTS = sorted(set(COMMON_PORTS + [
    7, 9, 13, 20, 26, 37, 79, 81, 106, 113, 119, 179, 199, 427, 543,
    544, 548, 646, 990, 1000, 1110, 1234, 1900, 2000, 2001, 2222, 4444,
    5001, 5222, 5357, 5666, 5800, 6000, 6001, 6666, 7070, 7777,
    8009, 8090, 9999, 32768, 49155, 49156, 49157,
]))
# ports pour le "TCP ping" (decouverte d'hote)
PROBE_PORTS = [80, 443, 22, 445, 3389, 135, 139, 21, 23, 3306, 8080, 53, 25, 111]

UDP_PROBES = {
    53:  b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07version\x04bind\x00\x00\x10\x00\x03",
    123: b"\x1b" + 47 * b"\0",
    161: (b"\x30\x26\x02\x01\x01\x04\x06public\xa0\x19\x02\x04\x00\x00\x00\x00"
          b"\x02\x01\x00\x02\x01\x00\x30\x0b\x30\x09\x06\x05\x2b\x06\x01\x02\x01\x05\x00"),
    137: b"\x12\x34\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x20CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\x00\x00\x21\x00\x01",
    69:  b"\x00\x01test\x00netascii\x00",
    500: b"\x00" * 8,
    1900: b"M-SEARCH * HTTP/1.1\r\nHOST:239.255.255.250:1900\r\nMAN:\"ssdp:discover\"\r\nMX:1\r\nST:ssdp:all\r\n\r\n",
}
UDP_PORTS = sorted(UDP_PROBES.keys())

SERVICES = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns", 69: "tftp",
    80: "http", 88: "kerberos", 110: "pop3", 111: "rpcbind", 123: "ntp",
    135: "msrpc", 137: "netbios-ns", 139: "netbios-ssn", 143: "imap",
    161: "snmp", 389: "ldap", 443: "https", 445: "smb", 464: "kpasswd",
    500: "isakmp", 514: "syslog", 587: "smtp-sub", 593: "rpc-http",
    636: "ldaps", 873: "rsync", 993: "imaps", 995: "pop3s", 1433: "mssql",
    1521: "oracle", 1900: "ssdp", 2049: "nfs", 3128: "squid", 3268: "gc-ldap",
    3306: "mysql", 3389: "rdp", 5432: "postgresql", 5900: "vnc",
    5985: "winrm", 5986: "winrm-ssl", 6379: "redis", 8000: "http-alt",
    8080: "http-proxy", 8443: "https-alt", 9200: "elasticsearch",
    27017: "mongodb",
}
HTTP_PORTS = {80, 81, 591, 3000, 5000, 8000, 8008, 8080, 8081, 8090, 8888, 9000, 9090, 10000}
SSL_PORTS  = {443, 993, 995, 8443, 5986, 636, 989, 990}

# Prefixes MAC (OUI) des hyperviseurs -> reperer une VM instantanement
OUI = {
    "00:0c:29": "VMware", "00:50:56": "VMware", "00:05:69": "VMware",
    "00:1c:14": "VMware", "08:00:27": "VirtualBox", "0a:00:27": "VirtualBox",
    "00:15:5d": "Hyper-V", "00:16:3e": "Xen", "52:54:00": "QEMU/KVM",
    "00:1c:42": "Parallels", "00:03:ff": "Microsoft VM",
}
def mac_vendor(mac):
    if not mac:
        return ""
    return OUI.get(mac.lower()[:8], "")

# ----------------------------------------------------------------------
# OS via TTL
# ----------------------------------------------------------------------
def guess_os_from_ttl(ttl):
    if ttl is None: return "?"
    if ttl <= 64:   return "Linux/Unix (TTL~64)"
    if ttl <= 128:  return "Windows (TTL~128)"
    return "Reseau/Cisco (TTL~255)"

def _ping_cmd(ip, timeout):
    if platform.system() == "Windows":
        return ["ping", "-n", "1", "-w", str(int(timeout * 1000)), ip]
    return ["ping", "-c", "1", "-W", str(max(1, int(timeout))), ip]

def get_ttl_from_ping(ip, timeout=1):
    try:
        out = subprocess.run(_ping_cmd(ip, timeout), capture_output=True,
                             text=True, timeout=timeout + 2)
        if out.returncode != 0:
            return None
        m = re.search(r"[Tt][Tt][Ll][=:]\s*(\d+)", out.stdout + out.stderr)
        return int(m.group(1)) if m else -1   # -1 = repond au ping mais TTL introuvable
    except Exception:
        return None

# ----------------------------------------------------------------------
# Reseau local (auto) + ARP
# ----------------------------------------------------------------------
def get_local_networks():
    """Renvoie la liste des reseaux directement connectes (cidr, ip_locale)."""
    nets = []
    if not SCAPY_OK:
        return nets
    seen = set()
    try:
        for route in scapy_conf.route.routes:
            try:
                network, netmask, gateway, iface, out_ip = route[0], route[1], route[2], route[3], route[4]
            except Exception:
                continue
            if network == 0 or netmask == 0:
                continue
            if str(out_ip).startswith("127.") or out_ip == "0.0.0.0":
                continue
            try:
                prefix = bin(netmask).count("1")
                if prefix < 22:      # on evite les reseaux enormes
                    continue
                net = ipaddress.ip_network((network, prefix), strict=False)
                if net.is_loopback or net.is_multicast or net.is_link_local:
                    continue
                if str(net) in seen:
                    continue
                seen.add(str(net))
                nets.append((str(net), str(out_ip)))
            except Exception:
                continue
    except Exception:
        pass
    return nets

def arp_scan(cidr, timeout=2):
    """Scan ARP couche 2 : renvoie {ip: mac}. Revele meme les hotes qui bloquent tout."""
    res = {}
    if not SCAPY_OK:
        return res
    try:
        ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=cidr),
                     timeout=timeout, verbose=0)
        for _, rcv in ans:
            res[rcv.psrc] = rcv.hwsrc
    except Exception:
        pass
    return res

def resolve_hostname(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return None

# ----------------------------------------------------------------------
# asyncio : TCP ping (decouverte) + scan de ports
# ----------------------------------------------------------------------
async def _connect_once(ip, port, timeout, sem):
    async with sem:
        try:
            fut = asyncio.open_connection(ip, port)
            reader, writer = await asyncio.wait_for(fut, timeout=timeout)
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
            return True
        except Exception:
            return False

async def tcp_ping_async(ip, timeout, sem):
    tasks = [_connect_once(ip, p, timeout, sem) for p in PROBE_PORTS]
    results = await asyncio.gather(*tasks)
    return ip, any(results)

async def scan_ports_async(ip, ports, timeout, sem):
    async def one(p):
        ok = await _connect_once(ip, p, timeout, sem)
        return p, ok
    results = await asyncio.gather(*[one(p) for p in ports])
    return sorted(p for p, ok in results if ok)

# SYN scan (scapy, furtif) -- alternative
def scan_ports_syn(ip, ports, timeout=1.0):
    open_ports = []
    for port in ports:
        try:
            resp = sr1(IP(dst=ip) / TCP(dport=port, flags="S"), timeout=timeout, verbose=0)
            if resp and resp.haslayer(TCP) and resp[TCP].flags == 0x12:
                sr1(IP(dst=ip) / TCP(dport=port, flags="R"), timeout=0.3, verbose=0)
                open_ports.append(port)
        except Exception:
            continue
    return sorted(open_ports)

# ----------------------------------------------------------------------
# Detection de version
# ----------------------------------------------------------------------
def parse_version(port, banner):
    if not banner:
        return ""
    for pat in (r"Server:\s*([^\r\n]+)", r"SSH-[\d.]+-([^\r\n]+)",
                r"220[- ]([^\r\n]+)", r"([\d]+\.[\d]+\.[\d]+)"):
        m = re.search(pat, banner)
        if m:
            return m.group(1).strip()[:80]
    return banner[:80]

def probe_service(ip, port, timeout=2.0):
    svc = SERVICES.get(port, "?")
    banner = ""
    if port in SSL_PORTS:
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            raw = socket.create_connection((ip, port), timeout=timeout)
            ss = ctx.wrap_socket(raw, server_hostname=ip)
            cert = ss.getpeercert()
            cn = ""
            if cert and "subject" in cert:
                for t in cert["subject"]:
                    for kk, vv in t:
                        if kk == "commonName":
                            cn = vv
            try:
                ss.sendall(b"GET / HTTP/1.0\r\nHost: %b\r\n\r\n" % ip.encode())
                data = ss.recv(512).decode("utf-8", "ignore")
                m = re.search(r"Server:\s*([^\r\n]+)", data)
                if m:
                    banner = m.group(1).strip()
            except Exception:
                pass
            ss.close()
            ver = banner or (f"TLS CN={cn}" if cn else "TLS")
            return svc, ver[:80], (f"CN={cn}; {banner}" if cn else banner)[:120]
        except Exception:
            return svc, "", ""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((ip, port))
        probe = None
        if port in HTTP_PORTS:
            probe = b"GET / HTTP/1.0\r\nHost: %b\r\n\r\n" % ip.encode()
        elif port == 6379:
            probe = b"INFO\r\n"
        elif port == 11211:
            probe = b"version\r\n"
        if probe:
            s.sendall(probe)
        data = s.recv(1024)
        s.close()
        banner = data.decode("utf-8", "ignore").strip()
        if port == 3306 and data:
            try:
                v = data[5:data.index(b"\x00", 5)].decode("utf-8", "ignore")
                return svc, v[:80], v[:120]
            except Exception:
                pass
        if port == 6379:
            m = re.search(r"redis_version:([^\r\n]+)", banner)
            if m:
                return svc, "Redis " + m.group(1), banner[:120]
        first = banner.split("\r\n")[0] if banner else ""
        return svc, parse_version(port, banner), first[:120]
    except Exception:
        return svc, "", ""

# ----------------------------------------------------------------------
# UDP
# ----------------------------------------------------------------------
def scan_udp_port(ip, port, timeout=2.0):
    payload = UDP_PROBES.get(port, b"\x00")
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(timeout)
        s.sendto(payload, (ip, port))
        data, _ = s.recvfrom(1024)
        s.close()
        if data:
            return port, "ouvert"
    except socket.timeout:
        return port, "ouvert|filtre"
    except Exception:
        return port, "ferme"
    return port, "ouvert|filtre"

def scan_ports_udp(ip, timeout=2.0):
    out = []
    with ThreadPoolExecutor(max_workers=len(UDP_PORTS)) as ex:
        for f in [ex.submit(scan_udp_port, ip, p, timeout) for p in UDP_PORTS]:
            port, state = f.result()
            if state in ("ouvert", "ouvert|filtre"):
                out.append((port, state))
    return sorted(out)

# ----------------------------------------------------------------------
# SMB / NetBIOS
# ----------------------------------------------------------------------
def netbios_query(ip, timeout=2.0):
    pkt = (b"\x12\x34\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00"
           b"\x20CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\x00\x00\x21\x00\x01")
    info = {"names": [], "workgroup": None, "mac": None}
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(timeout)
        s.sendto(pkt, (ip, 137))
        data, _ = s.recvfrom(2048)
        s.close()
        if len(data) < 57:
            return info
        num = data[56]
        off = 57
        for _ in range(num):
            if off + 18 > len(data):
                break
            name = data[off:off + 15].decode("ascii", "ignore").rstrip()
            suffix = data[off + 15]
            flags = struct.unpack(">H", data[off + 16:off + 18])[0]
            group = bool(flags & 0x8000)
            if suffix == 0x20:
                info["names"].append(f"{name} (partage fichier)")
            elif suffix == 0x00 and group:
                info["workgroup"] = name
            elif suffix == 0x00:
                info["names"].append(name)
            off += 18
        if off + 6 <= len(data):
            mac = ":".join("%02x" % b for b in data[off:off + 6])
            if mac != "00:00:00:00:00:00":
                info["mac"] = mac
    except Exception:
        pass
    return info

def nmap_smb_enum(ip):
    if not shutil.which("nmap"):
        return {}
    out = {}
    try:
        cmd = ["nmap", "-p", "139,445", "-Pn", "-T4",
               "--script", "smb-os-discovery,smb-enum-shares,smb-security-mode", ip]
        t = subprocess.run(cmd, capture_output=True, text=True, timeout=120).stdout
        for key, pat in (("smb_os", r"OS:\s*([^\n]+)"),
                         ("computer", r"Computer name:\s*([^\n]+)"),
                         ("domain", r"Domain name:\s*([^\n]+)")):
            m = re.search(pat, t)
            if m:
                out[key] = m.group(1).strip()
        shares = re.findall(r"\\\\[^\s]+\\([^\s:]+)", t)
        if shares:
            out["shares"] = sorted(set(shares))
    except Exception:
        pass
    return out

# ----------------------------------------------------------------------
# OS via nmap
# ----------------------------------------------------------------------
def nmap_available():
    return shutil.which("nmap") is not None

def nmap_os_scan(ip):
    try:
        t = subprocess.run(["nmap", "-O", "-Pn", "--osscan-guess", "-T4", ip],
                           capture_output=True, text=True, timeout=120).stdout
        for pat in (r"OS details: (.+)", r"Running: (.+)", r"Aggressive OS guesses: (.+)"):
            m = re.search(pat, t)
            if m:
                return m.group(1).strip().split(",")[0]
    except Exception:
        pass
    return None

# ----------------------------------------------------------------------
# Parsing des cibles
# ----------------------------------------------------------------------
def parse_all_targets(targets, input_file=None):
    """Agrege plusieurs cibles (IP, CIDR, plages, 'auto') + un fichier liste.
    Accepte aussi les IP separees par virgule dans un meme argument."""
    ips = []
    items = []
    for t in (targets or []):
        items += [x for x in t.replace(",", " ").split() if x]
    if input_file:
        try:
            with open(input_file, encoding="utf-8") as f:
                for line in f:
                    line = line.split("#")[0].strip()   # ignore commentaires
                    if line:
                        items += [x for x in line.replace(",", " ").split() if x]
        except Exception as e:
            raise ValueError(f"lecture du fichier '{input_file}' impossible : {e}")
    if not items:
        raise ValueError("aucune cible fournie")
    for it in items:
        ips += parse_targets(it)
    # dedoublonne + trie
    return sorted(set(ips), key=lambda x: ipaddress.ip_address(x))

def parse_targets(target):
    target = target.strip()
    if target.lower() == "auto":
        nets = get_local_networks()
        if not nets:
            raise ValueError("auto-detection impossible (scapy absent ou pas de reseau). "
                             "Donne un CIDR, ex: 192.168.1.0/24")
        ips = []
        for cidr, _ in nets:
            ips += [str(h) for h in ipaddress.ip_network(cidr).hosts()]
        log(f"{C.GR}[i] Reseaux locaux detectes : {', '.join(c for c, _ in nets)}{C.X}")
        return sorted(set(ips), key=lambda x: ipaddress.ip_address(x))
    if "-" in target and "/" not in target:
        base, rng = target.rsplit(".", 1)
        if "-" in rng:
            a, b = rng.split("-", 1)
            if "." in b:
                s = ipaddress.ip_address(target.split("-")[0])
                e = ipaddress.ip_address(target.split("-")[1])
                return [str(ipaddress.ip_address(i)) for i in range(int(s), int(e) + 1)]
            return [f"{base}.{i}" for i in range(int(a), int(b) + 1)]
    if "/" in target:
        return [str(h) for h in ipaddress.ip_network(target, strict=False).hosts()]
    ipaddress.ip_address(target)
    return [target]

# ----------------------------------------------------------------------
# Decouverte (ARP + ICMP + TCP), asyncio
# ----------------------------------------------------------------------
async def discover(ips, args, loop, pool):
    log(f"\n{C.B}{C.BD}[*] Etape 1 : decouverte ({len(ips)} IP)...{C.X}")
    alive = {}   # ip -> {mac, vendor, ttl, methods:set}

    def add(ip, method):
        alive.setdefault(ip, {"mac": None, "vendor": "", "ttl": None, "methods": set()})
        alive[ip]["methods"].add(method)

    # --- 1. ARP couche 2 (revele tout sur le reseau local) ---
    if not args.no_arp and SCAPY_OK:
        locals_ = get_local_networks()
        target_set = set(ips)
        cidrs = set()
        for cidr, _ in locals_:
            net = ipaddress.ip_network(cidr)
            if any(ipaddress.ip_address(ip) in net for ip in target_set):
                cidrs.add(cidr)
        for cidr in cidrs:
            log(f"{C.GR}    ARP scan de {cidr}...{C.X}")
            res = await loop.run_in_executor(pool, arp_scan, cidr, 2)
            for ip, mac in res.items():
                if ip in target_set:
                    add(ip, "arp")
                    alive[ip]["mac"] = mac
                    alive[ip]["vendor"] = mac_vendor(mac)
    elif not args.no_arp and not SCAPY_OK:
        log(f"{C.GR}    (ARP indisponible : scapy absent -> ICMP/TCP seulement){C.X}")

    # --- 2. TCP ping asyncio (attrape ceux qui bloquent l'ICMP) ---
    sem = asyncio.Semaphore(args.concurrency)
    tcp_tasks = [tcp_ping_async(ip, args.timeout, sem) for ip in ips]
    done = 0
    for coro in asyncio.as_completed(tcp_tasks):
        ip, up = await coro
        done += 1
        if done % 32 == 0 or done == len(ips):
            sys.stdout.write(f"\r{C.GR}    TCP ping {done}/{len(ips)}{C.X}")
            sys.stdout.flush()
        if up:
            add(ip, "tcp")
    print()

    # --- 3. ICMP ping (donne le TTL -> OS ; attrape ceux qui bloquent le TCP) ---
    # on ping tout le monde en parallele via le pool de threads
    icmp_futs = {ip: loop.run_in_executor(pool, get_ttl_from_ping, ip, int(args.timeout) or 1)
                 for ip in ips}
    for ip, fut in icmp_futs.items():
        ttl = await fut
        if ttl is not None:            # None = pas de reponse ICMP
            add(ip, "icmp")
            if ttl and ttl > 0:
                alive[ip]["ttl"] = ttl

    ordered = dict(sorted(alive.items(), key=lambda kv: ipaddress.ip_address(kv[0])))
    log(f"{C.G}[+] {len(ordered)} hote(s) actif(s) trouve(s).{C.X}")
    return ordered

# ----------------------------------------------------------------------
# Scan complet d'un hote
# ----------------------------------------------------------------------
async def scan_host(ip, meta, ports, args, use_nmap, loop, pool, sem):
    r = {"ip": ip, "hostname": resolve_hostname(ip),
         "mac": meta.get("mac"), "vendor": meta.get("vendor", ""),
         "ttl": meta.get("ttl"), "methods": sorted(meta.get("methods", [])),
         "os": "", "tcp": [], "udp": [], "smb": {}}

    if args.syn and SCAPY_OK:
        open_tcp = await loop.run_in_executor(pool, scan_ports_syn, ip, ports, args.timeout)
    else:
        open_tcp = await scan_ports_async(ip, ports, args.timeout, sem)

    if open_tcp:
        vers = await asyncio.gather(*[
            loop.run_in_executor(pool, probe_service, ip, p, args.timeout + 1)
            for p in open_tcp])
        r["tcp"] = [{"port": p, "service": s, "version": v, "banner": b}
                    for p, (s, v, b) in zip(open_tcp, vers)]

    if args.udp:
        r["udp"] = await loop.run_in_executor(pool, scan_ports_udp, ip, args.timeout + 1)

    if args.smb:
        nb = await loop.run_in_executor(pool, netbios_query, ip, 2.0)
        smb = await loop.run_in_executor(pool, nmap_smb_enum, ip) if use_nmap else {}
        r["smb"] = {**nb, **smb}
        if r["smb"].get("mac") and not r["mac"]:
            r["mac"] = r["smb"]["mac"]
            r["vendor"] = mac_vendor(r["smb"]["mac"])

    if use_nmap:
        r["os"] = await loop.run_in_executor(pool, nmap_os_scan, ip) or guess_os_from_ttl(r["ttl"])
    else:
        r["os"] = guess_os_from_ttl(r["ttl"])
    return r

# ----------------------------------------------------------------------
# Affichage
# ----------------------------------------------------------------------
def print_host_report(r):
    log("")
    log(f"{C.CY}{C.BD}{'='*70}{C.X}")
    head = f"{C.CY}{C.BD}  {r['ip']}{C.X}"
    if r["hostname"]:
        head += f"  {C.GR}({r['hostname']}){C.X}"
    if r["vendor"]:
        head += f"  {C.Y}[VM {r['vendor']}]{C.X}"
    log(head)
    log(f"{C.CY}{C.BD}{'='*70}{C.X}")
    line = f"  {C.Y}OS :{C.X} {r['os']}"
    if r["ttl"]: line += f"{C.GR} (TTL={r['ttl']}){C.X}"
    log(line)
    if r["mac"]:
        v = f" {C.Y}({r['vendor']}){C.X}" if r["vendor"] else ""
        log(f"  {C.Y}MAC :{C.X} {r['mac']}{v}")
    if r["methods"]:
        log(f"  {C.GR}detecte via : {', '.join(r['methods'])}{C.X}")

    if r["smb"]:
        s = r["smb"]
        for k, lbl in (("computer", "SMB nom"), ("smb_os", "SMB OS"),
                       ("domain", "Domaine"), ("workgroup", "Workgroup")):
            if s.get(k):
                log(f"  {C.Y}{lbl} :{C.X} {s[k]}")
        if s.get("names"):
            log(f"  {C.Y}NetBIOS :{C.X} {', '.join(s['names'])}")
        if s.get("shares"):
            log(f"  {C.Y}Partages :{C.X} {C.G}{', '.join(s['shares'])}{C.X}")

    if r["tcp"]:
        log(f"  {C.Y}Ports TCP ouverts :{C.X}")
        log(f"    {C.BD}{'PORT':<8}{'SERVICE':<14}{'VERSION / BANNIERE'}{C.X}")
        for d in r["tcp"]:
            info = d["version"] or d["banner"]
            log(f"    {C.G}{d['port']:<8}{C.X}{d['service']:<14}{C.GR}{info}{C.X}")
    else:
        log(f"  {C.R}Aucun port TCP ouvert (dans la plage scannee).{C.X}")

    if r["udp"]:
        log(f"  {C.Y}Ports UDP :{C.X}")
        for port, state in r["udp"]:
            col = C.G if state == "ouvert" else C.Y
            log(f"    {col}{port:<8}{C.X}{SERVICES.get(port,'?'):<14}{C.GR}{state}{C.X}")

# ----------------------------------------------------------------------
# Export
# ----------------------------------------------------------------------
def _clean(r):
    d = dict(r)
    d["methods"] = list(r.get("methods", []))
    return d

def export_json(results, path):
    with open(path, "w", encoding="utf-8") as f:
        json.dump([_clean(r) for r in results], f, indent=2, ensure_ascii=False)
    log(f"{C.G}[+] JSON : {path}{C.X}")

def export_html(results, path):
    rows = []
    for r in results:
        tcp = "<br>".join(f"<b>{d['port']}</b> {d['service']} "
                          f"<span class=g>{html.escape(d['version'] or d['banner'])}</span>"
                          for d in r["tcp"]) or "-"
        udp = ", ".join(f"{p} ({s})" for p, s in r["udp"]) or "-"
        smb_txt = "<br>".join(f"{k}: {html.escape(str(v))}" for k, v in (r["smb"] or {}).items()) or "-"
        vm = f"<span class=vm>[VM {r['vendor']}]</span>" if r["vendor"] else ""
        mac = f"<br><span class=g>{r['mac']}</span>" if r["mac"] else ""
        rows.append(f"<tr><td class=ip>{r['ip']} {vm}<br><span class=g>"
                    f"{html.escape(r['hostname'] or '')}</span>{mac}</td>"
                    f"<td>{html.escape(r['os'])}</td><td>{tcp}</td>"
                    f"<td>{udp}</td><td>{smb_txt}</td></tr>")
    doc = f"""<!doctype html><meta charset=utf-8><title>ReconX</title>
<style>body{{font-family:monospace;background:#0d1117;color:#c9d1d9;padding:20px}}
h1{{color:#58a6ff}}table{{border-collapse:collapse;width:100%}}
td,th{{border:1px solid #30363d;padding:8px;vertical-align:top;text-align:left}}
th{{background:#161b22;color:#58a6ff}}.ip{{color:#79c0ff;font-weight:bold}}
.g{{color:#8b949e}}.vm{{color:#d29922}}</style>
<h1>ReconX - Rapport ({len(results)} hote(s))</h1>
<p class=g>Genere le {time.strftime('%Y-%m-%d %H:%M')}</p>
<table><tr><th>Hote</th><th>OS</th><th>Ports TCP</th><th>UDP</th><th>SMB/NetBIOS</th></tr>
{''.join(rows)}</table>"""
    with open(path, "w", encoding="utf-8") as f:
        f.write(doc)
    log(f"{C.G}[+] HTML : {path}{C.X}")

def save_live_ips(ips, path):
    """Ecrit les IP actives (une par ligne) -> reutilisable avec -iL."""
    try:
        ordered = sorted(set(ips), key=lambda x: ipaddress.ip_address(x))
        with open(path, "w", encoding="utf-8") as f:
            f.write("\n".join(ordered) + "\n")
        log(f"{C.G}[+] {len(ordered)} IP active(s) sauvegardee(s) dans : {path}{C.X}")
        return path
    except Exception as e:
        log(f"{C.R}[!] Ecriture de '{path}' impossible : {e}{C.X}")
        return None

def export_txt(results, path):
    with open(path, "w", encoding="utf-8") as f:
        for r in results:
            f.write(f"[{r['ip']}] {r['hostname'] or ''} {'[VM '+r['vendor']+']' if r['vendor'] else ''}\n")
            f.write(f"  OS: {r['os']} (TTL={r['ttl']})  MAC: {r['mac'] or '-'}\n")
            for k, v in (r["smb"] or {}).items():
                f.write(f"  SMB {k}: {v}\n")
            for d in r["tcp"]:
                f.write(f"  {d['port']}/tcp  {d['service']}  {d['version'] or d['banner']}\n")
            for p, s in r["udp"]:
                f.write(f"  {p}/udp  {SERVICES.get(p,'?')}  {s}\n")
            f.write("\n")
    log(f"{C.G}[+] TXT : {path}{C.X}")

# ----------------------------------------------------------------------
# Orchestration asyncio
# ----------------------------------------------------------------------
async def run(ips, ports, args, use_nmap):
    loop = asyncio.get_event_loop()
    pool = ThreadPoolExecutor(max_workers=args.threads)
    start = time.time()

    alive = await discover(ips, args, loop, pool)
    if not alive:
        log(f"\n{C.R}[!] Aucun hote actif. Essaie --timeout 2, ou verifie le reseau/VPN.{C.X}")
        return

    # Sauvegarde des IP actives (auto en mode --fast, sinon si --live-out demande)
    live_path = args.live_out
    if args.fast and live_path is None:
        live_path = "live_hosts.txt"
    if live_path:
        saved = save_live_ips(list(alive.keys()), live_path)
        if saved:
            log(f"{C.CY}[>] Etape suivante - scan complet des IP trouvees :{C.X}")
            log(f"{C.BD}    sudo python reconx.py -iL {saved} --full -A -o rapport{C.X}")

    if args.fast:
        log(f"\n{C.B}{C.BD}[*] Hotes actifs :{C.X}")
        for ip, m in alive.items():
            hn = resolve_hostname(ip)
            vm = f" {C.Y}[VM {m['vendor']}]{C.X}" if m.get("vendor") else ""
            mac = f" {C.GR}{m['mac']}{C.X}" if m.get("mac") else ""
            hnx = f" {C.GR}({hn}){C.X}" if hn else ""
            log(f"  {C.G}{ip:<16}{C.X}{hnx}{mac}{vm}  {C.Y}{guess_os_from_ttl(m.get('ttl'))}{C.X}")
        log(f"\n{C.GR}Termine en {time.time()-start:.1f}s{C.X}")
        return

    log(f"\n{C.B}{C.BD}[*] Etape 2 : scan complet "
        f"({len(ports)} ports TCP/hote sur {len(alive)} hote(s))...{C.X}")
    sem = asyncio.Semaphore(args.concurrency)
    tasks = [asyncio.ensure_future(scan_host(ip, m, ports, args, use_nmap, loop, pool, sem))
             for ip, m in alive.items()]
    results = []
    for coro in asyncio.as_completed(tasks):
        r = await coro
        results.append(r)
        print_host_report(r)

    results.sort(key=lambda r: ipaddress.ip_address(r["ip"]))
    log(f"\n{C.B}{C.BD}{'='*70}{C.X}\n{C.B}{C.BD}  RECAPITULATIF{C.X}\n{C.B}{C.BD}{'='*70}{C.X}")
    for r in results:
        n = len(r["tcp"])
        pl = f"{C.G}{n} port(s){C.X}" if n else f"{C.R}0 port{C.X}"
        vm = f" {C.Y}[VM {r['vendor']}]{C.X}" if r["vendor"] else ""
        log(f"  {C.CY}{r['ip']:<16}{C.X} {pl:<20} {C.Y}{r['os']}{C.X}{vm}")
    log(f"\n{C.GR}Termine en {time.time()-start:.1f}s{C.X}")

    if args.output:
        base = args.output.rsplit(".", 1)[0]
        export_txt(results, base + ".txt")
        export_json(results, base + ".json")
        export_html(results, base + ".html")

# ----------------------------------------------------------------------
# Main
# ----------------------------------------------------------------------
BANNER = f"""{C.CY}{C.BD}
  ____                        __  __
 |  _ \\ ___  ___ ___  _ __   \\ \\/ /
 | |_) / _ \\/ __/ _ \\| '_ \\   \\  /
 |  _ <  __/ (_| (_) | | | |  /  \\
 |_| \\_\\___|\\___\\___/|_| |_| /_/\\_\\
{C.X}{C.GR}  Scanner reseau asyncio - HTB / THM / VulnHub{C.X}
{C.Y}  by 12akHack{C.GR}  -  outil de securite offensive{C.X}
{C.R}  [!] Usage LEGAL uniquement : labs / CTF / reseau explicitement autorise.{C.X}
"""

def main():
    p = argparse.ArgumentParser(
        description="ReconX - scanner d'enumeration reseau (asyncio + ARP)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
------------------------------------------------------------------------
 GUIDE DES COMMANDES  (sudo recommande : ARP couche 2 + detection OS nmap)
------------------------------------------------------------------------

 1) DECOUVERTE - qui est actif sur le reseau ? (sauve les IP dans un .txt)
    sudo python reconx.py auto --fast              # auto-detecte ton reseau local (VulnHub)
    sudo python reconx.py 192.168.1.0/24 --fast    # un reseau precis
    sudo python reconx.py 192.168.10.0/22 --fast   # un gros reseau (/22, /16...)
       -> cree 'live_hosts.txt' + affiche la commande de l'etape suivante

 2) SCAN COMPLET des IP trouvees (OS, nom de machine, ports, versions...)
    sudo python reconx.py -iL live_hosts.txt -A            # OS + nom machine + ports courants (RAPIDE)
    sudo python reconx.py -iL live_hosts.txt --full -A -o rapport   # + les 65535 ports (COMPLET)

 3) SCAN d'UNE machine precise (typique HTB / TryHackMe)
    python reconx.py 10.10.10.5 -A                 # rapide
    python reconx.py 10.10.10.5 --full -A -o rapport   # tout, avec rapport txt/json/html

 4) PLUSIEURS IP a la main (espace ou virgule)
    sudo python reconx.py 192.168.1.5 192.168.1.10 192.168.1.20 -A
    sudo python reconx.py 192.168.1.5,192.168.1.10 --full -A

 5) MELANGE IP + reseaux + plages
    sudo python reconx.py 10.10.10.5 192.168.1.0/24 172.16.0.10-20 --fast

 CE QUE DONNE CHAQUE INFO :
    hostname   -> reverse DNS (auto)          OS         -> nmap -O (sudo) ou TTL
    nom machine-> -A (SMB/NetBIOS)             MAC + [VM] -> ARP (sudo)

 OPTIONS UTILES :
    -A            tout activer (UDP + SMB)          --full   les 65535 ports
    --fast        decouverte seulement             --syn    scan furtif (scapy+sudo)
    -o rapport    exporte .txt .json .html         --live-out f.txt   nom du fichier d'IP
    -c 1000       + de vitesse    --timeout 2   + fiable sur VPN HTB (latence)

 EXEMPLE COMPLET (VulnHub, de A a Z) :
    sudo python reconx.py auto --fast
        # -> trouve l'IP de ta VM, ex: 192.168.56.101 [VM VirtualBox]
    sudo python reconx.py 192.168.56.101 --full -A -o rapport
        # -> scan des 65535 ports + OS + services + versions + SMB + rapport
    # Resultat: tu sais quels services tournent et par ou attaquer.
------------------------------------------------------------------------
""")
    p.add_argument("target", nargs="*",
                   help="Une ou plusieurs cibles : 'auto', IP, CIDR (192.168.1.0/24), "
                        "plage (192.168.1.10-50), ou liste separee par virgule/espace")
    p.add_argument("-iL", "--input-list", dest="input_list",
                   help="Fichier contenant les cibles (une ou plusieurs par ligne)")
    p.add_argument("-p", "--ports", help="Ports : '80,443', '1-1000' ou 'all'. Defaut = top ~100")
    p.add_argument("--full", action="store_true", help="Scan des 65535 ports TCP")
    p.add_argument("--fast", action="store_true", help="Decouverte des hotes seulement")
    p.add_argument("--udp", action="store_true", help="Ajoute le scan UDP")
    p.add_argument("--smb", action="store_true", help="Enumeration SMB/NetBIOS")
    p.add_argument("--syn", action="store_true", help="SYN scan furtif (scapy + admin)")
    p.add_argument("-A", "--all", action="store_true", help="Tout activer (--udp --smb)")
    p.add_argument("--no-arp", action="store_true", help="Desactiver le scan ARP")
    p.add_argument("-c", "--concurrency", type=int, default=500, help="Connexions simultanees (defaut 500)")
    p.add_argument("-t", "--threads", type=int, default=100, help="Threads pour ICMP/version/nmap (defaut 100)")
    p.add_argument("--timeout", type=float, default=1.0, help="Timeout par connexion (defaut 1.0)")
    p.add_argument("--no-nmap", action="store_true", help="Ne pas utiliser nmap")
    p.add_argument("-o", "--output", help="Nom de base de sortie (.txt .json .html)")
    p.add_argument("--live-out", nargs="?", const="live_hosts.txt", default=None,
                   help="Sauver les IP actives dans un fichier (defaut live_hosts.txt) "
                        "reutilisable avec -iL. Auto-active en mode --fast.")
    args = p.parse_args()

    if args.all:
        args.udp = True; args.smb = True

    print(BANNER)

    if not args.target and not args.input_list:
        p.print_help()
        sys.exit(0)
    try:
        ips = parse_all_targets(args.target, args.input_list)
    except Exception as e:
        log(f"{C.R}[!] Cible invalide : {e}{C.X}"); sys.exit(1)
    log(f"{C.GR}[i] {len(ips)} IP a traiter.{C.X}")

    if args.full or (args.ports and args.ports.lower() == "all"):
        ports = list(range(1, 65536))
    elif args.ports:
        if "-" in args.ports:
            a, b = args.ports.split("-"); ports = list(range(int(a), int(b) + 1))
        else:
            ports = [int(x) for x in args.ports.split(",")]
    else:
        ports = TOP_PORTS

    use_nmap = (not args.no_nmap) and nmap_available()
    if not args.fast:
        log(f"{C.GR}[i] nmap:{'oui' if use_nmap else 'non'} | scapy/ARP:{'oui' if SCAPY_OK else 'non'} "
            f"| TCP:{'SYN' if (args.syn and SCAPY_OK) else 'connect asyncio'} "
            f"| concurrence:{args.concurrency}{C.X}")
        if args.syn and not SCAPY_OK:
            log(f"{C.R}[!] --syn demande mais scapy absent -> connect scan.{C.X}")
        # Gros scan sur Windows : conseiller un reglage plus rapide
        if len(ports) > 3000 and platform.system() == "Windows" \
                and args.timeout >= 1.0 and args.concurrency <= 500:
            log(f"{C.Y}[astuce] Gros scan sous Windows : ajoute '--timeout 0.5 -c 1000' "
                f"pour aller ~3x plus vite (sur Linux ce n'est pas necessaire).{C.X}")

    try:
        asyncio.run(run(ips, ports, args, use_nmap))
    except KeyboardInterrupt:
        log(f"\n{C.R}[!] Interrompu.{C.X}")


if __name__ == "__main__":
    main()
