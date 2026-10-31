#!/usr/bin/env python3
"""Audite-moi — vulnérabilités connues, vue depuis Internet et domaines.

Appelé par audite-moi.sh (en root), en lecture seule. Écrit sur la sortie standard des lignes
séparées par \\x1f, comme l'analyse d'OPNsense :
  F niveau titre détail correctif      un constat
  T table cellules (tabulations)       une ligne de tableau (la première ligne d'une table = en-têtes)
et dépose l'inventaire (JSON) dans le dossier --inventaire.

Sources publiques et gratuites, sans compte : OSV.dev (failles des paquets Ubuntu), NVD (failles
des services détectés sur le réseau, clé facultative), catalogue CISA KEV (failles exploitées
activement), FIRST EPSS (probabilité d'exploitation), Shodan InternetDB (ce qu'Internet voit de
votre adresse), DNS public de Cloudflare en HTTPS, RDAP (expiration du domaine), crt.sh (journaux
publics de certificats). Les réponses sont gardées en cache pour ne pas solliciter ces services.
"""
import argparse
import concurrent.futures
import datetime
import hashlib
import ipaddress
import json
import os
import re
import socket
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET

US = "\x1f"
UA = "Audite-moi (audit de son propre serveur)"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
CACHE = os.environ.get("AUDITE_MOI_CACHE", "/var/lib/audite-moi/cache")
INV = None


class Echec(Exception):
    pass


# ----------------------------------------------------------------- sortie --
def F(niv, titre, detail="", correctif=""):
    print(US.join(["F", niv, titre.replace(US, " "), detail.replace("\n", "\\n").replace(US, " "), correctif.replace(US, " ")]), flush=True)


def T(table, *cellules):
    print(US.join(["T", table, "\t".join(str(c).replace("\t", " ").replace("\n", " ") for c in cellules)]), flush=True)


def inventaire(cle, donnees):
    if INV:
        os.makedirs(INV, exist_ok=True)
        with open(os.path.join(INV, cle + ".json"), "w", encoding="utf-8") as f:
            json.dump(donnees, f, ensure_ascii=False)


def liste(elements, n=6):
    elements = list(elements)
    return ", ".join(elements[:n]) + (" (+{})".format(len(elements) - n) if len(elements) > n else "")


# ------------------------------------------------------------------- HTTP --
def _mock(url):
    """Tests : réponses simulées ({"morceau d'URL": "fichier" | {"status": 404, "fichier": …}}), jamais de réseau."""
    chemin = os.environ.get("AUDITE_MOI_HTTP_MOCK")
    if not chemin:
        return None
    with open(chemin, encoding="utf-8") as f:
        table = json.load(f)
    for morceau, rep in table.items():
        if morceau in url:
            if isinstance(rep, str):
                rep = {"status": 200, "fichier": rep}
            if rep.get("erreur"):
                raise Echec(rep["erreur"])
            corps = b""
            if rep.get("fichier"):
                with open(os.path.join(os.path.dirname(chemin), rep["fichier"]), "rb") as f:
                    corps = f.read()
            return rep.get("status", 200), corps
    raise Echec("hors ligne (test) : " + url)


def http(url, donnees=None, entetes=None, delai=20, cache_h=0):
    """(code, corps) ; les réponses 200 sont mises en cache cache_h heures."""
    cle = hashlib.sha256((url + "\n" + (donnees or b"").decode("utf-8", "replace")).encode()).hexdigest()
    fichier = os.path.join(CACHE, cle[:2], cle)
    if cache_h and not os.environ.get("AUDITE_MOI_HTTP_MOCK"):
        try:
            if time.time() - os.path.getmtime(fichier) < cache_h * 3600:
                with open(fichier, "rb") as f:
                    return 200, f.read()
        except OSError:
            pass
    m = _mock(url)
    if m is not None:
        return m
    req = urllib.request.Request(url, data=donnees, headers=dict({"User-Agent": UA}, **(entetes or {})))
    try:
        with urllib.request.urlopen(req, timeout=delai) as r:
            code, corps = r.status, r.read(30_000_000)
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read(200_000) if exc.fp else b""
    except (OSError, ValueError) as exc:
        raise Echec("{} : {}".format(urllib.parse.urlsplit(url).hostname, type(exc).__name__))
    if code == 200 and cache_h:
        try:
            os.makedirs(os.path.dirname(fichier), mode=0o700, exist_ok=True)
            with open(fichier + ".tmp", "wb") as f:
                f.write(corps)
            os.replace(fichier + ".tmp", fichier)
        except OSError:
            pass
    return code, corps


def http_json(url, **k):
    code, corps = http(url, **k)
    if code != 200:
        raise Echec("HTTP {}".format(code))
    try:
        return json.loads(corps)
    except ValueError:
        raise Echec("réponse illisible")


# --------------------------------------------------- KEV, EPSS : priorités --
_KEV = None


def kev():
    """{CVE: entrée du catalogue CISA des failles exploitées activement} ({} si injoignable)."""
    global _KEV
    if _KEV is None:
        try:
            _KEV = {v["cveID"]: v for v in http_json(KEV_URL, delai=40, cache_h=24).get("vulnerabilities", []) if v.get("cveID")}
        except Echec:
            _KEV = {}
    return _KEV


def epss(cves):
    """{CVE: probabilité d'exploitation dans les 30 jours (0 à 1)}."""
    res, cves = {}, sorted(set(cves))
    for i in range(0, len(cves), 80):
        lot = cves[i:i + 80]
        try:
            d = http_json("https://api.first.org/data/v1/epss?cve=" + ",".join(lot), cache_h=24)
        except Echec:
            continue
        for e in d.get("data", []):
            try:
                res[e["cve"]] = float(e["epss"])
            except (KeyError, ValueError):
                pass
    return res


def pct(x):
    return "{:.0f} %".format(100 * x) if x is not None and x >= 0.01 else ("< 1 %" if x is not None else "?")


# ------------------------------------------------- paquets du serveur (OSV) --
def cmd_paquets(a):
    """Failles connues corrigées par les mises à jour de sécurité en attente (paquets source Ubuntu)."""
    paquets = []
    with open(a.fichier, encoding="utf-8") as f:
        for l in f:
            p = l.split()
            if len(p) == 2:
                paquets.append((p[0], p[1]))
    paquets = sorted(set(paquets))[:300]
    if not paquets:
        return
    eco = a.ecosysteme
    try:
        res = http_json("https://api.osv.dev/v1/querybatch", donnees=json.dumps({"queries": [
            {"package": {"name": n, "ecosystem": eco}, "version": v} for n, v in paquets]}).encode(),
            entetes={"Content-Type": "application/json"}, delai=60)
    except Echec as exc:
        F("INFO", "Base de vulnérabilités OSV injoignable", "Les failles corrigées par les mises à jour en attente n'ont pas pu être identifiées ({}).".format(exc))
        return
    ids = {}
    for (n, v), r in zip(paquets, res.get("results", [])):
        for vu in (r or {}).get("vulns", []) or []:
            ids.setdefault(vu["id"], set()).add(n)
    failles = {}   # CVE → paquets
    for vid in list(ids)[:200]:
        try:
            d = http_json("https://api.osv.dev/v1/vulns/" + urllib.parse.quote(vid), cache_h=168)
        except Echec:
            continue
        corrige = any(ev.get("fixed") for af in d.get("affected", []) if af.get("package", {}).get("name") in ids[vid]
                      for rg in af.get("ranges", []) for ev in rg.get("events", []))
        if not corrige:
            continue
        cves = {x for x in [d.get("id", "")] + d.get("aliases", []) + d.get("upstream", []) if x.startswith("CVE-")}
        m = re.match(r"^UBUNTU-(CVE-\d+-\d+)$", vid)
        if m:
            cves.add(m.group(1))
        for c in cves:
            failles.setdefault(c, set()).update(ids[vid])
    if not failles:
        inventaire("paquets", {"failles": 0})
        return
    k, e = kev(), epss(failles)
    exploitees = sorted(c for c in failles if c in k)
    rang = sorted(failles, key=lambda c: (c not in k, -(e.get(c) or 0), c))
    T("Failles corrigées par les mises à jour en attente", "Faille", "Paquet(s)", "Probabilité d'exploitation (EPSS)", "Exploitée activement (CISA)")
    for c in rang[:40]:
        T("Failles corrigées par les mises à jour en attente", c, liste(sorted(failles[c]), 3), pct(e.get(c)), "@CRIT oui" if c in k else "non")
    fix = "`sudo apt update && sudo apt full-upgrade`, puis redémarrez si un nouveau noyau ou une bibliothèque système a été installé"
    if exploitees:
        F("CRIT", "{} faille(s) exploitée(s) activement, corrigée(s) par les mises à jour en attente".format(len(exploitees)),
          "\n".join("{} ({}) : {}".format(c, liste(sorted(failles[c]), 3), k[c].get("vulnerabilityName", "")) for c in exploitees[:8]) +
          "\nCes failles figurent au catalogue CISA des failles réellement exploitées par des attaquants.", "Installez les mises à jour sans attendre : " + fix)
    elif any((e.get(c) or 0) >= 0.1 for c in failles):
        hautes = [c for c in rang if (e.get(c) or 0) >= 0.1]
        F("WARN", "Mises à jour en attente : {} faille(s) à forte probabilité d'exploitation".format(len(hautes)),
          "\n".join("{} ({}) : {} de probabilité d'exploitation dans les 30 jours".format(c, liste(sorted(failles[c]), 3), pct(e.get(c))) for c in hautes[:8]), fix)
    else:
        F("INFO", "{} faille(s) connue(s) corrigée(s) par les mises à jour en attente".format(len(failles)),
          "Aucune n'est exploitée activement ni probable à court terme (EPSS) : mettez à jour au prochain créneau.", fix)
    inventaire("paquets", {"failles": len(failles), "exploitees": exploitees, "epss_max": max([e.get(c) or 0 for c in failles] or [0])})


# ------------------------------------------------------- images (Trivy) --
def cmd_images(a):
    """Failles des images Docker (résultats de Trivy) classées par exploitation réelle."""
    images = []
    for nom in sorted(os.listdir(a.dossier)):
        if not nom.endswith(".json"):
            continue
        try:
            with open(os.path.join(a.dossier, nom), encoding="utf-8") as f:
                d = json.load(f)
        except (OSError, ValueError):
            continue
        meta = {}
        try:
            with open(os.path.join(a.dossier, nom[:-5] + ".meta"), encoding="utf-8") as f:
                meta = json.load(f)
        except (OSError, ValueError):
            pass
        cves, sev = {}, []
        for r in d.get("Results") or []:
            for v in r.get("Vulnerabilities") or []:
                sev.append(v.get("Severity", ""))
                if str(v.get("VulnerabilityID", "")).startswith("CVE-"):
                    cves.setdefault(v["VulnerabilityID"], (v.get("PkgName", ""), v.get("Severity", "")))
        images.append({"image": meta.get("image") or d.get("ArtifactName", nom), "expose": meta.get("expose", ""), "cves": cves, "sev": sev})
    tout = {c for i in images for c in i["cves"]}
    if not tout:
        inventaire("images", [{"image": i["image"], "expose": i["expose"], "critiques": i["sev"].count("CRITICAL"), "hautes": i["sev"].count("HIGH"),
                               "exploitees": []} for i in images])
        return
    k, e = kev(), epss(tout)
    inv = []
    for i in images:
        ex = sorted(c for c in i["cves"] if c in k)
        inv.append({"image": i["image"], "expose": i["expose"], "critiques": i["sev"].count("CRITICAL"), "hautes": i["sev"].count("HIGH"), "exploitees": ex,
                    "epss_max": max([e.get(c) or 0 for c in i["cves"]] or [0])})
        if ex:
            F("CRIT" if i["expose"] else "WARN", "Image {} : {} faille(s) exploitée(s) activement".format(i["image"], len(ex)),
              "\n".join("{} ({}) : {}".format(c, i["cves"][c][0], k[c].get("vulnerabilityName", "")) for c in ex[:6]) +
              ("\nLe conteneur {} est joignable depuis Internet.".format(i["expose"]) if i["expose"] else ""),
              "Mettez l'image à jour (`docker compose pull && docker compose up -d`) ; si aucune version corrigée n'existe, changez d'image ou retirez l'accès depuis Internet")
    T("Images : failles exploitées et probabilité d'exploitation", "Image", "Critiques", "Élevées", "Exploitées activement", "EPSS max", "Exposition")
    for i in sorted(inv, key=lambda x: (-len(x["exploitees"]), -x["epss_max"])):
        T("Images : failles exploitées et probabilité d'exploitation", i["image"], i["critiques"], i["hautes"],
          "@CRIT " + liste(i["exploitees"], 3) if i["exploitees"] else "—", pct(i["epss_max"]), i["expose"] or "—")
    inventaire("images", inv)


# ------------------------------------------ appareils du réseau (nmap + NVD) --
def cpe23(cpe):
    """cpe:/a:openbsd:openssh:7.4 → cpe:2.3:a:openbsd:openssh:7.4:*:… (None sans version précise)."""
    m = re.match(r"^cpe:/([aho]):([^:]+):([^:]+):([^:]+)", cpe or "")
    if not m or not re.match(r"^[0-9]", m.group(4)):
        return None
    champs = [m.group(1), m.group(2), m.group(3), m.group(4)] + ["*"] * 7
    return "cpe:2.3:" + ":".join(c.replace("%", "") for c in champs)


def nvd(cpe, cle):
    """Failles connues pour cette version : [(CVE, score CVSS, exploitée selon CISA)]."""
    url = "https://services.nvd.nist.gov/rest/json/cves/2.0?" + urllib.parse.urlencode({"virtualMatchString": cpe, "resultsPerPage": 500})
    d = http_json(url, entetes={"apiKey": cle} if cle else None, delai=40, cache_h=168)
    res = []
    for v in d.get("vulnerabilities", []):
        c = v.get("cve", {})
        score = 0.0
        for m in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            for x in c.get("metrics", {}).get(m, []):
                score = max(score, float(x.get("cvssData", {}).get("baseScore", 0)))
            if score:
                break
        res.append((c.get("id", ""), score, bool(c.get("cisaExploitAdd"))))
    return res


def cmd_lan(a):
    try:
        racine = ET.parse(a.xml).getroot()
    except (OSError, ET.ParseError):
        return
    exposes = set(a.exposes.split()) if a.exposes else set()
    appareils = []
    for h in racine.findall("host"):
        s = h.find("status")
        if s is None or s.get("state") != "up":
            continue
        ip = mac = fab = ""
        for ad in h.findall("address"):
            if ad.get("addrtype") == "ipv4":
                ip = ad.get("addr", "")
            elif ad.get("addrtype") == "mac":
                mac, fab = ad.get("addr", ""), ad.get("vendor", "")
        hn = h.find("hostnames/hostname")
        services = []
        for p in h.findall("ports/port"):
            st = p.find("state")
            if st is None or st.get("state") != "open":
                continue
            sv = p.find("service")
            sv = sv if sv is not None else ET.Element("service")
            cpes = [c.text for c in sv.findall("cpe") if c.text]
            services.append({"port": int(p.get("portid", 0)), "proto": p.get("protocol", "tcp"), "service": sv.get("name", ""),
                             "produit": sv.get("product", ""), "version": sv.get("version", ""), "tunnel": sv.get("tunnel", ""),
                             "cpe": next((c for c in (cpe23(x) for x in cpes) if c), None)})
        appareils.append({"ip": ip, "nom": hn.get("name", "") if hn is not None else "", "mac": mac, "fabricant": fab, "services": services,
                          "expose": sorted("{}:{}".format(ip, s["port"]) for s in services if "{}:{}".format(ip, s["port"]) in exposes)})
    # failles connues par version (NVD), avec un budget de temps : l'API publique limite le débit
    cpes = sorted({s["cpe"] for ap in appareils for s in ap["services"] if s["cpe"]})
    connus, debut, ignores = {}, time.time(), 0
    for c in cpes[:40]:
        if time.time() - debut > a.budget:
            ignores += 1
            continue
        try:
            connus[c] = nvd(c, a.nvd_cle)
        except Echec:
            ignores += 1
        if not os.environ.get("AUDITE_MOI_HTTP_MOCK"):
            time.sleep(0.8 if a.nvd_cle else 6.5)
    k = kev()
    http_seul = []
    T("Services et versions détectés", "Adresse", "Nom", "Port", "Service", "Version", "Failles connues", "Exploitées")
    for ap in appareils:
        ports = {s["port"] for s in ap["services"]}
        for s in ap["services"]:
            vul = connus.get(s["cpe"], []) if s["cpe"] else []
            ex = sorted({c for c, _, x in vul if x or c in k})
            s["failles"], s["exploitees"] = len(vul), ex
            s["cvss_max"] = max([sc for _, sc, _ in vul] or [0])
            T("Services et versions détectés", ap["ip"], ap["nom"] or ap["fabricant"], "{}/{}".format(s["port"], s["proto"]), s["service"],
              " ".join(x for x in (s["produit"], s["version"]) if x) or "—",
              ("@WARN " if s["cvss_max"] >= 7 else "") + str(len(vul)) if vul else "0", "@CRIT " + liste(ex, 2) if ex else "—")
            if not vul:
                continue
            qui = "{}{}".format(ap["ip"], " ({})".format(ap["nom"] or ap["fabricant"]) if ap["nom"] or ap["fabricant"] else "")
            produit = " ".join(x for x in (s["produit"], s["version"]) if x)
            expose = "{}:{}".format(ap["ip"], s["port"]) in ap["expose"]
            pires = sorted(vul, key=lambda v: (not (v[2] or v[0] in k), -v[1]))[:6]
            detail = "\n".join("{} : CVSS {:.1f}{}".format(c, sc, ", exploitée activement" if (x or c in k) else "") for c, sc, x in pires)
            detail += "\nCorrespondance faite sur le numéro de version annoncé par le service : un correctif rétroporté par le fabricant peut ne pas changer ce numéro."
            if expose:
                detail += "\nCe service est redirigé depuis Internet par le routeur."
            fix = ("Mettez à jour le logiciel ou le firmware de l'appareil ; s'il n'est plus maintenu, isolez-le dans un réseau séparé (VLAN) "
                   "sans accès au reste du réseau" + (" et supprimez la redirection de port" if expose else ""))
            if ex:
                F("CRIT", "{} : {} sur le port {} — {} faille(s) exploitée(s) activement".format(qui, produit, s["port"], len(ex)), detail, fix)
            elif s["cvss_max"] >= 9 or (expose and s["cvss_max"] >= 7):
                F("CRIT" if expose else "WARN", "{} : {} sur le port {} — {} faille(s) connue(s), jusqu'à CVSS {:.1f}".format(qui, produit, s["port"], len(vul), s["cvss_max"]), detail, fix)
            elif s["cvss_max"] >= 7:
                F("INFO", "{} : {} sur le port {} — {} faille(s) connue(s)".format(qui, produit, s["port"], len(vul)), detail, fix)
        if ports & {80, 8080} and not ports & {443, 8443} and ap["ip"] not in a.nas.split():
            http_seul.append("{}{}".format(ap["ip"], " ({})".format(ap["nom"] or ap["fabricant"]) if ap["nom"] or ap["fabricant"] else ""))
    if http_seul:
        F("INFO", "{} appareil(s) administré(s) en HTTP non chiffré".format(len(http_seul)), liste(http_seul, 10) +
          "\nSur le réseau local, le mot de passe d'administration de ces appareils peut être intercepté.",
          "Activez HTTPS dans leur interface si c'est possible ; sinon, réservez leur administration à un réseau séparé")
    if ignores:
        F("INFO", "{} version(s) de service non vérifiée(s) dans la base NVD".format(ignores),
          "La base publique limite le nombre de requêtes : les autres seront vérifiées aux audits suivants (résultats gardés 7 jours).",
          "Une clé API NVD gratuite accélère la vérification : Réglages › Vulnérabilités")
    inventaire("appareils", appareils)


# --------------------------------------------- vue depuis Internet (Shodan) --
RISQUES = {21: "FTP", 22: "SSH", 23: "Telnet", 445: "SMB", 139: "SMB", 3389: "RDP", 5900: "VNC", 3306: "MySQL", 5432: "PostgreSQL",
           6379: "Redis", 2375: "API Docker", 9200: "Elasticsearch", 27017: "MongoDB", 1883: "MQTT", 554: "RTSP (caméra)", 8291: "Winbox"}


def cmd_internet(a):
    vues = []
    for ip in a.ip:
        try:
            ipaddress.ip_address(ip)
        except ValueError:
            continue
        try:
            code, corps = http("https://internetdb.shodan.io/" + ip, delai=20)
        except Echec as exc:
            F("INFO", "Vue depuis Internet indisponible ({})".format(ip), "Shodan InternetDB n'a pas répondu ({}).".format(exc))
            continue
        if code == 404:
            vues.append({"ip": ip, "ports": [], "vulns": [], "tags": [], "hostnames": []})
            continue
        try:
            d = json.loads(corps)
        except ValueError:
            continue
        vues.append({"ip": ip, "ports": sorted(d.get("ports", [])), "vulns": sorted(d.get("vulns", [])), "tags": d.get("tags", []),
                     "hostnames": d.get("hostnames", []), "cpes": d.get("cpes", [])})
    if not vues:
        return
    k = kev()
    for v in vues:
        if not v["ports"]:
            F("OK", "Shodan ne voit aucun port ouvert sur {}".format(v["ip"]),
              "Les scanners d'Internet n'ont trouvé aucun service sur votre adresse publique (l'accès passe par les tunnels).")
            continue
        risques = ["{} ({})".format(p, RISQUES[p]) for p in v["ports"] if p in RISQUES]
        F("CRIT" if risques else "WARN", "Internet voit {} port(s) ouvert(s) sur {} : {}".format(len(v["ports"]), v["ip"], liste(map(str, v["ports"]), 10)),
          ("Services sensibles : {}.\n".format(", ".join(risques)) if risques else "") +
          "Relevé par Shodan, qui scanne tout Internet en continu : n'importe qui peut trouver ces ports. Les données peuvent dater de quelques jours."
          + ("\nNoms associés : {}".format(liste(v["hostnames"], 5)) if v["hostnames"] else ""),
          "Fermez chaque port inutile (redirections du routeur ou de la box) ; pour l'accès distant, préférez un VPN ou les tunnels Cloudflare")
        if v["vulns"]:
            ex = [c for c in v["vulns"] if c in k]
            F("CRIT" if ex else "WARN", "Shodan associe {} faille(s) connue(s) à {}{}".format(len(v["vulns"]), v["ip"],
                                                                                         ", dont {} exploitée(s) activement".format(len(ex)) if ex else ""),
              liste(ex + [c for c in v["vulns"] if c not in ex], 10) + "\nDéduites des versions affichées par vos services : à vérifier, mais c'est ce que voit un attaquant.",
              "Mettez à jour les services exposés, ou retirez-les d'Internet")
        if set(v["tags"]) & {"compromised", "malware", "c2", "botnet"}:
            F("CRIT", "Shodan signale {} comme compromise ({})".format(v["ip"], ", ".join(v["tags"])), "",
              "Vérifiez le routeur et les machines exposées ; changez les mots de passe d'administration")
    inventaire("internet", vues)


# ------------------------------------------------------------------ DNS --
TYPES = {"A": 1, "NS": 2, "CNAME": 5, "SOA": 6, "MX": 15, "TXT": 16, "AAAA": 28, "CAA": 257}
CF_V4 = ["173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22", "141.101.64.0/18", "108.162.192.0/18", "190.93.240.0/20",
         "188.114.96.0/20", "197.234.240.0/22", "198.41.128.0/17", "162.158.0.0/15", "104.16.0.0/13", "104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22"]
CF_V6 = ["2400:cb00::/32", "2606:4700::/32", "2803:f800::/32", "2405:b500::/32", "2405:8100::/32", "2a06:98c0::/29", "2c0f:f248::/32"]
CF = [ipaddress.ip_network(n) for n in CF_V4 + CF_V6]


def dns(nom, typ):
    """(statut DNS, validé DNSSEC, [données du type demandé], [cibles CNAME])."""
    d = http_json("https://cloudflare-dns.com/dns-query?" + urllib.parse.urlencode({"name": nom, "type": typ, "do": "1"}),
                  entetes={"accept": "application/dns-json"}, delai=10)
    rep = d.get("Answer") or []
    t = TYPES[typ]
    return (d.get("Status", 2), bool(d.get("AD")), [r["data"].strip('"') if typ == "TXT" else r["data"] for r in rep if r.get("type") == t],
            [r["data"].rstrip(".") for r in rep if r.get("type") == 5])


def txt(nom):
    try:
        return ["".join(re.findall(r'"([^"]*)"', x)) if '" "' in x else x for x in dns(nom, "TXT")[2]]
    except Echec:
        return []


def cloudflare(ip):
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(a in n for n in CF if n.version == a.version)


PRISE = {   # services où un sous-domaine qui pointe vers une ressource supprimée peut être repris par un inconnu
    "github.io": "There isn't a GitHub Pages site here", "herokuapp.com": "No such app", "herokudns.com": "No such app",
    "azurewebsites.net": "404 Web Site not found", "cloudapp.net": "", "cloudapp.azure.com": "", "trafficmanager.net": "",
    "blob.core.windows.net": "The specified resource does not exist", "s3.amazonaws.com": "NoSuchBucket", "amazonaws.com": "NoSuchBucket",
    "elasticbeanstalk.com": "", "ghost.io": "Domain is not configured", "pantheonsite.io": "The gods are wise", "netlify.app": "Not Found - Request ID",
    "surge.sh": "project not found", "bitbucket.io": "Repository not found", "zendesk.com": "Help Center Closed", "readme.io": "Project doesnt exist",
    "myshopify.com": "Sorry, this shop is currently unavailable", "webflow.io": "The page you are looking for doesn't exist", "wordpress.com": "Do you want to register",
    "fastly.net": "Fastly error: unknown domain", "vercel.app": "DEPLOYMENT_NOT_FOUND",
}


def prise_possible(cname):
    for suffixe, empreinte in PRISE.items():
        if cname == suffixe or cname.endswith("." + suffixe):
            return suffixe, empreinte
    return None, None


def certificat(nom):
    """Jours avant l'expiration du certificat HTTPS de nom (None si pas de HTTPS), et validité."""
    if os.environ.get("AUDITE_MOI_HTTP_MOCK"):
        m = json.loads(os.environ.get("AUDITE_MOI_CERTS", "{}"))
        return tuple(m[nom]) if nom in m else (None, None)
    ctx = ssl.create_default_context()
    valide = True
    try:
        with socket.create_connection((nom, 443), timeout=5) as s, ctx.wrap_socket(s, server_hostname=nom) as t:
            c = t.getpeercert()
    except ssl.SSLCertVerificationError:
        valide = False
        ctx.check_hostname, ctx.verify_mode = False, ssl.CERT_NONE
        try:
            with socket.create_connection((nom, 443), timeout=5) as s, ctx.wrap_socket(s, server_hostname=nom) as t:
                der = t.getpeercert(binary_form=True)
            return None, False if der else None
        except (OSError, ssl.SSLError):
            return None, None
    except (OSError, ssl.SSLError):
        return None, None
    try:
        fin = datetime.datetime.strptime(c["notAfter"], "%b %d %H:%M:%S %Y %Z")
    except (KeyError, ValueError):
        return None, valide
    return (fin - datetime.datetime.utcnow()).days, valide


def rdap(domaine):
    try:
        d = http_json("https://rdap.org/domain/" + urllib.parse.quote(domaine), delai=20, cache_h=24)
    except Echec:
        return None, None
    fin = next((e.get("eventDate") for e in d.get("events", []) if e.get("eventAction") == "expiration"), None)
    jours = None
    if fin:
        try:
            jours = (datetime.datetime.fromisoformat(fin.replace("Z", "+00:00")) - datetime.datetime.now(datetime.timezone.utc)).days
        except ValueError:
            pass
    statuts = [s.lower() for s in d.get("status", [])]
    return jours, any("transfer prohibited" in s for s in statuts)


SELECTEURS = ["default", "dkim", "mail", "selector1", "selector2", "google", "k1", "k2", "s1", "s2", "sig1", "smtp", "mx", "fm1", "fm2", "fm3",
              "protonmail", "protonmail2", "protonmail3", "zoho", "mailjet", "sendinblue", "brevo", "mandrill", "everlytickey1", "ovh", "mailo", "gandi"]


def sous_domaines(domaine):
    try:
        d = http_json("https://crt.sh/?" + urllib.parse.urlencode({"q": "%." + domaine, "output": "json"}), delai=60, cache_h=24)
    except Echec:
        return None
    noms = set()
    for c in d if isinstance(d, list) else []:
        for n in str(c.get("name_value", "")).lower().split("\n"):
            n = n.strip().lstrip("*.").rstrip(".")
            if n and (n == domaine or n.endswith("." + domaine)) and re.fullmatch(r"[a-z0-9.-]+", n):
                noms.add(n)
    return sorted(noms)


INTERNES = [ipaddress.ip_network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10", "169.254.0.0/16", "fc00::/7", "fe80::/10")]


def interne(ip):
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(a in n for n in INTERNES if n.version == a.version)


def analyser_nom(nom, ip_pub):
    """Résolution d'un nom : adresses, CNAME, Cloudflare, adresse de la maison, risque de reprise."""
    r = {"nom": nom, "ips": [], "cname": "", "cloudflare": False, "maison": False, "interne": False, "alerte": ""}
    try:
        st, _, a, cn = dns(nom, "A")
        st6, _, a6, _ = dns(nom, "AAAA")
    except Echec:
        r["alerte"] = "DNS injoignable"
        return r
    r["ips"], r["cname"] = a + a6, (cn[-1] if cn else "")
    r["cloudflare"] = any(cloudflare(x) for x in r["ips"])
    r["maison"] = bool(ip_pub) and ip_pub in r["ips"]
    r["interne"] = any(interne(x) for x in r["ips"])
    if r["cname"]:
        service, empreinte = prise_possible(r["cname"])
        if not r["ips"] and st == 3:
            r["alerte"] = "prise" if service else "pendant"
        elif service and empreinte and r["ips"]:
            try:
                code, corps = http("https://" + nom + "/", delai=8)
                if empreinte.encode() in corps:
                    r["alerte"] = "prise"
            except Echec:
                pass
        r["service"] = service or ""
    return r


def cmd_domaines(a):
    ip_pub = a.ip_publique or ""
    tout = []
    for domaine in [d.lower().rstrip(".") for d in a.domaines.split() if d]:
        info = {"domaine": domaine}
        try:
            st, ad, ns, _ = dns(domaine, "NS")
        except Echec as exc:
            F("INFO", "Domaine {} : DNS public injoignable".format(domaine), str(exc))
            continue
        if st == 3:
            F("CRIT", "Le domaine {} n'existe pas (ou plus) dans le DNS".format(domaine),
              "Le DNS public répond « domaine inexistant » : nom mal saisi, ou domaine expiré et supprimé.",
              "Vérifiez l'orthographe dans Réglages › Domaines, puis le renouvellement chez votre registraire")
            continue
        info["ns"] = ns
        T("Domaine " + domaine, "Contrôle", "Résultat")
        T("Domaine " + domaine, "Serveurs DNS", liste(ns, 4))
        # Expiration et verrou de transfert (RDAP)
        jours, verrou = rdap(domaine)
        info["expiration_jours"], info["verrou"] = jours, verrou
        if jours is None:
            T("Domaine " + domaine, "Expiration", "inconnue (registre sans RDAP)")
        elif jours < 0:
            F("CRIT", "Le domaine {} a expiré".format(domaine), "Expiré depuis {} jour(s) : sites et e-mails vont s'arrêter, et le nom peut être racheté.".format(-jours),
              "Renouvelez-le immédiatement chez votre registraire")
        elif jours < 30:
            F("CRIT", "Le domaine {} expire dans {} jour(s)".format(domaine, jours), "", "Renouvelez-le et activez le renouvellement automatique")
        elif jours < 60:
            F("WARN", "Le domaine {} expire dans {} jours".format(domaine, jours), "", "Renouvelez-le et activez le renouvellement automatique")
        else:
            F("OK", "Domaine {} : enregistré pour encore {} jours".format(domaine, jours))
        if jours is not None:
            T("Domaine " + domaine, "Expiration", "dans {} jours".format(jours))
        if verrou is False:
            F("WARN", "Domaine {} : transfert non verrouillé".format(domaine),
              "Sans verrou, un transfert frauduleux vers un autre registraire est plus facile (après vol du compte ou du code d'autorisation).",
              "Activez le verrou de transfert (« transfer lock ») chez votre registraire")
        # DNSSEC et CAA
        info["dnssec"] = ad
        T("Domaine " + domaine, "DNSSEC", "@OK signé" if ad else "@WARN non signé")
        if not ad:
            F("INFO", "Domaine {} : DNS non signé (DNSSEC)".format(domaine),
              "Sans DNSSEC, une réponse DNS falsifiée (empoisonnement de cache) ne peut pas être détectée par les résolveurs.",
              "Activez DNSSEC chez votre hébergeur DNS (souvent un simple bouton, ex. Cloudflare › DNS › Paramètres)")
        try:
            caa = dns(domaine, "CAA")[2]
        except Echec:
            caa = []
        T("Domaine " + domaine, "CAA", liste(caa, 3) if caa else "@INFO aucun")
        if not caa:
            F("INFO", "Domaine {} : aucune autorité de certification désignée (CAA)".format(domaine),
              "N'importe quelle autorité peut émettre un certificat pour ce domaine.",
              "Ajoutez un enregistrement CAA, ex. `{} CAA 0 issue \"letsencrypt.org\"` (et celles de Cloudflare si le proxy est actif)".format(domaine))
        # Messagerie
        try:
            mx = dns(domaine, "MX")[2]
        except Echec:
            mx = []
        info["mx"] = mx
        spf = [t for t in txt(domaine) if t.lower().startswith("v=spf1")]
        dmarc = [t for t in txt("_dmarc." + domaine) if t.lower().startswith("v=dmarc1")]
        info["spf"], info["dmarc"] = spf, dmarc
        T("Domaine " + domaine, "MX (e-mails reçus)", liste(mx, 3) if mx else "aucun")
        T("Domaine " + domaine, "SPF", spf[0] if len(spf) == 1 else ("@WARN plusieurs" if spf else "@WARN absent"))
        T("Domaine " + domaine, "DMARC", dmarc[0] if dmarc else "@WARN absent")
        pol = re.search(r"\bp=(\w+)", dmarc[0]).group(1).lower() if dmarc and re.search(r"\bp=(\w+)", dmarc[0]) else ""
        nul_mx = mx == ["0 ."] or mx == ["0 ."]
        if mx and not nul_mx:
            if not spf:
                F("WARN", "Domaine {} : pas d'enregistrement SPF".format(domaine), "N'importe quel serveur peut envoyer des e-mails « de » ce domaine sans être repéré.",
                  "Publiez un SPF listant vos serveurs d'envoi, ex. `v=spf1 include:<votre fournisseur> -all`")
            elif len(spf) > 1:
                F("WARN", "Domaine {} : plusieurs enregistrements SPF".format(domaine), "\n".join(spf) + "\nPlusieurs SPF rendent le contrôle invalide (RFC 7208).",
                  "Fusionnez-les en un seul enregistrement")
            elif re.search(r"[+]all\b", spf[0]):
                F("CRIT", "Domaine {} : le SPF autorise tout le monde (+all)".format(domaine), spf[0], "Remplacez `+all` par `-all` (ou `~all`)")
            elif not re.search(r"[-~]all\b", spf[0]):
                F("WARN", "Domaine {} : SPF sans règle finale stricte".format(domaine), spf[0], "Terminez le SPF par `-all` (ou `~all` pendant une période de test)")
            if not dmarc:
                F("WARN", "Domaine {} : pas de politique DMARC".format(domaine),
                  "Sans DMARC, les messageries des destinataires ne savent pas quoi faire d'un e-mail usurpant votre domaine.",
                  "Publiez `_dmarc.{} TXT \"v=DMARC1; p=quarantine; rua=mailto:dmarc@{}\"`, puis passez à `p=reject`".format(domaine, domaine))
            elif pol == "none":
                F("WARN", "Domaine {} : DMARC en mode observation (p=none)".format(domaine), dmarc[0] + "\nLes e-mails usurpant votre domaine sont quand même livrés.",
                  "Passez à `p=quarantine`, puis `p=reject` une fois les rapports vérifiés")
            else:
                F("OK", "Domaine {} : SPF et DMARC en place (p={})".format(domaine, pol or "?"))
            selecteurs = [s for s in (a.selecteurs or "").split() if re.fullmatch(r"[A-Za-z0-9._-]{1,63}", s)] + SELECTEURS
            trouves = []
            for s in dict.fromkeys(selecteurs):
                if any("p=" in t for t in txt("{}._domainkey.{}".format(s, domaine))):
                    trouves.append(s)
                if len(trouves) >= 3:
                    break
            info["dkim"] = trouves
            T("Domaine " + domaine, "DKIM", ("sélecteur(s) " + ", ".join(trouves)) if trouves else "@INFO non trouvé")
            if not trouves:
                F("INFO", "Domaine {} : aucune clé DKIM trouvée".format(domaine),
                  "Sélecteurs essayés : {}. Votre fournisseur en utilise peut-être un autre.".format(liste(dict.fromkeys(selecteurs), 8)),
                  "Indiquez votre sélecteur DKIM dans Réglages › Domaines (il figure dans l'en-tête DKIM-Signature d'un e-mail envoyé, champ s=)")
            sts, rpt = txt("_mta-sts." + domaine), txt("_smtp._tls." + domaine)
            T("Domaine " + domaine, "MTA-STS / TLS-RPT", "{} / {}".format("oui" if sts else "non", "oui" if rpt else "non"))
            if not sts:
                F("INFO", "Domaine {} : MTA-STS non configuré".format(domaine),
                  "Sans MTA-STS, un attaquant placé sur le chemin peut forcer la réception de vos e-mails sans chiffrement.",
                  "Activez MTA-STS et TLS-RPT si votre hébergeur de messagerie le propose")
        else:
            protege = any(re.search(r"-all\b", s) for s in spf) and pol == "reject"
            if protege:
                F("OK", "Domaine {} : protégé contre l'usurpation (pas d'e-mail, SPF -all et DMARC reject)".format(domaine))
            else:
                F("WARN", "Domaine {} : sans e-mail, mais pas protégé contre l'usurpation".format(domaine),
                  "Le domaine ne reçoit pas d'e-mails ; un attaquant peut pourtant en envoyer « de » ce domaine (hameçonnage).",
                  "Publiez `v=spf1 -all`, `_dmarc.{} TXT \"v=DMARC1; p=reject\"` et un MX nul `0 .`".format(domaine))
        # Sous-domaines (journaux publics de certificats)
        noms = [domaine, "www." + domaine]
        if a.sous_domaines:
            trouves = sous_domaines(domaine)
            if trouves is None:
                F("INFO", "Domaine {} : liste des sous-domaines indisponible".format(domaine), "crt.sh (journaux publics de certificats) n'a pas répondu ; nouvel essai au prochain audit.")
            else:
                noms += trouves
        noms = list(dict.fromkeys(noms))[:150]
        with concurrent.futures.ThreadPoolExecutor(8) as ex:
            res = list(ex.map(lambda n: analyser_nom(n, ip_pub), noms))
        actifs = [r for r in res if r["ips"]]
        with concurrent.futures.ThreadPoolExecutor(8) as ex:
            certs = dict(zip([r["nom"] for r in actifs[:60]], ex.map(lambda r: certificat(r["nom"]), actifs[:60])))
        T("Sous-domaines de " + domaine, "Nom", "Adresse", "Cloudflare", "Certificat", "Remarque")
        for r in res:
            j, valide = certs.get(r["nom"], (None, None))
            r["cert_jours"], r["cert_valide"] = j, valide
            if not r["ips"] and not r["alerte"]:
                continue
            rem = {"prise": "@CRIT reprise possible", "pendant": "@WARN pointe vers un nom disparu"}.get(r["alerte"], "")
            if r["maison"] and not r["cloudflare"]:
                rem = rem or "@WARN adresse de la maison"
            if r["interne"]:
                rem = rem or "adresse interne"
            cert = "—" if j is None and valide is None else ("@CRIT expiré" if j is not None and j < 0 else
                                                             "@WARN invalide" if valide is False else "{} j".format(j) if j is not None else "?")
            T("Sous-domaines de " + domaine, r["nom"], liste(r["ips"], 2) or ("→ " + r["cname"] if r["cname"] else "—"), "oui" if r["cloudflare"] else "non", cert, rem)
        for r in res:
            if r["alerte"] == "prise":
                F("CRIT", "{} : sous-domaine pouvant être repris par un inconnu".format(r["nom"]),
                  "Il pointe ({}) vers une ressource {} qui n'existe plus : quelqu'un peut la recréer à son nom et publier ce qu'il veut sur votre sous-domaine.".format(r["cname"], r.get("service", "")),
                  "Supprimez l'enregistrement DNS de {} (ou recréez la ressource)".format(r["nom"]))
            elif r["alerte"] == "pendant":
                F("WARN", "{} : sous-domaine qui pointe vers un nom disparu".format(r["nom"]), "CNAME vers {} (inexistant).".format(r["cname"]),
                  "Supprimez cet enregistrement DNS s'il ne sert plus")
        maison = [r["nom"] for r in res if r["maison"] and not r["cloudflare"]]
        if maison:
            F("WARN", "Domaine {} : {} nom(s) révèlent l'adresse de la maison".format(domaine, len(maison)), liste(maison, 8) +
              "\nCes noms pointent directement vers votre adresse publique : elle devient connue, et les services derrière sont attaquables sans passer par Cloudflare.",
              "Activez le proxy Cloudflare (nuage orange) sur ces noms, ou supprimez-les s'ils ne servent plus")
        internes = [r["nom"] for r in res if r["interne"]]
        if internes:
            F("INFO", "Domaine {} : {} nom(s) public(s) pointent vers une adresse interne".format(domaine, len(internes)), liste(internes, 8) +
              "\nSans danger direct, mais cela décrit votre réseau à qui le demande.", "Gardez ces noms dans le DNS local (OPNsense) plutôt que dans le DNS public")
        exp = [(r["nom"], r["cert_jours"]) for r in res if r["cert_jours"] is not None and r["cert_jours"] < 14]
        for n, j in exp:
            F("CRIT" if j < 0 else "WARN", "{} : certificat HTTPS {}".format(n, "expiré" if j < 0 else "qui expire dans {} jour(s)".format(j)), "",
              "Vérifiez le renouvellement automatique (Let's Encrypt, proxy inverse ou Cloudflare)")
        inval = [r["nom"] for r in res if r["cert_valide"] is False]
        if inval:
            F("WARN", "Domaine {} : certificat HTTPS invalide sur {} nom(s)".format(domaine, len(inval)), liste(inval, 8) +
              "\nLe navigateur affiche une alerte : vos visiteurs prennent l'habitude de l'ignorer.", "Installez un certificat valide pour ces noms (ou retirez-les du DNS)")
        if a.sous_domaines and len(noms) > 2:
            F("INFO", "Domaine {} : {} sous-domaine(s) connus publiquement, {} en service".format(
                domaine, len([n for n in noms if n != domaine]), len([r for r in actifs if r["nom"] != domaine])),
              "Tous les noms pour lesquels un certificat a été émis sont publics (journaux de transparence des certificats) : un attaquant commence par là.")
        info["sous_domaines"] = res
        tout.append(info)
    inventaire("domaines", tout)


def main():
    global CACHE, INV
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--cache", default=CACHE)
    ap.add_argument("--inventaire", default="")
    sp = ap.add_subparsers(dest="cmd", required=True)
    p = sp.add_parser("paquets")
    p.add_argument("fichier")
    p.add_argument("--ecosysteme", default="Ubuntu:24.04:LTS")
    p = sp.add_parser("images")
    p.add_argument("dossier")
    p = sp.add_parser("lan")
    p.add_argument("xml")
    p.add_argument("--exposes", default="")
    p.add_argument("--nas", default="")
    p.add_argument("--nvd-cle", default=os.environ.get("AUDITE_MOI_NVD_CLE", ""))
    p.add_argument("--budget", type=int, default=240)
    p = sp.add_parser("internet")
    p.add_argument("ip", nargs="*")
    p = sp.add_parser("domaines")
    p.add_argument("domaines")
    p.add_argument("--selecteurs", default="")
    p.add_argument("--sous-domaines", action="store_true")
    p.add_argument("--ip-publique", default="")
    a = ap.parse_args()
    CACHE, INV = a.cache, a.inventaire or None
    {"paquets": cmd_paquets, "images": cmd_images, "lan": cmd_lan, "internet": cmd_internet, "domaines": cmd_domaines}[a.cmd](a)


if __name__ == "__main__":
    main()
