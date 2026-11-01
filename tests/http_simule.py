"""Réponses simulées des services publics interrogés par audite-moi-analyse.py (aucun accès réseau pendant les tests).

ecrire(dossier, ip_publique) crée les fichiers et renvoie le chemin de la table à passer dans AUDITE_MOI_HTTP_MOCK.
"""
import datetime
import json
import os


def ecrire(dossier, ip_publique="203.0.113.7"):
    os.makedirs(dossier, exist_ok=True)
    table = {}

    def rep(morceau, donnees, status=200):
        nom = "r{}.json".format(len(table))
        with open(os.path.join(dossier, nom), "w", encoding="utf-8") as f:
            f.write(donnees if isinstance(donnees, str) else json.dumps(donnees))
        table[morceau] = {"status": status, "fichier": nom}

    def dns(nom, typ, reponses=(), status=0, ad=False, cname=None):
        code = {"A": 1, "NS": 2, "CNAME": 5, "MX": 15, "TXT": 16, "AAAA": 28, "CAA": 257}[typ]
        rr = ([{"name": nom, "type": 5, "data": cname + "."}] if cname else []) + [{"name": nom, "type": code, "data": d} for d in reponses]
        rep("name={}&type={}&".format(nom, typ), {"Status": status, "AD": ad, "Answer": rr})

    # --- paquets (OSV), catalogue KEV, EPSS
    # une seule réponse (premier paquet demandé, « openssl ») : UBUNTU-CVE-2024-0002 concerne curl et doit être écartée
    rep("api.osv.dev/v1/querybatch", {"results": [{"vulns": [{"id": "UBUNTU-CVE-2024-0002"}, {"id": "UBUNTU-CVE-2024-0001"}, {"id": "USN-7000-1"}]}]})
    rep("api.osv.dev/v1/vulns/UBUNTU-CVE-2024-0001", {"id": "UBUNTU-CVE-2024-0001", "upstream": ["CVE-2024-0001"], "affected": [
        {"package": {"name": "openssl"}, "ranges": [{"events": [{"introduced": "0"}, {"fixed": "3.0.13-0ubuntu3.6"}]}]}]})
    rep("api.osv.dev/v1/vulns/USN-7000-1", {"id": "USN-7000-1", "upstream": ["CVE-2024-0003"], "affected": [
        {"package": {"name": "openssl"}, "ranges": [{"events": [{"introduced": "0"}, {"fixed": "3.0.13-0ubuntu3.6"}]}]}]})
    rep("api.osv.dev/v1/vulns/UBUNTU-CVE-2024-0002", {"id": "UBUNTU-CVE-2024-0002", "upstream": ["CVE-2024-0002"], "affected": [
        {"package": {"name": "curl"}, "ranges": [{"events": [{"introduced": "0"}]}]}]})
    rep("known_exploited_vulnerabilities.json", {"vulnerabilities": [
        {"cveID": "CVE-2024-0001", "vulnerabilityName": "OpenSSL : faille d'exemple exploitée"},
        {"cveID": "CVE-2023-9999", "vulnerabilityName": "Boa : dépassement de tampon d'exemple"}]})
    rep("api.first.org/data/v1/epss", {"data": [{"cve": "CVE-2024-0003", "epss": "0.35"}, {"cve": "CVE-2024-0001", "epss": "0.92"}]})
    # --- services du réseau (NVD)
    rep("virtualMatchString=cpe%3A2.3%3Aa%3Aboa%3Aboa%3A0.94.14rc21", {"vulnerabilities": [
        {"cve": {"id": "CVE-2023-9999", "cisaExploitAdd": "2023-01-01", "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 9.8}}]}}},
        {"cve": {"id": "CVE-2017-9833", "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 7.5}}]}}}]})
    rep("services.nvd.nist.gov", {"vulnerabilities": []})
    # --- vue depuis Internet
    rep("internetdb.shodan.io/" + ip_publique, {"ip": ip_publique, "ports": [22, 443], "vulns": ["CVE-2023-9999"], "tags": [], "hostnames": ["box.fai.example"]})
    rep("internetdb.shodan.io/", {"detail": "No information available"}, 404)
    # --- domaine exemple.fr (avec e-mails) et sansmail.fr (sans)
    fin = (datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=20, hours=12)).strftime("%Y-%m-%dT%H:%M:%SZ")
    rep("rdap.org/domain/exemple.fr", {"events": [{"eventAction": "expiration", "eventDate": fin}], "status": ["active"]})
    rep("rdap.org/domain/", {}, 404)
    rep("crt.sh/", [{"name_value": "exemple.fr\nwww.exemple.fr"}, {"name_value": "*.exemple.fr\nnc.exemple.fr"},
                    {"name_value": "vieux.exemple.fr"}, {"name_value": "blog.exemple.fr"}, {"name_value": "interne.exemple.fr\nautre.org"}])
    rep("https://blog.exemple.fr/", "<h1>404</h1><p>There isn't a GitHub Pages site here.</p>")
    dns("exemple.fr", "NS", ["ns1.hebergeur.example.", "ns2.hebergeur.example."])
    dns("exemple.fr", "MX", ["10 mx.hebergeur.example."])
    dns("exemple.fr", "TXT", ['"v=spf1 include:_spf.hebergeur.example ~all"', '"google-site-verification=x"'])
    dns("_dmarc.exemple.fr", "TXT", ['"v=DMARC1; p=none; rua=mailto:dmarc@exemple.fr"'])
    dns("default._domainkey.exemple.fr", "TXT", ['"v=DKIM1; k=rsa; p=MIIBIjAN"'])
    dns("exemple.fr", "A", ["104.16.1.2"])
    dns("www.exemple.fr", "A", ["104.16.1.1"])
    dns("nc.exemple.fr", "A", [ip_publique])
    dns("vieux.exemple.fr", "A", [], status=3, cname="vieux-site.herokuapp.com")
    dns("blog.exemple.fr", "A", ["185.199.108.153"], cname="olivier.github.io")
    dns("interne.exemple.fr", "A", ["192.168.1.10"])
    dns("sansmail.fr", "NS", ["ns1.hebergeur.example."], ad=True)
    dns("sansmail.fr", "CAA", ['0 issue "letsencrypt.org"'])
    dns("sansmail.fr", "TXT", ['"v=spf1 -all"'])
    dns("inexistant-xyz.fr", "NS", [], status=3)
    rep("cloudflare-dns.com/dns-query", {"Status": 0, "AD": False, "Answer": []})   # tout le reste : aucune réponse
    chemin = os.path.join(dossier, "table.json")
    with open(chemin, "w", encoding="utf-8") as f:
        json.dump(table, f, indent=1)
    return chemin


CERTS = {"exemple.fr": [-2, True], "www.exemple.fr": [80, True], "nc.exemple.fr": [5, True], "blog.exemple.fr": [None, False]}
