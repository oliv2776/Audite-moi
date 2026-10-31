#!/usr/bin/env python3
"""Tests du module d'analyse : vulnérabilités connues, vue depuis Internet, domaines (réseau simulé)."""
import json
import os
import subprocess
import sys
import tempfile
import unittest

ICI = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, ICI)
import http_simule  # noqa: E402

ANALYSE = os.path.join(os.path.dirname(ICI), "audite-moi-analyse.py")


class TestAnalyse(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.table = http_simule.ecrire(os.path.join(cls.tmp.name, "http"))

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def lancer(self, *args, env=None):
        inv = os.path.join(self.tmp.name, "inv")
        e = dict(os.environ, AUDITE_MOI_HTTP_MOCK=self.table, AUDITE_MOI_CERTS=json.dumps(http_simule.CERTS))
        e.update(env or {})
        p = subprocess.run([sys.executable, "-I", ANALYSE, "--cache", os.path.join(self.tmp.name, "cache"), "--inventaire", inv] + list(args),
                           capture_output=True, text=True, env=e, timeout=60)
        self.assertEqual(p.returncode, 0, p.stderr)
        constats = [l.split("\x1f")[1:] for l in p.stdout.splitlines() if l.startswith("F\x1f")]
        tables = [l.split("\x1f")[1:] for l in p.stdout.splitlines() if l.startswith("T\x1f")]
        return constats, tables, inv

    def titres(self, constats, niveau=None):
        return [c[1] for c in constats if niveau is None or c[0] == niveau]

    def test_paquets(self):
        f = os.path.join(self.tmp.name, "paquets.txt")
        with open(f, "w") as fh:
            fh.write("zlib 1:1.3.dfsg-3.1ubuntu2.1\nopenssl 3.0.13-0ubuntu3.5\n")
        c, t, inv = self.lancer("paquets", f)
        self.assertIn("1 faille(s) exploitée(s) activement, corrigée(s) par les mises à jour en attente", self.titres(c, "CRIT"))
        det = next(x[2] for x in c if x[0] == "CRIT")
        self.assertIn("CVE-2024-0001 (openssl)", det)
        lignes = [x[1] for x in t if x[0].startswith("Failles corrigées")]
        self.assertEqual(len(lignes), 3)                        # en-tête + CVE-2024-0001 + CVE-2024-0003 ; CVE-2024-0002 sans correctif
        self.assertTrue(lignes[1].startswith("CVE-2024-0001\topenssl\t92 %\t@CRIT oui"))
        self.assertEqual(json.load(open(os.path.join(inv, "paquets.json")))["exploitees"], ["CVE-2024-0001"])

    def test_images(self):
        d = os.path.join(self.tmp.name, "trivy")
        os.makedirs(d)
        with open(os.path.join(d, "0.json"), "w") as f:
            json.dump({"ArtifactName": "boa:latest", "Results": [{"Vulnerabilities": [
                {"VulnerabilityID": "CVE-2023-9999", "PkgName": "boa", "Severity": "CRITICAL"},
                {"VulnerabilityID": "CVE-2017-9833", "PkgName": "boa", "Severity": "HIGH"}]}]}, f)
        with open(os.path.join(d, "0.meta"), "w") as f:
            json.dump({"image": "boa:latest", "expose": "camera-web"}, f)
        c, t, inv = self.lancer("images", d)
        self.assertIn("Image boa:latest : 1 faille(s) exploitée(s) activement", self.titres(c, "CRIT"))   # exposée : critique
        i = json.load(open(os.path.join(inv, "images.json")))[0]
        self.assertEqual((i["critiques"], i["hautes"], i["exploitees"]), (1, 1, ["CVE-2023-9999"]))

    def test_lan(self):
        c, t, inv = self.lancer("lan", os.path.join(ICI, "fixtures", "nmap.xml"), "--exposes", "192.168.20.5:80", "--nas", "192.168.1.10")
        crit = self.titres(c, "CRIT")
        self.assertIn("192.168.20.5 (camera-entree) : Boa HTTPd 0.94.14rc21 sur le port 80 — 1 faille(s) exploitée(s) activement", crit)
        det = next(x[2] for x in c if x[1].startswith("192.168.20.5"))
        self.assertIn("redirigé depuis Internet", det)
        self.assertIn("1 appareil(s) administré(s) en HTTP non chiffré", self.titres(c, "INFO"))
        ap = {a["ip"]: a for a in json.load(open(os.path.join(inv, "appareils.json")))}
        self.assertEqual(ap["192.168.1.10"]["services"][0]["cpe"], "cpe:2.3:a:openbsd:openssh:9.6p1:*:*:*:*:*:*:*")
        self.assertEqual(ap["192.168.20.5"]["expose"], ["192.168.20.5:80"])

    def test_cpe(self):
        import importlib.util
        spec = importlib.util.spec_from_file_location("an", ANALYSE)
        an = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(an)
        self.assertIsNone(an.cpe23("cpe:/o:linux:linux_kernel"))      # sans version : trop vague
        self.assertIsNone(an.cpe23("cpe:/a:lighttpd:lighttpd"))
        self.assertEqual(an.cpe23("cpe:/a:openbsd:openssh:7.4"), "cpe:2.3:a:openbsd:openssh:7.4:*:*:*:*:*:*:*")

    def test_internet(self):
        c, t, inv = self.lancer("internet", "203.0.113.7", "2a01:e0a:1:2::10", "pas-une-ip")
        self.assertIn("Internet voit 2 port(s) ouvert(s) sur 203.0.113.7 : 22, 443", self.titres(c, "CRIT"))
        self.assertIn("Shodan associe 1 faille(s) connue(s) à 203.0.113.7, dont 1 exploitée(s) activement", self.titres(c, "CRIT"))
        self.assertIn("Shodan ne voit aucun port ouvert sur 2a01:e0a:1:2::10", self.titres(c, "OK"))
        self.assertEqual(len(json.load(open(os.path.join(inv, "internet.json")))), 2)

    def test_domaines(self):
        c, t, inv = self.lancer("domaines", "exemple.fr sansmail.fr inexistant-xyz.fr", "--sous-domaines", "--ip-publique", "203.0.113.7")
        crit, warn, info = self.titres(c, "CRIT"), self.titres(c, "WARN"), self.titres(c, "INFO")
        self.assertTrue(any(x.startswith("Le domaine exemple.fr expire dans 2") for x in crit), crit)
        self.assertIn("Domaine exemple.fr : transfert non verrouillé", warn)
        self.assertIn("Domaine exemple.fr : DMARC en mode observation (p=none)", warn)
        self.assertIn("Domaine exemple.fr : DNS non signé (DNSSEC)", info)
        self.assertIn("vieux.exemple.fr : sous-domaine pouvant être repris par un inconnu", crit)
        self.assertIn("blog.exemple.fr : sous-domaine pouvant être repris par un inconnu", crit)   # empreinte GitHub Pages
        self.assertIn("Domaine exemple.fr : 1 nom(s) révèlent l'adresse de la maison", warn)
        self.assertIn("exemple.fr : certificat HTTPS expiré", crit)
        self.assertIn("nc.exemple.fr : certificat HTTPS qui expire dans 5 jour(s)", warn)
        self.assertIn("Domaine exemple.fr : 1 nom(s) public(s) pointent vers une adresse interne", info)
        self.assertFalse(any("autre.org" in x for x in self.titres(c)))   # hors du domaine
        self.assertIn("Domaine sansmail.fr : sans e-mail, mais pas protégé contre l'usurpation", warn)
        self.assertNotIn("Domaine sansmail.fr : DNS non signé (DNSSEC)", info)
        self.assertIn("Le domaine inexistant-xyz.fr n'existe pas (ou plus) dans le DNS", crit)
        dkim = [x for x in t if x[0] == "Domaine exemple.fr" and x[1].startswith("DKIM")]
        self.assertEqual(dkim[0][1], "DKIM\tsélecteur(s) default")
        d = json.load(open(os.path.join(inv, "domaines.json")))
        self.assertEqual([x["domaine"] for x in d], ["exemple.fr", "sansmail.fr"])

    def test_hors_ligne(self):
        vide = os.path.join(self.tmp.name, "vide.json")
        with open(vide, "w") as f:
            json.dump({}, f)
        f = os.path.join(self.tmp.name, "p2.txt")
        with open(f, "w") as fh:
            fh.write("openssl 3.0.13-0ubuntu3.5\n")
        c, _, _ = self.lancer("paquets", f, env={"AUDITE_MOI_HTTP_MOCK": vide})
        self.assertEqual(self.titres(c), ["Base de vulnérabilités OSV injoignable"])   # jamais de faux « tout va bien »


if __name__ == "__main__":
    unittest.main()
