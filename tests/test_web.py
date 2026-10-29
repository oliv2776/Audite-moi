#!/usr/bin/env python3
"""Tests de l'interface web d'Audite-moi (bibliothèque standard uniquement) :  python3 tests/test_web.py"""
import http.client
import importlib.util
import json
import os
import re
import tempfile
import threading
import time
import unittest
import urllib.parse

ICI = os.path.dirname(os.path.abspath(__file__))
spec = importlib.util.spec_from_file_location("web", os.path.join(ICI, "..", "web", "audite-moi-web.py"))
web = importlib.util.module_from_spec(spec)
spec.loader.exec_module(web)

MDP = "un-mot-de-passe-de-test"


def rapport(dossier, nom, t, sante, secu):
    d = {"version": "1.0.0", "hote": "nas-test", "date": "01/01/2026 à 10:00", "horodatage": t, "os": "Ubuntu", "noyau": "6.8",
         "duree_s": 42, "mode": "complet",
         "notes": {"sante": {"score": sante, "lettre": "C"}, "securite": {"score": secu, "lettre": "D"}},
         "compteurs": {"CRIT": 1, "WARN": 1, "OK": 3, "INFO": 2},
         "fichiers": {"html": nom + ".html", "txt": nom + ".txt", "json": nom + ".json"},
         "sections": {"ssh": {"titre": "SSH", "categorie": "secu"}},
         "constats": [{"section": "ssh", "niveau": "CRIT", "titre": "Titre <script>alert(1)</script>", "detail": "d", "correctif": "Faites `ceci`"},
                      {"section": "ssh", "niveau": "WARN", "titre": "Un avertissement", "detail": "", "correctif": ""}]}
    with open(os.path.join(dossier, nom + ".json"), "w", encoding="utf-8") as f:
        json.dump(d, f)
    with open(os.path.join(dossier, nom + ".html"), "w", encoding="utf-8") as f:
        f.write("<!DOCTYPE html><html><body><title>rapport</title></body></html>")
    with open(os.path.join(dossier, nom + ".txt"), "w", encoding="utf-8") as f:
        f.write("RAPPORT TEXTE <b>\n")


class TestInterface(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        base = cls.tmp.name
        for d in ("rapports", "demande", "etat"):
            os.mkdir(os.path.join(base, d))
        with open(os.path.join(base, "secret.txt"), "w") as f:
            f.write("ne doit pas sortir")
        rapport(os.path.join(base, "rapports"), "rapport-nas-test-20260101-1000", 1767258000, 55, 40)
        rapport(os.path.join(base, "rapports"), "rapport-nas-test-20260108-1000", 1767862800, 61, 47)
        conf = dict(web.DEFAUTS, ecoute="127.0.0.1", port=0, mot_de_passe=web.hacher(MDP, iterations=1000),
                    rapports=os.path.join(base, "rapports"), demandes=os.path.join(base, "demande"), etat=os.path.join(base, "etat"))
        cls.srv = web.Serveur(("127.0.0.1", 0), web.Gestionnaire)
        cls.srv.app = web.Application(conf)
        cls.port = cls.srv.server_address[1]
        threading.Thread(target=cls.srv.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()
        cls.tmp.cleanup()

    def req(self, methode, chemin, corps=None, cookie=None, entetes=None):
        c = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        h = {"Host": "127.0.0.1:%d" % self.port}
        if corps is not None:
            corps = urllib.parse.urlencode(corps)
            h["Content-Type"] = "application/x-www-form-urlencoded"
            h["Origin"] = "http://127.0.0.1:%d" % self.port
        if cookie:
            h["Cookie"] = cookie
        h.update(entetes or {})
        c.request(methode, chemin, body=corps, headers=h)
        r = c.getresponse()
        texte = r.read().decode("utf-8", "replace")
        c.close()
        return r, texte

    def connexion(self):
        r, _ = self.req("POST", "/connexion", {"mot_de_passe": MDP})
        self.assertEqual(r.status, 303)
        return r.getheader("Set-Cookie").split(";")[0]

    def test_hachage(self):
        h = web.hacher("abc")
        self.assertTrue(web.verifier("abc", h))
        self.assertFalse(web.verifier("abd", h))
        self.assertFalse(web.verifier("abc", "n'importe quoi"))

    def test_redirection_sans_session(self):
        r, _ = self.req("GET", "/")
        self.assertEqual(r.status, 303)
        self.assertEqual(r.getheader("Location"), "/connexion")
        r, _ = self.req("GET", "/rapports/rapport-nas-test-20260101-1000.html")
        self.assertEqual(r.status, 303)

    def test_mauvais_mot_de_passe(self):
        r, t = self.req("POST", "/connexion", {"mot_de_passe": "faux"}, entetes={"X-Test": "1"})
        self.assertIn(r.status, (401, 429))

    def test_tableau_de_bord(self):
        ck = self.connexion()
        r, t = self.req("GET", "/", cookie=ck)
        self.assertEqual(r.status, 200)
        self.assertIn("nas-test", t)
        self.assertIn("61", t)                                    # dernière note de santé
        self.assertIn("&lt;script&gt;alert(1)&lt;/script&gt;", t)  # contenu échappé
        self.assertIn("<code>ceci</code>", t)
        self.assertIn("<polyline", t)                             # graphique d'évolution (2 rapports)
        csp = r.getheader("Content-Security-Policy")
        self.assertIn("nonce-", csp)
        for nonce in re.findall(r'nonce="([^"]+)"', t):
            self.assertIn(nonce, csp)
        self.assertNotIn('style="', t)                            # aucun style en ligne (bloqué par la CSP)

    def test_rapports_et_traversee(self):
        ck = self.connexion()
        r, _ = self.req("GET", "/rapports/rapport-nas-test-20260101-1000.html", cookie=ck)
        self.assertEqual(r.status, 200)
        for mauvais in ("/rapports/..%2Fsecret.txt", "/rapports/../secret.txt", "/rapports/rapport-x-20260101-1000.html%00",
                        "/rapports/rapport-nas-test-20991231-0000.html"):
            r, t = self.req("GET", mauvais, cookie=ck)
            self.assertIn(r.status, (303, 404), mauvais)
            self.assertNotIn("ne doit pas sortir", t)

    def test_lancer_csrf_et_origine(self):
        ck = self.connexion()
        _, t = self.req("GET", "/", cookie=ck)
        csrf = re.search(r'name="csrf" value="([^"]+)"', t).group(1)
        r, _ = self.req("POST", "/lancer", {"mode": "rapide"}, cookie=ck)
        self.assertEqual(r.status, 403)
        r, _ = self.req("POST", "/lancer", {"mode": "rapide", "csrf": csrf}, cookie=ck, entetes={"Origin": "https://pirate.example"})
        self.assertEqual(r.status, 403)
        r, _ = self.req("POST", "/lancer", {"mode": "rapide", "csrf": csrf}, cookie=ck)
        self.assertEqual(r.status, 303)
        f = os.path.join(self.tmp.name, "demande", "lancer")
        with open(f) as fh:
            self.assertEqual(fh.read().strip(), "rapide")
        r, _ = self.req("POST", "/lancer", {"mode": "complet", "csrf": csrf}, cookie=ck)
        self.assertIn("m=occupe", r.getheader("Location"))
        r, t = self.req("GET", "/etat.json", cookie=ck)
        self.assertTrue(json.loads(t)["demande"])
        os.remove(f)

    def test_limite_tentatives(self):
        web_ip = "127.0.0.1"
        app = self.srv.app
        for _ in range(5):
            app.echec(web_ip)
        r, _ = self.req("POST", "/connexion", {"mot_de_passe": MDP})
        self.assertEqual(r.status, 429)
        app._echecs.clear()

    def test_navigation(self):
        ck = self.connexion()
        r, t = self.req("GET", "/rapports/rapport-nas-test-20260101-1000.html", cookie=ck)
        self.assertIn('href="/"', t)                               # barre de retour injectée dans le rapport
        r, t = self.req("GET", "/texte/rapport-nas-test-20260101-1000.txt", cookie=ck)
        self.assertEqual(r.status, 200)
        self.assertIn("RAPPORT TEXTE &lt;b&gt;", t)
        self.assertIn("Tableau de bord", t)
        r, _ = self.req("GET", "/texte/..%2Fsecret.txt", cookie=ck)
        self.assertEqual(r.status, 404)
        r, t = self.req("GET", "/?rapport=rapport-nas-test-20260101-1000.json", cookie=ck)
        self.assertIn("ancien rapport", t)
        self.assertIn('data-niv="CRIT"', t)
        self.assertIn('data-f="cat:sante"', t)                     # tuiles cliquables
        r, t = self.req("GET", "/?rapport=../../etc/passwd", cookie=ck)
        self.assertEqual(r.status, 200)
        self.assertNotIn("ancien rapport", t)

    def test_deconnexion(self):
        ck = self.connexion()
        _, t = self.req("GET", "/", cookie=ck)
        csrf = re.search(r'name="csrf" value="([^"]+)"', t).group(1)
        r, _ = self.req("POST", "/deconnexion", {"csrf": csrf}, cookie=ck)
        self.assertEqual(r.status, 303)
        r, _ = self.req("GET", "/", cookie=ck)
        self.assertEqual(r.getheader("Location"), "/connexion")


if __name__ == "__main__":
    unittest.main(verbosity=2)
