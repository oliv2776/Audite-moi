#!/usr/bin/env python3
"""Tests de l'interface web d'Audite-moi (bibliothèque standard uniquement) :  python3 tests/test_web.py"""
import gzip
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
         "constats": [{"section": "ssh", "niveau": "CRIT", "titre": "Titre <script>alert(1)</script>", "detail": "d", "correctif": "Faites `ceci`",
                       "actions": [{"type": "zfs-scrub", "cible": "stockage", "libelle": "Lancer un scrub", "apercu": "sudo zpool scrub stockage"}]},
                      {"section": "ssh", "niveau": "WARN", "titre": "Un avertissement", "detail": "", "correctif": ""}]}
    with open(os.path.join(dossier, nom + ".json"), "w", encoding="utf-8") as f:
        json.dump(d, f)
    with open(os.path.join(dossier, nom + ".html"), "w", encoding="utf-8") as f:
        f.write("<!DOCTYPE html><html><body><title>rapport</title></body></html>")
    with open(os.path.join(dossier, nom + ".txt"), "w", encoding="utf-8") as f:
        f.write("RAPPORT TEXTE <b>\n")


def ecrire(chemin, texte):
    os.makedirs(os.path.dirname(chemin), exist_ok=True)
    with open(chemin, "w", encoding="utf-8") as f:
        f.write(texte)


def faux_proc(base, stat="cpu  100 0 100 800 0 0 0 0\ncpu0 50 0 50 400 0 0 0 0\ncpu1 50 0 50 400 0 0 0 0\n"):
    p = os.path.join(base, "proc")
    ecrire(os.path.join(p, "stat"), stat)
    ecrire(os.path.join(p, "meminfo"), "MemTotal: 8000000 kB\nMemFree: 2000000 kB\nMemAvailable: 5000000 kB\nBuffers: 100000 kB\n"
                                        "Cached: 900000 kB\nSReclaimable: 0 kB\nSwapTotal: 0 kB\nSwapFree: 0 kB\n")
    ecrire(os.path.join(p, "spl", "kstat", "zfs", "arcstats"), "13 1 0x01\nname type data\nsize 4 2048000000\n")
    ecrire(os.path.join(p, "cpuinfo"), "model name\t: Intel(R) Core(TM) i5-13400\ncpu MHz\t\t: 2500.000\nmodel name\t: Intel(R) Core(TM) i5-13400\ncpu MHz\t\t: 3500.000\n")
    ecrire(os.path.join(p, "loadavg"), "0.50 0.40 0.30 1/200 1234\n")
    ecrire(os.path.join(p, "uptime"), "7200.00 1000.00\n")
    return p


def faux_sys(base):
    s = os.path.join(base, "sys")
    amd = os.path.join(base, "pci", "amd")
    for f, v in (("vendor", "0x1002"), ("device", "0x7340"), ("gpu_busy_percent", "42"), ("mem_info_vram_used", "1073741824"),
                 ("mem_info_vram_total", "8589934592"), ("hwmon/hwmon3/temp1_input", "55000"), ("hwmon/hwmon3/temp1_label", "edge"),
                 ("hwmon/hwmon3/power1_average", "30000000")):
        ecrire(os.path.join(amd, f), v)
    os.makedirs(os.path.join(amd, "drm", "renderD128"))
    os.makedirs(os.path.join(s, "class", "drm", "card1"))
    os.symlink(amd, os.path.join(s, "class", "drm", "card1", "device"))
    os.makedirs(os.path.join(s, "class", "drm", "card1-HDMI-A-1"))
    ecrire(os.path.join(s, "class", "hwmon", "hwmon0", "name"), "coretemp")
    ecrire(os.path.join(s, "class", "hwmon", "hwmon0", "temp1_input"), "47000")
    ecrire(os.path.join(s, "class", "hwmon", "hwmon0", "temp1_label"), "Package id 0")
    return s


class TestInterface(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        base = cls.tmp.name
        for d in ("rapports", "demande", "etat", "reglages"):
            os.mkdir(os.path.join(base, d))
        with open(os.path.join(base, "secret.txt"), "w") as f:
            f.write("ne doit pas sortir")
        rapport(os.path.join(base, "rapports"), "rapport-nas-test-20260101-1000", 1767258000, 55, 40)
        rapport(os.path.join(base, "rapports"), "rapport-nas-test-20260108-1000", 1767862800, 61, 47)
        cls.proc, cls.sys = faux_proc(base), faux_sys(base)
        with open(os.path.join(base, "etat", "mesures.json"), "w", encoding="utf-8") as f:
            json.dump({"horodatage": int(time.time()) - 120, "volumes": [],
                       "pools": [{"nom": "stockage<b>", "taille": 1000, "utilise": 850, "libre": 150, "etat": "ONLINE", "jeux": [],
                                  "disques": [{"disque": "sda", "role": "donnees", "etat": "ONLINE", "erreurs": [0, 0, 0]}]}],
                       "disques": [{"nom": "sda", "pool": "stockage<b>", "role": "donnees", "etat": "attention", "type": "HDD",
                                    "modele": "Disque <i>test</i>", "raisons": ["3 erreur(s) CRC"]}]}, f)
        conf = dict(web.DEFAUTS, ecoute="127.0.0.1", port=0, mot_de_passe=web.hacher(MDP, iterations=1000),
                    rapports=os.path.join(base, "rapports"), demandes=os.path.join(base, "demande"), etat=os.path.join(base, "etat"),
                    racine_proc=cls.proc, racine_sys=cls.sys, reglages=os.path.join(base, "reglages"), pci_ids=os.path.join(ICI, "fixtures", "pci.ids"))
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
        self.assertIn("À corriger en priorité", t)
        self.assertIn("<polyline", t)                             # graphique d'évolution (2 rapports)
        self.assertIn('<a href="/" aria-current="page">', t)        # barre latérale, page active
        self.assertIn('<span class="cpt" title="1 critique(s), 1 à surveiller">2</span>', t)
        r2, t2 = self.req("GET", "/constats", cookie=ck)
        self.assertEqual(r2.status, 200)
        self.assertIn("<code>ceci</code>", t2)
        self.assertIn('data-f="cat:sante"', t2)
        for page_ in ("/corrections", "/historique", "/reglages", "/reglages/journal", "/reglages/acceptes"):
            r2, t2 = self.req("GET", page_, cookie=ck)
            self.assertEqual(r2.status, 200, page_)
            self.assertNotIn('style="', t2, page_)
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
        r, _ = self.req("POST", "/lancer", {"mode": "rapide", "csrf": csrf}, cookie=ck, entetes={"Origin": "http://[adresse-invalide"})
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
        chemin = app._fichier_echecs()
        app._echecs.clear()
        try:
            os.unlink(chemin)
        except FileNotFoundError:
            pass
        for _ in range(5):
            app.echec(web_ip)
        self.assertTrue(app.bloque(web_ip))
        # Un nouveau processus recharge les échecs depuis le fichier privé.
        redemarre = web.Application(app.conf)
        self.assertTrue(redemarre.bloque(web_ip))
        r, _ = self.req("POST", "/connexion", {"mot_de_passe": MDP})
        self.assertEqual(r.status, 429)
        app._echecs.clear()
        try:
            os.unlink(chemin)
        except FileNotFoundError:
            pass

    def test_sessions_bornees(self):
        app = self.srv.app
        limite = app.MAX_SESSIONS
        app._sessions.clear()
        app.MAX_SESSIONS = 2
        try:
            a, _, c = app.nouvelle_session(), app.nouvelle_session(), app.nouvelle_session()
            self.assertEqual(len(app._sessions), 2)
            self.assertIsNone(app.session_valide(a))
            self.assertIsNotNone(app.session_valide(c))
        finally:
            app.MAX_SESSIONS = limite
            app._sessions.clear()

    def test_formulaire_longueur_invalide(self):
        r, _ = self.req("POST", "/connexion", None, entetes={"Content-Length": "-1"})
        self.assertEqual(r.status, 400)
        r, _ = self.req("POST", "/connexion", {"mot_de_passe": "x" * 17000})
        self.assertEqual(r.status, 413)

    def test_formulaire_trop_de_champs(self):
        corps = {"k{}".format(i): "v" for i in range(201)}
        r, _ = self.req("POST", "/connexion", corps)
        self.assertEqual(r.status, 400)

    def test_limite_connexions_simultanees(self):
        class ServeurSature(web.Serveur):
            MAX_THREADS = 0

        srv = ServeurSature(("127.0.0.1", 0), web.Gestionnaire)
        fil = threading.Thread(target=srv.serve_forever, daemon=True)
        fil.start()
        try:
            c = http.client.HTTPConnection("127.0.0.1", srv.server_address[1], timeout=5)
            c.request("GET", "/")
            r = c.getresponse()
            self.assertEqual(r.status, 503)
            self.assertEqual(r.read(), b"")
            c.close()
        finally:
            srv.shutdown()
            srv.server_close()
            fil.join(timeout=2)

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
        r, _ = self.req("GET", "/?rapport=rapport-nas-test-20260101-1000.json", cookie=ck)
        self.assertEqual(r.getheader("Location"), "/constats?rapport=rapport-nas-test-20260101-1000.json")   # ancien lien
        r, t = self.req("GET", "/constats?rapport=rapport-nas-test-20260101-1000.json", cookie=ck)
        self.assertIn("ancien rapport", t)
        self.assertIn('data-niv="CRIT"', t)
        self.assertIn('data-f="cat:sante"', t)                     # tuiles cliquables
        r, t = self.req("GET", "/constats?rapport=../../etc/passwd", cookie=ck)
        self.assertEqual(r.status, 200)
        self.assertNotIn("ancien rapport", t)

    def test_mesures_directes(self):
        m = self.srv.app.mesures
        m.echantillon()
        ecrire(os.path.join(self.proc, "stat"), "cpu  250 0 250 900 0 0 0 0\ncpu0 150 0 150 400 0 0 0 0\ncpu1 100 0 100 500 0 0 0 0\n")
        d = m.echantillon()
        self.assertEqual(d["cpu"]["pourcent"], 75.0)               # 300 actifs sur 400
        self.assertEqual(d["cpu"]["coeurs"], [100.0, 50.0])
        self.assertEqual(d["cpu"]["temperature"], 47)
        self.assertEqual(d["cpu"]["frequence"], 3000)
        self.assertEqual(d["cpu"]["modele"], "Intel Core i5-13400")
        mem = d["memoire"]
        self.assertEqual(mem["arc"], 2048000000)
        self.assertEqual(mem["applis"], (8000000 - 2000000 - 1000000) * 1024 - 2048000000)
        self.assertEqual(len(d["gpus"]), 1)                          # card1-HDMI-A-1 (connecteur) ignoré
        g = d["gpus"][0]
        self.assertEqual((g["marque"], g["occupation"], g["temperature"], g["puissance"], g["noeud"]), ("AMD", 42, 55, 30.0, "renderD128"))
        self.assertEqual(g["vram_totale"], 8589934592)
        self.assertEqual(g["nom"], "AMD Radeon RX 5500/5500M / Pro 5500M")

    def test_page_materiel(self):
        r, _ = self.req("GET", "/materiel.json")
        self.assertEqual(r.status, 401)
        cookie = self.connexion()
        r, t = self.req("GET", "/materiel", cookie=cookie)
        self.assertEqual(r.status, 200)
        csp = r.getheader("Content-Security-Policy")
        self.assertRegex(csp, r"script-src 'self' 'nonce-[^']+'")
        self.assertIn('<script src="{}" defer></script>'.format(web.statique("materiel.js")), t)
        self.assertIn('<link rel="stylesheet" href="{}">'.format(web.statique("app.css")), t)
        self.assertNotIn(' style="', t)
        self.assertNotIn("<style", t)
        self.assertNotIn("<b>", t.split('id="init">')[1].split("</script>")[0])   # données échappées dans le JSON embarqué
        self.assertIn('<a href="/materiel" aria-current="page">', t)
        r, t = self.req("GET", "/materiel.json", cookie=cookie)
        self.assertEqual(r.status, 200)
        d = json.loads(t)
        self.assertEqual(d["releve"]["pools"][0]["nom"], "stockage<b>")
        self.assertIsNotNone(d["direct"]["cpu"]["pourcent"])
        self.assertIn("demande", d)

    def test_fichiers_statiques(self):
        url = web.statique("app.css")
        self.assertRegex(url, r"^/static/app\.[0-9a-f]{12}\.css$")
        r, t = self.req("GET", url)                                  # sans session : contenu fixe, rien de sensible
        self.assertEqual(r.status, 200)
        self.assertEqual(r.getheader("Cache-Control"), "public, max-age=31536000, immutable")
        self.assertIn(".sidebar", t)
        etag = r.getheader("ETag")
        r, _ = self.req("GET", url, entetes={"If-None-Match": etag})
        self.assertEqual(r.status, 304)
        c = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        c.request("GET", web.statique("materiel.js"), headers={"Accept-Encoding": "gzip"})
        r = c.getresponse()
        brut = r.read()
        c.close()
        self.assertEqual(r.getheader("Content-Encoding"), "gzip")
        self.assertIn(b"use strict", gzip.decompress(brut))
        for mauvais in ("/static/app.css", "/static/app.000000000000.css", "/static/../web.json", "/static/"):
            r, _ = self.req("GET", mauvais)
            self.assertEqual(r.status, 404, mauvais)                  # seuls les noms avec empreinte sont servis

    def test_cache_des_rapports(self):
        d = web.Donnees({"rapports": self.tmp.name + "/cache-rapports"})
        os.mkdir(d.conf["rapports"])
        rapport(d.conf["rapports"], "rapport-nas-test-20260101-1000", 1767258000, 55, 40)
        premier = d.rapports()
        self.assertIs(d.rapports()[0], premier[0])                   # fichier inchangé : pas de relecture
        chemin = os.path.join(d.conf["rapports"], "rapport-nas-test-20260101-1000.json")
        with open(chemin, encoding="utf-8") as f:
            contenu = json.load(f)
        contenu["hote"] = "autre-nom-plus-long"
        with open(chemin, "w", encoding="utf-8") as f:
            json.dump(contenu, f)
        self.assertEqual(d.rapports()[0]["hote"], "autre-nom-plus-long")   # fichier modifié : relu
        os.remove(chemin)
        self.assertEqual(d.rapports(), [])
        self.assertEqual(d._cache, {})                              # rapport supprimé : oublié

    def test_tendances(self):
        h = os.path.join(self.tmp.name, "etat", "historique.jsonl")
        t = int(time.time())
        with open(h, "w") as f:
            for i in range(3):
                f.write(json.dumps({"t": t - (3 - i) * 3600, "pools": {"stockage<b>": [500 + i * 100, 1000]},
                                    "disques": {"sda": [40 + i, 0, 0], "sdz": [30, 0, 0]}}) + "\n")
            f.write("pas du json\n")
            f.write(json.dumps({"t": t - 400 * 86400, "pools": {"vieux": [1, 2]}}) + "\n")
        r, _ = self.req("GET", "/tendances.json")
        self.assertEqual(r.status, 401)
        cookie = self.connexion()
        _, txt = self.req("GET", "/tendances.json?jours=7", cookie=cookie)
        d = json.loads(txt)
        self.assertEqual(d["jours"], 7)
        self.assertEqual([v for _, v in d["remplissage"]["stockage<b>"]], [50.0, 60.0, 70.0])
        self.assertNotIn("vieux", d["remplissage"])
        self.assertEqual([v for _, v in d["temperatures"]["stockage<b>"]], [40, 41, 42])
        self.assertEqual(d["temperatures"]["autres disques"][0][1], 30)
        _, txt = self.req("GET", "/tendances.json?jours=abc", cookie=cookie)
        self.assertEqual(json.loads(txt)["jours"], 30)

    def test_reglages(self):
        cookie = self.connexion()
        r, t = self.req("GET", "/reglages", cookie=cookie)
        self.assertEqual(r.status, 200)
        self.assertIn('name="pool_attention"', t)
        self.assertNotIn(' style="', t)
        csrf = re.search(r'name="csrf" value="([^"]+)"', t).group(1)
        f = os.path.join(self.tmp.name, "reglages", "seuils.json")
        r, t = self.req("POST", "/reglages", {"csrf": csrf, "pool_attention": "85", "pool_critique": "84"}, cookie=cookie)
        self.assertEqual(r.status, 400)
        self.assertIn("Doit être supérieur à 85", t)
        self.assertFalse(os.path.exists(f))
        r, _ = self.req("POST", "/reglages", {"csrf": csrf, "scrub_max_jours": "9999"}, cookie=cookie)
        self.assertEqual(r.status, 400)
        r, _ = self.req("POST", "/reglages", {"csrf": csrf, "scrub_max_jours": "abc"}, cookie=cookie)
        self.assertEqual(r.status, 400)
        r, _ = self.req("POST", "/reglages", {"csrf": "faux", "pool_attention": "85"}, cookie=cookie)
        self.assertEqual(r.status, 403)
        r, _ = self.req("POST", "/reglages", {"csrf": csrf, "pool_attention": "85", "pool_critique": "95", "disque_temp_hdd_attention": "50", "inconnu": "3"}, cookie=cookie)
        self.assertEqual(r.status, 303)
        self.assertEqual(json.load(open(f)), {"pool_attention": 85, "pool_critique": 95})      # seulement ce qui diffère du défaut
        _, t = self.req("GET", "/materiel.json", cookie=cookie)
        self.assertEqual(json.loads(t)["seuils"]["pool_critique"], 95)
        _, t = self.req("GET", "/reglages", cookie=cookie)
        self.assertIn("2 seuil(s) personnalisé(s)", t)
        self.req("POST", "/reglages", {"csrf": csrf}, cookie=cookie)                           # champs vides : valeurs par défaut
        self.assertEqual(json.load(open(f)), {})

    def test_mesurer_csrf(self):
        cookie = self.connexion()
        r, _ = self.req("POST", "/mesurer", {"csrf": "faux"}, cookie=cookie)
        self.assertEqual(r.status, 403)
        _, t = self.req("GET", "/materiel", cookie=cookie)
        csrf = re.search(r'name="csrf" value="([^"]+)"', t).group(1)
        r, _ = self.req("POST", "/mesurer", {"csrf": csrf}, cookie=cookie)
        self.assertEqual(r.status, 202)
        self.assertTrue(os.path.exists(os.path.join(self.tmp.name, "demande", "mesurer")))
        _, t = self.req("GET", "/materiel.json", cookie=cookie)
        self.assertTrue(json.loads(t)["demande"])

    def csrf_de(self, cookie):
        _, t = self.req("GET", "/constats", cookie=cookie)
        return re.search(r'name="csrf" value="([^"]+)"', t).group(1), t

    def test_nouveaux_et_resolus(self):
        cookie = self.connexion()
        _, t = self.req("GET", "/", cookie=cookie)
        self.assertIn("Rien de nouveau depuis l’audit du", t)        # deux rapports aux constats identiques

    def test_accepter(self):
        cookie = self.connexion()
        csrf, t = self.csrf_de(cookie)
        cle = "ssh|Un avertissement"
        self.assertIn('data-cle="{}"'.format(cle), t)
        r, _ = self.req("POST", "/accepter", {"csrf": csrf, "cle": "inexistant", "raison": "x"}, cookie=cookie)
        self.assertIn("corr-invalide", r.getheader("Location"))
        r, _ = self.req("POST", "/accepter", {"csrf": csrf, "cle": cle, "raison": "  voulu   ici "}, cookie=cookie)
        self.assertIn("m=accepte", r.getheader("Location"))
        acc = json.load(open(os.path.join(self.tmp.name, "reglages", "acceptes.json")))
        self.assertEqual(acc[cle]["raison"], "voulu ici")
        _, t = self.req("GET", "/constats", cookie=cookie)
        self.assertIn('data-niv="ACC"', t)
        self.assertIn('<div class="v">0</div><div class="l">À surveiller', t)   # le constat accepté ne compte plus
        _, t = self.req("GET", "/reglages/acceptes", cookie=cookie)
        self.assertIn("voulu ici", t)
        r, _ = self.req("POST", "/accepter", {"csrf": csrf, "cle": cle, "retirer": "1", "retour": "acceptes"}, cookie=cookie)
        self.assertEqual(r.getheader("Location"), "/reglages/acceptes?m=retire")
        self.assertNotIn(cle, json.load(open(os.path.join(self.tmp.name, "reglages", "acceptes.json"))))

    def test_corriger(self):
        cookie = self.connexion()
        csrf, t = self.csrf_de(cookie)
        dem = os.path.join(self.tmp.name, "demande", "corriger")
        m = re.search(r'data-dlg="corriger" data-cle="([^"]+)" data-i="0" data-rapport="([^"]+)"', t)
        self.assertIsNotNone(m)
        cle, rap = web.html.unescape(m.group(1)), m.group(2)
        self.assertEqual(rap, "rapport-nas-test-20260108-1000.json")
        base = {"csrf": csrf, "cle": cle, "i": "0", "rapport": rap}
        r, _ = self.req("POST", "/corriger", dict(base, mot_de_passe="faux"), cookie=cookie)
        self.assertIn("m=mdp", r.getheader("Location"))
        self.assertFalse(os.path.exists(dem))
        for mauvais in ({"i": "-1"}, {"i": "5"}, {"rapport": "rapport-nas-test-20260101-1000.json"}, {"cle": "ssh|autre"}):
            r, _ = self.req("POST", "/corriger", dict(base, mot_de_passe=MDP, **mauvais), cookie=cookie)
            self.assertIn("corr-invalide", r.getheader("Location"), mauvais)
            self.assertFalse(os.path.exists(dem))
        r, _ = self.req("POST", "/corriger", dict(base, mot_de_passe=MDP), cookie=cookie)
        self.assertIn("m=correction", r.getheader("Location"))
        d = json.load(open(dem))
        self.assertEqual((d["type"], d["cible"]), ("zfs-scrub", "stockage"))   # repris du rapport, jamais du formulaire
        r, _ = self.req("POST", "/corriger", dict(base, mot_de_passe=MDP), cookie=cookie)
        self.assertIn("corr-occupe", r.getheader("Location"))
        os.remove(dem)
        with open(os.path.join(self.tmp.name, "etat", "corrections.json"), "w") as f:
            json.dump([{"id": d["id"], "date": int(time.time()), "type": "zfs-scrub", "cible": "stockage", "libelle": "Scrub", "ok": True,
                        "annulation": [["zpool", "scrub", "-s", "stockage"]]}], f)
        _, t = self.req("GET", "/constats", cookie=cookie)
        self.assertIn("corrigé le", t)
        _, t = self.req("GET", "/corrections", cookie=cookie)
        self.assertIn('data-dlg="annuler"', t)
        r, _ = self.req("POST", "/annuler", {"csrf": csrf, "id": d["id"], "mot_de_passe": MDP}, cookie=cookie)
        self.assertIn("m=correction", r.getheader("Location"))
        self.assertEqual(json.load(open(dem))["annuler"], d["id"])
        os.remove(dem)

    def test_reglages_serveur(self):
        cookie = self.connexion()
        etat, dem = os.path.join(self.tmp.name, "etat"), os.path.join(self.tmp.name, "demande", "configurer")
        vue = os.path.join(etat, "configuration.json")
        if os.path.exists(vue):
            os.remove(vue)
        _, t = self.req("GET", "/reglages/telegram", cookie=cookie)
        self.assertIn("pas encore lisibles", t)                  # service root pas encore passé
        with open(vue, "w") as f:
            json.dump({"controles": {"externe": True, "domaines_extra": "", "scan_reseau": True, "scan_reseaux": ""}, "sauvegardes": [],
                       "opnsense": {"url": "", "cle_definie": False, "cle_fin": "", "secret_defini": False, "verifier_tls": True},
                       "telegram": {"jeton_defini": True, "chat_id": "42", "alertes": True, "interface_url": ""},
                       "planification": {"actif": True, "frequence": "hebdomadaire", "jour": "lun", "jour_mois": 1, "heure": "07:20", "garder": 60},
                       "interface": {}}, f)
        for onglet in ("controles", "domaines", "vulnerabilites", "sauvegardes", "opnsense", "telegram", "planification", "interface"):
            r, t = self.req("GET", "/reglages/" + onglet, cookie=cookie)
            self.assertEqual(r.status, 200, onglet)
            self.assertIn('aria-current="page">', t)
        csrf = re.search(r'name="csrf" value="([^"]+)"', t).group(1)
        base = {"csrf": csrf, "externe": "oui", "domaines_extra": "nc.exemple.fr", "scan_reseau": "oui", "scan_reseaux": "192.168.1.0/24"}
        r, t = self.req("POST", "/reglages/controles", dict(base, mot_de_passe="faux"), cookie=cookie)
        self.assertEqual(r.status, 403)
        self.assertIn("mot de passe incorrect", t)
        self.assertFalse(os.path.exists(dem))
        r, t = self.req("POST", "/reglages/controles", dict(base, scan_reseaux="10.0.0.0/8", mot_de_passe=MDP), cookie=cookie)
        self.assertEqual(r.status, 400)
        self.assertIn("réseau trop grand", t)
        self.assertIn('value="10.0.0.0/8"', t)                     # saisie conservée
        self.assertFalse(os.path.exists(dem))
        r, _ = self.req("POST", "/reglages/controles", base, cookie=cookie)
        self.assertEqual(r.status, 403)                            # mot de passe obligatoire
        r, _ = self.req("POST", "/reglages/controles", dict(base, mot_de_passe=MDP), cookie=cookie)
        self.assertEqual(r.status, 303)
        ident = r.getheader("Location").rsplit("=", 1)[1]
        self.assertEqual(r.getheader("Location"), "/reglages/controles?attente=" + ident)
        self.assertEqual(oct(os.stat(dem).st_mode & 0o777), "0o600")
        d = json.load(open(dem))
        self.assertEqual((d["action"], d["valeurs"]["scan_reseaux"], d["id"]), ("controles", "192.168.1.0/24", ident))
        r, _ = self.req("POST", "/reglages/controles", dict(base, mot_de_passe=MDP), cookie=cookie)
        self.assertEqual(r.status, 409)                            # un réglage à la fois
        _, t = self.req("GET", "/reglages/resultat.json?id=" + ident, cookie=cookie)
        self.assertFalse(json.loads(t)["fait"])
        os.remove(dem)
        with open(os.path.join(etat, "configuration-resultat.json"), "w") as f:
            json.dump({"id": ident, "ok": True, "libelle": "Contrôles réseau", "message": "Enregistré <b>"}, f)
        _, t = self.req("GET", "/reglages/resultat.json?id=" + ident, cookie=cookie)
        self.assertTrue(json.loads(t)["fait"])
        _, t = self.req("GET", "/reglages/controles?r=" + ident, cookie=cookie)
        self.assertIn("Enregistré &lt;b&gt;", t)
        # domaines : saisie validée avant envoi
        r, t = self.req("POST", "/reglages/domaines", {"csrf": csrf, "domaines": "exemple.fr pas_un_domaine", "mot_de_passe": MDP}, cookie=cookie)
        self.assertEqual(r.status, 400)
        self.assertIn("hôte invalide : pas_un_domaine", t)
        r, _ = self.req("POST", "/reglages/domaines", {"csrf": csrf, "domaines": "exemple.fr", "sous_domaines": "oui", "mot_de_passe": MDP}, cookie=cookie)
        self.assertEqual(r.status, 303)
        self.assertEqual(json.load(open(dem))["valeurs"], {"domaines": "exemple.fr", "selecteurs": "", "sous_domaines": "oui"})
        os.remove(dem)
        # test Telegram : sans mot de passe, rien n'est modifié
        r, _ = self.req("POST", "/reglages/telegram-tester", {"csrf": csrf}, cookie=cookie)
        self.assertEqual(r.status, 303)
        self.assertEqual(json.load(open(dem))["action"], "telegram-tester")
        os.remove(dem)
        # mot de passe de l'interface
        mdp = {"csrf": csrf, "actuel": MDP, "nouveau": "nouveau-mot-de-passe", "confirmation": "nouveau-mot-de-passe"}
        r, t = self.req("POST", "/reglages/mot-de-passe", dict(mdp, nouveau="court", confirmation="court"), cookie=cookie)
        self.assertEqual(r.status, 400)
        self.assertIn("12 caractères au moins", t)
        self.assertNotIn('value="court"', t)                       # un mot de passe n'est jamais réaffiché
        r, _ = self.req("POST", "/reglages/mot-de-passe", dict(mdp, confirmation="autre-mot-de-passe"), cookie=cookie)
        self.assertEqual(r.status, 400)
        r, _ = self.req("POST", "/reglages/mot-de-passe", mdp, cookie=cookie)
        self.assertEqual(r.status, 303)
        h = json.load(open(dem))["valeurs"]["mot_de_passe"]
        self.assertTrue(web.verifier("nouveau-mot-de-passe", h))
        self.assertNotIn("nouveau-mot-de-passe", open(dem).read())
        os.remove(dem)
        r, _ = self.req("POST", "/reglages/executer", {"csrf": csrf, "mot_de_passe": MDP}, cookie=cookie)
        self.assertEqual(r.status, 404)
        r, _ = self.req("POST", "/reglages/controles", dict(base, csrf="faux", mot_de_passe=MDP), cookie=cookie)
        self.assertEqual(r.status, 403)
        self.srv.app._echecs.clear()

    def test_inventaire(self):
        cookie = self.connexion()
        _, t = self.req("GET", "/inventaire", cookie=cookie)
        self.assertIn("pas encore d’inventaire", t)
        f = os.path.join(self.tmp.name, "rapports", "rapport-nas-test-20260108-1000.json")
        d = json.load(open(f))
        d["inventaire"] = {"serveur": {"hote": "nas-test", "ip": ["192.168.1.10"], "ip_publique": "203.0.113.7"},
                           "internet": [{"ip": "203.0.113.7", "ports": [22], "vulns": ["CVE-2023-9999"]}],
                           "conteneurs": [{"nom": "web<b>", "image": "boa:1", "etat": "running", "ports": ["0.0.0.0:80 → 80/tcp"], "internet": True}],
                           "images": [{"image": "boa:1", "critiques": 1, "hautes": 0, "exploitees": ["CVE-2023-9999"]}],
                           "appareils": [{"ip": "192.168.20.5", "nom": "camera", "fabricant": "", "expose": ["192.168.20.5:80"], "services": [
                               {"port": 80, "service": "http", "produit": "Boa", "version": "0.94", "failles": 2, "exploitees": ["CVE-2023-9999"]}]}],
                           "domaines": [{"domaine": "exemple.fr", "expiration_jours": 20, "verrou": False, "dnssec": False, "mx": [], "spf": [], "dmarc": [],
                                         "sous_domaines": [{"nom": "vieux.exemple.fr", "ips": [], "cname": "x.herokuapp.com", "alerte": "prise"}]}]}
        json.dump(d, open(f, "w"))
        try:
            _, t = self.req("GET", "/inventaire", cookie=cookie)
            self.assertIn('<a href="/inventaire" aria-current="page">', t)
            self.assertIn("web&lt;b&gt;", t)                        # échappé
            self.assertIn("reprise possible", t)
            self.assertIn('<div class="v">1</div><div class="l">Failles exploitées activement', t)
            self.assertIn("Boa 0.94", t)
            self.assertNotIn('style="', t)
        finally:
            del d["inventaire"]
            json.dump(d, open(f, "w"))

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
