#!/usr/bin/env python3
"""Tests du service de réglages (audite-moi-configurer) : validation, écriture, secrets, journal."""
import importlib.util
import json
import os
import stat
import sys
import tempfile
import unittest
from importlib.machinery import SourceFileLoader
from unittest.mock import patch

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LOADER = SourceFileLoader("audite_moi_configurer", os.path.join(ROOT, "systemd", "audite-moi-configurer"))
cfg = importlib.util.module_from_spec(importlib.util.spec_from_loader(LOADER.name, LOADER))
LOADER.exec_module(cfg)

JETON = "123456789:AAH_un-jeton-de-test-assez-long-pour-le-format"
HASH = "pbkdf2_sha256$600000$c2VsLWRlLXRlc3QtMTIzNA==$" + "A" * 43 + "="


class TestValidation(unittest.TestCase):
    def test_domaines_et_reseaux(self):
        self.assertEqual(cfg.domaines("Nc.Exemple.fr, photos.exemple.fr nc.exemple.fr"), "nc.exemple.fr photos.exemple.fr")
        for mauvais in ("exemple", "a b;rm -rf /", 'x".fr', "-x.fr"):
            with self.assertRaises(cfg.Refus, msg=mauvais):
                cfg.domaines(mauvais)
        self.assertEqual(cfg.reseaux("192.168.1.7/24 10.0.0.0/22"), "192.168.1.0/24 10.0.0.0/22")
        for mauvais in ("10.0.0.0/16", "fd00::/64", "192.168.1.0/24;id", "abc"):
            with self.assertRaises(cfg.Refus, msg=mauvais):
                cfg.reseaux(mauvais)

    def test_urls(self):
        self.assertEqual(cfg.url("192.168.1.1"), "https://192.168.1.1")
        self.assertEqual(cfg.url("http://opnsense.lan:8443/"), "http://opnsense.lan:8443")
        self.assertEqual(cfg.url_interface("https://192.168.1.10:8765"), "https://192.168.1.10:8765/")
        for mauvais in ("https://a/b", "https://x.lan:99999", "javascript:alert(1)", 'https://a"b', "https://a b"):
            with self.assertRaises(cfg.Refus, msg=mauvais):
                cfg.url(mauvais)

    def test_sauvegardes(self):
        lignes = [{"nom": "photos", "type": "zfs", "cible": "usb/photos", "heures": "26"},
                  {"nom": "", "type": "zfs", "cible": "", "heures": ""},
                  {"nom": "cloud", "type": "unite", "cible": "restic-cloud.service", "heures": "26"},
                  {"nom": "dup", "type": "fichier", "cible": "/mnt/backup/dernier", "heures": "48"}]
        self.assertEqual(cfg.sauvegardes(lignes),
                         "photos:zfs:usb/photos:26 cloud:unite:restic-cloud.service:26 dup:fichier:/mnt/backup/dernier:48")
        self.assertEqual(cfg.lire_sauvegardes(cfg.sauvegardes(lignes))[2]["cible"], "/mnt/backup/dernier")
        for mauvaise in ({"nom": "a", "type": "fichier", "cible": "/mnt/a:b", "heures": "1"},
                         {"nom": "a", "type": "fichier", "cible": "/mnt/a b", "heures": "1"},
                         {"nom": "a", "type": "fichier", "cible": "relatif", "heures": "1"},
                         {"nom": "a", "type": "fichier", "cible": "/mnt/../etc", "heures": "1"},
                         {"nom": "a", "type": "zfs", "cible": "/usb", "heures": "1"},
                         {"nom": "a b", "type": "zfs", "cible": "usb", "heures": "1"},
                         {"nom": "a", "type": "autre", "cible": "usb", "heures": "1"},
                         {"nom": "a", "type": "zfs", "cible": "usb", "heures": "0"}):
            with self.assertRaises(cfg.Refus, msg=str(mauvaise)):
                cfg.sauvegardes([mauvaise])
        with self.assertRaises(cfg.Refus):
            cfg.sauvegardes([lignes[0], lignes[0]])          # nom en double

    def test_planning(self):
        for p, attendu in (({"actif": "oui", "frequence": "hebdomadaire", "jour": "mer", "heure": "03:15"}, "Wed *-*-* 03:15:00"),
                           ({"actif": "oui", "frequence": "quotidien", "heure": "23:59"}, "*-*-* 23:59:00"),
                           ({"actif": "non", "frequence": "mensuel", "jour_mois": "7", "heure": "00:00"}, "*-*-07 00:00:00")):
            pl = cfg.planning(p)
            self.assertEqual(cfg.oncalendar(pl), attendu)
            relu = cfg.lire_oncalendar(attendu)
            self.assertEqual((relu["frequence"], relu["heure"]), (pl["frequence"], pl["heure"]))
        for mauvais in ({"frequence": "horaire", "heure": "01:00"}, {"frequence": "quotidien", "heure": "24:00"},
                        {"frequence": "quotidien", "heure": "1:00\nOnCalendar=*"}, {"frequence": "mensuel", "jour_mois": "31", "heure": "01:00"},
                        {"frequence": "quotidien", "heure": "01:00", "garder": "2"}):
            with self.assertRaises(cfg.Refus, msg=str(mauvais)):
                cfg.planning(mauvais)

    def test_empreinte(self):
        self.assertEqual(cfg.hash_mdp(HASH), HASH)
        for mauvais in ("motdepasse", "pbkdf2_sha256$1000$" + "a" * 20 + "$" + "b" * 43, HASH + "\n"):
            with self.assertRaises(cfg.Refus):
                cfg.hash_mdp(mauvais)

    def test_modifier_conf(self):
        with tempfile.TemporaryDirectory() as d:
            c = os.path.join(d, "audit.conf")
            with open(c, "w") as f:
                f.write("# commentaire\nEXTERNE=oui\nSCAN_RESEAU=oui\n")
            cfg.modifier_conf(c, {"EXTERNE": "non", "DOMAINES_EXTRA": "a.fr"})
            texte = open(c).read()
            self.assertIn("# commentaire", texte)
            self.assertIn('EXTERNE="non"', texte)
            self.assertIn('DOMAINES_EXTRA="a.fr"', texte)
            self.assertEqual(stat.S_IMODE(os.stat(c).st_mode), 0o600)
            for v in ('a"; rm', "a\nB=1", "a\\", "$(id)", "`id`"):
                with self.assertRaises(cfg.Refus):
                    cfg.modifier_conf(c, {"DOMAINES_EXTRA": v})


class TestService(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        b = self.tmp.name
        self.conf, self.web, self.etat, self.sd = (os.path.join(b, "audit.conf"), os.path.join(b, "web.json"),
                                                   os.path.join(b, "etat"), os.path.join(b, "systemd"))
        os.mkdir(self.etat)
        with open(self.conf, "w") as f:
            f.write("# Audite-moi\nEXTERNE=oui\nSCAN_RESEAU=oui\nALERTES=oui\n")
        with open(self.web, "w") as f:
            json.dump({"ecoute": "0.0.0.0", "port": 8765, "mot_de_passe": "ancien", "tls_cert": "/x", "duree_session_h": 12}, f)
        os.chmod(self.web, 0o640)
        self.msgs = os.path.join(b, "telegram.txt")
        self.trace = os.path.join(b, "systemctl.txt")
        self.env = patch.dict(os.environ, {"AUDITE_MOI_TELEGRAM_FICHIER": self.msgs, "AUDITE_MOI_SYSTEMCTL_TRACE": self.trace})
        self.env.start()

    def tearDown(self):
        self.env.stop()
        self.tmp.cleanup()

    def lancer(self, action, valeurs=None, ident="demande-0001"):
        dem = os.path.join(self.tmp.name, "configurer")
        with open(dem, "w") as f:
            json.dump({"id": ident, "action": action, "valeurs": valeurs or {}, "par": "192.168.1.20"}, f)
        argv = ["x", "--demande", dem, "--etat", self.etat, "--conf", self.conf, "--web", self.web, "--systemd", self.sd, "--groupe", "nogroup"]
        with patch.object(sys, "argv", argv):
            cfg.main()
        self.assertFalse(os.path.exists(dem))
        with open(os.path.join(self.etat, "configuration-resultat.json")) as f:
            return json.load(f)

    def tout_le_texte(self):
        t = ""
        for n in os.listdir(self.etat):
            t += open(os.path.join(self.etat, n), encoding="utf-8").read()
        return t

    def test_telegram_secrets_jamais_exposes(self):
        with patch.object(cfg, "trouver_chat", return_value=("424242", "Olivier")):
            r = self.lancer("telegram", {"jeton": JETON, "chat_id": "", "alertes": "oui", "interface_url": "https://192.168.1.10:8765"})
        self.assertTrue(r["ok"], r)
        self.assertTrue(r["test_ok"])
        self.assertIn("Olivier", r["message"])
        c = cfg.lire_conf(self.conf)
        self.assertEqual((c["TELEGRAM_TOKEN"], c["TELEGRAM_CHAT_ID"], c["INTERFACE_URL"]), (JETON, "424242", "https://192.168.1.10:8765/"))
        self.assertNotIn(JETON, self.tout_le_texte())              # ni dans le résultat, ni le journal, ni la vue publique
        vue = json.load(open(os.path.join(self.etat, "configuration.json")))
        self.assertTrue(vue["telegram"]["jeton_defini"])
        msgs = open(self.msgs).read()
        self.assertIn("les alertes Telegram fonctionnent", msgs)
        self.assertIn("Réglages modifiés depuis l'interface", msgs)
        self.assertIn("192.168.1.20", msgs)
        # jeton laissé vide : conservé
        r = self.lancer("telegram", {"jeton": "", "chat_id": "424242", "alertes": "oui", "interface_url": ""}, "demande-0002")
        self.assertTrue(r["ok"], r)
        self.assertEqual(cfg.lire_conf(self.conf)["TELEGRAM_TOKEN"], JETON)

    def test_desactivation_signalee_avec_l_ancienne_configuration(self):
        cfg.modifier_conf(self.conf, {"TELEGRAM_TOKEN": JETON, "TELEGRAM_CHAT_ID": "1"})
        r = self.lancer("telegram-effacer")
        self.assertTrue(r["ok"])
        self.assertEqual(cfg.lire_conf(self.conf)["TELEGRAM_TOKEN"], "")
        self.assertIn("jeton effacé", open(self.msgs).read())
        self.assertEqual([n for n in os.listdir(self.etat) if n.startswith(".configuration-avant")], [])

    def test_telegram_sans_conversation(self):
        with patch.object(cfg, "trouver_chat", return_value=(None, "")):
            r = self.lancer("telegram", {"jeton": JETON, "alertes": "oui"})
        self.assertFalse(r["ok"])
        self.assertIn("envoyez-lui un message", r["message"])
        self.assertNotIn("TELEGRAM_TOKEN=\"1", open(self.conf).read())
        self.assertEqual(cfg.lire_conf(self.conf).get("TELEGRAM_TOKEN"), None)

    def test_opnsense(self):
        with patch.dict(os.environ, {"AUDITE_MOI_OPNSENSE_TEST": "401"}):
            r = self.lancer("opnsense", {"url": "192.168.1.1", "cle": "A" * 40, "secret": "b" * 60, "verifier_tls": "non"})
        self.assertTrue(r["ok"])
        self.assertFalse(r["test_ok"])
        self.assertIn("HTTP 401", r["message"])
        c = cfg.lire_conf(self.conf)
        self.assertEqual((c["OPNSENSE_URL"], c["OPNSENSE_VERIFIER_TLS"]), ("https://192.168.1.1", "non"))
        self.assertNotIn("b" * 60, self.tout_le_texte())
        vue = json.load(open(os.path.join(self.etat, "configuration.json")))["opnsense"]
        self.assertEqual((vue["cle_definie"], vue["cle_fin"], vue["secret_defini"]), (True, "AAAA", True))
        with patch.dict(os.environ, {"AUDITE_MOI_OPNSENSE_TEST": "200"}):
            r = self.lancer("opnsense-tester", ident="demande-0002")
        self.assertTrue(r["ok"])
        r = self.lancer("opnsense", {"url": "https://192.168.1.1", "cle": "", "secret": "x'y", "verifier_tls": "oui"}, "demande-0003")
        self.assertFalse(r["ok"])
        self.assertEqual(cfg.lire_conf(self.conf)["OPNSENSE_SECRET"], "b" * 60)

    def test_controles_et_sauvegardes(self):
        r = self.lancer("controles", {"externe": "non", "domaines_extra": "nc.exemple.fr", "scan_reseau": "oui", "scan_reseaux": "192.168.1.0/24"})
        self.assertTrue(r["ok"], r)
        r = self.lancer("sauvegardes", {"lignes": [{"nom": "p", "type": "zfs", "cible": "usb/p", "heures": "26"}]}, "demande-0002")
        self.assertTrue(r["ok"], r)
        c = cfg.lire_conf(self.conf)
        self.assertEqual((c["EXTERNE"], c["SCAN_RESEAUX"], c["SAUVEGARDES"]), ("non", "192.168.1.0/24", "p:zfs:usb/p:26"))
        vue = json.load(open(os.path.join(self.etat, "configuration.json")))
        self.assertFalse(vue["controles"]["externe"])
        self.assertEqual(vue["sauvegardes"][0]["cible"], "usb/p")
        journal = json.load(open(os.path.join(self.etat, "configuration-journal.json")))
        self.assertEqual([e["action"] for e in journal], ["controles", "sauvegardes"])

    def test_planification(self):
        r = self.lancer("planification", {"actif": "oui", "frequence": "quotidien", "heure": "02:30", "garder": "90"})
        self.assertTrue(r["ok"], r)
        t = open(os.path.join(self.sd, "audite-moi.timer.d", cfg.FICHIER_UNITE)).read()
        self.assertIn("OnCalendar=\nOnCalendar=*-*-* 02:30:00", t)
        self.assertIn("AUDITE_MOI_GARDER=90", open(os.path.join(self.sd, "audite-moi.service.d", cfg.FICHIER_UNITE)).read())
        self.assertIn("enable audite-moi.timer", open(self.trace).read())
        with patch.dict(os.environ, {"AUDITE_MOI_TIMER_ACTIF": "1"}):
            p = cfg.planning_actuel(self.sd)
        self.assertEqual((p["actif"], p["frequence"], p["heure"], p["garder"]), (True, "quotidien", "02:30", 90))
        r = self.lancer("planification", {"actif": "non", "frequence": "hebdomadaire", "jour": "dim", "heure": "04:00", "garder": "60"}, "demande-0002")
        self.assertIn("disable --now audite-moi.timer", open(self.trace).read())

    def test_interface(self):
        r = self.lancer("interface", {"duree_session_h": "24", "mot_de_passe": HASH})
        self.assertTrue(r["ok"], r)
        w = json.load(open(self.web))
        self.assertEqual((w["duree_session_h"], w["mot_de_passe"], w["port"]), (24, HASH, 8765))
        self.assertEqual(stat.S_IMODE(os.stat(self.web).st_mode), 0o640)
        self.assertIn("restart --no-block audite-moi-web.service", open(self.trace).read())
        self.assertNotIn(HASH, self.tout_le_texte())
        r = self.lancer("interface", {"mot_de_passe": "pas-une-empreinte"}, "demande-0002")
        self.assertFalse(r["ok"])
        self.assertEqual(json.load(open(self.web))["mot_de_passe"], HASH)

    def test_refus(self):
        r = self.lancer("executer", {"cmd": "id"})
        self.assertFalse(r["ok"])
        self.assertIn("inconnu", r["message"])
        r = self.lancer("controles", {}, ident="x")
        self.assertFalse(r["ok"])
        self.assertIn("Modification de réglage refusée", open(self.msgs).read() if os.path.exists(self.msgs) else "Modification de réglage refusée")


if __name__ == "__main__":
    unittest.main()
