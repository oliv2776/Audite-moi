#!/usr/bin/env python3
"""Tests de robustesse de l'inventaire SMART et des alertes de disparition."""
import importlib.util
import json
import os
import tempfile
import unittest
from unittest.mock import patch

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
# Le script de mesures n'a volontairement pas d'extension .py.
# Charger explicitement son code source évite que spec_from_file_location()
# ne retourne aucun chargeur selon la version de Python.
from importlib.machinery import SourceFileLoader

MODULE_PATH = os.path.join(ROOT, "systemd", "audite-moi-mesures")
LOADER = SourceFileLoader("audite_moi_mesures", MODULE_PATH)
SPEC = importlib.util.spec_from_loader(LOADER.name, LOADER)
mesures = importlib.util.module_from_spec(SPEC)
LOADER.exec_module(mesures)


class TestInventaireSMART(unittest.TestCase):
    def setUp(self):
        self.precedent = {"disques": [
            {"nom": "sda", "etat": "ok", "modele": "Disque test", "crc": 0}
        ]}

    def test_echec_commande_conserve_dernieres_mesures(self):
        with patch.object(mesures, "cmd", return_value=(1, "")):
            disques, scan_ok = mesures.disques({}, self.precedent, 123456)
        self.assertFalse(scan_ok)
        self.assertEqual(len(disques), 1)
        self.assertEqual(disques[0]["nom"], "sda")
        self.assertTrue(disques[0]["donnees_perimees"])
        self.assertIn("indisponible", disques[0]["raison_peremption"])

    def test_json_invalide_ne_signale_pas_tous_les_disques_absents(self):
        with patch.object(mesures, "cmd", return_value=(0, "{json invalide")):
            disques, scan_ok = mesures.disques({}, self.precedent, 123456)
        self.assertFalse(scan_ok)
        self.assertEqual([d["nom"] for d in disques], ["sda"])
        self.assertTrue(disques[0]["donnees_perimees"])

    def test_inventaire_valide_vide_est_distinct_d_un_echec(self):
        with patch.object(mesures, "cmd", return_value=(0, json.dumps({"devices": []}))):
            disques, scan_ok = mesures.disques({}, self.precedent, 123456)
        self.assertTrue(scan_ok)
        self.assertEqual(disques, [])

    def test_echec_inventaire_ne_declenche_pas_alerte_disque_absent(self):
        with tempfile.TemporaryDirectory() as tmp:
            etat = os.path.join(tmp, "alertes.json")
            rapports = os.path.join(tmp, "rapports")
            os.mkdir(rapports)
            with open(etat, "w", encoding="utf-8") as f:
                json.dump({"disques": {"sda": {"etat": "ok", "crc": 0, "vu": 1}}}, f)
            mes = {"disques": [{"nom": "sda", "etat": "ok", "donnees_perimees": True}],
                   "smart_scan_ok": False, "pools": []}
            with patch.object(mesures, "unites_sauvegarde", return_value={}):
                messages = mesures.alertes({}, mes, {}, etat, rapports, 123456, "root")
            self.assertFalse(any("introuvable" in message for message in messages))
            with open(etat, encoding="utf-8") as f:
                sauvegarde = json.load(f)
            self.assertEqual(sauvegarde["disques"]["sda"]["etat"], "ok")


    def test_echecs_smart_repetes_previennent_puis_retablissement(self):
        with tempfile.TemporaryDirectory() as tmp:
            etat = os.path.join(tmp, "alertes.json")
            rapports = os.path.join(tmp, "rapports")
            os.mkdir(rapports)
            with open(etat, "w", encoding="utf-8") as f:
                json.dump({"disques": {"sda": {"etat": "ok", "crc": 0, "vu": 1}}}, f)
            echec = {"disques": [{"nom": "sda", "etat": "ok", "donnees_perimees": True}], "smart_scan_ok": False, "pools": []}
            ok = {"disques": [{"nom": "sda", "etat": "ok"}], "smart_scan_ok": True, "pools": []}
            recus = []
            with patch.object(mesures, "unites_sauvegarde", return_value={}):
                for n, mes in enumerate([echec, echec, echec, echec, ok]):
                    recus.append(mesures.alertes({}, mes, {}, etat, rapports, 123456 + n * 600, "root"))
            indispo = [i for i, m in enumerate(recus) if any("Relevé SMART indisponible" in x for x in m)]
            self.assertEqual(indispo, [2], "une seule alerte, au 3e relevé raté")
            self.assertTrue(any("de nouveau disponible" in x for x in recus[4]))

class TestDisquesParNumeroDeSerie(unittest.TestCase):
    """Les noms sdX changent quand un disque disparaît : le suivi se fait par numéro de série."""

    def alertes(self, etat, listes, debut=200000):
        with tempfile.TemporaryDirectory() as tmp:
            chemin = os.path.join(tmp, "alertes.json")
            rapports = os.path.join(tmp, "rapports")
            os.mkdir(rapports)
            with open(chemin, "w", encoding="utf-8") as f:
                json.dump(etat, f)
            recus = []
            with patch.object(mesures, "unites_sauvegarde", return_value={}):
                for n, disques in enumerate(listes):
                    recus.append(mesures.alertes({}, {"disques": disques, "smart_scan_ok": True, "pools": []}, {}, chemin, rapports, debut + n * 3600, "root"))
            with open(chemin, encoding="utf-8") as f:
                return recus, json.load(f)

    def test_disque_renomme_sans_fausse_alerte(self):
        avant = [{"nom": "sdh", "serie": "A1", "modele": "SSD", "etat": "ok"}, {"nom": "sdi", "serie": "B2", "modele": "SSD", "etat": "ok"}]
        apres = [{"nom": "sdh", "serie": "B2", "modele": "SSD", "etat": "ok"}, {"nom": "sdi", "serie": "A1", "modele": "SSD", "etat": "ok"}]
        recus, _ = self.alertes({}, [avant, apres])
        self.assertFalse(any("introuvable" in m for m in recus[1]))

    def test_disque_absent_puis_revenu(self):
        deux = [{"nom": "sdh", "serie": "A1", "modele": "SSD", "etat": "ok", "pool": "poolSSD"}, {"nom": "sdi", "serie": "B2", "modele": "SSD", "etat": "ok", "pool": "poolSSD"}]
        recus, etat = self.alertes({}, [deux, deux[:1], deux])
        absent = [m for m in recus[1] if "introuvable" in m]
        self.assertEqual(len(absent), 1)
        self.assertIn("n° B2", absent[0])
        self.assertIn("pool poolSSD", absent[0])
        self.assertTrue(any("de nouveau visible" in m and "B2" in m for m in recus[2]))
        self.assertNotIn("absent", etat["disques"]["serie:B2"])

    def test_etat_ancien_par_nom_migre(self):
        etat = {"actif": True, "disques": {"sda": {"etat": "ok", "crc": 0, "vu": 1}}}
        recus, etat = self.alertes(etat, [[{"nom": "sda", "serie": "S1", "modele": "SSD", "etat": "ok"}]])
        self.assertFalse(any("introuvable" in m for m in recus[0]))
        self.assertIn("serie:S1", etat["disques"])
        self.assertNotIn("sda", etat["disques"])

    def test_historique_crc_suit_le_numero_de_serie(self):
        smart = {"device": {"name": "/dev/sdj", "protocol": "ATA"}, "serial_number": "B2", "model_name": "SSD", "rotation_rate": 0,
                 "smart_status": {"passed": True}, "ata_smart_attributes": {"table": [{"id": 199, "raw": {"value": 380}}]}}
        precedent = {"disques": [{"nom": "sdi", "serie": "B2", "crc": 380, "crc_hausse": 1000},
                                 {"nom": "sdj", "serie": "C3", "crc": 0}]}
        scan = {"devices": [{"name": "/dev/sdj", "type": "sat"}]}

        def faux_cmd(*args, **kw):
            return (0, json.dumps(scan)) if "--scan-open" in args else (0, json.dumps(smart))
        with patch.object(mesures, "cmd", side_effect=faux_cmd):
            disques, _ = mesures.disques({}, precedent, 10 ** 7)
        self.assertEqual(disques[0]["crc_hausse"], 1000, "le compteur figé de B2 ne doit pas passer pour une hausse")


class TestCoupuresSATA(unittest.TestCase):
    def test_coupure_reliee_au_disque_et_signalee(self):
        noyau = ("ata5: SError: { PHYRdyChg CommWake }\nata5: hard resetting link\nata5.00: configured for UDMA/133\n"
                 "ata6: SError: { PHYRdyChg }\nsd 5:0:0:0: [sdg] tag#3 FAILED\n")
        with tempfile.TemporaryDirectory() as tmp:
            bloc, dev = os.path.join(tmp, "block"), os.path.join(tmp, "devices", "pci0000:00", "ata5", "host4", "target4:0:0", "4:0:0:0")
            os.makedirs(os.path.join(bloc, "sdg"))
            os.makedirs(dev)
            os.symlink(dev, os.path.join(bloc, "sdg", "device"))
            etat = os.path.join(tmp, "alertes.json")
            rapports = os.path.join(tmp, "rapports")
            os.mkdir(rapports)
            with open(etat, "w", encoding="utf-8") as f:
                json.dump({"actif": True, "noyau_vu": 1000}, f)
            mes = {"disques": [{"nom": "sdg", "serie": "2138E5D4C296", "modele": "CT1000BX500SSD1", "etat": "ok", "pool": "poolSSD"}],
                   "smart_scan_ok": True, "pools": []}

            def faux_cmd(*args, **kw):
                return (0, noyau) if args[0] == "journalctl" else (1, "")
            with patch.object(mesures, "SYS_BLOCK", bloc), patch.object(mesures, "cmd", side_effect=faux_cmd), \
                    patch.object(mesures, "unites_sauvegarde", return_value={}):
                msgs = mesures.alertes({}, mes, {}, etat, rapports, 5000, "root")
        coupure = [m for m in msgs if "Coupures de liaison SATA" in m]
        self.assertEqual(len(coupure), 1)
        self.assertIn("ata5 → sdg (CT1000BX500SSD1, n° 2138E5D4C296, pool poolSSD) : 2 message(s)", coupure[0])
        self.assertIn("ata6 → port vide : 1 message(s)", coupure[0])


if __name__ == "__main__":
    unittest.main()
