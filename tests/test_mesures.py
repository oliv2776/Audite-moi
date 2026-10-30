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


if __name__ == "__main__":
    unittest.main()
