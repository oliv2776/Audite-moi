#!/usr/bin/env python3
"""Tests de sécurité du moteur de corrections root."""
import os
import stat
import tempfile
import unittest
from importlib.machinery import SourceFileLoader
from importlib.util import module_from_spec, spec_from_loader

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PATH = os.path.join(ROOT, "systemd", "audite-moi-corriger")
LOADER = SourceFileLoader("audite_moi_corriger", PATH)
SPEC = spec_from_loader(LOADER.name, LOADER)
MODULE = module_from_spec(SPEC)
LOADER.exec_module(MODULE)


class TestChmodSecurise(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = os.path.join(self.tmp.name, ".env")
        with open(self.path, "w", encoding="utf-8") as f:
            f.write("SECRET=test\n")
        os.chmod(self.path, 0o644)

    def plan(self):
        return MODULE.chmod_600(self.path)

    def test_appliquer_et_annuler_sur_le_descripteur(self):
        _, appliquer, annuler = self.plan()
        ok, sortie = MODULE.executer(appliquer)
        self.assertTrue(ok, sortie)
        self.assertEqual(stat.S_IMODE(os.stat(self.path).st_mode), 0o600)
        ok, sortie = MODULE.executer(annuler)
        self.assertTrue(ok, sortie)
        self.assertEqual(stat.S_IMODE(os.stat(self.path).st_mode), 0o644)

    def test_refuse_un_lien_symbolique_final(self):
        cible = os.path.join(self.tmp.name, "secret.env")
        os.symlink(self.path, cible)
        with self.assertRaises((MODULE.Refus, OSError)):
            MODULE.chmod_600(cible)
        self.assertEqual(stat.S_IMODE(os.stat(self.path).st_mode), 0o644)

    def test_refuse_un_repertoire_parent_symbolique(self):
        vrai = os.path.join(self.tmp.name, "vrai")
        os.mkdir(vrai)
        cible = os.path.join(vrai, ".env")
        with open(cible, "w", encoding="utf-8") as f:
            f.write("SECRET=test\n")
        os.chmod(cible, 0o644)
        lien = os.path.join(self.tmp.name, "lien")
        os.symlink(vrai, lien)
        with self.assertRaises((MODULE.Refus, OSError)):
            MODULE.chmod_600(os.path.join(lien, ".env"))
        self.assertEqual(stat.S_IMODE(os.stat(cible).st_mode), 0o644)

    def test_refuse_un_fichier_remplace_apres_validation(self):
        _, appliquer, _ = self.plan()
        remplace = self.path + ".nouveau"
        with open(remplace, "w", encoding="utf-8") as f:
            f.write("AUTRE_SECRET=test\n")
        os.chmod(remplace, 0o644)
        os.replace(remplace, self.path)
        ok, sortie = MODULE.executer(appliquer)
        self.assertFalse(ok)
        self.assertIn("remplacé", sortie)
        self.assertEqual(stat.S_IMODE(os.stat(self.path).st_mode), 0o644)


if __name__ == "__main__":
    unittest.main(verbosity=2)
