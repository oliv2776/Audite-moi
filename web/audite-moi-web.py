#!/usr/bin/env python3
"""Audite-moi — interface web.

Petit serveur HTTP(S) sans dépendance (bibliothèque standard Python 3.8+) qui :
  * affiche le dernier audit (notes, plan d'action), l'historique et l'évolution des notes ;
  * sert les rapports HTML / texte / JSON produits par audite-moi.sh ;
  * permet de demander un nouvel audit.

Il tourne SANS droits root (utilisateur « audite-moi ») : il se contente de déposer
un fichier de demande que systemd (audite-moi.path → audite-moi.service) traite.

Utilisation :
  audite-moi-web.py --config /etc/audite-moi/web.json     # lancer le serveur
  audite-moi-web.py --hachage                             # hacher un mot de passe (lu sur l'entrée standard)
"""
import argparse
import base64
import collections
import getpass
import gzip
import hashlib
import ipaddress
import hmac
import html
import http.server
import json
import os
import re
import secrets
import socket
import ssl
import subprocess
import sys
import threading
import tempfile
import time
import urllib.parse
from datetime import datetime

VERSION = "1.3.0"
COOKIE = "audite_moi_session"
ITERATIONS = 600_000
NOM_RAPPORT = re.compile(r"^rapport-[A-Za-z0-9._-]+-\d{8}-\d{4}\.(html|txt|json)$")
DEFAUTS = {
    "ecoute": "0.0.0.0",
    "port": 8765,
    "mot_de_passe": "",
    "rapports": "/var/lib/audite-moi/rapports",
    "demandes": "/var/lib/audite-moi/demande",
    "etat": "/var/lib/audite-moi/etat",
    "tls_cert": "",
    "tls_cle": "",
    "duree_session_h": 12,
    "reglages": "/var/lib/audite-moi/reglages",
}
TYPES_CORRECTION = {"ufw-supprimer", "docker-restart", "chmod-600", "zfs-scrub", "zfs-autotrim", "smartd-activer",
                    "nc-debug-off", "nc-2fa-imposer", "nc-liens-mdp"}
ID_DEMANDE = re.compile(r"^[A-Za-z0-9_-]{8,40}$")


def cle_constat(section, titre):
    """Identifiant stable d'un constat (même règle que audite-moi.sh) : chiffres remplacés par « # »."""
    return re.sub(r"#+", "#", re.sub(r"\d", "#", "{}|{}".format(section, titre)))


def cle_de(c):
    return c.get("cle") or cle_constat(c.get("section", ""), c.get("titre", ""))


def note_score(c, w):
    return int(100 * (0.75 ** c) * (0.96 ** w) + 0.5)


def lettre(s):
    return "A" if s >= 90 else "B" if s >= 75 else "C" if s >= 60 else "D" if s >= 40 else "E"


# ------------------------------------------------------------- mots de passe --
def hacher(mdp, sel=None, iterations=ITERATIONS):
    sel = sel or secrets.token_bytes(16)
    h = hashlib.pbkdf2_hmac("sha256", mdp.encode(), sel, iterations)
    return "pbkdf2_sha256${}${}${}".format(iterations, base64.b64encode(sel).decode(), base64.b64encode(h).decode())


def verifier(mdp, stocke):
    try:
        algo, it, sel, h = stocke.split("$")
        if algo != "pbkdf2_sha256":
            return False
        calc = hashlib.pbkdf2_hmac("sha256", mdp.encode(), base64.b64decode(sel), int(it))
        return hmac.compare_digest(calc, base64.b64decode(h))
    except (ValueError, TypeError):
        return False


# ------------------------------------------------------------------ données --
VERROU_REGLAGES = threading.Lock()


class Donnees:
    def __init__(self, conf):
        self.conf = conf
        # Rapports déjà lus, par nom : (mtime_ns, taille, contenu). Chaque page
        # relisait jusqu'à 60 rapports JSON (plusieurs Mo) ; seuls les fichiers
        # nouveaux ou modifiés sont désormais relus.
        self._cache = {}
        self._verrou_cache = threading.Lock()

    def rapports(self):
        """Rapports JSON, du plus ancien au plus récent (à traiter en lecture seule)."""
        dossier = self.conf["rapports"]
        res = []
        try:
            noms = os.listdir(dossier)
        except OSError:
            return res
        vus = set()
        for nom in noms:
            if not (NOM_RAPPORT.match(nom) and nom.endswith(".json")):
                continue
            chemin = os.path.join(dossier, nom)
            try:
                st = os.stat(chemin)
            except OSError:
                continue
            cle = (st.st_mtime_ns, st.st_size)
            with self._verrou_cache:
                deja = self._cache.get(nom)
            if deja and deja[0] == cle:
                d = deja[1]
            else:
                try:
                    with open(chemin, encoding="utf-8") as f:
                        d = json.load(f)
                except (OSError, ValueError):
                    continue
                if not isinstance(d, dict):
                    continue
                d["_fichier"] = nom
                with self._verrou_cache:
                    self._cache[nom] = (cle, d)
            vus.add(nom)
            res.append(d)
        with self._verrou_cache:
            for nom in [n for n in self._cache if n not in vus]:
                del self._cache[nom]
        res.sort(key=lambda d: d.get("horodatage", 0))
        return res

    def etat(self):
        e = {"en_cours": False, "demande": False, "journal": "", "depuis": None, "mode": None, "bloque": False}
        f = os.path.join(self.conf["etat"], "en-cours")
        try:
            with open(f, encoding="utf-8") as fh:
                d = json.load(fh)
            e["en_cours"] = True
            e["depuis"] = int(d.get("debut", 0))
            e["mode"] = d.get("mode")
            if time.time() - e["depuis"] > 3 * 3600:   # trace d'un audit interrompu brutalement
                e["en_cours"] = False
        except (OSError, ValueError):
            pass
        e["correction"] = os.path.exists(os.path.join(self.conf["demandes"], "corriger"))
        dem = os.path.join(self.conf["demandes"], "lancer")
        if os.path.exists(dem):
            e["demande"] = True
            try:
                e["bloque"] = (time.time() - os.path.getmtime(dem)) > 90 and not e["en_cours"]
            except OSError:
                pass
        try:
            with open(os.path.join(self.conf["etat"], "journal.log"), encoding="utf-8", errors="replace") as fh:
                lignes = fh.read().splitlines()
            e["journal"] = "\n".join(re.sub(r"\x1b\[[0-9;]*m", "", l) for l in lignes[-40:])
        except OSError:
            pass
        return e

    def demander(self, mode):
        mode = "rapide" if mode == "rapide" else "complet"
        d = self.conf["demandes"]
        tmp = os.path.join(d, ".demande-{}".format(secrets.token_hex(6)))
        with open(tmp, "w", encoding="utf-8") as f:
            f.write(mode + "\n")
        os.replace(tmp, os.path.join(d, "lancer"))

    # -- constats acceptés (« c'est voulu »)
    def _fichier_acceptes(self):
        return os.path.join(self.conf["reglages"], "acceptes.json")

    def acceptes(self):
        try:
            with open(self._fichier_acceptes(), encoding="utf-8") as f:
                d = json.load(f)
            return d if isinstance(d, dict) else {}
        except (OSError, ValueError):
            return {}

    def modifier_acceptes(self, cle, valeur):
        with VERROU_REGLAGES:
            d = self.acceptes()
            if valeur is None:
                d.pop(cle, None)
            else:
                d[cle] = valeur
            f = self._fichier_acceptes()
            tmp = f + ".{}".format(secrets.token_hex(4))
            with open(tmp, "w", encoding="utf-8") as fh:
                json.dump(d, fh, ensure_ascii=False, indent=1)
            os.chmod(tmp, 0o660)
            os.replace(tmp, f)

    def vue_rapport(self, r):
        """Rapport tel qu'affiché : acceptations récentes appliquées, compteurs et notes recalculés."""
        acc = self.acceptes()
        cn = {"CRIT": 0, "WARN": 0, "OK": 0, "INFO": 0}
        par_cat = {"sante": [0, 0], "secu": [0, 0]}
        cats = {k: v.get("categorie", "") for k, v in r.get("sections", {}).items()}
        constats = []
        for c in r.get("constats", []):
            c = dict(c)
            k = cle_de(c)
            c["cle"] = k
            if not c.get("accepte") and k in acc and c.get("niveau") != "OK":
                c["accepte"] = acc[k].get("raison") or "accepté"
            if not c.get("accepte"):
                cn[c.get("niveau", "INFO")] = cn.get(c.get("niveau", "INFO"), 0) + 1
                cat = cats.get(c.get("section"), "")
                if cat in par_cat and c.get("niveau") in ("CRIT", "WARN"):
                    par_cat[cat][0 if c["niveau"] == "CRIT" else 1] += 1
            constats.append(c)
        v = dict(r, constats=constats, compteurs=cn)
        notes = {}
        for k, cat in (("sante", "sante"), ("securite", "secu")):
            sc = note_score(*par_cat[cat])
            notes[k] = {"score": sc, "lettre": lettre(sc)}
        v["notes_origine"], v["notes"] = r.get("notes"), notes
        return v

    # -- corrections en un clic
    def corrections(self):
        try:
            with open(os.path.join(self.conf["etat"], "corrections.json"), encoding="utf-8") as f:
                d = json.load(f)
            return d if isinstance(d, list) else []
        except (OSError, ValueError):
            return []

    def correction_en_attente(self):
        return os.path.exists(os.path.join(self.conf["demandes"], "corriger"))

    def demander_correction(self, demande):
        d = self.conf["demandes"]
        tmp = os.path.join(d, ".corriger-{}".format(secrets.token_hex(6)))
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(demande, f)
        os.replace(tmp, os.path.join(d, "corriger"))

    # -- réglages du serveur (appliqués par audite-moi-configurer, root)
    def configuration(self):
        d = self._json_etat("configuration.json", {})
        return d if d.get("controles") else None

    def journal_configuration(self):
        return self._json_etat("configuration-journal.json", [])

    def resultat_configuration(self):
        return self._json_etat("configuration-resultat.json", {})

    def _json_etat(self, nom, defaut):
        try:
            with open(os.path.join(self.conf["etat"], nom), encoding="utf-8") as f:
                d = json.load(f)
            return d if isinstance(d, type(defaut)) else defaut
        except (OSError, ValueError):
            return defaut

    def configuration_en_attente(self):
        return os.path.exists(os.path.join(self.conf["demandes"], "configurer"))

    def demander_configuration(self, demande):
        d = self.conf["demandes"]
        tmp = os.path.join(d, ".configurer.{}".format(secrets.token_hex(4)))
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(demande, f)
        os.chmod(tmp, 0o600)          # peut contenir un secret (jeton, clé API) : root seul la lit
        os.replace(tmp, os.path.join(d, "configurer"))

    def alertes(self):
        try:
            with open(os.path.join(self.conf["etat"], "alertes.json"), encoding="utf-8") as f:
                return json.load(f)
        except (OSError, ValueError):
            return {}

    @staticmethod
    def prochain_audit():
        for args in (["--timestamp=unix"], []):
            try:
                out = subprocess.run(["systemctl", "show", "audite-moi.timer", "-p", "NextElapseUSecRealtime", "--value"] + args,
                                     capture_output=True, text=True, timeout=5).stdout.strip()
            except (OSError, subprocess.SubprocessError):
                return None
            if out.startswith("@"):
                try:
                    return datetime.fromtimestamp(int(out[1:])).strftime("%d/%m/%Y à %H:%M")
                except ValueError:
                    pass
            elif out and out != "n/a" and not args:
                return out
        return None


# ------------------------------------------------------ mesures en direct --
class Mesures:
    """Processeur, mémoire et GPU lus dans /proc et /sys (aucun droit particulier),
    plus le relevé des disques écrit par audite-moi-mesures (root).
    Un échantillon toutes les 2 s, seulement quand la page Matériel est ouverte."""
    PAS = 2.0
    GARDE = 90          # 90 × 2 s = 3 minutes d'historique
    VENDEURS = {"0x1002": "AMD", "0x8086": "Intel", "0x10de": "NVIDIA"}

    def __init__(self, conf):
        self.proc = conf.get("racine_proc", "/proc")
        self.sys = conf.get("racine_sys", "/sys")
        self.fichier = os.path.join(conf["etat"], "mesures.json")
        self.demande = os.path.join(conf["demandes"], "mesurer")
        self.pci_ids = conf.get("pci_ids") or next((p for p in ("/usr/share/misc/pci.ids", "/usr/share/hwdata/pci.ids") if os.path.exists(p)), "")
        self.hist = collections.deque(maxlen=self.GARDE)
        self.dernier = None
        self.vu = 0.0
        self._cpu_prec = None
        self._rc6 = {}
        self._noms = {}
        self._modele = None
        self._verrou = threading.Lock()

    # -- lecture de fichiers
    def _lire(self, *chemin):
        try:
            with open(os.path.join(*chemin), encoding="utf-8", errors="replace") as f:
                return f.read().strip()
        except OSError:
            return None

    def _nombre(self, *chemin):
        v = self._lire(*chemin)
        try:
            return int(v)
        except (TypeError, ValueError):
            return None

    # -- processeur
    def _cpu_brut(self):
        res = {}
        for l in (self._lire(self.proc, "stat") or "").splitlines():
            if not l.startswith("cpu"):
                break
            c = l.split()
            v = [int(x) for x in c[1:9]]
            res[c[0]] = (sum(v), v[3] + v[4])    # total, inactif (idle + iowait)
        return res

    def _cpu_pourcent(self, brut):
        prec, self._cpu_prec = self._cpu_prec, brut
        if not prec:
            return None, []
        def pc(k):
            if k not in prec or k not in brut:
                return None
            dt, di = brut[k][0] - prec[k][0], brut[k][1] - prec[k][1]
            return round(100.0 * (dt - di) / dt, 1) if dt > 0 else 0.0
        coeurs = sorted((k for k in brut if k != "cpu"), key=lambda k: int(k[3:]))
        return pc("cpu"), [pc(k) for k in coeurs]

    def _hwmon_temp(self, noms):
        base = os.path.join(self.sys, "class", "hwmon")
        meilleur = None
        for h in sorted(os.listdir(base)) if os.path.isdir(base) else []:
            if self._lire(base, h, "name") not in noms:
                continue
            temps = []
            for f in os.listdir(os.path.join(base, h)):
                m = re.match(r"temp(\d+)_input$", f)
                if m:
                    lab = (self._lire(base, h, "temp{}_label".format(m.group(1))) or "").lower()
                    v = self._nombre(base, h, f)
                    if v is not None:
                        temps.append((0 if ("package" in lab or "tctl" in lab or "tdie" in lab) else 1, v / 1000.0))
            if temps:
                v = sorted(temps)[0][1]
                meilleur = v if meilleur is None else max(meilleur, v)
        return round(meilleur) if meilleur is not None else None

    def _info_cpu(self):
        txt = self._lire(self.proc, "cpuinfo") or ""
        if self._modele is None:
            m = re.search(r"^model name\s*:\s*(.+)$", txt, re.M)
            self._modele = re.sub(r"\s+", " ", m.group(1)).replace("(R)", "").replace("(TM)", "").strip() if m else ""
        f = [float(x) for x in re.findall(r"^cpu MHz\s*:\s*([\d.]+)", txt, re.M)]
        return self._modele, (round(sum(f) / len(f)) if f else None)

    # -- mémoire
    def _memoire(self):
        mi = {}
        for l in (self._lire(self.proc, "meminfo") or "").splitlines():
            k, _, v = l.partition(":")
            try:
                mi[k] = int(v.split()[0]) * 1024
            except (ValueError, IndexError):
                pass
        arc = 0
        for l in (self._lire(self.proc, "spl", "kstat", "zfs", "arcstats") or "").splitlines():
            c = l.split()
            if len(c) == 3 and c[0] == "size":
                arc = int(c[2])
        total = mi.get("MemTotal", 0)
        if not total:
            return None
        cache = mi.get("Buffers", 0) + mi.get("Cached", 0) + mi.get("SReclaimable", 0)
        libre = mi.get("MemFree", 0)
        appli = max(0, total - libre - cache - arc)
        return {"total": total, "applis": appli, "arc": arc, "cache": cache, "libre": libre,
                "disponible": mi.get("MemAvailable", 0), "swap_total": mi.get("SwapTotal", 0),
                "swap_utilise": mi.get("SwapTotal", 0) - mi.get("SwapFree", 0), "pourcent": round(100.0 * appli / total, 1)}

    # -- GPU
    def _nom_pci(self, vendeur, device):
        cle = (vendeur, device)
        if cle in self._noms:
            return self._noms[cle]
        v, d = vendeur[2:].lower(), device[2:].lower()
        nom = ""
        if self.pci_ids:
            try:
                dans = False
                with open(self.pci_ids, encoding="utf-8", errors="replace") as f:
                    for l in f:
                        if not l.startswith("\t") and not l.startswith("#"):
                            dans = l[:4].lower() == v
                        elif dans and l.startswith("\t") and not l.startswith("\t\t") and l[1:5].lower() == d:
                            nom = l[5:].strip()
                            break
            except OSError:
                pass
        m = re.search(r"\[([^\]]+)\]\s*$", nom)
        nom = m.group(1) if m else nom
        marque = self.VENDEURS.get(vendeur, "GPU")
        self._noms[cle] = "{} {}".format(marque, nom) if nom else "{} ({}:{})".format("Carte " + marque if marque != "GPU" else "GPU", v, d)
        return self._noms[cle]

    def _gpus(self, maintenant):
        base = os.path.join(self.sys, "class", "drm")
        res = []
        for carte in sorted(os.listdir(base)) if os.path.isdir(base) else []:
            if not re.match(r"card\d+$", carte):
                continue
            dev = os.path.join(base, carte, "device")
            vendeur, device = self._lire(dev, "vendor") or "", self._lire(dev, "device") or ""
            pilote = os.path.basename(os.path.realpath(os.path.join(dev, "driver"))) if os.path.exists(os.path.join(dev, "driver")) else ""
            try:
                noeud = next((n for n in sorted(os.listdir(os.path.join(dev, "drm"))) if n.startswith("renderD")), "")
            except OSError:
                noeud = ""
            g = {"id": carte, "nom": self._nom_pci(vendeur, device), "marque": self.VENDEURS.get(vendeur, ""), "pilote": pilote, "noeud": noeud,
                 "occupation": None, "vram_utilisee": None, "vram_totale": None, "temperature": None, "jonction": None,
                 "puissance": None, "frequence": None, "frequence_max": None, "estimation": False}
            if vendeur == "0x1002":
                g["occupation"] = self._nombre(dev, "gpu_busy_percent")
                g["vram_utilisee"], g["vram_totale"] = self._nombre(dev, "mem_info_vram_used"), self._nombre(dev, "mem_info_vram_total")
                hw = os.path.join(dev, "hwmon")
                for h in sorted(os.listdir(hw)) if os.path.isdir(hw) else []:
                    for i in (1, 2, 3):
                        lab = (self._lire(hw, h, "temp{}_label".format(i)) or "").lower()
                        v = self._nombre(hw, h, "temp{}_input".format(i))
                        if v is None:
                            continue
                        if lab in ("edge", "") and g["temperature"] is None:
                            g["temperature"] = round(v / 1000)
                        elif lab == "junction":
                            g["jonction"] = round(v / 1000)
                    p = self._nombre(hw, h, "power1_average") or self._nombre(hw, h, "power1_input")
                    if p is not None:
                        g["puissance"] = round(p / 1e6, 1)
                    f = self._nombre(hw, h, "freq1_input")
                    if f is not None:
                        g["frequence"] = round(f / 1e6)
            elif vendeur == "0x8086":
                c = os.path.join(base, carte)
                g["frequence"] = self._nombre(c, "gt_act_freq_mhz") or self._nombre(c, "gt", "gt0", "rps_act_freq_mhz")
                g["frequence_max"] = self._nombre(c, "gt_max_freq_mhz") or self._nombre(c, "gt", "gt0", "rps_max_freq_mhz")
                rc6 = self._nombre(c, "gt", "gt0", "rc6_residency_ms")
                if rc6 is None:
                    rc6 = self._nombre(c, "power", "rc6_residency_ms")
                if rc6 is not None:
                    prec = self._rc6.get(carte)
                    self._rc6[carte] = (maintenant, rc6)
                    if prec and maintenant > prec[0]:
                        repos = (rc6 - prec[1]) / ((maintenant - prec[0]) * 1000.0)
                        g["occupation"] = int(round(max(0.0, min(1.0, 1 - repos)) * 100))
                        g["estimation"] = True
            res.append(g)
        return res

    # -- échantillons
    def echantillon(self):
        with self._verrou:
            t = time.time()
            brut = self._cpu_brut()
            cpu, coeurs = self._cpu_pourcent(brut)
            modele, freq = self._info_cpu()
            charge = (self._lire(self.proc, "loadavg") or "").split()[:3]
            up = (self._lire(self.proc, "uptime") or "0").split()[0]
            d = {"t": t, "cpu": {"pourcent": cpu, "coeurs": coeurs, "modele": modele, "frequence": freq,
                                 "temperature": self._hwmon_temp({"coretemp", "k10temp", "zenpower", "cpu_thermal", "acpitz"}),
                                 "charge": [float(x) for x in charge] if len(charge) == 3 else None},
                 "memoire": self._memoire(), "gpus": self._gpus(t), "demarrage": t - float(up or 0)}
            self.dernier = d
            if cpu is not None:
                self.hist.append({"t": round(t, 1), "cpu": cpu, "ram": (d["memoire"] or {}).get("pourcent"),
                                  "gpu": {g["id"]: g["occupation"] for g in d["gpus"]}})
            return d

    def boucle(self):
        while True:
            if time.time() - self.vu < 600:     # page consultée dans les 10 dernières minutes
                try:
                    self.echantillon()
                except Exception as exc:          # une mesure ratée ne doit pas arrêter la boucle
                    sys.stderr.write("mesure : {}\n".format(exc))
            time.sleep(self.PAS)

    def demarrer(self):
        threading.Thread(target=self.boucle, name="mesures", daemon=True).start()

    def stockage(self):
        try:
            with open(self.fichier, encoding="utf-8") as f:
                s = json.load(f)
        except (OSError, ValueError):
            s = None
        return {"releve": s, "demande": os.path.exists(self.demande)}

    def tendances(self, jours):
        """Historique horaire (audite-moi-mesures) : remplissage des pools et température maximale des disques par pool."""
        jours = jours if jours in (7, 30, 90, 365) else 30
        debut = time.time() - jours * 86400
        releve = self.stockage()["releve"] or {}
        pool_de = {d.get("nom"): d.get("pool") or "autres disques" for d in releve.get("disques", [])}
        points = []
        try:
            with open(os.path.join(os.path.dirname(self.fichier), "historique.jsonl"), encoding="utf-8") as f:
                for l in f:
                    try:
                        p = json.loads(l)
                    except ValueError:
                        continue
                    if isinstance(p, dict) and p.get("t", 0) >= debut:
                        points.append(p)
        except OSError:
            pass
        pas = max(1, -(-len(points) // 240))          # au plus 240 points par courbe (moyenne par paquet)
        rempl, temp = {}, {}
        for i in range(0, len(points), pas):
            paquet = points[i:i + pas]
            t = paquet[-1]["t"]
            somme = {}
            for p in paquet:
                for nom, v in (p.get("pools") or {}).items():
                    if isinstance(v, list) and len(v) == 2 and v[0] is not None and v[1]:
                        somme.setdefault(nom, []).append(100.0 * v[0] / v[1])
            for nom, vals in somme.items():
                rempl.setdefault(nom, []).append([t, round(sum(vals) / len(vals), 2)])
            maxi = {}
            for p in paquet:
                for disque, v in (p.get("disques") or {}).items():
                    if isinstance(v, list) and v and isinstance(v[0], (int, float)):
                        g = pool_de.get(disque, "autres disques")
                        maxi[g] = max(maxi.get(g, -99), v[0])
            for g, v in maxi.items():
                temp.setdefault(g, []).append([t, v])
        prev = {p["nom"]: p["tendance"] for p in releve.get("pools", []) if p.get("tendance")}
        return {"jours": jours, "points": len(points), "remplissage": rempl, "temperatures": temp, "previsions": prev}

    def demander(self):
        tmp = os.path.join(os.path.dirname(self.demande), ".mesurer-{}".format(secrets.token_hex(6)))
        with open(tmp, "w", encoding="utf-8") as f:
            f.write("mesurer\n")
        os.replace(tmp, self.demande)

    def instantane(self):
        inactif = time.time() - self.vu > 600 or self.dernier is None
        self.vu = time.time()
        if inactif:                     # retour sur la page : mesure immédiate (deux échantillons pour le % processeur)
            self.echantillon()
            time.sleep(0.25)
            self.echantillon()
        with self._verrou:
            return {"direct": self.dernier, "historique": list(self.hist), "maintenant": time.time(), **self.stockage()}


# ------------------------------------------------------------------ gabarits --
CSS = """
:root{--bg:#f6f5f1;--card:#fff;--ink:#1d232b;--muted:#6a7280;--line:#e4e2db;--soft:#f1efea;--accent:#2557b8;--accent-ink:#fff;--sel:#e6edf9;
--crit:#a3312b;--crit-bg:#f9e3e1;--warn:#9a5b00;--warn-bg:#fbf0dc;--ok:#2c6e3f;--ok-bg:#e1f1e5;--info:#2f5b8a;--info-bg:#e3ecf6;
--s1:#2a78d6;--s2:#eb6834;--s3:#1baf7a;--trk:#dfe7f5;--free:#e7e5df;--grid:#e9e7e1;--r:10px;
--sb-w:248px;--sb-bg:#1b3c78;--sb-ink:#e6edfa;--sb-muted:#a9bde3;--sb-hover:rgba(255,255,255,.08);--sb-active:rgba(255,255,255,.15);--sb-mark:#9fc2ff;--sb-line:rgba(255,255,255,.13);
--mono:ui-monospace,SFMono-Regular,Menlo,Consolas,"Liberation Mono",monospace;color-scheme:light}
@media (prefers-color-scheme:dark){:root:not([data-theme=light]){--bg:#14171b;--card:#1c2026;--ink:#e8e6e1;--muted:#9aa1ab;--line:#2c3139;--soft:#232830;--accent:#7ea6f2;--accent-ink:#0d1526;--sel:#1f2a3d;
--crit:#e27a72;--crit-bg:#3a2220;--warn:#e0a64d;--warn-bg:#33291a;--ok:#79c08d;--ok-bg:#1e3024;--info:#8db4e0;--info-bg:#1f2a37;
--s1:#3987e5;--s2:#d95926;--s3:#199e70;--trk:#1f2b40;--free:#2a2f37;--grid:#2a2f37;--sb-bg:#10151d;--sb-ink:#dfe5ee;--sb-muted:#8d97a6;--sb-mark:#7ea6f2;--sb-line:rgba(255,255,255,.08);color-scheme:dark}}
:root[data-theme=dark]{--bg:#14171b;--card:#1c2026;--ink:#e8e6e1;--muted:#9aa1ab;--line:#2c3139;--soft:#232830;--accent:#7ea6f2;--accent-ink:#0d1526;--sel:#1f2a3d;
--crit:#e27a72;--crit-bg:#3a2220;--warn:#e0a64d;--warn-bg:#33291a;--ok:#79c08d;--ok-bg:#1e3024;--info:#8db4e0;--info-bg:#1f2a37;
--s1:#3987e5;--s2:#d95926;--s3:#199e70;--trk:#1f2b40;--free:#2a2f37;--grid:#2a2f37;--sb-bg:#10151d;--sb-ink:#dfe5ee;--sb-muted:#8d97a6;--sb-mark:#7ea6f2;--sb-line:rgba(255,255,255,.08);color-scheme:dark}
*{box-sizing:border-box}[hidden]{display:none!important}html{scroll-behavior:smooth;scroll-padding-top:20px}
body{margin:0;background:var(--bg);color:var(--ink);font:15px/1.5 ui-sans-serif,system-ui,-apple-system,"Segoe UI",Roboto,Ubuntu,"Helvetica Neue",Arial,sans-serif}
a{color:var(--accent);text-decoration:none}a:hover{text-decoration:underline}
h1{font-size:1.6rem;margin:0 0 .2rem;letter-spacing:-.01em;line-height:1.25}
h2{font-size:1.1rem;margin:0 0 .75rem;display:flex;gap:10px;align-items:baseline;flex-wrap:wrap}
h2 .mini{margin-left:auto;font-size:.82rem;color:var(--muted);font-weight:500}
.muted{color:var(--muted)}.small{font-size:.85rem}
/* coque : barre latérale + contenu */
.ico{width:18px;height:18px;flex:none;fill:none;stroke:currentColor;stroke-width:1.7;stroke-linecap:round;stroke-linejoin:round}
.brand{display:flex;align-items:center;gap:.6rem;font-weight:700;font-size:1.12rem;color:var(--ink)}
.brand:hover{text-decoration:none}
.logo{width:26px;height:26px;border-radius:7px;background:var(--accent);display:grid;place-items:center;flex:none}
.logo svg{width:16px;height:16px;fill:none;stroke:#fff;stroke-width:2.4;stroke-linecap:round;stroke-linejoin:round}
.sidebar{position:fixed;inset:0 auto 0 0;width:var(--sb-w);z-index:20;display:flex;flex-direction:column;padding:1.1rem .8rem .8rem;overflow-y:auto;background:var(--sb-bg);color:var(--sb-ink)}
.sidebar .brand,.mobilebar .brand{color:#fff}
.sidebar .logo,.mobilebar .logo{background:rgba(255,255,255,.16)}
.sb-head{display:flex;align-items:center;padding:0 .45rem}
.sb-host{padding:.15rem .45rem 0 2.75rem;font-size:.8rem;color:var(--sb-muted);overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.sb-audit{margin:1rem .2rem .9rem;display:grid;gap:.4rem}
.sb-audit form{margin:0}
.sb-audit button{width:100%;justify-content:center}
.sb-audit .btn-lancer{background:#fff;color:var(--sb-bg);border-color:#fff}
.sb-audit .btn-rapide{background:transparent;color:var(--sb-ink);border-color:var(--sb-line);font-weight:500;font-size:.84rem;padding:.32rem .6rem}
.sb-audit .btn-rapide:hover:not(:disabled){background:var(--sb-hover)}
.sb-audit .encours{display:flex;align-items:center;gap:.5rem;padding:.5rem .65rem;border-radius:8px;background:var(--sb-active);font-size:.88rem;color:#fff}
.sb-audit .encours .spin{border-color:var(--sb-mark);border-right-color:transparent;margin:0}
.sb-nav{display:flex;flex-direction:column;gap:2px}
.sb-nav a{position:relative;display:flex;align-items:center;gap:.7rem;padding:.48rem .65rem;border-radius:8px;color:var(--sb-ink);font-size:.93rem;font-weight:500}
.sb-nav a .ico{opacity:.8}
.sb-nav a:hover{background:var(--sb-hover);text-decoration:none}
.sb-nav a[aria-current=page]{background:var(--sb-active);color:#fff}.sb-nav a[aria-current=page] .ico{opacity:1}
.sb-nav a[aria-current=page]::before{content:"";position:absolute;left:-.8rem;top:.45rem;bottom:.45rem;width:3px;border-radius:0 3px 3px 0;background:var(--sb-mark)}
.cpt{margin-left:auto;min-width:1.5em;padding:0 .42em;border-radius:999px;background:#d8473d;color:#fff;font-size:.72rem;line-height:1.5;text-align:center;font-weight:700}
.cpt.w{background:#c98a1c}
.sb-group{margin:1.1rem .65rem .3rem;font-size:.76rem;font-weight:600;color:var(--sb-muted);text-transform:none}
.sb-foot{margin-top:auto;padding-top:.7rem;border-top:1px solid var(--sb-line);display:flex;flex-direction:column;gap:.45rem}
.sb-row{display:flex;align-items:center;justify-content:space-between;gap:.5rem;padding:0 .2rem}
.sb-theme select{width:auto;padding:.28rem .5rem;font-size:.82rem;color:var(--sb-ink);border:1px solid var(--sb-line);border-radius:6px;background:rgba(255,255,255,.06);cursor:pointer}
.sb-theme select option{color:var(--ink);background:var(--card)}
.sb-logout{display:inline-flex;align-items:center;gap:.4rem;padding:.3rem .45rem;border:0;border-radius:6px;background:none;color:var(--sb-muted);font:inherit;font-size:.85rem;cursor:pointer;font-weight:500}
.sb-logout .ico{width:16px;height:16px}.sb-logout:hover{color:#fff;background:var(--sb-hover)}
.sidebar a:focus-visible,.sidebar button:focus-visible,.sidebar select:focus-visible,.mobilebar button:focus-visible{outline:2px solid var(--sb-mark);outline-offset:1px}
.sb-close,.mobilebar,.sb-backdrop{display:none}
body.with-nav .content{margin-left:var(--sb-w)}
.content{min-width:0}
main{max-width:1200px;margin:0 auto;padding:1.75rem 2rem 3rem}
.page-head{display:flex;justify-content:space-between;align-items:flex-end;gap:1rem;margin-bottom:1.25rem;flex-wrap:wrap}
.page-head .sous{color:var(--muted);margin:0}
.page-head .sous b{color:var(--ink);font-weight:600}
.page-head .actions{display:flex;gap:.5rem;flex-wrap:wrap;align-items:center}
@media (max-width:900px){
body.with-nav .content{margin-left:0}
main{padding:1.1rem 1rem 2.5rem}
.mobilebar{display:flex;position:sticky;top:0;z-index:15;align-items:center;gap:.8rem;padding:.55rem .9rem;background:var(--sb-bg);color:var(--sb-ink)}
.menu-btn{display:inline-flex;align-items:center;gap:.45rem;padding:.42rem .7rem;border:0;border-radius:8px;background:rgba(255,255,255,.1);color:var(--sb-ink);font:inherit;font-weight:600;font-size:.9rem;cursor:pointer}
.mobile-pb{margin-left:auto;color:var(--sb-ink);font-size:.86rem;font-weight:600;white-space:nowrap}
.sb-close{display:inline-flex;margin-left:auto;padding:.35rem;border:0;border-radius:8px;background:none;color:var(--sb-ink);cursor:pointer}
.js .sidebar{transform:translateX(-100%);visibility:hidden;transition:transform .2s ease,visibility 0s linear .2s}
.js body.nav-open .sidebar{transform:none;visibility:visible;transition:transform .2s ease;box-shadow:0 0 48px rgba(0,0,0,.35)}
.js body.nav-open{overflow:hidden}
.js .sb-backdrop:not([hidden]){display:block;position:fixed;inset:0;z-index:19;background:rgba(8,12,20,.45)}
html:not(.js) .sidebar{position:static;width:auto}
h1{font-size:1.35rem}}
@media (prefers-reduced-motion:reduce){.js .sidebar,.js body.nav-open .sidebar{transition:none}}
/* éléments communs */
button,.btn{display:inline-flex;align-items:center;gap:.35rem;font:inherit;font-size:.9rem;font-weight:600;border-radius:8px;padding:.48rem .95rem;border:1px solid var(--line);background:var(--card);color:var(--ink);cursor:pointer;white-space:nowrap;line-height:1.3}
.btn:hover{text-decoration:none}
button:hover:not(:disabled),.btn:hover{border-color:var(--muted)}
button.primary,.btn.primary{background:var(--accent);border-color:var(--accent);color:var(--accent-ink)}
button.primary:hover:not(:disabled),.btn.primary:hover{filter:brightness(1.08);border-color:var(--accent)}
button.danger{color:var(--crit);border-color:color-mix(in srgb,var(--crit) 40%,transparent)}
button.sm,.btn.sm{padding:.25rem .6rem;font-size:.8rem}
button:disabled{opacity:.5;cursor:not-allowed}
form.inline{display:inline}
.card{background:var(--card);border:1px solid var(--line);border-radius:var(--r);padding:1.1rem 1.2rem;margin:0 0 1rem}
.banner{border-radius:var(--r);padding:.7rem 1rem;margin:0 0 1rem;border:1px solid transparent;background:var(--info-bg);color:var(--ink)}
.banner.run{background:var(--info-bg)}.banner.okb{background:var(--ok-bg);color:var(--ok)}.banner.warnb{background:var(--warn-bg);color:var(--warn);border-color:color-mix(in srgb,var(--warn) 25%,transparent)}
.banner.errb{background:var(--crit-bg);color:var(--crit)}
.banner a{color:inherit;text-decoration:underline}
.banner pre{margin:10px 0 0;max-height:240px;overflow:auto;background:var(--card);border-radius:8px;padding:10px;font:12px/1.45 var(--mono);white-space:pre-wrap;color:var(--ink)}
.spin{display:inline-block;width:12px;height:12px;border:2px solid var(--info);border-right-color:transparent;border-radius:50%;animation:r 1s linear infinite;margin-right:8px;vertical-align:-1px}
@keyframes r{to{transform:rotate(360deg)}}
@media (prefers-reduced-motion:reduce){.spin{animation:none}html{scroll-behavior:auto}}
.meta{color:var(--muted);font-size:13.5px;margin:0 0 12px;display:flex;gap:12px;flex-wrap:wrap;align-items:center}
.hero{display:grid;grid-template-columns:repeat(2,minmax(0,1.15fr)) repeat(4,minmax(0,1fr));gap:12px;margin-bottom:18px}
.tile{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:12px 16px;text-align:left;width:100%;font:inherit;color:inherit;cursor:pointer;transition:border-color .15s}
.tile:hover{border-color:var(--muted)}
.tile[aria-pressed=true]{outline:2px solid var(--accent);outline-offset:1px;background:var(--sel)}
.tile .l{color:var(--muted);font-size:12px;text-transform:uppercase;letter-spacing:.06em;font-weight:650}
.tile .v{font-size:28px;font-weight:750;line-height:1.25}
.tile .v small{font-size:13px;color:var(--muted);font-weight:500}
.tile .h{display:block;font-size:11.5px;color:var(--muted);margin-top:2px}
.score{display:flex;align-items:center;gap:12px}
.grade{font-size:24px;font-weight:800;width:44px;height:44px;border-radius:10px;display:grid;place-items:center;color:#fff;flex:none}
.g-A{background:#1d7a4c}.g-B{background:#4c8a2a}.g-C{background:#a35f00}.g-D{background:#c4561c}.g-E{background:#c4352f}
.kpi{border-left:4px solid var(--c)}.k-CRIT{--c:var(--crit)}.k-WARN{--c:var(--warn)}.k-OK{--c:var(--ok)}.k-INFO{--c:var(--info)}
.filters{display:flex;gap:10px;flex-wrap:wrap;align-items:center;margin:0 0 6px}
.seg{display:inline-flex;border:1px solid var(--line);border-radius:9px;overflow:hidden;background:var(--soft)}
.seg button{border:0;border-radius:0;background:transparent;padding:6px 11px;font-size:13px;color:var(--muted)}
.seg button+button{border-left:1px solid var(--line)}
.seg button[aria-pressed=true]{background:var(--card);color:var(--ink);box-shadow:inset 0 -2px 0 var(--accent)}
select,input[type=search]{font:inherit;font-size:13.5px;padding:6px 10px;border-radius:9px;border:1px solid var(--line);background:var(--card);color:var(--ink)}
input[type=search]{min-width:200px;flex:1}
.count{font-size:13px;color:var(--muted);margin:4px 0 2px}
.count button{font-size:12.5px;padding:2px 8px;margin-left:6px}
.badge{display:inline-block;min-width:78px;text-align:center;font-size:11px;font-weight:750;padding:3px 8px;border-radius:999px;text-transform:uppercase;letter-spacing:.04em}
.b-CRIT{background:var(--crit-bg);color:var(--crit)}.b-WARN{background:var(--warn-bg);color:var(--warn)}.b-OK{background:var(--ok-bg);color:var(--ok)}.b-INFO{background:var(--info-bg);color:var(--info)}
ol.items{list-style:none;margin:0;padding:0}
ol.items li{display:grid;grid-template-columns:92px 1fr;gap:8px;padding:10px 0;border-top:1px solid var(--line)}
ol.items li:first-child{border-top:0}
.sec{font-size:12px;color:var(--muted);margin-right:6px;background:var(--soft);padding:1px 7px;border-radius:999px;cursor:pointer;border:0;font-weight:600}
.sec:hover{color:var(--accent)}
.ttl{font-weight:600}
.fix{margin-top:5px;font-size:13.5px;padding:6px 10px;border-left:3px solid var(--info);background:var(--soft);border-radius:0 6px 6px 0;overflow-wrap:anywhere}
.fix::before{content:"À faire : ";font-weight:650}
.refs{margin-top:5px;font-size:12.5px;color:var(--muted)}.refs a{color:inherit;text-underline-offset:2px}.refs a:hover{color:var(--accent)}
details.d{margin-top:4px}details.d summary{cursor:pointer;color:var(--muted);font-size:13px}
.det{color:var(--muted);font-size:13.5px;white-space:pre-wrap;overflow-wrap:anywhere}
.msgd{color:var(--muted);font-size:13.5px;overflow-wrap:anywhere;margin-top:2px}
.vide{color:var(--muted);padding:18px 0;text-align:center}
code{font-family:var(--mono);font-size:12.5px;background:var(--soft);padding:1px 5px;border-radius:4px}
.fix code{background:var(--card)}
table{border-collapse:collapse;width:100%;font-size:14px}
th{text-align:left;font-size:12px;color:var(--muted);text-transform:uppercase;letter-spacing:.05em;padding:6px 8px;border-bottom:1px solid var(--line);white-space:nowrap}
td{padding:8px;border-bottom:1px solid var(--line);white-space:nowrap}
tr.cur td{background:var(--sel)}
td.num{text-align:right;font-variant-numeric:tabular-nums}
.pill{display:inline-flex;align-items:center;gap:6px}
.pill i{width:22px;height:22px;border-radius:6px;display:inline-grid;place-items:center;color:#fff;font-style:normal;font-weight:800;font-size:12px}
.tw{overflow-x:auto}
.chart{position:relative}
.chart svg{display:block;width:100%;height:auto}
.legend{display:flex;gap:16px;font-size:13px;color:var(--muted);margin:0 0 6px}
.legend span{display:inline-flex;align-items:center;gap:6px}
.sw{width:14px;height:3px;border-radius:2px;display:inline-block}.sw1{background:var(--s1)}.sw2{background:var(--s2)}
.gl{stroke:var(--grid);stroke-width:1}.ax{fill:var(--muted);font-size:11px}.lb{fill:var(--ink);font-size:12px}
.ln{fill:none;stroke-width:2;stroke-linejoin:round;stroke-linecap:round}.ln1{stroke:var(--s1)}.ln2{stroke:var(--s2)}
.pt{stroke:var(--card);stroke-width:2}.pt1{fill:var(--s1)}.pt2{fill:var(--s2)}
.cr{stroke:var(--muted);stroke-width:1;stroke-dasharray:3 3}.hit{fill:transparent}
.tip{position:absolute;pointer-events:none;background:var(--card);border:1px solid var(--line);border-radius:8px;padding:6px 10px;font-size:12.5px;box-shadow:0 4px 14px rgba(0,0,0,.12);display:none;white-space:nowrap}
.tip b{display:block;margin-bottom:2px}
.empty{color:var(--muted)}
.cache{display:none!important}
.err{color:var(--crit);font-weight:600;margin:0 0 10px}
pre.texte{margin:0;font:12.5px/1.5 var(--mono);white-space:pre-wrap;overflow-wrap:anywhere}
footer{color:var(--muted);font-size:12.5px;text-align:center;margin-top:24px}
/* suivi, acceptation, corrections */
.b-ACC{background:var(--soft);color:var(--muted);box-shadow:inset 0 0 0 1px var(--line)}
.nouv{display:inline-block;margin-top:5px;font-size:10.5px;font-weight:750;text-transform:uppercase;letter-spacing:.04em;color:var(--accent);background:var(--sel);border-radius:999px;padding:1px 7px}
.banner.evol{border-left:4px solid var(--accent)}
ul.res{margin:8px 0 0;padding:0;list-style:none}ul.res li{padding:3px 0;font-size:13.5px}ul.res .badge{min-width:0;margin-right:6px}
.msgd.acc{color:var(--ink)}
.acts{display:flex;gap:8px;flex-wrap:wrap;align-items:center;margin-top:8px}
button.corr{font-size:13px;padding:5px 11px;border-color:var(--accent);color:var(--accent)}
button.corr::before{content:"⚙ ";}
.lienbtn{border:0;background:none;color:var(--muted);font-size:13px;padding:4px 2px;text-decoration:underline;text-underline-offset:2px;cursor:pointer}
.lienbtn:hover{color:var(--accent)}
.fait{font-size:13px;color:var(--ok);font-weight:600}
.ab{font-size:12.5px;padding:2px 9px;border-radius:999px;background:var(--soft);color:var(--muted)}
.ab.ok{background:var(--ok-bg);color:var(--ok)}.ab.warn{background:var(--warn-bg);color:var(--warn)}
pre.sortie{margin:6px 0 0;max-height:220px;overflow:auto;background:var(--soft);border-radius:8px;padding:8px 10px;font:12px/1.45 var(--mono);white-space:pre-wrap;max-width:640px}
dialog{border:1px solid var(--line);border-radius:14px;background:var(--card);color:var(--ink);padding:20px 22px;width:min(560px,calc(100vw - 32px));box-shadow:0 18px 50px rgba(0,0,0,.25)}
dialog::backdrop{background:rgba(10,14,20,.45)}
dialog h3{margin:0 0 8px;font-size:17px}
.dlg-p{color:var(--muted);font-size:14px;margin:0 0 10px}
.dlg-c{background:var(--soft);border-radius:8px;padding:10px 12px;font:12.5px/1.5 var(--mono);white-space:pre-wrap;overflow-wrap:anywhere;margin:0 0 10px}
.dlg-a{border-left:3px solid var(--warn);background:var(--warn-bg);padding:8px 10px;border-radius:0 8px 8px 0;font-size:13.5px;margin:0 0 10px}
.dlg-l{display:block;font-size:13.5px;font-weight:600;margin:10px 0 0}.dlg-l span{font-weight:400;color:var(--muted)}
.dlg-l input{display:block;width:100%;font:inherit;font-weight:400;padding:9px 11px;border-radius:9px;border:1px solid var(--line);background:var(--soft);color:var(--ink);margin-top:5px}
.dlg-b{display:flex;justify-content:flex-end;gap:8px;margin-top:16px}
/* page Réglages */
.sl{display:grid;grid-template-columns:minmax(0,1fr) auto;gap:4px 18px;align-items:center;padding:10px 0;border-top:1px solid var(--line)}
.sl:first-of-type{border-top:0}
.sl label b{font-weight:600}.sl .aide{display:block;color:var(--muted);font-size:12.5px;margin-top:2px;max-width:640px}
.sv{display:flex;align-items:center;gap:8px;justify-content:flex-end}
.sv input{width:96px;font:inherit;font-variant-numeric:tabular-nums;text-align:right;padding:6px 9px;border-radius:9px;border:1px solid var(--line);background:var(--soft);color:var(--ink)}
.sv .u{color:var(--muted);font-size:13px;min-width:62px}
.sv .lienbtn{font-size:12px;min-width:76px;text-align:left}
.sl.modifie input{border-color:var(--accent);background:var(--sel);font-weight:700}
.sl.err input{border-color:var(--crit);background:var(--crit-bg)}
.errm{grid-column:1/-1;color:var(--crit);font-size:13px;font-weight:600;text-align:right}
.barre-bas{position:sticky;bottom:0;display:flex;justify-content:flex-end;gap:10px;padding:12px 0;background:var(--bg);border-top:1px solid var(--line);margin-bottom:10px}
@media (max-width:620px){.sl{grid-template-columns:1fr}.sv{justify-content:flex-start}.errm{text-align:left}}
/* page Matériel */
.kpis{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:12px;margin-bottom:18px}
a.stat{display:block;background:var(--card);border:1px solid var(--line);border-radius:12px;padding:12px 16px;color:inherit;text-decoration:none;transition:border-color .15s;min-width:0}
a.stat:hover{border-color:var(--muted)}
.stat .l,.lbl{color:var(--muted);font-size:12px;text-transform:uppercase;letter-spacing:.06em;font-weight:650}
.stat .v{font-size:28px;font-weight:750;line-height:1.25;font-variant-numeric:tabular-nums}
.stat .v small{font-size:13px;color:var(--muted);font-weight:500}
.stat .s{font-size:12.5px;color:var(--muted);white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.stat svg{display:block;width:100%;height:28px;margin-top:6px}
.spk{fill:none;stroke:var(--s1);stroke-width:2;stroke-linejoin:round;stroke-linecap:round}.spd{fill:var(--s1);stroke:var(--card);stroke-width:2}
.grid2{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:14px}
.bloc{border:1px solid var(--line);border-radius:12px;padding:14px 16px;min-width:0}
.bh{display:flex;align-items:center;gap:8px;flex-wrap:wrap;margin-bottom:8px}
.bh b{font-size:16px}.tag{font-size:12px;color:var(--muted);background:var(--soft);border-radius:999px;padding:1px 8px;font-weight:600}
.bh .badge{margin-left:auto;min-width:0}
.big{font-size:24px;font-weight:750;font-variant-numeric:tabular-nums;line-height:1.2}.big small{font-size:13px;color:var(--muted);font-weight:500}
.meter{height:8px;border-radius:999px;background:var(--trk);overflow:hidden;margin:8px 0 6px}
.meter>i{display:block;height:100%;border-radius:999px;background:var(--s1);min-width:2px;transition:width .4s}
.meter.warn{background:var(--warn-bg)}.meter.warn>i{background:var(--warn)}.meter.crit{background:var(--crit-bg)}.meter.crit>i{background:var(--crit)}
.meter.fin{height:6px;margin:4px 0}
.sub{font-size:13px;color:var(--muted)}.sub b{color:var(--ink);font-weight:600}
.lignes{list-style:none;margin:10px 0 0;padding:0}
.lignes li{display:grid;grid-template-columns:minmax(0,1.2fr) minmax(0,1.5fr) 5.5em;gap:10px;align-items:center;font-size:13px;padding:3px 0}
.lignes.vol li{grid-template-columns:minmax(0,1fr) minmax(0,1.6fr) 15em}
.lignes li span:first-child{overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.lignes li .num{color:var(--muted);font-variant-numeric:tabular-nums;text-align:right;min-width:62px}
.membres{display:flex;gap:6px;flex-wrap:wrap;margin-top:10px}
.mb{display:inline-flex;align-items:center;gap:5px;font-size:12.5px;border:1px solid var(--line);border-radius:999px;padding:2px 9px 2px 7px;background:var(--card);color:var(--ink);text-decoration:none}
.mb:hover{border-color:var(--muted)}
.ic{font-style:normal;font-weight:800;width:16px;height:16px;border-radius:50%;display:inline-grid;place-items:center;font-size:10px;color:#fff;flex:none}
.ic.OK{background:var(--ok)}.ic.WARN{background:var(--warn)}.ic.CRIT{background:var(--crit)}.ic.INFO{background:var(--info)}
.faits{display:flex;gap:18px;flex-wrap:wrap;margin-top:8px}
.faits div{min-width:0}.faits .val{font-size:17px;font-weight:700;font-variant-numeric:tabular-nums}
.alerte-perime{margin:0 0 10px;padding:8px 12px;border-radius:8px;background:var(--warn-bg);font-size:13.5px}
.raisons{font-size:12.5px;color:var(--muted);white-space:normal;margin-top:2px;max-width:420px}
td.etat{white-space:normal}
.modele{display:block;font-size:12px;color:var(--muted);max-width:260px;overflow:hidden;text-overflow:ellipsis}
.segbar{display:flex;gap:2px;height:28px;margin:10px 0 8px}
.segbar>i{display:block;height:100%;border-radius:4px;min-width:0}
.c1{background:var(--s1)}.c2{background:var(--s2)}.c3{background:var(--s3)}.c0{background:var(--free)}
.leg{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:8px}
.leg div{font-size:12.5px;color:var(--muted);min-width:0}.leg b{display:block;color:var(--ink);font-size:15px;font-variant-numeric:tabular-nums}
.leg .sq{display:inline-block;width:10px;height:10px;border-radius:3px;margin-right:6px;vertical-align:0}
.coeurs{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:2px 14px;margin-top:10px}
.coeurs .cl{font-size:12px;color:var(--muted);display:flex;justify-content:space-between;font-variant-numeric:tabular-nums}
.rang{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:18px;margin-bottom:18px}.rang>.card{margin:0;min-width:0}
h3.lbl{margin:18px 0 4px}
.courbe{position:relative;margin-top:8px}
.courbe svg{display:block;width:100%;height:auto}
.courbe .tip{top:4px}
.actualiser{font-size:12.5px;padding:3px 10px;margin-left:8px}
.ln3{stroke:var(--s3)}.pt3{fill:var(--s3)}.sw3{background:var(--s3)}
.seuil{stroke:var(--warn);stroke-width:1.5;stroke-dasharray:5 4}.seuil-t{fill:var(--warn);font-size:11px}
.fin-l{font-size:12px;fill:var(--ink)}
#t-per button{font-size:12.5px;padding:4px 10px}
ul.prev li{grid-template-columns:minmax(0,10em) minmax(0,1fr)}
.lbl+.legend{margin-top:6px}
@media (max-width:980px){.rang{grid-template-columns:1fr}.kpis,.grid2{grid-template-columns:repeat(2,minmax(0,1fr))}.leg{grid-template-columns:repeat(2,minmax(0,1fr))}}
@media (max-width:620px){.kpis,.grid2{grid-template-columns:1fr}.coeurs{grid-template-columns:repeat(2,minmax(0,1fr))}}
@media (max-width:620px){ol.items li{grid-template-columns:1fr}}
select{max-width:100%}
/* harmonisation (style Oubliez-moi) */
.tile,a.stat{border-radius:var(--r);padding:1rem 1.1rem}
.tile .l,.stat .l{text-transform:none;letter-spacing:0;font-size:.85rem;font-weight:500}
.tile .v,.stat .v{font-size:1.9rem;font-weight:700;letter-spacing:-.02em}
.kpi{border-left:0}.kpi .v{color:var(--c)}.k-OK .v{color:var(--ink)}
.tile[aria-pressed=true]{outline:2px solid var(--accent);outline-offset:-1px;background:var(--sel)}
a.tile,button.tile{display:block;color:inherit;white-space:normal;font-weight:inherit;line-height:1.5}a.tile.score,button.tile.score{display:flex}a.tile:hover{text-decoration:none;border-color:var(--muted)}
.grid2c+.card{margin-top:1rem}
@media (max-width:1440px){.hero{grid-template-columns:repeat(4,minmax(0,1fr))}.hero .score{grid-column:span 2}}
.tile .v{white-space:nowrap}
@media (max-width:620px){.hero{grid-template-columns:repeat(2,minmax(0,1fr));gap:.6rem}.hero .score{grid-column:span 1;gap:8px;padding:.8rem}.hero .grade{width:36px;height:36px;font-size:19px}
.tile .v,.stat .v{font-size:1.6rem}.page-head .actions .btn{padding:.35rem .7rem;font-size:.84rem}.grid2c{grid-template-columns:minmax(0,1fr)}}
.skip{position:absolute;left:-999px;top:.75rem;z-index:50;background:var(--card);color:var(--ink);padding:.5rem .8rem;border-radius:8px}.skip:focus{left:.75rem}
.badge{min-width:74px;font-size:.74rem;font-weight:650;padding:.12rem .55rem;text-transform:none;letter-spacing:0;border:1px solid transparent}
.bh .badge,ul.res .badge,td .badge{min-width:0}
select,input[type=search],input[type=text],input[type=password],input[type=number],input[type=url],input[type=time],textarea{font:inherit;font-size:.92rem;padding:.5rem .7rem;border-radius:8px;border:1px solid var(--line);background:var(--card);color:var(--ink)}
input:focus,select:focus,textarea:focus{outline:2px solid color-mix(in srgb,var(--accent) 45%,transparent);border-color:var(--accent)}
.seg{border-radius:8px;background:var(--soft)}
.seg button{border:0;border-radius:0;font-weight:600}
.seg button:hover:not(:disabled){border-color:transparent;color:var(--ink)}
.count button{padding:2px 8px}
.fix{border-left-color:var(--accent);border-radius:0 8px 8px 0}
.lienbtn{display:inline;font-weight:500}
button.corr{border-color:var(--accent);color:var(--accent);background:var(--card)}button.corr{white-space:normal;text-align:left}ol.items li>div{min-width:0}
footer{padding:1.5rem 0 0}
.sec{background:var(--soft)}
.grid2c{display:grid;grid-template-columns:repeat(auto-fit,minmax(340px,1fr));gap:1rem;align-items:start}
.grid2c>.card{margin:0}
.hero{gap:1rem;margin-bottom:1rem}
.kpis{gap:1rem;margin-bottom:1rem}
/* tableau de bord */
ul.prio{list-style:none;margin:0;padding:0}
ul.prio li{display:flex;gap:.7rem;align-items:flex-start;padding:.6rem 0;border-top:1px solid var(--line)}
ul.prio li:first-child{border-top:0;padding-top:0}
ul.prio .badge{min-width:74px;text-align:center;margin-top:1px}
ul.prio .t{font-weight:600;overflow-wrap:anywhere}ul.prio .s{display:block;color:var(--muted);font-size:.84rem}
.voir{display:inline-block;margin-top:.7rem;font-weight:600}
dl.kv{display:grid;grid-template-columns:max-content 1fr;gap:.4rem 1rem;margin:0}
dl.kv dt{color:var(--muted)}dl.kv dd{margin:0;overflow-wrap:anywhere}
.pastille{display:inline-flex;align-items:center;gap:.35rem;font-size:.82rem;font-weight:600;padding:.1rem .55rem;border-radius:999px;background:var(--soft);color:var(--muted)}
.pastille.ok{background:var(--ok-bg);color:var(--ok)}.pastille.warn{background:var(--warn-bg);color:var(--warn)}.pastille.crit{background:var(--crit-bg);color:var(--crit)}
/* onglets et formulaires (Réglages) */
.tabs{display:flex;gap:.25rem;border-bottom:1px solid var(--line);margin-bottom:1.25rem;overflow-x:auto;scrollbar-width:thin}
.tabs a{border-bottom:2px solid transparent;margin-bottom:-1px;padding:.6rem .8rem;font-weight:600;color:var(--muted);white-space:nowrap;display:flex;align-items:center;gap:.45rem}
.tabs a:hover{color:var(--ink);text-decoration:none}
.tabs a[aria-current=page]{color:var(--ink);border-bottom-color:var(--accent)}
.tabs .dot{width:8px;height:8px;border-radius:50%;background:var(--line)}
.tabs .dot.ok{background:var(--ok)}.tabs .dot.warn{background:var(--warn)}.tabs .dot.bad{background:var(--crit)}
.etroit{max-width:780px}
.champ{margin:0 0 1rem}
.champ>label,.champ>.lab{display:block;font-weight:600;font-size:.9rem;margin:0 0 .3rem}
.champ .hint,.hint{font-weight:400;color:var(--muted);font-size:.83rem}
.champ input[type=text],.champ input[type=password],.champ input[type=url],.champ input[type=number],.champ input[type=time],.champ select,.champ textarea{width:100%}
.champ input.court{width:9rem}
.champ p.hint{margin:.3rem 0 0}
.check{display:flex;gap:.55rem;align-items:flex-start;font-weight:500;font-size:.92rem;margin:0 0 .9rem;cursor:pointer}
.check input{margin:.2rem 0 0;width:auto;accent-color:var(--accent)}
.check .hint{display:block}
.row2{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:0 1rem}
.savebar{position:sticky;bottom:0;z-index:3;background:var(--bg);box-shadow:0 -8px 16px -12px rgba(0,0,0,.25);padding:.75rem 0;margin-top:.5rem;border-top:1px solid var(--line);display:flex;justify-content:space-between;align-items:center;gap:.8rem;flex-wrap:wrap}
.card .savebar{position:static;background:none;box-shadow:none;padding:.8rem 0 0;margin-top:.6rem}
.savebar .mdp{display:flex;align-items:center;gap:.5rem;flex-wrap:wrap}
.savebar .mdp label{font-size:.88rem;font-weight:600}
.savebar .mdp input{width:14rem}
.savebar .btns{display:flex;gap:.5rem;margin-left:auto}
.etat-ligne{display:flex;gap:.5rem;flex-wrap:wrap;align-items:center}
.secret{display:inline-flex;align-items:center;gap:.35rem;font-size:.83rem;color:var(--ok);font-weight:600}
.secret.non{color:var(--muted)}
table.edit td{padding:.35rem .35rem;vertical-align:middle;white-space:normal}
table.edit input,table.edit select{width:100%}
table.edit td.h input{width:5.5rem}
.erreurs{margin:0 0 1rem}
.zone-danger{border-color:color-mix(in srgb,var(--crit) 35%,var(--line))}
ol.etapes{padding-left:1.3rem;margin:.4rem 0 1rem}ol.etapes li{margin-bottom:.35rem}ol.etapes li::marker{font-weight:700;color:var(--accent)}
/* connexion */
.login{max-width:380px;margin:12vh auto 0;padding:0 1rem}
.login .brand{margin-bottom:1rem;justify-content:center}
.login .card{padding:1.4rem 1.4rem 1.2rem}
.login label{display:block;font-weight:600;font-size:.9rem;margin:0 0 .3rem}
.login input{width:100%;margin:0 0 1rem}
.login button{width:100%;justify-content:center}
@media (max-width:620px){ol.items li{grid-template-columns:1fr}.savebar .mdp input{width:100%}.savebar .btns{margin-left:0}}
"""

GRADE = lambda s: "A" if s >= 90 else "B" if s >= 75 else "C" if s >= 60 else "D" if s >= 40 else "E"
NIV_FR = {"CRIT": "Critique", "WARN": "Attention", "OK": "OK", "INFO": "Info"}
ORDRE = {"CRIT": 0, "WARN": 1, "INFO": 2, "OK": 3}


def esc(s):
    return html.escape(str(s), quote=True)


def fmt(s):
    """Texte → HTML : échappement, `code` → <code>, sauts de ligne conservés."""
    s = esc(s or "")
    s = re.sub(r"`([^`]+)`", r"<code>\1</code>", s)
    return s.replace("\n", "<br>")


def graphique(hist, nonce):
    """Évolution des notes Santé / Sécurité (SVG + survol)."""
    pts = [(d["horodatage"], d["notes"]["sante"]["score"], d["notes"]["securite"]["score"], d.get("date", "")) for d in hist
           if isinstance(d.get("notes"), dict)]
    if len(pts) < 2:
        return '<p class="empty">L’évolution des notes s’affichera dès le deuxième audit.</p>'
    W, H, ml, mr, mt, mb = 860, 230, 34, 96, 12, 28
    t0, t1 = pts[0][0], pts[-1][0]
    span = max(t1 - t0, 1)
    X = lambda t: ml + (t - t0) / span * (W - ml - mr)
    Y = lambda v: mt + (100 - v) / 100 * (H - mt - mb)
    g = []
    for v in (0, 25, 50, 75, 100):
        g.append('<line class="gl" x1="{a}" x2="{b}" y1="{y:.1f}" y2="{y:.1f}"/>'
                 '<text class="ax" x="{t}" y="{ty:.1f}" text-anchor="end">{v}</text>'
                 .format(a=ml, b=W - mr, y=Y(v), t=ml - 6, ty=Y(v) + 4, v=v))
    for i in sorted({0, len(pts) - 1, (len(pts) - 1) // 2}):
        ts = pts[i][0]
        anchor = "start" if i == 0 else "end" if i == len(pts) - 1 else "middle"
        g.append('<text class="ax" x="{x:.1f}" y="{y}" text-anchor="{a}">{d}</text>'
                 .format(x=X(ts), y=H - 8, a=anchor, d=datetime.fromtimestamp(ts).strftime("%d/%m/%y")))
    series = []
    for k, nom in ((1, "Santé"), (2, "Sécurité")):
        line = " ".join("{:.1f},{:.1f}".format(X(p[0]), Y(p[k])) for p in pts)
        series.append('<polyline class="ln ln{}" points="{}"/>'.format(k, line))
        if len(pts) <= 40:
            series.extend('<circle class="pt pt{}" cx="{:.1f}" cy="{:.1f}" r="4"/>'.format(k, X(p[0]), Y(p[k])) for p in pts)
        last = pts[-1]
        moi, autre = last[k], last[3 - k]
        dy = 4
        if abs(moi - autre) < 8:   # étiquettes trop proches : on les écarte
            dy += -7 if (moi > autre or (moi == autre and k == 1)) else 7
        series.append('<text class="lb" x="{x:.1f}" y="{y:.1f}">{n} {v}</text>'.format(x=X(last[0]) + 10, y=Y(last[k]) + dy, n=nom, v=last[k]))
    data = json.dumps([{"x": round(X(p[0]), 1), "s": p[1], "c": p[2], "d": p[3]} for p in pts])
    return """<div class="legend"><span><i class="sw sw1"></i>Santé</span><span><i class="sw sw2"></i>Sécurité</span></div>
<div class="chart" id="chart"><svg viewBox="0 0 {W} {H}" role="img" aria-label="Évolution des notes de santé et de sécurité">{g}{s}
<line id="cross" class="cr" x1="0" x2="0" y1="{mt}" y2="{yb}" visibility="hidden"/>
<rect id="hit" class="hit" x="{ml}" y="0" width="{hw}" height="{H}"/></svg><div class="tip" id="tip"></div></div>
<script type="application/json" id="pts">{data}</script>
<script nonce="{n}">(function(){{var c=document.getElementById('chart'),s=c.querySelector('svg'),h=document.getElementById('hit'),x=document.getElementById('cross'),t=document.getElementById('tip'),P=JSON.parse(document.getElementById('pts').textContent);
function mv(e){{var r=s.getBoundingClientRect(),k={W}/r.width,px=(e.clientX-r.left)*k,b=P[0];P.forEach(function(p){{if(Math.abs(p.x-px)<Math.abs(b.x-px))b=p;}});
x.setAttribute('x1',b.x);x.setAttribute('x2',b.x);x.setAttribute('visibility','visible');
t.innerHTML='<b></b><span></span><br><span></span>';t.children[0].textContent=b.d;t.children[1].textContent='Santé : '+b.s+' / 100';t.children[3].textContent='Sécurité : '+b.c+' / 100';
t.style.display='block';var l=b.x/k+12;if(l+t.offsetWidth>r.width)l=b.x/k-t.offsetWidth-12;t.style.left=l+'px';t.style.top='8px';}}
h.addEventListener('mousemove',mv);h.addEventListener('mouseleave',function(){{x.setAttribute('visibility','hidden');t.style.display='none';}});}})();</script>
""".format(W=W, H=H, g="".join(g), s="".join(series), mt=mt, yb=H - mb, ml=ml, hw=W - ml - mr, data=data.replace("</", "<\\/"), n=nonce)


ICONES = {
    "tdb": '<rect x="3.5" y="3.5" width="7" height="7" rx="1.5"/><rect x="13.5" y="3.5" width="7" height="4.5" rx="1.5"/><rect x="13.5" y="11" width="7" height="9.5" rx="1.5"/><rect x="3.5" y="13.5" width="7" height="7" rx="1.5"/>',
    "constats": '<path d="M12 3.5 19.5 6v5.5c0 4.4-3.1 7.9-7.5 9-4.4-1.1-7.5-4.6-7.5-9V6z"/><path d="m9 12 2.2 2.2L15.5 10"/>',
    "materiel": '<rect x="3.5" y="4" width="17" height="6.5" rx="1.5"/><rect x="3.5" y="13.5" width="17" height="6.5" rx="1.5"/><path d="M7 7.25h.01M7 16.75h.01M11 7.25h6M11 16.75h6"/>',
    "corrections": '<path d="M14.7 6.3a4 4 0 0 0-5.4 5.2L4 16.8 7.2 20l5.3-5.3a4 4 0 0 0 5.2-5.4l-2.4 2.4-2.6-.6-.6-2.6z"/>',
    "historique": '<path d="M3.5 12a8.5 8.5 0 1 0 2.5-6"/><path d="M3.5 4.5V9H8"/><path d="M12 7.5V12l3 2"/>',
    "rapport": '<path d="M6.5 3.5h7l4 4v13h-11z"/><path d="M13.5 3.5v4h4M9 12h6M9 15.5h6"/>',
    "reglages": '<path d="M4 7h9M17 7h3M4 17h3M11 17h9"/><circle cx="15" cy="7" r="2"/><circle cx="9" cy="17" r="2"/>',
    "deconnexion": '<path d="M14 4.5h4A1.5 1.5 0 0 1 19.5 6v12a1.5 1.5 0 0 1-1.5 1.5h-4"/><path d="m10 8-4 4 4 4M6 12h9"/>',
    "menu": '<path d="M4 7h16M4 12h16M4 17h16"/>',
    "fermer": '<path d="M6 6l12 12M18 6 6 18"/>',
    "lancer": '<path d="M7 5.5v13l11-6.5z"/>',
}
LOGO = '<span class="logo"><svg viewBox="0 0 16 16" aria-hidden="true"><path d="M4 8.5l2.5 2.5L12 5"/></svg></span>'


def icone(nom):
    return '<svg class="ico" viewBox="0 0 24 24" aria-hidden="true" focusable="false">{}</svg>'.format(ICONES[nom])


def page(titre, corps, nonce, nu=False, classe=""):
    # Le thème choisi (clair / sombre) est appliqué avant l'affichage pour éviter un flash.
    return """<!DOCTYPE html>
<html lang="fr"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex"><title>{t}</title>
<link rel="icon" href="data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 16 16'%3E%3Crect width='16' height='16' rx='4' fill='%232557b8'/%3E%3Cpath d='M4 8.5l2.5 2.5L12 5' stroke='white' stroke-width='2' fill='none'/%3E%3C/svg%3E">
<link rel="stylesheet" href="{css}">
<script nonce="{n}">document.documentElement.classList.add('js');try{{var t=localStorage.getItem('audite-moi-theme');if(t==='light'||t==='dark')document.documentElement.dataset.theme=t;}}catch(e){{}}</script>
<script src="{app}" defer></script></head><body{cl}>{c}</body></html>""".format(
        t=esc(titre), css=statique("app.css"), app=statique("app.js"), n=nonce, cl=' class="{}"'.format(classe) if classe else "",
        c=corps if nu else '<main>' + corps + "</main>")


JS_APP = r"""(function(){'use strict';
var html=document.documentElement,body=document.body;
/* thème : auto (système), clair ou sombre, mémorisé dans ce navigateur */
var th=document.getElementById('theme');
if(th){var v='auto';try{v=localStorage.getItem('audite-moi-theme')||'auto';}catch(e){}
  th.value=(v==='light'||v==='dark')?v:'auto';
  th.addEventListener('change',function(){var x=th.value;if(x==='auto')delete html.dataset.theme;else html.dataset.theme=x;
    try{localStorage.setItem('audite-moi-theme',x);}catch(e){}});}
/* menu en tiroir sur petit écran */
var btn=document.querySelector('.menu-btn'),sb=document.getElementById('sidebar'),fond=document.querySelector('.sb-backdrop'),fer=document.querySelector('.sb-close');
function tiroir(o){body.classList.toggle('nav-open',o);btn.setAttribute('aria-expanded',String(o));fond.hidden=!o;
  if(o){(sb.querySelector('a[aria-current]')||sb.querySelector('a')).focus();}else btn.focus();}
if(btn&&sb&&fond&&fer){btn.addEventListener('click',function(){tiroir(true);});fer.addEventListener('click',function(){tiroir(false);});
  fond.addEventListener('click',function(){tiroir(false);});
  document.addEventListener('keydown',function(e){if(e.key==='Escape'&&body.classList.contains('nav-open'))tiroir(false);});}
/* audit ou correction en cours : suivi, puis rechargement à la fin */
var att=body.dataset.attente;
if(att){var j=document.getElementById('journal');
  setInterval(function(){fetch('/etat.json',{credentials:'same-origin'}).then(function(r){if(r.status===401){location.href='/connexion';throw 0;}return r.json();}).then(function(e){
    if(!e.en_cours&&!e.demande&&!e.correction){location.assign(att==='correction'?'/corrections?m=fin':location.pathname);return;}
    if(j&&e.journal){j.textContent=e.journal;j.scrollTop=j.scrollHeight;}
    if(!j&&e.en_cours&&location.pathname==='/'&&att==='demande'){location.reload();}}).catch(function(){});},2500);}
/* réglage du serveur en cours d'application : on attend le résultat */
var cfg=document.querySelector('[data-attente-config]');
if(cfg){var id=cfg.dataset.attenteConfig,n=0;
  var t=setInterval(function(){n++;fetch('/reglages/resultat.json?id='+encodeURIComponent(id),{credentials:'same-origin'}).then(function(r){
    if(r.status===401){clearInterval(t);location.href='/connexion?m=redemarre';throw 0;}return r.json();}).then(function(e){
    if(e.fait){clearInterval(t);location.replace(location.pathname+'?r='+encodeURIComponent(id));}
    else if(n>60){clearInterval(t);cfg.textContent='Le réglage n’a pas été pris en charge : vérifiez « systemctl status audite-moi-configurer.path » sur le serveur.';cfg.className='banner warnb';}}).catch(function(){});},1500);}
/* Planification : n'afficher que le champ utile (jour de la semaine ou du mois) */
var fr=document.getElementById('p-frequence');
if(fr){var maj=function(){document.getElementById('c-jour').hidden=fr.value!=='hebdomadaire';document.getElementById('c-jour-mois').hidden=fr.value!=='mensuel';};
  fr.addEventListener('change',maj);maj();}
/* Sauvegardes : ajouter une ligne */
var aj=document.getElementById('ajout-ligne');
if(aj){aj.addEventListener('click',function(){var tb=document.querySelector('#sauvegardes tbody'),l=tb.querySelectorAll('tr'),
  der=l[l.length-1],n=l.length;if(n>=30)return;var c=der.cloneNode(true);
  Array.prototype.forEach.call(c.querySelectorAll('input,select'),function(x){x.name=x.name.replace(/_\d+$/,'_'+n);if(x.tagName==='INPUT')x.value='';});
  tb.appendChild(c);c.querySelector('input').focus();});}
})();"""


def barre_laterale(csrf, actif, ctx):
    etat = ctx["etat"]
    if etat["en_cours"]:
        audit = '<div class="encours"><span class="spin"></span>Audit {} en cours…</div>'.format(esc(etat.get("mode") or ""))
    else:
        dis = " disabled" if etat["demande"] else ""
        audit = ('<form method="post" action="/lancer"><input type="hidden" name="csrf" value="{c}"><input type="hidden" name="mode" value="complet">'
                 '<button class="btn-lancer"{d} title="Audit complet (quelques minutes)">{i}Lancer un audit</button></form>'
                 '<form method="post" action="/lancer"><input type="hidden" name="csrf" value="{c}"><input type="hidden" name="mode" value="rapide">'
                 '<button class="btn-rapide"{d} title="Sans Lynis, Trivy, scan du réseau local ni recherche des fichiers SUID">Audit rapide</button></form>').format(
                     c=esc(csrf), d=dis, i=icone("lancer"))
    pb = ctx["a_corriger"]
    cpt = '<span class="cpt{}" title="{} critique(s), {} à surveiller">{}</span>'.format(
        "" if pb[0] else " w", pb[0], pb[1], pb[0] + pb[1]) if pb[0] + pb[1] else ""

    def lien(href, ico, texte, cle, extra=""):
        return '<a href="{}"{}>{}<span>{}</span>{}</a>'.format(esc(href), ' aria-current="page"' if cle == actif else "", icone(ico), texte, extra)

    der = ctx["der"]
    rapport = lien("/rapports/" + der["fichiers"]["html"], "rapport", "Rapport complet", "rapport") if der else ""
    return """<a class="skip" href="#contenu">Aller au contenu</a>
<div class="mobilebar"><button type="button" class="menu-btn" aria-controls="sidebar" aria-expanded="false">{menu}<span>Menu</span></button>
<a class="brand" href="/">{logo}<span>Audite-moi</span></a>{mpb}</div>
<aside class="sidebar" id="sidebar" aria-label="Navigation principale">
<div class="sb-head"><a class="brand" href="/">{logo}<span>Audite-moi</span></a><button type="button" class="sb-close" aria-label="Fermer le menu">{fermer}</button></div>
<div class="sb-host" title="Serveur audité">{hote}</div>
<div class="sb-audit">{audit}</div>
<nav class="sb-nav">{tdb}{constats}{materiel}
<p class="sb-group" id="nav-suivi">Suivi</p><div role="group" aria-labelledby="nav-suivi">{corr}{hist}{rapport}</div></nav>
<div class="sb-foot"><nav class="sb-nav" aria-label="Configuration">{regl}</nav>
<div class="sb-row"><label class="sb-theme"><span class="cache">Thème</span><select id="theme" aria-label="Thème"><option value="auto">Thème auto</option><option value="light">Thème clair</option><option value="dark">Thème sombre</option></select></label></div>
<div class="sb-row"><form method="post" action="/deconnexion" class="inline"><input type="hidden" name="csrf" value="{c}"><button class="sb-logout">{deco}<span>Déconnexion</span></button></form></div></div>
</aside><div class="sb-backdrop" hidden></div>""".format(
        menu=icone("menu"), logo=LOGO, fermer=icone("fermer"), deco=icone("deconnexion"), hote=esc(ctx["hote"]), audit=audit, c=esc(csrf),
        mpb='<a class="mobile-pb" href="/constats">{} à corriger</a>'.format(pb[0] + pb[1]) if pb[0] + pb[1] else "",
        tdb=lien("/", "tdb", "Tableau de bord", "tdb"), constats=lien("/constats", "constats", "Constats", "constats", cpt),
        materiel=lien("/materiel", "materiel", "Matériel", "materiel"), corr=lien("/corrections", "corrections", "Corrections", "corrections"),
        hist=lien("/historique", "historique", "Historique", "historique"), rapport=rapport, regl=lien("/reglages", "reglages", "Réglages", "reglages"))


def contexte(donnees, choix=""):
    """Ce dont toutes les pages ont besoin : rapports, état de l'audit, problèmes à corriger (barre latérale)."""
    hist = donnees.rapports()
    etat = donnees.etat()
    der = hist[-1] if hist else None
    brut = der
    if choix:
        brut = next((d for d in hist if d["_fichier"] == choix), der)
    vu = donnees.vue_rapport(brut) if brut else None
    vu_der = vu if brut is der else (donnees.vue_rapport(der) if der else None)
    a_corriger = (0, 0)
    if vu_der:
        a_corriger = (vu_der["compteurs"].get("CRIT", 0), vu_der["compteurs"].get("WARN", 0))
    return {"hist": hist, "etat": etat, "der": der, "brut": brut, "vu": vu, "est_dernier": brut is der, "a_corriger": a_corriger,
            "hote": der.get("hote", "") if der else socket.gethostname()}


def evolution(donnees, ctx):
    """Nouveaux problèmes et problèmes résolus depuis l'audit précédent."""
    hist, brut, vu = ctx["hist"], ctx["brut"], ctx["vu"]
    if not vu or brut not in hist or hist.index(brut) == 0:
        return None, set(), []
    prec = donnees.vue_rapport(hist[hist.index(brut) - 1])
    pv, pp = problemes_vus(vu), problemes_vus(prec)
    return prec, {k for k in pv if k not in pp}, [pp[k] for k in pp if k not in pv]


def coque(donnees, csrf, nonce, actif, titre, corps, ctx=None, sous_titre="", actions="", titre_onglet=None):
    """Page complète : barre latérale, en-tête (titre, sous-titre, actions) et contenu."""
    ctx = ctx or contexte(donnees)
    etat = ctx["etat"]
    attente = "correction" if etat.get("correction") else "audit" if etat["en_cours"] else "demande" if etat["demande"] else ""
    prochain = donnees.prochain_audit()
    tete = '<div class="page-head"><div><h1>{}</h1>{}</div>{}</div>'.format(
        titre, '<p class="sous">{}</p>'.format(sous_titre) if sous_titre else "", '<div class="actions">{}</div>'.format(actions) if actions else "")
    pied = '<footer>Audite-moi {v}{p} · <a href="https://github.com/oliv2776/Audite-moi">GitHub</a></footer>'.format(
        v=VERSION, p=" · prochain audit automatique : " + esc(prochain) if prochain else "")
    html_ = barre_laterale(csrf, actif, ctx) + '<div class="content"><main id="contenu">' + tete + corps + pied + "</main></div>"
    page_ = page("{} — Audite-moi — {}".format(titre_onglet or re.sub(r"<[^>]+>", "", titre), ctx["hote"]), html_, nonce, nu=True, classe="with-nav")
    if attente:
        page_ = page_.replace('<body class="with-nav">', '<body class="with-nav" data-attente="{}">'.format(attente), 1)
    return page_


def bannieres_etat(ctx, message, csrf=""):
    etat, out = ctx["etat"], []
    if etat["en_cours"]:
        depuis = int((time.time() - (etat["depuis"] or time.time())) // 60)
        out.append('<div class="banner run" id="etat"><span class="spin"></span><b>Audit {m} en cours</b> depuis {d} min — la page se mettra à jour à la fin.<pre id="journal">{j}</pre></div>'
                   .format(m=esc(etat["mode"] or ""), d=depuis, j=esc(etat["journal"])))
    elif etat["bloque"]:
        out.append('<div class="banner warnb"><b>La demande d’audit n’a pas été prise en charge.</b> Vérifiez sur le serveur : <code>systemctl status audite-moi.path audite-moi.service</code></div>')
    elif etat["demande"]:
        out.append('<div class="banner run" id="etat"><span class="spin"></span>Demande enregistrée, démarrage imminent…</div>')
    elif message in MESSAGES and not etat.get("correction"):
        out.append('<div class="banner {}">{}</div>'.format(*MESSAGES[message]))
    if etat.get("correction"):
        out.append('<div class="banner run"><span class="spin"></span>Correction en cours d’application…</div>')
    if ctx["vu"] and not ctx["est_dernier"]:
        out.append('<div class="banner warnb">Vous consultez un <b>ancien rapport</b> ({}). <a href="{}">Revenir au dernier audit</a></div>'.format(
            esc(ctx["vu"].get("date", "")), "/constats"))
    return "".join(out)


def filtre(**k):
    st = {"cat": "", "niv": "PB", "sec": "", "q": ""}
    st.update(k)
    return "/constats#f=" + urllib.parse.quote(json.dumps(st, separators=(",", ":")))


def tuiles(vu, liens=False):
    n, c = vu["notes"], vu["compteurs"]
    orig = vu.get("notes_origine") or {}
    t = []
    for lib, k, cat in (("Santé", "sante", "sante"), ("Sécurité", "securite", "secu")):
        aide = "Avec vos acceptations" if orig.get(k, {}).get("score", n[k]["score"]) != n[k]["score"] else ("Voir les constats" if liens else "Cliquer pour filtrer")
        interieur = ('<span class="grade g-{g}">{g}</span><div><div class="l">{l}</div><div class="v">{v}<small> / 100</small></div><span class="h">{h}</span></div>'
                     .format(g=esc(n[k]["lettre"]), l=lib, v=esc(n[k]["score"]), h=aide))
        if liens:
            t.append('<a class="tile score" href="{}">{}</a>'.format(esc(filtre(cat=cat)), interieur))
        else:
            t.append('<button type="button" class="tile score" data-f="cat:{}" aria-pressed="false" title="N’afficher que les contrôles « {} »">{}</button>'.format(cat, lib, interieur))
    for k, lib in (("CRIT", "Critiques"), ("WARN", "À surveiller"), ("OK", "Contrôles OK"), ("INFO", "Informations")):
        interieur = '<div class="v">{}</div><div class="l">{}</div>'.format(esc(c.get(k, 0)), lib)
        if liens:
            t.append('<a class="tile kpi k-{}" href="{}">{}</a>'.format(k, esc(filtre(niv=k)), interieur))
        else:
            t.append('<button type="button" class="tile kpi k-{k}" data-f="niv:{k}" aria-pressed="false">{i}</button>'.format(k=k, i=interieur))
    return '<div class="hero">{}</div>'.format("".join(t))


def sous_titre_audit(vu):
    return "Audit du <b>{d}</b> · mode {m} · {os} · durée {s} s".format(
        d=esc(vu.get("date", "")), m=esc(vu.get("mode", "")), os=esc(vu.get("os", "")), s=esc(vu.get("duree_s", "?")))


def boutons_rapport(vu):
    f = vu["fichiers"]
    return ('<a class="btn" href="/rapports/{h}">Rapport complet</a><a class="btn" href="/texte/{t}">Version texte</a>'
            '<a class="btn" href="/rapports/{j}">JSON</a>').format(h=esc(f["html"]), t=esc(f["txt"]), j=esc(f["json"]))


def aucun_rapport():
    return ('<div class="card"><h2>Aucun rapport pour l’instant</h2><p class="muted">Lancez un premier audit avec le bouton « Lancer un audit » '
            'de la barre de gauche : un audit complet prend quelques minutes.</p></div>')


def planif_courte(donnees, prochain):
    conf = donnees.configuration()
    p = (conf or {}).get("planification") or {}
    if conf and not p.get("actif"):
        return '<span class="pastille warn">Désactivé</span>'
    if prochain:
        return "prochain le {}".format(esc(prochain))
    return esc(description_planning(p)) if p else '<span class="pastille">Inconnu</span>'


def tableau_bord(app, csrf, nonce, message):
    donnees = app.donnees
    ctx = contexte(donnees)
    vu = ctx["vu"]
    out = [bannieres_etat(ctx, message)]
    if not vu:
        out.append(aucun_rapport())
        return coque(donnees, csrf, nonce, "tdb", "Tableau de bord", "".join(out), ctx, "Santé et sécurité du serveur")
    prec, nouveaux, resolus = evolution(donnees, ctx)
    if prec is not None:
        if nouveaux or resolus:
            det = ""
            if resolus:
                det = '<details class="d"><summary>Voir les problèmes résolus</summary><ul class="res">{}</ul></details>'.format(
                    "".join('<li><span class="badge b-OK">Résolu</span> {}</li>'.format(fmt(x["titre"])) for x in resolus[:40]))
            lien = ' <a href="{}">Afficher les nouveaux</a>'.format(esc(filtre(niv="NEW"))) if nouveaux else ""
            out.append('<div class="banner evol">Depuis l’audit du {d} : <b>{n} nouveau(x) problème(s)</b>{l} · <b>{r} résolu(s)</b>{det}</div>'.format(
                d=esc(prec.get("date", "")), n=len(nouveaux), l=lien, r=len(resolus), det=det))
        else:
            out.append('<div class="banner evol">Rien de nouveau depuis l’audit du {} : aucun problème apparu ni résolu.</div>'.format(esc(prec.get("date", ""))))
    out.append(tuiles(vu, liens=True))

    # À corriger en priorité
    secs = vu.get("sections", {})
    pbs = sorted([c for c in vu.get("constats", []) if c.get("niveau") in ("CRIT", "WARN") and not c.get("accepte")],
                 key=lambda x: (ORDRE.get(x.get("niveau"), 9), x["cle"] not in nouveaux))
    if pbs:
        lis = "".join('<li><span class="badge b-{n}">{nf}</span><div><span class="t">{t}</span><span class="s">{s}{nv}</span></div></li>'.format(
            n=esc(x["niveau"]), nf=NIV_FR.get(x["niveau"], ""), t=fmt(x["titre"]),
            s=esc((secs.get(x.get("section", ""), {}) or {}).get("titre", x.get("section", ""))), nv=" · nouveau" if x["cle"] in nouveaux else "")
            for x in pbs[:7])
        prio = '<ul class="prio">{}</ul><a class="voir" href="/constats">Voir les {} constats à corriger →</a>'.format(lis, len(pbs))
    else:
        prio = '<p class="muted">Aucun problème à corriger : bravo. Les points d’information restent consultables dans <a href="/constats">Constats</a>.</p>'
    gauche = '<div class="card"><h2>À corriger en priorité</h2>{}</div>'.format(prio)

    # Surveillance : alertes, planification, matériel, corrections
    al = donnees.alertes()
    if al.get("erreur"):
        tg = '<span class="pastille warn">Échec d’envoi le {}</span>'.format(esc(datetime.fromtimestamp(al["erreur"]).strftime("%d/%m à %H:%M")))
    elif al.get("actif"):
        tg = '<span class="pastille ok">Actives</span>'
    else:
        tg = '<span class="pastille">Non configurées</span> <a href="/reglages/telegram">Configurer</a>'
    prochain = donnees.prochain_audit()
    kv = [("Alertes Telegram", tg),
          ("Audit automatique", '{} <a href="/reglages/planification">Modifier</a>'.format(planif_courte(donnees, prochain)))]
    mes = (app.mesures.stockage() or {}).get("releve") or {}
    dq = mes.get("disques") or []
    if dq:
        nc = sum(1 for d in dq if d.get("etat") == "critique")
        nw = sum(1 for d in dq if d.get("etat") == "attention")
        p = ('<span class="pastille crit">{} critique(s)</span> '.format(nc) if nc else "") + \
            ('<span class="pastille warn">{} à surveiller</span> '.format(nw) if nw else "") + \
            ('<span class="pastille ok">{} sain(s)</span>'.format(len(dq) - nc - nw) if len(dq) - nc - nw else "")
        if mes.get("smart_scan_ok") is False:
            p = '<span class="pastille warn">Relevé SMART indisponible</span>'
        kv.append(("Disques", p + ' <a href="/materiel#disques">Détail</a>'))
    pools = [x for x in (mes.get("pools") or []) if x.get("taille")]
    if pools:
        seuil_a, seuil_c = app.seuils.effectifs().get("pool_attention", 80), app.seuils.effectifs().get("pool_critique", 90)
        txt = []
        for x in pools:
            pct = 100.0 * x["utilise"] / x["taille"]
            cl = "crit" if pct >= seuil_c else "warn" if pct >= seuil_a else "ok"
            txt.append('<span class="pastille {}">{} {:.0f} %</span>'.format(cl, esc(x["nom"]), pct))
        kv.append(("Pools ZFS", " ".join(txt)))
    journal = donnees.corrections()
    if journal:
        e = journal[-1]
        kv.append(("Dernière correction", '{} — {} <a href="/corrections">Journal</a>'.format(
            esc(e.get("libelle", "")), esc(datetime.fromtimestamp(e.get("date", 0)).strftime("%d/%m à %H:%M")))))
    surv = '<div class="card"><h2>Surveillance</h2><dl class="kv">{}</dl></div>'.format("".join("<dt>{}</dt><dd>{}</dd>".format(a, b) for a, b in kv))
    evol = '<div class="card"><h2>Évolution des notes <span class="mini"><a href="/historique">Historique</a></span></h2>{}</div>'.format(graphique(ctx["hist"], nonce))
    out.append('<div class="grid2c">{}{}</div>{}'.format(gauche, surv, evol))
    return coque(donnees, csrf, nonce, "tdb", "Tableau de bord", "".join(out), ctx, sous_titre_audit(vu), boutons_rapport(vu))


def page_constats(app, csrf, nonce, message, choix=""):
    donnees = app.donnees
    ctx = contexte(donnees, choix)
    vu, brut, est_dernier = ctx["vu"], ctx["brut"], ctx["est_dernier"]
    out = [bannieres_etat(ctx, message)]
    if not vu:
        out.append(aucun_rapport())
        return coque(donnees, csrf, nonce, "constats", "Constats", "".join(out), ctx)
    prec, nouveaux, _ = evolution(donnees, ctx)
    out.append(tuiles(vu))
    journal = donnees.corrections()
    faites = {}
    for e in journal:
        if e.get("ok") and e.get("type") in TYPES_CORRECTION and not e.get("annule") and e.get("date", 0) >= vu.get("horodatage", 0):
            faites[(e["type"], e.get("cible"))] = e
    secs = vu.get("sections", {})
    constats = sorted(vu.get("constats", []), key=lambda x: (ORDRE.get(x.get("niveau"), 9) if not x.get("accepte") else 5))
    lis, vues = [], []
    nb_acc = 0
    for x in constats:
        sid = x.get("section", "")
        info = secs.get(sid, {})
        court = info.get("court") or info.get("titre", sid)
        if sid not in vues:
            vues.append(sid)
        niv = "ACC" if x.get("accepte") else x.get("niveau")
        nb_acc += niv == "ACC"
        msg = ""
        if x.get("accepte"):
            msg += '<div class="msgd acc">Accepté ({}) : {}</div>'.format(NIV_FR.get(x.get("niveau"), ""), fmt(x["accepte"]))
        if x.get("detail"):
            d = x["detail"]
            if x["niveau"] in ("CRIT", "WARN") or len(d) > 160 or "\n" in d:
                msg += '<details class="d"><summary>Détail</summary><div class="det">{}</div></details>'.format(fmt(d))
            else:
                msg += '<div class="msgd">{}</div>'.format(fmt(d))
        fx = '<div class="fix">{}</div>'.format(fmt(x["correctif"])) if x.get("correctif") and not x.get("accepte") else ""
        refs = [r for r in (x.get("references") or []) if isinstance(r, dict) and str(r.get("url", "")).startswith("https://")]
        if refs:
            fx += '<div class="refs">Références : {}</div>'.format(" · ".join(
                '<a href="{u}" title="{t}" target="_blank" rel="noopener noreferrer">{s} {i}</a>'.format(
                    u=esc(r["url"]), t=esc(r.get("titre", "")), s=esc(r.get("source", "")), i=esc(r.get("id", ""))) for r in refs))
        acts = []
        if est_dernier and not x.get("accepte"):
            for i, a in enumerate(x.get("actions") or []):
                if a.get("type") not in TYPES_CORRECTION:
                    continue
                e = faites.get((a["type"], a.get("cible")))
                if e:
                    acts.append('<span class="fait">✓ {} — corrigé le {}</span>'.format(esc(a.get("libelle", "")), esc(datetime.fromtimestamp(e["date"]).strftime("%d/%m à %H:%M"))))
                    continue
                acts.append('<button type="button" class="corr" data-dlg="corriger" data-cle="{k}" data-i="{i}" data-rapport="{r}" data-titre="{t}" '
                            'data-texte="Cette commande sera exécutée sur le serveur, en root. Elle pourra être annulée depuis la page Corrections." '
                            'data-cmd="{cmd}" data-avert="{av}">Corriger : {l}</button>'.format(
                                k=esc(x["cle"]), i=i, r=esc(brut["_fichier"]), t=esc(a.get("libelle", "")), cmd=esc(a.get("apercu", "")),
                                av=esc(AVERTISSEMENTS.get(a["type"], "")), l=esc(a.get("libelle", ""))))
        if est_dernier and x.get("niveau") != "OK":
            if x.get("accepte"):
                acts.append('<form class="inline" method="post" action="/accepter"><input type="hidden" name="csrf" value="{c}"><input type="hidden" name="cle" value="{k}">'
                            '<input type="hidden" name="retirer" value="1"><button class="lienbtn">Ne plus accepter</button></form>'.format(c=esc(csrf), k=esc(x["cle"])))
            elif x.get("niveau") in ("CRIT", "WARN", "INFO"):
                acts.append('<button type="button" class="lienbtn" data-dlg="accepter" data-cle="{k}" data-titre="Accepter : {t}" '
                            'data-texte="Le constat restera visible, avec votre raison, mais ne comptera plus comme un problème ni dans la note, et ne déclenchera plus d’alerte. Vous pourrez revenir en arrière.">'
                            'C’est voulu…</button>'.format(k=esc(x["cle"]), t=esc(x["titre"][:120])))
        acts_html = '<div class="acts">{}</div>'.format("".join(acts)) if acts else ""
        nv = x["cle"] in nouveaux
        lis.append('<li data-niv="{n}" data-cat="{cat}" data-sec="{sid}" data-nouveau="{nv}"><div><span class="badge b-{n}">{nf}</span>{tag}</div><div>'
                   '<button type="button" class="sec" data-sec="{sid}" title="N’afficher que cette section">{s}</button><span class="ttl">{t}</span>{msg}{fx}{acts}</div></li>'.format(
                       n=esc(niv), cat=esc(info.get("categorie", "")), sid=esc(sid), nf="Accepté" if niv == "ACC" else NIV_FR.get(niv, ""),
                       nv="1" if nv else "0", tag='<span class="nouv">Nouveau</span>' if nv else "",
                       s=esc(court), t=fmt(x["titre"]), msg=msg, fx=fx, acts=acts_html))
    opts = "".join('<option value="{}">{}</option>'.format(esc(s), esc(secs.get(s, {}).get("titre", s))) for s in vues)
    seg_cat = "".join('<button type="button" data-v="{}">{}</button>'.format(v, t) for v, t in (("", "Toutes"), ("sante", "Santé"), ("secu", "Sécurité")))
    niveaux = [("PB", "À corriger"), ("CRIT", "Critiques"), ("WARN", "Attention")]
    if nouveaux:
        niveaux.append(("NEW", "Nouveaux"))
    niveaux += [("OK", "OK"), ("INFO", "Info")]
    if nb_acc:
        niveaux.append(("ACC", "Acceptés"))
    niveaux.append(("", "Tout"))
    seg_niv = "".join('<button type="button" data-v="{}">{}</button>'.format(v, t) for v, t in niveaux)
    out.append("""<div class="card" id="constats"><h2>Liste des constats <span class="mini">par défaut : ce qu’il faut corriger, du plus urgent au moins urgent</span></h2>
<div class="filters"><div class="seg" data-g="cat" role="group" aria-label="Catégorie">{sc}</div><div class="seg" data-g="niv" role="group" aria-label="Niveau">{sn}</div>
<select id="fsec" aria-label="Section"><option value="">Toutes les sections</option>{o}</select><input id="fq" type="search" placeholder="Rechercher (ex. ssh, zfs, docker…)" aria-label="Rechercher"></div>
<div class="count" id="fcount"><span></span><button type="button" id="freset" class="cache">Réinitialiser les filtres</button></div>
<ol class="items" id="items">{li}</ol><p class="vide cache" id="fvide">Aucun constat ne correspond à ces filtres.</p></div>""".format(
        sc=seg_cat, sn=seg_niv, o=opts, li="".join(lis)))
    out.append('<script src="{}" defer></script>'.format(statique("filtres.js")))
    out.append(DIALOGUE.format(csrf=esc(csrf)))
    out.append('<script src="{}" defer></script>'.format(statique("dialogue.js")))
    return coque(donnees, csrf, nonce, "constats", "Constats", "".join(out), ctx,
                 "{} constats · {}".format(len(constats), sous_titre_audit(vu)), boutons_rapport(vu))


def page_corrections(app, csrf, nonce, message):
    donnees = app.donnees
    ctx = contexte(donnees)
    etat = ctx["etat"]
    journal = donnees.corrections()
    out = [bannieres_etat(ctx, message)]
    if not journal and not etat.get("correction"):
        out.append('<div class="card"><p class="muted">Aucune correction pour l’instant. Les problèmes qui peuvent être corrigés en un clic portent un bouton '
                   '« Corriger » dans <a href="/constats">Constats</a> : la commande exacte est affichée, le mot de passe redemandé, et chaque correction peut être annulée ici.</p></div>')
    else:
        rows = []
        annulees = {e.get("cible") for e in journal if e.get("type") == "annulation" and e.get("ok")}
        for e in reversed(journal[-50:]):
            if e.get("type") == "refus":
                badge = '<span class="badge b-WARN">Refusée</span>'
            elif e.get("type") == "annulation":
                badge = '<span class="badge b-INFO">Effectuée</span>' if e.get("ok") else '<span class="badge b-CRIT">Échec</span>'
            elif e.get("annule") or e.get("id") in annulees:
                badge = '<span class="badge b-ACC">Annulée</span>'
            else:
                k, t = ETAT_CORR[bool(e.get("ok"))]
                badge = '<span class="badge b-{}">{}</span>'.format(k, t)
            bouton = ""
            if e.get("ok") and e.get("annulation") and not e.get("annule") and e.get("type") in TYPES_CORRECTION:
                cmd = "\n".join(" ".join(x) for x in e["annulation"])
                bouton = ('<button type="button" class="lienbtn" data-dlg="annuler" data-id="{i}" data-titre="Annuler : {l}" data-cmd="{c}" '
                          'data-texte="Cette commande remet le réglage tel qu’il était avant la correction.">Annuler</button>').format(
                              i=esc(e["id"]), l=esc(e.get("libelle", "")), c=esc(cmd))
            sortie = '<details class="d"><summary>Commandes et sortie</summary><pre class="sortie">{}</pre></details>'.format(
                esc("\n".join(e.get("commandes") or []) + ("\n\n" if e.get("commandes") else "") + (e.get("sortie") or ""))) if (e.get("sortie") or e.get("commandes")) else ""
            rows.append('<tr><td>{d}</td><td class="etat"><b>{l}</b>{s}</td><td>{b}</td><td>{a}</td></tr>'.format(
                d=esc(datetime.fromtimestamp(e.get("date", 0)).strftime("%d/%m/%Y %H:%M")), l=esc(e.get("libelle", "")), s=sortie, b=badge, a=bouton))
        attente = '<p class="sub"><span class="spin"></span>Une correction est en cours…</p>' if etat.get("correction") else ""
        out.append('<div class="card" id="corrections">{}<div class="tw"><table><thead><tr><th>Date</th><th>Correction</th><th>Résultat</th><th></th></tr></thead>'
                   '<tbody>{}</tbody></table></div></div>'.format(attente, "".join(rows)))
        out.append(DIALOGUE.format(csrf=esc(csrf)))
        out.append('<script src="{}" defer></script>'.format(statique("dialogue.js")))
    return coque(donnees, csrf, nonce, "corrections", "Corrections", "".join(out), ctx,
                 "Appliquées depuis l’interface, en root, avec votre mot de passe · chacune peut être annulée")


def page_historique(app, csrf, nonce):
    donnees = app.donnees
    ctx = contexte(donnees)
    hist = ctx["hist"]
    out = []
    if not hist:
        out.append(aucun_rapport())
    else:
        out.append('<div class="card" id="evolution"><h2>Évolution des notes</h2>{}</div>'.format(graphique(hist, nonce)))
        rows = []
        for d in reversed(hist[-60:]):
            n_, c_, f_ = d["notes"], d["compteurs"], d["fichiers"]
            rows.append("<tr><td><a href='/constats?rapport={j}' title='Afficher les constats de ce rapport'>{date}</a></td><td>{mode}</td>"
                        "<td><span class='pill'><i class='g-{gs}'>{gs}</i>{s}</span></td><td><span class='pill'><i class='g-{gc}'>{gc}</i>{c}</span></td>"
                        "<td class='num'>{cr}</td><td class='num'>{w}</td><td><a href='/rapports/{h}'>rapport</a> · <a href='/texte/{t}'>texte</a></td></tr>".format(
                            j=esc(d["_fichier"]), date=esc(d.get("date", "")), mode=esc(d.get("mode", "")), gs=esc(n_["sante"]["lettre"]), s=esc(n_["sante"]["score"]),
                            gc=esc(n_["securite"]["lettre"]), c=esc(n_["securite"]["score"]), cr=esc(c_.get("CRIT", 0)), w=esc(c_.get("WARN", 0)),
                            h=esc(f_["html"]), t=esc(f_["txt"])))
        out.append('<div class="card" id="historique"><h2>Rapports <span class="mini">cliquez sur une date pour afficher ses constats</span></h2><div class="tw"><table><thead><tr><th>Date</th><th>Mode</th><th>Santé</th><th>Sécurité</th>'
                   '<th class="num">Critiques</th><th class="num">À surveiller</th><th>Fichiers</th></tr></thead><tbody>{}</tbody></table></div></div>'.format("".join(rows)))
    return coque(donnees, csrf, nonce, "historique", "Historique", "".join(out), ctx,
                 "{} rapport(s) conservé(s) · <a href=\"/reglages/planification\">conservation et planification</a>".format(len(hist)))


JS_FILTRES = """(function(){
var st={cat:'',niv:'PB',sec:'',q:''},L=document.getElementById('items');if(!L)return;
var Q=function(s,r){return Array.prototype.slice.call((r||document).querySelectorAll(s));};
var items=Q('li[data-niv]',L),fs=document.getElementById('fsec'),fq=document.getElementById('fq'),cnt=document.getElementById('fcount'),vide=document.getElementById('fvide');
function okNiv(li){var n=li.dataset.niv;if(!st.niv)return true;if(st.niv==='PB')return n==='CRIT'||n==='WARN';if(st.niv==='NEW')return li.dataset.nouveau==='1';return n===st.niv;}
function apply(){
  var k=0;items.forEach(function(li){var v=(!st.cat||li.dataset.cat===st.cat)&&okNiv(li)&&(!st.sec||li.dataset.sec===st.sec)&&(!st.q||li.textContent.toLowerCase().indexOf(st.q)>=0);li.classList.toggle('cache',!v);if(v)k++;});
  cnt.firstChild.textContent=k+' constat(s) affiché(s) sur '+items.length;
  vide.classList.toggle('cache',k>0);
  Q('.seg').forEach(function(g){Q('button',g).forEach(function(b){b.setAttribute('aria-pressed',st[g.dataset.g]===b.dataset.v?'true':'false');});});
  Q('button.tile').forEach(function(b){var p=b.dataset.f.split(':');b.setAttribute('aria-pressed',st[p[0]]===p[1]?'true':'false');});
  fs.value=st.sec;
  var defaut=!st.cat&&st.niv==='PB'&&!st.sec&&!st.q;document.getElementById('freset').classList.toggle('cache',defaut);
  try{history.replaceState(null,'',location.pathname+location.search+(defaut?'':'#f='+encodeURIComponent(JSON.stringify(st))));}catch(e){}
}
Q('.seg').forEach(function(g){Q('button',g).forEach(function(b){b.addEventListener('click',function(){st[g.dataset.g]=b.dataset.v;apply();});});});
Q('button.tile').forEach(function(b){b.addEventListener('click',function(){var p=b.dataset.f.split(':');
  st[p[0]]=(st[p[0]]===p[1])?(p[0]==='niv'?'PB':''):p[1];
  apply();document.getElementById('constats').scrollIntoView();});});
Q('button.sec',L).forEach(function(b){b.addEventListener('click',function(){st.sec=b.dataset.sec;apply();});});
Q('[data-voir-nouveaux]').forEach(function(b){b.addEventListener('click',function(){st={cat:'',niv:'NEW',sec:'',q:''};fq.value='';apply();document.getElementById('constats').scrollIntoView();});});
fs.addEventListener('change',function(){st.sec=fs.value;apply();});
fq.addEventListener('input',function(){st.q=fq.value.trim().toLowerCase();apply();});
document.getElementById('freset').addEventListener('click',function(){st={cat:'',niv:'PB',sec:'',q:''};fq.value='';apply();});
var m=/#f=(.*)$/.exec(location.hash);if(m){try{var o=JSON.parse(decodeURIComponent(m[1]));['cat','niv','sec','q'].forEach(function(k){if(typeof o[k]==='string')st[k]=o[k];});fq.value=st.q;}catch(e){}}
apply();
})();"""

# Fenêtre de confirmation commune : corriger, annuler une correction, accepter un constat
DIALOGUE = """<dialog id="dlg" aria-labelledby="dlg-t"><form method="post" id="dlg-f">
<input type="hidden" name="csrf" value="{csrf}"><input type="hidden" name="cle"><input type="hidden" name="i"><input type="hidden" name="rapport"><input type="hidden" name="id">
<h3 id="dlg-t"></h3><p id="dlg-p" class="dlg-p"></p><pre id="dlg-c" class="dlg-c"></pre><p id="dlg-a" class="dlg-a"></p>
<label id="dlg-rl" class="dlg-l">Pourquoi est-ce voulu ? <span>(affiché dans les rapports)</span><input name="raison" maxlength="200" placeholder="ex. accès réservé au réseau local, choix assumé"></label>
<label id="dlg-ml" class="dlg-l">Mot de passe de l’interface<input type="password" name="mot_de_passe" autocomplete="current-password"></label>
<div class="dlg-b"><button type="button" id="dlg-x">Fermer</button><button class="primary" id="dlg-ok">Confirmer</button></div></form></dialog>"""

JS_DIALOGUE = """(function(){
var d=document.getElementById('dlg');if(!d||!d.showModal)return;var f=document.getElementById('dlg-f');
function $(i){return document.getElementById(i);}
function montre(el,v){el.classList.toggle('cache',!v);}
Array.prototype.forEach.call(document.querySelectorAll('[data-dlg]'),function(b){b.addEventListener('click',function(){
  var k=b.dataset.dlg;f.reset();f.action={corriger:'/corriger',annuler:'/annuler',accepter:'/accepter'}[k];
  ['cle','i','rapport','id'].forEach(function(n){f.elements[n].value=b.dataset[n]||'';});
  $('dlg-t').textContent=b.dataset.titre||'';$('dlg-p').textContent=b.dataset.texte||'';
  $('dlg-c').textContent=b.dataset.cmd||'';montre($('dlg-c'),!!b.dataset.cmd);
  $('dlg-a').textContent=b.dataset.avert||'';montre($('dlg-a'),!!b.dataset.avert);
  montre($('dlg-rl'),k==='accepter');montre($('dlg-ml'),k!=='accepter');
  f.elements.mot_de_passe.required=k!=='accepter';
  $('dlg-ok').textContent={corriger:'Appliquer la correction',annuler:'Annuler cette correction',accepter:'Accepter'}[k];
  d.showModal();(k==='accepter'?f.elements.raison:f.elements.mot_de_passe).focus();});});
$('dlg-x').addEventListener('click',function(){d.close();});
f.addEventListener('submit',function(){$('dlg-ok').disabled=true;});
})();"""

AVERTISSEMENTS = {
    "nc-2fa-imposer": "Chaque utilisateur devra configurer une application d’authentification (TOTP) à sa prochaine connexion. Les clients de synchronisation "
                      "connectés avec un mot de passe d’application continuent de fonctionner.",
    "ufw-supprimer": "Si un service doit utiliser ce port plus tard, il faudra rouvrir le port.",
    "docker-restart": "Le conteneur redémarrera automatiquement avec le NAS et après un plantage.",
    "chmod-600": "Seul le propriétaire du fichier (root) pourra le lire ; Docker Compose lancé avec sudo n’est pas gêné.",
    "zfs-scrub": "Le scrub lit tous les disques du pool : les performances baissent pendant quelques heures.",
}
MESSAGES = {"lance": ("okb", "Demande enregistrée : l’audit démarre dans quelques secondes."),
            "occupe": ("warnb", "Un audit est déjà en cours ou en attente."),
            "erreur": ("warnb", "Impossible d’enregistrer la demande (droits du dossier de demandes ?)."),
            "correction": ("okb", "Correction demandée : elle est appliquée dans quelques secondes, le résultat s’affichera ci-dessous."),
            "corr-occupe": ("warnb", "Une correction est déjà en cours : réessayez dans quelques secondes."),
            "corr-invalide": ("warnb", "Cette correction n’est plus disponible : relancez un audit."),
            "mdp": ("warnb", "Mot de passe incorrect : rien n’a été modifié."),
            "bloque": ("warnb", "Trop d’essais de mot de passe : réessayez dans 15 minutes."),
            "accepte": ("okb", "Constat accepté : il ne compte plus dans la note (recalculée ici, puis par le prochain audit)."),
            "retire": ("okb", "Le constat compte de nouveau comme un problème."),
            "fin": ("okb", "Correction traitée : voyez le résultat ci-dessous. L’audit suivant confirmera que le problème a disparu.")}
ETAT_CORR = {True: ("OK", "Réussie"), False: ("CRIT", "Échec")}


def problemes_vus(v):
    return {c["cle"]: c for c in v.get("constats", []) if c.get("niveau") in ("CRIT", "WARN") and not c.get("accepte")}


HTML_MATERIEL = """<div class="kpis">
<a class="stat" href="#cpu"><div class="l">Processeur</div><div class="v" id="k-cpu">—</div><div class="s" id="k-cpu-s">&nbsp;</div><svg id="k-cpu-g" viewBox="0 0 120 28" preserveAspectRatio="none" aria-hidden="true"></svg></a>
<a class="stat" href="#memoire"><div class="l">Mémoire</div><div class="v" id="k-ram">—</div><div class="s" id="k-ram-s">&nbsp;</div><svg id="k-ram-g" viewBox="0 0 120 28" preserveAspectRatio="none" aria-hidden="true"></svg></a>
<a class="stat" href="#gpu"><div class="l">GPU</div><div class="v" id="k-gpu">—</div><div class="s" id="k-gpu-s">&nbsp;</div><svg id="k-gpu-g" viewBox="0 0 120 28" preserveAspectRatio="none" aria-hidden="true"></svg></a>
<a class="stat" href="#stockage"><div class="l">Stockage</div><div class="v" id="k-sto">—</div><div class="s" id="k-sto-s">&nbsp;</div><div class="s" id="k-sto-e">&nbsp;</div></a>
</div>
<div class="card" id="stockage"><h2>Stockage <span class="mini"><span id="st-age"></span><button type="button" class="actualiser" id="st-maj">Actualiser</button></span></h2>
<div class="grid2" id="st-pools"></div><div id="st-vol"></div></div>
<div class="card" id="disques"><h2>Disques <span class="mini">état SMART, du plus urgent au moins urgent dans chaque pool</span></h2><div class="tw" id="st-disques"></div></div>
<div class="card" id="tendances"><h2>Tendances <span class="mini"><span class="seg" id="t-per" role="group" aria-label="Période">
<button type="button" data-j="7">7 jours</button><button type="button" data-j="30" aria-pressed="true">30 jours</button><button type="button" data-j="90">90 jours</button><button type="button" data-j="365">1 an</button></span></span></h2>
<div class="grid2"><div><div class="lbl">Remplissage des pools</div><div class="legend" id="t-leg1"></div><div class="courbe" id="t-rempl"></div></div>
<div><div class="lbl">Température maximale des disques, par pool</div><div class="legend" id="t-leg2"></div><div class="courbe" id="t-temp"></div></div></div>
<ul class="lignes prev" id="t-prev"></ul></div>
<div class="rang">
<div class="card" id="cpu"><h2>Processeur <span class="mini" id="cpu-modele"></span></h2><div class="faits" id="cpu-faits"></div><div class="courbe" id="cpu-courbe"></div><div class="coeurs" id="cpu-coeurs"></div></div>
<div class="card" id="memoire"><h2>Mémoire <span class="mini" id="ram-total"></span></h2><div class="segbar" id="ram-seg" role="img"></div><div class="leg" id="ram-leg"></div>
<div class="sub" id="ram-swap"></div><div class="courbe" id="ram-courbe"></div><p class="sub">Le cache ZFS (ARC) et le cache système se libèrent tout seuls quand les applications ont besoin de mémoire : seule la part « Applications » compte vraiment.</p></div>
</div>
<div class="card" id="gpu"><h2>GPU <span class="mini">occupation, mémoire vidéo, température — utile pendant un transcodage</span></h2><div class="grid2" id="gpus"></div></div>
"""

JS_MATERIEL = r"""(function(){'use strict';
var D=JSON.parse(document.getElementById('init').textContent),CSRF=(document.querySelector('input[name=csrf]')||{}).value||'';
var $=function(i){return document.getElementById(i);},NF={};
function nf(v,d){d=d==null?1:d;NF[d]=NF[d]||new Intl.NumberFormat('fr-FR',{maximumFractionDigits:d});return NF[d].format(v);}
function h(s){return String(s==null?'':s).replace(/[&<>"']/g,function(c){return{'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c];});}
function oct(b){if(b==null)return '—';var u=['o','Ko','Mo','Go','To','Po'],i=0;while(Math.abs(b)>=1024&&i<5){b/=1024;i++;}return nf(b,(b>=100||i===0)?0:1)+' '+u[i];}
function pc(v){return v==null?'—':nf(v,0)+' %';}
function niv(p,w,c){return p>=c?'crit':p>=w?'warn':'';}
function SE(k,d){var v=(D.seuils||{})[k];return typeof v==='number'?v:d;}
function meter(p,cls,lab){p=Math.max(0,Math.min(100,p||0));return '<div class="meter '+(cls||'')+'" role="meter" aria-valuemin="0" aria-valuemax="100" aria-valuenow="'+Math.round(p)+'" aria-label="'+h(lab)+'"><i data-w="'+p.toFixed(1)+'"></i></div>';}
function largeurs(r){Array.prototype.forEach.call(r.querySelectorAll('[data-w]'),function(e){e.style.width=e.getAttribute('data-w')+'%';});}
var ET={ok:['OK','✓','OK'],attention:['WARN','!','Attention'],critique:['CRIT','✕','Critique'],veille:['INFO','–','En veille'],inconnu:['INFO','?','Inconnu']};
function badge(e){e=ET[e]||ET.inconnu;return '<span class="badge b-'+e[0]+'">'+e[2]+'</span>';}
function icone(e){e=ET[e]||ET.inconnu;return '<i class="ic '+e[0]+'" aria-hidden="true">'+e[1]+'</i>';}
function ilya(s){s=Math.max(0,Math.round(s));if(s<60)return 'à l’instant';if(s<3600)return 'il y a '+Math.round(s/60)+' min';if(s<172800)return 'il y a '+Math.round(s/3600)+' h';return 'il y a '+Math.round(s/86400)+' jours';}
function duree(x){if(x==null)return '—';var a=x/8766;if(a>=1)return nf(a,1)+' an'+(a>=2?'s':'');var m=x/730.5;return m>=1?nf(m,0)+' mois':nf(x,0)+' h';}
function faits(id,l){$(id).innerHTML=l.map(function(f){return '<div><div class="lbl">'+h(f[0])+'</div><div class="val">'+h(f[1])+'</div></div>';}).join('');}
function spark(svg,v){v=v.filter(function(x){return x!=null;}).slice(-45);if(v.length<2){svg.innerHTML='';return;}
  svg.innerHTML='<polyline class="spk" vector-effect="non-scaling-stroke" points="'+v.map(function(x,i){return (i/(v.length-1)*120).toFixed(1)+','+(26-Math.min(100,x)/100*24).toFixed(1);}).join(' ')+'"/>';}
var FEN=180;
function courbe(el,pts,nom,H){
  var W=Math.max(280,Math.round(el.clientWidth||600)),ml=42,mr=10,mt=10,mb=22,now=D.maintenant;H=H||150;
  var X=function(t){return ml+(1-(now-t)/FEN)*(W-ml-mr);},Y=function(v){return mt+(100-Math.min(100,Math.max(0,v)))/100*(H-mt-mb);};
  var g='';[0,50,100].forEach(function(v){g+='<line class="gl" x1="'+ml+'" x2="'+(W-mr)+'" y1="'+Y(v)+'" y2="'+Y(v)+'"/><text class="ax" x="'+(ml-6)+'" y="'+(Y(v)+4)+'" text-anchor="end">'+v+' %</text>';});
  g+='<text class="ax" x="'+ml+'" y="'+(H-5)+'">il y a 3 min</text><text class="ax" x="'+(W-mr)+'" y="'+(H-5)+'" text-anchor="end">maintenant</text>';
  var p=pts.filter(function(q){return q.v!=null&&now-q.t<=FEN;}),l='';
  if(p.length>1)l='<polyline class="ln ln1" points="'+p.map(function(q){return X(q.t).toFixed(1)+','+Y(q.v).toFixed(1);}).join(' ')+'"/>';
  var z=p[p.length-1];if(z)l+='<circle class="pt pt1" cx="'+X(z.t).toFixed(1)+'" cy="'+Y(z.v).toFixed(1)+'" r="4"/>';
  el.innerHTML='<svg viewBox="0 0 '+W+' '+H+'" role="img" aria-label="'+h(nom)+' sur les 3 dernières minutes : '+(z?pc(z.v):'pas encore de mesure')+'">'+g+l+
    '<line class="cr" y1="'+mt+'" y2="'+(H-mb)+'" visibility="hidden"/><rect class="hit" x="'+ml+'" y="0" width="'+(W-ml-mr)+'" height="'+H+'"/></svg><div class="tip"></div>';
  var svg=el.firstChild,cr=svg.querySelector('.cr'),hit=svg.querySelector('.hit'),tip=el.querySelector('.tip');
  function show(cx){if(!p.length)return;var r=svg.getBoundingClientRect(),k=W/r.width,px=cx*k,b=p[0];
    p.forEach(function(q){if(Math.abs(X(q.t)-px)<Math.abs(X(b.t)-px))b=q;});
    var x=X(b.t),s=Math.round(now-b.t);cr.setAttribute('x1',x);cr.setAttribute('x2',x);cr.setAttribute('visibility','visible');
    tip.innerHTML='<b></b><span></span>';tip.children[0].textContent=nom+' : '+pc(b.v);tip.children[1].textContent=s<3?'maintenant':'il y a '+(s<60?s+' s':Math.floor(s/60)+' min '+(s%60)+' s');
    tip.style.display='block';var lf=x/k+12;if(lf+tip.offsetWidth>r.width)lf=x/k-tip.offsetWidth-12;tip.style.left=lf+'px';}
  hit.addEventListener('mousemove',function(e){el._mx=e.clientX-svg.getBoundingClientRect().left;show(el._mx);});
  hit.addEventListener('mouseleave',function(){el._mx=null;cr.setAttribute('visibility','hidden');tip.style.display='none';});
  if(el._mx!=null)show(el._mx);
}
function principal(gs){return gs.filter(function(g){return g.marque==='AMD'||g.marque==='NVIDIA';})[0]||gs[0];}

function direct(){
  var d=D.direct||{},c=d.cpu||{},m=d.memoire,gs=d.gpus||[],Hs=D.historique||[];
  /* tuiles */
  $('k-cpu').innerHTML=c.pourcent==null?'—':nf(c.pourcent,0)+'<small> %</small>';
  $('k-cpu-s').textContent=[c.temperature!=null?c.temperature+' °C':'',c.charge?'charge '+nf(c.charge[0],2):''].filter(Boolean).join(' · ')||' ';
  spark($('k-cpu-g'),Hs.map(function(x){return x.cpu;}));
  if(m){$('k-ram').innerHTML=nf(m.pourcent,0)+'<small> %</small>';$('k-ram-s').textContent=oct(m.applis)+' sur '+oct(m.total)+' (applications)';}
  spark($('k-ram-g'),Hs.map(function(x){return x.ram;}));
  var gp=principal(gs);
  if(gp){$('k-gpu').innerHTML=gp.occupation==null?'—':nf(gp.occupation,0)+'<small> %</small>';$('k-gpu-s').textContent=gp.nom+(gp.temperature!=null?' · '+gp.temperature+' °C':'');
    spark($('k-gpu-g'),Hs.map(function(x){return (x.gpu||{})[gp.id];}));}
  else{$('k-gpu').textContent='—';$('k-gpu-s').textContent='Aucun GPU détecté';}
  /* processeur */
  var up=d.demarrage?(D.maintenant-d.demarrage)/3600:null;
  $('cpu-modele').textContent=[c.modele,c.coeurs&&c.coeurs.length?c.coeurs.length+' cœurs logiques':'',up==null?'':'allumé depuis '+(up<48?nf(up,0)+' h':nf(up/24,0)+' jours')].filter(Boolean).join(' · ');
  faits('cpu-faits',[['Utilisation',pc(c.pourcent)],['Température',c.temperature!=null?c.temperature+' °C':'—'],['Fréquence',c.frequence?nf(c.frequence/1000,2)+' GHz':'—'],
    ['Charge 1 · 5 · 15 min',c.charge?c.charge.map(function(v){return nf(v,2);}).join(' · '):'—']]);
  courbe($('cpu-courbe'),Hs.map(function(x){return {t:x.t,v:x.cpu};}),'Processeur');
  var co=$('cpu-coeurs');co.innerHTML=(c.coeurs||[]).map(function(v,i){return '<div><div class="cl"><span>'+(i+1)+'</span><span>'+pc(v)+'</span></div>'+meter(v,'fin','Cœur '+(i+1))+'</div>';}).join('');largeurs(co);
  /* mémoire */
  if(m){
    var parts=[['Applications',m.applis,'c1'],['Cache ZFS (ARC)',m.arc,'c2'],['Cache système',m.cache,'c3'],['Libre',m.libre,'c0']];
    $('ram-total').textContent=oct(m.total)+' au total';
    var sg=$('ram-seg');sg.setAttribute('aria-label',parts.map(function(p){return p[0]+' '+oct(p[1]);}).join(', '));
    sg.innerHTML=parts.filter(function(p){return p[1]>0;}).map(function(p){return '<i class="'+p[2]+'" data-w="'+(100*p[1]/m.total).toFixed(2)+'" title="'+h(p[0]+' : '+oct(p[1]))+'"></i>';}).join('');largeurs(sg);
    $('ram-leg').innerHTML=parts.map(function(p){return '<div><span class="sq '+p[2]+'"></span>'+h(p[0])+'<b>'+oct(p[1])+'</b>'+pc(100*p[1]/m.total)+'</div>';}).join('');
    var sw=$('ram-swap');
    if(m.swap_total>0){var sp=100*m.swap_utilise/m.swap_total;sw.innerHTML='Swap utilisé : <b>'+oct(m.swap_utilise)+'</b> sur '+oct(m.swap_total)+meter(sp,niv(sp,50,80)+' fin','Swap');largeurs(sw);}
    else sw.textContent='Pas de swap configuré.';
  }
  courbe($('ram-courbe'),Hs.map(function(x){return {t:x.t,v:x.ram};}),'Mémoire des applications',120);
  /* GPU */
  var zone=$('gpus'),ids=gs.map(function(g){return g.id;}).join(',');
  if(zone.getAttribute('data-ids')!==ids){zone.setAttribute('data-ids',ids);
    zone.innerHTML=gs.length?gs.map(function(g){return '<div class="bloc" id="g-'+g.id+'"><div class="bh"><b>'+h(g.nom)+'</b><span class="tag">'+h([g.pilote,g.noeud?'/dev/dri/'+g.noeud:''].filter(Boolean).join(' · '))+'</span></div>'+
      '<div data-r="occ"></div><div data-r="vram"></div><div class="faits" data-r="faits"></div><div class="courbe" data-r="courbe"></div></div>';}).join('')
      :'<p class="empty">Aucun GPU trouvé dans /sys/class/drm.</p>';}
  gs.forEach(function(g){var b=$('g-'+g.id);if(!b)return;var q=function(r){return b.querySelector('[data-r="'+r+'"]');};
    if(g.occupation==null)q('occ').innerHTML='<div class="sub">'+(g.marque==='NVIDIA'?'Occupation non disponible sans les outils NVIDIA.':g.marque==='Intel'?'Occupation non disponible (pilote ou noyau trop ancien).':'Occupation non disponible.')+'</div>';
    else{q('occ').innerHTML='<div class="sub">Occupation'+(g.estimation?' (estimée)':'')+' <b>'+pc(g.occupation)+'</b></div>'+meter(g.occupation,'','Occupation de '+g.nom);}
    if(g.vram_totale){var vp=100*g.vram_utilisee/g.vram_totale;q('vram').innerHTML='<div class="sub">Mémoire vidéo <b>'+oct(g.vram_utilisee)+'</b> sur '+oct(g.vram_totale)+'</div>'+meter(vp,niv(vp,85,95),'Mémoire vidéo');}
    else q('vram').innerHTML='';
    largeurs(b);
    var f=[];if(g.temperature!=null)f.push(['Température',g.temperature+' °C'+(g.jonction!=null?' (jonction '+g.jonction+' °C)':'')]);
    if(g.puissance!=null)f.push(['Puissance',nf(g.puissance,0)+' W']);
    if(g.frequence!=null)f.push(['Fréquence',nf(g.frequence,0)+(g.frequence_max?' / '+nf(g.frequence_max,0):'')+' MHz']);
    q('faits').innerHTML=f.map(function(x){return '<div><div class="lbl">'+h(x[0])+'</div><div class="val">'+h(x[1])+'</div></div>';}).join('');
    if(g.occupation!=null)courbe(q('courbe'),Hs.map(function(x){return {t:x.t,v:(x.gpu||{})[g.id]};}),'Occupation du GPU',110);});
}

var ROLE={cache:'cache',logs:'journal',spares:'secours',special:'spécial',dedup:'dédup.'};
var RANG={critique:0,attention:1,inconnu:2,veille:3,ok:4};
function age(){var r=D.releve;$('st-age').textContent=D.demande?'Relevé en cours… ':r?'Relevé '+ilya(D.maintenant-r.horodatage)+' ':'Aucun relevé ';var b=$('st-maj');b.disabled=!!D.demande;}
function stockage(){
  var r=D.releve;age();
  var P=$('st-pools'),V=$('st-vol'),T=$('st-disques');
  if(!r){P.innerHTML='<p class="empty">Pas encore de relevé des disques. Il est produit par le service <code>audite-moi-mesures</code> (toutes les 10 minutes) : cliquez sur « Actualiser », ou vérifiez <code>systemctl status audite-moi-mesures.timer</code>.</p>';V.innerHTML='';T.innerHTML='';$('k-sto').textContent='—';return;}
  var ds={};(r.disques||[]).forEach(function(d){ds[d.nom]=d;});
  var tot=0,lib=0,nC=0,nW=0;(r.disques||[]).forEach(function(d){if(d.etat==='critique')nC++;else if(d.etat==='attention')nW++;});
  P.innerHTML=(r.pools||[]).map(function(p){
    var t=p.taille||p.brut||0,u=p.utilise!=null?p.utilise:p.alloue,l=p.libre!=null?p.libre:t-u,pct=t?100*u/t:0,lv=niv(pct,SE('pool_attention',80),SE('pool_critique',90));tot+=t;lib+=l;
    var e=p.etat&&p.etat!=='ONLINE'?'critique':p.disques_critiques?'critique':p.disques_attention?'attention':'ok';
    var bd=p.etat&&p.etat!=='ONLINE'?'<span class="badge b-CRIT">'+h(p.etat)+'</span>':'<span class="badge b-'+ET[e][0]+'" title="État du pool et de ses disques">'+{ok:'Sain',attention:'À surveiller',critique:'Critique'}[e]+'</span>';
    var tag=[p.type,{mirror:'miroir',simple:'sans redondance'}[p.disposition]||(p.disposition||'').toUpperCase()].filter(Boolean).join(' · ');
    var jeux=(p.jeux||[]).map(function(j){return '<li><span title="'+h(j.nom)+'">'+h(j.nom)+'</span>'+meter(t?100*j.utilise/t:0,'fin','Part de '+j.nom)+'<span class="num">'+oct(j.utilise)+'</span></li>';}).join('');
    var mb=(p.disques||[]).map(function(m){var d=ds[m.disque]||{};return '<a class="mb" href="#d-'+h(m.disque)+'" title="'+h((d.modele||'')+(d.raisons&&d.raisons.length?' — '+d.raisons.join(' ; '):''))+'">'+icone(d.etat||'inconnu')+h(m.disque)+(m.role!=='donnees'?' <span class="tag">'+h(ROLE[m.role]||m.role)+'</span>':'')+'</a>';}).join('');
    return '<div class="bloc"><div class="bh"><b>'+h(p.nom)+'</b>'+(tag?'<span class="tag">'+h(tag)+'</span>':'')+bd+'</div>'+
      '<div class="big">'+oct(l)+'<small> libres sur '+oct(t)+'</small></div>'+meter(pct,lv,'Remplissage du pool '+p.nom)+
      '<div class="sub"><b>'+pc(pct)+'</b> utilisés ('+oct(u)+')'+(p.frag!=null?' · fragmentation '+p.frag+' %':'')+'</div>'+
      (lv?'<div class="sub">'+(lv==='crit'?'Pool presque plein : libérez de la place ou agrandissez-le.':'Au-delà de '+SE('pool_attention',80)+' %, ZFS ralentit : prévoyez de la place.')+'</div>':'')+
      (jeux?'<ul class="lignes" aria-label="Principaux jeux de données">'+jeux+'</ul>':'')+'<div class="membres">'+mb+'</div></div>';}).join('')||'<p class="empty">Aucun pool ZFS.</p>';
  var vols=r.volumes||[];
  V.innerHTML=vols.length?'<h3 class="lbl">Autres volumes</h3><ul class="lignes vol">'+vols.map(function(v){var pct=v.taille?100*v.utilise/v.taille:0;if(!(r.pools||[]).length){tot+=v.taille;lib+=v.libre;}
    return '<li><span title="'+h(v.source)+'">'+h(v.point)+' <span class="tag">'+h(v.type)+'</span></span>'+meter(pct,niv(pct,SE('espace_attention',85),SE('espace_critique',95))+' fin','Remplissage de '+v.point)+'<span class="num">'+oct(v.libre)+' libres sur '+oct(v.taille)+'</span></li>';}).join('')+'</ul>':'';
  largeurs(P);largeurs(V);
  var dl=(r.disques||[]).slice().sort(function(a,b){return (a.pool||'~').localeCompare(b.pool||'~')||(RANG[a.etat]-RANG[b.etat])||a.nom.localeCompare(b.nom);});
  T.innerHTML=dl.length?'<table><thead><tr><th>Disque</th><th>Type</th><th>Capacité</th><th>Pool</th><th class="num">Temp.</th><th class="num">En service</th><th class="num">Usure</th><th>État</th></tr></thead><tbody>'+
    dl.map(function(d){var ra=(d.raisons||[]).slice();if(d.note)ra.push(d.note);if(d.veille)ra.unshift('En veille : valeurs du relevé '+ilya(D.maintenant-(d.mesure||r.horodatage))+' (le disque n’est pas réveillé)');
      if(d.donnees_perimees)ra.unshift('Relevé SMART indisponible : valeurs '+ilya(D.maintenant-(d.mesure||r.horodatage))+', non actualisées');
      return '<tr id="d-'+h(d.nom)+'"><td><b>'+h(d.nom)+'</b><span class="modele" title="'+h(d.modele)+'">'+h(d.modele||'')+'</span></td><td>'+h(d.type||'—')+'</td><td>'+(d.taille?oct(d.taille):'—')+'</td>'+
      '<td>'+h(d.pool||'—')+(d.role&&d.role!=='donnees'?' <span class="tag">'+h(ROLE[d.role]||d.role)+'</span>':'')+'</td><td class="num">'+(d.temperature!=null?d.temperature+' °C':'—')+'</td>'+
      '<td class="num">'+duree(d.heures)+'</td><td class="num">'+(d.usure!=null?d.usure+' %':'—')+'</td><td class="etat">'+badge(d.veille&&d.etat==='ok'?'veille':d.etat)+
      (ra.length?'<div class="raisons">'+ra.map(h).join('<br>')+'</div>':'')+'</td></tr>';}).join('')+'</tbody></table>':'<p class="empty">Aucun disque trouvé par smartctl.</p>';
  $('k-sto').innerHTML=tot?oct(lib)+'<small> libres</small>':'—';
  $('k-sto-s').textContent=tot?'sur '+oct(tot)+((r.pools||[]).length?' · '+r.pools.length+' pool(s) ZFS':''):' ';
  var perime=r.smart_scan_ok===false;
  if(perime)T.insertAdjacentHTML('afterbegin','<p class="alerte-perime">'+icone('attention')+' smartctl n’a pas pu lister les disques au dernier relevé : les valeurs ci-dessous sont les dernières connues. Vérifiez <code>sudo smartctl --scan-open</code>.</p>');
  $('k-sto-e').innerHTML=perime?icone('attention')+' relevé SMART indisponible':nC?icone('critique')+' '+nC+' disque(s) en état critique':nW?icone('attention')+' '+nW+' disque(s) à surveiller':(r.disques||[]).length?icone('ok')+' tous les disques sont sains':' ';
}
$('st-maj').addEventListener('click',function(){var b=this;b.disabled=true;
  fetch('/mesurer',{method:'POST',credentials:'same-origin',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:'csrf='+encodeURIComponent(CSRF)})
  .then(function(r){if(r.ok){D.demande=true;age();}else b.disabled=false;}).catch(function(){b.disabled=false;});});
var occupe=false;
function maj(){if(document.hidden||occupe)return;occupe=true;
  fetch('/materiel.json',{credentials:'same-origin'}).then(function(r){if(r.status===401){location.href='/connexion';throw new Error('session');}return r.json();})
  .then(function(n){var avant=D.releve?D.releve.horodatage:null,dem=D.demande;D=n;direct();if((D.releve?D.releve.horodatage:null)!==avant||D.demande!==dem)stockage();else age();})
  .catch(function(){}).then(function(){occupe=false;});}
/* ---- tendances (historique horaire) ---- */
function dateC(t,j){var d=new Date(t*1000);return j<=2?d.toLocaleTimeString('fr-FR',{hour:'2-digit',minute:'2-digit'}):d.toLocaleDateString('fr-FR',{day:'2-digit',month:'2-digit'});}
function multi(el,leg,series,o){
  series=series.filter(function(s){return s.pts.length>0;}).slice(0,3);
  if(!series.length){el.innerHTML='<p class="empty">Pas encore assez de relevés (un point par heure).</p>';leg.innerHTML='';return;}
  leg.innerHTML=series.length>1?series.map(function(s,i){return '<span><i class="sw sw'+(i+1)+'"></i>'+h(s.nom)+'</span>';}).join(''):'';
  var W=Math.max(280,Math.round(el.clientWidth||600)),H=190,ml=42,mr=series.length>1?92:14,mt=10,mb=24;
  var tous=[];series.forEach(function(s){s.pts.forEach(function(p){tous.push(p);});});
  var t0=Math.min.apply(null,tous.map(function(p){return p[0];})),t1=Math.max.apply(null,tous.map(function(p){return p[0];}));
  if(t1-t0<3600)t0=t1-3600;
  var lo=o.min,hi=o.max;tous.forEach(function(p){lo=Math.min(lo,Math.floor(p[1]/10)*10);hi=Math.max(hi,Math.ceil(p[1]/10)*10);});
  var X=function(t){return ml+(t-t0)/(t1-t0)*(W-ml-mr);},Y=function(v){return mt+(hi-v)/(hi-lo)*(H-mt-mb);};
  var g='',pas=[5,10,20,25,50].filter(function(x){return (hi-lo)%x===0&&(hi-lo)/x<=5;})[0]||(hi-lo)/4;
  for(var v=lo;v<=hi+1e-9;v+=pas){g+='<line class="gl" x1="'+ml+'" x2="'+(W-mr)+'" y1="'+Y(v).toFixed(1)+'" y2="'+Y(v).toFixed(1)+'"/><text class="ax" x="'+(ml-6)+'" y="'+(Y(v)+4).toFixed(1)+'" text-anchor="end">'+nf(v,0)+' '+o.unite+'</text>';}
  var jr=(t1-t0)/86400;
  [[t0,'start'],[(t0+t1)/2,'middle'],[t1,'end']].forEach(function(x){g+='<text class="ax" x="'+X(x[0]).toFixed(1)+'" y="'+(H-6)+'" text-anchor="'+x[1]+'">'+dateC(x[0],jr)+'</text>';});
  (o.seuils||[]).forEach(function(sv){if(sv[0]>lo&&sv[0]<hi)g+='<line class="seuil" x1="'+ml+'" x2="'+(W-mr)+'" y1="'+Y(sv[0])+'" y2="'+Y(sv[0])+'"/><text class="seuil-t" x="'+(W-mr-4)+'" y="'+(Y(sv[0])+14)+'" text-anchor="end">'+h(sv[1])+'</text>';});
  var fins=[];
  series.forEach(function(s,i){var c=i+1;if(s.pts.length>1)g+='<polyline class="ln ln'+c+'" points="'+s.pts.map(function(p){return X(p[0]).toFixed(1)+','+Y(p[1]).toFixed(1);}).join(' ')+'"/>';
    var z=s.pts[s.pts.length-1];g+='<circle class="pt pt'+c+'" cx="'+X(z[0]).toFixed(1)+'" cy="'+Y(z[1]).toFixed(1)+'" r="4"/>';fins.push({y:Y(z[1]),t:s.nom});});
  if(series.length>1){fins.sort(function(a,b){return a.y-b.y;});for(var q=1;q<fins.length;q++)if(fins[q].y-fins[q-1].y<13)fins[q].y=fins[q-1].y+13;
    fins.forEach(function(f){g+='<text class="fin-l" x="'+(W-mr+10)+'" y="'+(f.y+4).toFixed(1)+'">'+h(f.t.length>12?f.t.slice(0,11)+'…':f.t)+'</text>';});}
  el.innerHTML='<svg viewBox="0 0 '+W+' '+H+'" role="img" aria-label="'+h(o.nom)+'">'+g+'<line class="cr" y1="'+mt+'" y2="'+(H-mb)+'" visibility="hidden"/><rect class="hit" x="'+ml+'" y="0" width="'+(W-ml-mr)+'" height="'+H+'"/></svg><div class="tip"></div>';
  var svg=el.firstChild,cr=svg.querySelector('.cr'),hit=svg.querySelector('.hit'),tip=el.querySelector('.tip');
  hit.addEventListener('mousemove',function(e){var r=svg.getBoundingClientRect(),k=W/r.width,px=(e.clientX-r.left)*k,tt=t0+(px-ml)/(W-ml-mr)*(t1-t0);
    var lignes=series.map(function(s){var b=s.pts[0];s.pts.forEach(function(p){if(Math.abs(p[0]-tt)<Math.abs(b[0]-tt))b=p;});return [s.nom,b];});
    var x=X(lignes[0][1][0]);cr.setAttribute('x1',x);cr.setAttribute('x2',x);cr.setAttribute('visibility','visible');
    tip.innerHTML='<b></b>'+lignes.map(function(){return '<span></span>';}).join('<br>');
    tip.children[0].textContent=new Date(lignes[0][1][0]*1000).toLocaleString('fr-FR',{day:'2-digit',month:'2-digit',hour:'2-digit',minute:'2-digit'});
    var sp=tip.querySelectorAll('span');lignes.forEach(function(l,i){sp[i].textContent=l[0]+' : '+nf(l[1][1],o.dec)+' '+o.unite;});
    tip.style.display='block';var lf=x/k+12;if(lf+tip.offsetWidth>r.width)lf=x/k-tip.offsetWidth-12;tip.style.left=lf+'px';});
  hit.addEventListener('mouseleave',function(){cr.setAttribute('visibility','hidden');tip.style.display='none';});
}
var TJ=30,TD=null;
function tendances(){if(!TD)return;
  var R=TD.remplissage||{},T=TD.temperatures||{};
  multi($('t-rempl'),$('t-leg1'),Object.keys(R).sort().map(function(k){return {nom:k,pts:R[k]};}),{min:0,max:100,unite:'%',dec:1,nom:'Remplissage des pools',seuils:[[SE('pool_attention',80),SE('pool_attention',80)+' % : ZFS ralentit au-delà']]});
  multi($('t-temp'),$('t-leg2'),Object.keys(T).sort().map(function(k){return {nom:k,pts:T[k]};}),{min:20,max:50,unite:'°C',dec:0,nom:'Température maximale des disques'});
  var P=TD.previsions||{},pl=Object.keys(P).sort();
  $('t-prev').innerHTML=pl.length?pl.map(function(k){var p=P[k],t;
    if(p.octets_par_jour<=0)t='stable ou en baisse sur '+nf(p.jours_observes,0)+' jours';
    else{t='+'+oct(p.octets_par_jour)+' par jour (sur '+nf(p.jours_observes,0)+' jours)';
      var jc=p.jours_avant_critique!=null?p.jours_avant_critique:p.jours_avant_90,sc=p.seuil_critique||90;
      if(jc!=null)t+=jc<=0?' · déjà au-delà de '+sc+' %':' · '+sc+' % dans '+(jc<60?'environ '+jc+' jours':'environ '+Math.round(jc/30)+' mois');}
    return '<li><span><b>'+h(k)+'</b></span><span class="sub">'+h(t)+'</span></li>';}).join('')
    :'<li><span class="sub">Prévision de remplissage disponible après 3 jours de relevés.</span></li>';}
function chargerT(){fetch('/tendances.json?jours='+TJ,{credentials:'same-origin'}).then(function(r){return r.json();}).then(function(d){TD=d;tendances();}).catch(function(){});}
Array.prototype.forEach.call(document.querySelectorAll('#t-per button'),function(b){b.addEventListener('click',function(){TJ=+b.dataset.j;
  Array.prototype.forEach.call(document.querySelectorAll('#t-per button'),function(x){x.setAttribute('aria-pressed',x===b?'true':'false');});chargerT();});});
chargerT();setInterval(chargerT,600000);
direct();stockage();setInterval(maj,2000);document.addEventListener('visibilitychange',maj);
})();"""


def page_materiel(app, csrf, nonce):
    init = json.dumps(dict(app.mesures.instantane(), seuils=app.seuils.effectifs()), ensure_ascii=False).replace("<", "\\u003c")
    corps = (HTML_MATERIEL + '<script type="application/json" id="init">{}</script><script src="{}" defer></script>'.format(init, statique("materiel.js")))
    return coque(app.donnees, csrf, nonce, "materiel", "Matériel", corps, sous_titre=(
        "Processeur, mémoire et GPU en direct (toutes les 2 s) · disques et pools relevés toutes les 10 minutes, sans réveiller les disques en veille"))


# ------------------------------------------------------------------ seuils --
CACHE_STATIQUE = "public, max-age=31536000, immutable"


def _statiques():
    res = {}
    for nom, texte, type_ in (("app.css", CSS, "text/css; charset=utf-8"), ("app.js", JS_APP, "text/javascript; charset=utf-8"), ("filtres.js", JS_FILTRES, "text/javascript; charset=utf-8"),
                              ("dialogue.js", JS_DIALOGUE, "text/javascript; charset=utf-8"),
                              ("materiel.js", JS_MATERIEL, "text/javascript; charset=utf-8"),
                              ("reglages.js", JS_REGLAGES, "text/javascript; charset=utf-8")):
        brut = texte.encode("utf-8")
        empreinte = hashlib.sha256(brut).hexdigest()[:12]
        f = {"brut": brut, "gz": gzip.compress(brut, 9, mtime=0), "type": type_, "etag": '"{}"'.format(empreinte)}
        base, ext = nom.rsplit(".", 1)
        f["url"] = "/static/{}.{}.{}".format(base, empreinte, ext)
        res[nom] = f
        res["{}.{}.{}".format(base, empreinte, ext)] = f
    return res


def statique(nom):
    return STATIQUES[nom]["url"]


def fichier_seuils_def(conf):
    ici = os.path.dirname(os.path.abspath(__file__))
    for f in (conf.get("seuils_def") or "", os.path.join(ici, "seuils.json"), os.path.join(ici, "..", "seuils.json"), "/usr/local/lib/audite-moi/seuils.json"):
        if f and os.path.isfile(f):
            return f
    return ""


class Seuils:
    """Définitions (seuils.json, en lecture seule) et valeurs choisies dans l'interface (reglages/seuils.json)."""

    def __init__(self, conf):
        self.conf = conf

    def definitions(self):
        try:
            with open(fichier_seuils_def(self.conf), encoding="utf-8") as f:
                d = json.load(f)
            return d if isinstance(d, dict) else {}
        except (OSError, ValueError):
            return {}

    def _fichier(self):
        return os.path.join(self.conf["reglages"], "seuils.json")

    def perso(self):
        try:
            with open(self._fichier(), encoding="utf-8") as f:
                d = json.load(f)
            return d if isinstance(d, dict) else {}
        except (OSError, ValueError):
            return {}

    def tous(self):
        return [s for g in self.definitions().get("groupes", []) for s in g.get("seuils", [])]

    def effectifs(self):
        p = self.perso()
        res = {}
        for s in self.tous():
            v = p.get(s["cle"])
            res[s["cle"]] = v if isinstance(v, int) and not isinstance(v, bool) and s["min"] <= v <= s["max"] else s["defaut"]
        return res

    def valider(self, form):
        """Formulaire → (valeurs différentes du défaut, erreurs par clé)."""
        valeurs, erreurs, eff = {}, {}, {}
        for s in self.tous():
            brut = (form.get(s["cle"]) or "").strip().replace(" ", "")
            if brut == "":
                v = s["defaut"]
            else:
                try:
                    v = int(brut)
                except ValueError:
                    erreurs[s["cle"]] = "Nombre entier attendu."
                    continue
                if not s["min"] <= v <= s["max"]:
                    erreurs[s["cle"]] = "Entre {} et {} {}.".format(s["min"], s["max"], s.get("unite", ""))
                    continue
            eff[s["cle"]] = v
            if v != s["defaut"]:
                valeurs[s["cle"]] = v
        libs = {s["cle"]: s["libelle"].replace("« ", "").replace(" »", "") for s in self.tous()}
        unites = {s["cle"]: s.get("unite", "") for s in self.tous()}
        for a, b in self.definitions().get("paires", []):
            if a in eff and b in eff and eff[a] >= eff[b] and b not in erreurs:
                erreurs[b] = "Doit être supérieur à {} {}, la valeur de « {} ».".format(eff[a], unites.get(a, ""), libs.get(a, a))
        return valeurs, erreurs

    def enregistrer(self, valeurs):
        with VERROU_REGLAGES:
            f = self._fichier()
            tmp = f + ".{}".format(secrets.token_hex(4))
            with open(tmp, "w", encoding="utf-8") as fh:
                json.dump(valeurs, fh, ensure_ascii=False, indent=1)
            os.chmod(tmp, 0o660)
            os.replace(tmp, f)


JS_REGLAGES = """(function(){
Array.prototype.forEach.call(document.querySelectorAll('button[data-defaut]'),function(b){b.addEventListener('click',function(){
  var i=document.getElementById(b.dataset.cible);i.value=b.dataset.defaut;i.dispatchEvent(new Event('input'));});});
Array.prototype.forEach.call(document.querySelectorAll('input.seuil'),function(i){i.addEventListener('input',function(){
  i.closest('.sl').classList.toggle('modifie',i.value!==''&&i.value!==i.dataset.defaut);});});
var t=document.getElementById('tout-defaut');if(t)t.addEventListener('click',function(){
  Array.prototype.forEach.call(document.querySelectorAll('input.seuil'),function(i){i.value=i.dataset.defaut;i.dispatchEvent(new Event('input'));});});
})();"""


STATIQUES = _statiques()


def charger_configurer(conf):
    """Fonctions de validation du service root (une seule définition des formats acceptés)."""
    ici = os.path.dirname(os.path.abspath(__file__))
    for f in (conf.get("configurer") or "", os.path.join(ici, "audite-moi-configurer"), os.path.join(ici, "..", "systemd", "audite-moi-configurer"),
              "/usr/local/lib/audite-moi/audite-moi-configurer"):
        if f and os.path.isfile(f):
            try:
                from importlib.machinery import SourceFileLoader
                import importlib.util
                chargeur = SourceFileLoader("audite_moi_configurer", f)
                mod = importlib.util.module_from_spec(importlib.util.spec_from_loader(chargeur.name, chargeur))
                chargeur.exec_module(mod)
                return mod
            except (OSError, SyntaxError, ImportError) as exc:
                sys.stderr.write("module de configuration illisible ({}) : {}\n".format(f, exc))
    return None


ONGLETS = [("seuils", "Seuils"), ("controles", "Réseau"), ("sauvegardes", "Sauvegardes"), ("opnsense", "OPNsense"),
           ("telegram", "Telegram"), ("planification", "Planification"), ("interface", "Interface"),
           ("acceptes", "Acceptés"), ("journal", "Journal")]
ACTIONS_CONFIG = {   # chemin POST → (action du service root, onglet, mot de passe redemandé)
    "controles": ("controles", "controles", True), "sauvegardes": ("sauvegardes", "sauvegardes", True),
    "opnsense": ("opnsense", "opnsense", True), "opnsense-tester": ("opnsense-tester", "opnsense", False),
    "opnsense-effacer": ("opnsense-effacer", "opnsense", True), "telegram": ("telegram", "telegram", True),
    "telegram-tester": ("telegram-tester", "telegram", False), "telegram-effacer": ("telegram-effacer", "telegram", True),
    "planification": ("planification", "planification", True), "interface": ("interface", "interface", True),
    "mot-de-passe": ("interface", "interface", False),
}
JOURS_FR = [("lun", "lundi"), ("mar", "mardi"), ("mer", "mercredi"), ("jeu", "jeudi"), ("ven", "vendredi"), ("sam", "samedi"), ("dim", "dimanche")]
SECRETS_FORM = {"jeton", "cle", "secret", "mot_de_passe", "actuel", "nouveau", "confirmation"}


def champ(nom, label, valeur="", hint="", type_="text", attrs="", id_=None):
    id_ = id_ or "c-" + nom
    return '<div class="champ"><label for="{i}">{l}</label><input type="{t}" id="{i}" name="{n}" value="{v}"{a}>{h}</div>'.format(
        i=id_, l=label, t=type_, n=nom, v=esc(valeur), a=attrs, h='<p class="hint">{}</p>'.format(hint) if hint else "")


def case(nom, label, coche, hint=""):
    return '<label class="check"><input type="checkbox" name="{}" value="oui"{}><span>{}{}</span></label>'.format(
        nom, " checked" if coche else "", label, '<span class="hint">{}</span>'.format(hint) if hint else "")


def barre_enregistrer(libelle="Enregistrer", mdp=True, id_="mdp"):
    m = ('<div class="mdp"><label for="{i}">Mot de passe de l’interface</label><input type="password" id="{i}" name="mot_de_passe" '
         'autocomplete="current-password" required></div>').format(i=id_) if mdp else ""
    return '<div class="savebar">{}<div class="btns"><button class="primary">{}</button></div></div>'.format(m, libelle)


def form(action, csrf, contenu, classe=""):
    return '<form method="post" action="/reglages/{}" autocomplete="off"{}><input type="hidden" name="csrf" value="{}">{}</form>'.format(
        action, ' class="{}"'.format(classe) if classe else "", esc(csrf), contenu)


def oui_form(form_, cle):
    return "oui" if form_.get(cle) in ("oui", "on", "1") else "non"


def valeurs_config(action, f, mod):
    """Formulaire → valeurs envoyées au service root, validées ici avec les mêmes fonctions que lui (Refus si invalide)."""
    if action == "controles":
        v = {"externe": oui_form(f, "externe"), "domaines_extra": f.get("domaines_extra", ""), "scan_reseau": oui_form(f, "scan_reseau"),
             "scan_reseaux": f.get("scan_reseaux", "")}
        mod.domaines(v["domaines_extra"])
        mod.reseaux(v["scan_reseaux"])
        return v
    if action == "sauvegardes":
        lignes = []
        for i in range(30):
            if "s_nom_{}".format(i) not in f and "s_cible_{}".format(i) not in f:
                continue
            lignes.append({k: f.get("s_{}_{}".format(k, i), "") for k in ("nom", "type", "cible", "heures")})
        mod.sauvegardes(lignes)
        return {"lignes": lignes}
    if action == "opnsense":
        v = {"url": f.get("url", ""), "cle": f.get("cle", "").strip(), "secret": f.get("secret", "").strip(), "verifier_tls": oui_form(f, "verifier_tls")}
        mod.url(v["url"], "adresse d'OPNsense", vide=False)
        for k, nom in (("cle", "Clé"), ("secret", "Secret")):
            if v[k] and not mod.CLE_API.fullmatch(v[k]):
                raise mod.Refus("{} d'API invalide (copiez la valeur après « key= » ou « secret= » dans apikey.txt)".format(nom))
        return v
    if action == "telegram":
        v = {"jeton": f.get("jeton", "").strip(), "chat_id": f.get("chat_id", "").strip(), "alertes": oui_form(f, "alertes"),
             "interface_url": f.get("interface_url", "")}
        if v["jeton"] and not mod.JETON_TG.fullmatch(v["jeton"]):
            raise mod.Refus("Jeton du bot invalide (format 123456789:AA…, donné par @BotFather)")
        if v["chat_id"] and not mod.CHAT_TG.fullmatch(v["chat_id"]):
            raise mod.Refus("Identifiant de conversation invalide (nombre)")
        mod.url_interface(v["interface_url"])
        return v
    if action == "planification":
        v = {"actif": oui_form(f, "actif"), "frequence": f.get("frequence", ""), "jour": f.get("jour", "lun"),
             "jour_mois": f.get("jour_mois", "1") or "1", "heure": f.get("heure", ""), "garder": f.get("garder", "")}
        mod.planning(v)
        return v
    if action == "interface":
        mod.entier(f.get("duree_session_h"), 1, 168, "durée de session (heures)")
        return {"duree_session_h": f.get("duree_session_h")}
    return {}


def onglets(actif, conf):
    pts = {}
    if conf:
        pts["telegram"] = "ok" if conf["telegram"]["jeton_defini"] and conf["telegram"]["alertes"] else ""
        pts["opnsense"] = "ok" if conf["opnsense"]["cle_definie"] else ""
        pts["sauvegardes"] = "ok" if conf["sauvegardes"] else ""
        pts["planification"] = "ok" if conf["planification"].get("actif") else "warn"
    return '<nav class="tabs" aria-label="Sections des réglages">{}</nav>'.format("".join(
        '<a href="{h}"{c}>{d}{t}</a>'.format(h="/reglages" if k == "seuils" else "/reglages/" + k, c=' aria-current="page"' if k == actif else "",
                                            d='<span class="dot {}"></span>'.format(pts[k]) if k in pts else "", t=t) for k, t in ONGLETS))


def bandeau_config(app, q):
    d = app.donnees
    attente = q.get("attente", [""])[0]
    if ID_DEMANDE.match(attente):
        return ('<div class="banner run" data-attente-config="{}"><span class="spin"></span>Application du réglage sur le serveur… '
                '(quelques secondes ; un test de connexion peut prendre jusqu’à 30 s)</div>').format(esc(attente))
    r = q.get("r", [""])[0]
    res = d.resultat_configuration()
    if ID_DEMANDE.match(r) and res.get("id") == r:
        cl = "errb" if not res.get("ok") else "warnb" if res.get("test_ok") is False else "okb"
        return '<div class="banner {}"><b>{} :</b> {}</div>'.format(cl, esc(res.get("libelle", "Réglage")), esc(res.get("message", "")))
    if d.configuration_en_attente():
        return '<div class="banner run"><span class="spin"></span>Un réglage est en cours d’application sur le serveur.</div>'
    return ""


def r_seuils(app, csrf, q, erreurs, saisie):
    defs = app.seuils.definitions()
    eff = app.seuils.effectifs()
    out = []
    if erreurs:
        out.append('<div class="banner warnb"><b>Rien n’a été enregistré :</b> corrigez les valeurs signalées en rouge.</div>')
    elif q.get("m", [""])[0] == "ok":
        out.append('<div class="banner okb">Seuils enregistrés. Ils s’appliquent au prochain audit et au prochain relevé des disques (10 minutes au plus). '
                   '<form class="inline" method="post" action="/lancer"><input type="hidden" name="csrf" value="{}"><input type="hidden" name="mode" value="complet">'
                   '<button class="primary sm">Lancer un audit maintenant</button></form></div>'.format(esc(csrf)))
    if not defs:
        return '<div class="card"><p class="muted">Fichier des seuils introuvable (seuils.json) : réinstallez Audite-moi.</p></div>'
    nmod = sum(1 for s in app.seuils.tous() if eff[s["cle"]] != s["defaut"])
    out.append('<p class="muted">Seuils à partir desquels un constat passe en « attention » ou en « critique ». {} '
               'Les valeurs par défaut suivent les recommandations courantes (voir les références dans les rapports).</p>'.format(
                   "<b>{} seuil(s) personnalisé(s).</b>".format(nmod) if nmod else "Tous les seuils sont à leur valeur par défaut."))
    out.append('<form method="post" action="/reglages" class="reglages"><input type="hidden" name="csrf" value="{}">'.format(esc(csrf)))
    for g in defs.get("groupes", []):
        lignes = []
        for s in g.get("seuils", []):
            k = s["cle"]
            v = (saisie or {}).get(k, eff[k])
            mod = str(v) != str(s["defaut"])
            err = (erreurs or {}).get(k)
            lignes.append(
                '<div class="sl{m}{e}"><label for="s-{k}"><b>{l}</b>{a}</label>'
                '<div class="sv"><input class="seuil" id="s-{k}" name="{k}" type="number" inputmode="numeric" step="1" min="{mi}" max="{ma}" value="{v}" data-defaut="{d}" required>'
                '<span class="u">{u}</span><button type="button" class="lienbtn" data-defaut="{d}" data-cible="s-{k}" title="Rétablir la valeur par défaut">défaut : {d}</button></div>'
                '{er}</div>'.format(m=" modifie" if mod else "", e=" err" if err else "", k=esc(k), l=esc(s["libelle"]),
                                    a='<span class="aide">{}</span>'.format(esc(s["aide"])) if s.get("aide") else "",
                                    mi=s["min"], ma=s["max"], v=esc(v), d=s["defaut"], u=esc(s.get("unite", "")),
                                    er='<div class="errm">{}</div>'.format(esc(err)) if err else ""))
        out.append('<div class="card"><h2>{}</h2>{}</div>'.format(esc(g["nom"]), "".join(lignes)))
    out.append('<div class="savebar"><span class="hint">Appliqués au prochain audit et au prochain relevé des disques.</span>'
               '<div class="btns"><button type="button" id="tout-defaut">Tout rétablir par défaut</button><button class="primary">Enregistrer</button></div></div></form>')
    out.append('<script src="{}" defer></script>'.format(statique("reglages.js")))
    return "".join(out)


def r_controles(app, csrf, conf, s):
    c = conf["controles"]
    v = lambda k: s.get(k, c[k]) if s else c[k]
    coche = lambda k: (s.get(k) in ("oui", "on")) if s else c[k]
    return form("controles", csrf, """<div class="etroit">
<div class="card"><h2>Vu d’Internet</h2>{ext}{dom}</div>
<div class="card"><h2>Réseau local</h2>{scan}{res}</div>{bar}</div>""".format(
        ext=case("externe", "Tester les services publiés comme un visiteur sur Internet", coche("externe"),
                 "Chaque nom d’hôte des tunnels Cloudflare est testé : authentification, fichiers sensibles, HSTS, adresse de la maison qui fuit dans le DNS…"),
        dom=champ("domaines_extra", "Noms d’hôte supplémentaires", v("domaines_extra"),
                  "Séparés par des espaces, ex. <code>nc.exemple.fr photos.exemple.fr</code>. Ceux des tunnels Cloudflare sont trouvés automatiquement."),
        scan=case("scan_reseau", "Scanner le réseau local pendant l’audit complet (nmap)", coche("scan_reseau"),
                  "Inventaire des appareils, services risqués (Telnet, RDP, VNC, bases de données, caméras…), nouveaux appareils depuis le dernier scan."),
        res=champ("scan_reseaux", "Réseaux à scanner", v("scan_reseaux"),
                  "Vide : les réseaux déclarés dans OPNsense, sinon ceux du NAS. Sinon, ex. <code>192.168.1.0/24 10.10.20.0/24</code> (1 024 adresses au plus par réseau)."),
        bar=barre_enregistrer()))


def r_sauvegardes(app, csrf, conf, s):
    if s:
        lignes = [{k: s.get("s_{}_{}".format(k, i), "") for k in ("nom", "type", "cible", "heures")} for i in range(30) if "s_nom_{}".format(i) in s]
    else:
        lignes = list(conf["sauvegardes"])
    lignes = [l for l in lignes if l.get("nom") or l.get("cible")]
    lignes += [{"nom": "", "type": "zfs", "cible": "", "heures": "26"}] * max(1, 3 - len(lignes))
    rows = []
    for i, l in enumerate(lignes[:30]):
        opts = "".join('<option value="{}"{}>{}</option>'.format(t, " selected" if l.get("type") == t else "", lib)
                       for t, lib in (("zfs", "Snapshot ZFS"), ("fichier", "Fichier ou dossier"), ("unite", "Service systemd")))
        rows.append('<tr><td><input type="text" name="s_nom_{i}" value="{n}" aria-label="Nom" placeholder="photos-usb" maxlength="40"></td>'
                    '<td><select name="s_type_{i}" aria-label="Type">{o}</select></td>'
                    '<td><input type="text" name="s_cible_{i}" value="{c}" aria-label="Cible" placeholder="usb/photos"></td>'
                    '<td class="h"><input type="number" name="s_heures_{i}" value="{h}" aria-label="Délai en heures" min="1" max="8760"></td></tr>'.format(
                        i=i, n=esc(l.get("nom", "")), o=opts, c=esc(l.get("cible", "")), h=esc(l.get("heures", ""))))
    return form("sauvegardes", csrf, """<div class="card"><h2>Preuves de sauvegarde à vérifier</h2>
<p class="muted">L’audit trouve déjà les tâches de sauvegarde planifiées (restic, borg, kopia, syncoid, rclone…). Ajoutez ici ce qui prouve qu’une autre sauvegarde a réussi :
l’audit signale un problème si la preuve date de plus que le délai indiqué.</p>
<ul class="small muted"><li><b>Snapshot ZFS</b> : date du dernier snapshot du dataset (ex. <code>usb/photos</code>, réplication syncoid ou zfs send reçue) ;</li>
<li><b>Fichier ou dossier</b> : fichier le plus récent (ex. <code>/mnt/backup/duplicati</code>) ;</li>
<li><b>Service systemd</b> : dernière exécution réussie (ex. <code>restic-cloud.service</code>).</li></ul>
<div class="tw"><table class="edit" id="sauvegardes"><thead><tr><th>Nom</th><th>Type</th><th>Cible</th><th>Délai (h)</th></tr></thead><tbody>{r}</tbody></table></div>
<p class="hint">Pour retirer une sauvegarde, videz sa ligne. 26 h conviennent à une sauvegarde quotidienne, 170 h à une hebdomadaire.</p>
<button type="button" id="ajout-ligne" class="sm">+ Ajouter une ligne</button></div>{b}""".format(r="".join(rows), b=barre_enregistrer()))


def r_opnsense(app, csrf, conf, s):
    o = conf["opnsense"]
    if o["cle_definie"]:
        etat = '<p class="etat-ligne"><span class="pastille ok">Clé enregistrée{}</span> <span class="muted">{}</span></p>'.format(
            " (…{})".format(esc(o["cle_fin"])) if o.get("cle_fin") else "", esc(o["url"]))
    else:
        etat = '<p class="etat-ligne"><span class="pastille">Non configuré</span> <span class="muted">l’audit du routeur est ignoré</span></p>'
    ph = ' placeholder="déjà enregistré : laisser vide pour conserver"'
    verif = (s.get("verifier_tls") in ("oui", "on")) if s else o["verifier_tls"]
    aide = """<details class="card"><summary><b>Créer la clé API dans OPNsense</b> (lecture seule)</summary>
<ol class="etapes"><li><b>Système › Accès › Utilisateurs › +</b> : utilisateur <code>audite-moi</code>, cochez « Générer un mot de passe brouillé » (il ne se connectera jamais).</li>
<li>Dans <b>Privilèges effectifs</b>, ajoutez uniquement <b>System: Firmware</b> et <b>Diagnostics: Backup &amp; Restore</b> (selon la version : <b>System: Configuration: Backups</b>).</li>
<li>Rouvrez l’utilisateur, section <b>Clés API</b>, bouton <b>+</b> : OPNsense télécharge <code>apikey.txt</code> avec <code>key=</code> et <code>secret=</code>.</li></ol>
<p class="hint">Ces privilèges permettent de lire toute la configuration (redirections, règles, empreintes de mots de passe) : la clé reste dans
<code>/etc/audite-moi/audit.conf</code>, lisible par root seulement, et n’est jamais renvoyée à cette page ni écrite dans les rapports.</p></details>"""
    principal = form("opnsense", csrf, """<div class="card"><h2>Connexion au routeur</h2>{e}{u}<div class="row2">{k}{sec}</div>{v}</div>{b}""".format(
        e=etat, u=champ("url", "Adresse de l’interface d’OPNsense", (s or {}).get("url", o["url"]) if s else o["url"], "ex. <code>https://192.168.1.1</code>",
                        attrs=' placeholder="https://192.168.1.1" required'),
        k=champ("cle", "Clé API (key)", "", "", "password", (ph if o["cle_definie"] else "") + ' autocomplete="off"'),
        sec=champ("secret", "Secret API (secret)", "", "", "password", (ph if o["secret_defini"] else "") + ' autocomplete="off"'),
        v=case("verifier_tls", "Vérifier le certificat HTTPS du routeur", verif,
               "Décochez seulement si le routeur garde son certificat auto-signé d’origine (sinon la connexion est refusée)."),
        b=barre_enregistrer("Enregistrer et tester")))
    autres = ""
    if o["cle_definie"]:
        autres = """<div class="card"><h2>Connexion</h2><p class="muted">Vérifie que la clé enregistrée est acceptée par le routeur.</p>{t}</div>
<div class="card zone-danger"><h2>Effacer la clé</h2><p class="muted">L’audit du routeur sera désactivé. Pensez à supprimer aussi la clé dans OPNsense.</p>{x}</div>""".format(
            t=form("opnsense-tester", csrf, '<button>Tester la connexion</button>'),
            x=form("opnsense-effacer", csrf, '<div class="savebar"><div class="mdp"><label for="mdp-x">Mot de passe de l’interface</label>'
                   '<input type="password" id="mdp-x" name="mot_de_passe" autocomplete="current-password" required></div>'
                   '<div class="btns"><button class="danger">Effacer la clé</button></div></div>'))
    return '<div class="etroit">{}{}{}</div>'.format(aide, principal, autres)


def r_telegram(app, csrf, conf, s, hote):
    t = conf["telegram"]
    al = app.donnees.alertes()
    if not t["jeton_defini"]:
        etat = '<span class="pastille">Non configurées</span>'
    elif not t["alertes"]:
        etat = '<span class="pastille warn">Désactivées</span>'
    elif al.get("erreur"):
        etat = '<span class="pastille warn">Échec d’envoi le {}</span>'.format(esc(datetime.fromtimestamp(al["erreur"]).strftime("%d/%m à %H:%M")))
    else:
        etat = '<span class="pastille ok">Actives</span>'
    url_def = t["interface_url"] or ("{}://{}/".format("https" if app.tls else "http", hote) if hote else "")
    aide = """<details class="card"{o}><summary><b>Créer le bot Telegram</b> (2 minutes)</summary>
<ol class="etapes"><li>Dans Telegram, ouvrez une conversation avec <b>@BotFather</b>, envoyez <code>/newbot</code>, choisissez un nom (ex. « NAS maison ») puis un identifiant finissant par « bot ».</li>
<li>BotFather répond avec un jeton du type <code>123456789:AA…</code> : collez-le ci-dessous.</li>
<li>Ouvrez la conversation avec votre nouveau bot et envoyez-lui un message (ex. « bonjour »), puis enregistrez : la conversation est trouvée automatiquement.</li></ol></details>""".format(
        o="" if t["jeton_defini"] else " open")
    principal = form("telegram", csrf, """<div class="card"><h2>Bot et conversation</h2><p class="etat-ligne">{e}</p><div class="row2">{j}{c}</div>{a}{u}</div>{b}""".format(
        e=etat,
        j=champ("jeton", "Jeton du bot", "", "", "password",
                (' placeholder="déjà enregistré : laisser vide pour conserver"' if t["jeton_defini"] else ' placeholder="123456789:AA…"') + ' autocomplete="off"'),
        c=champ("chat_id", "Conversation", (s or {}).get("chat_id", t["chat_id"]) if s else t["chat_id"],
                "Laissez vide pour la trouver automatiquement (écrivez d’abord au bot).", attrs=' inputmode="numeric"'),
        a=case("alertes", "Envoyer les alertes", (s.get("alertes") in ("oui", "on")) if s else (t["alertes"] or not t["jeton_defini"]),
               "Pool dégradé ou presque plein, disque qui faiblit, sauvegarde en échec, nouveau port ouvert, résumé de chaque audit, chaque correction et chaque réglage modifié ici."),
        u=champ("interface_url", "Lien vers cette interface dans les messages", (s or {}).get("interface_url", url_def) if s else url_def,
                "Ouvert depuis votre téléphone sur le réseau local (ou par VPN). Laissez vide pour ne pas ajouter de lien."),
        b=barre_enregistrer("Enregistrer et envoyer un test")))
    autres = ""
    if t["jeton_defini"]:
        autres = """<div class="card"><h2>Message de test</h2><p class="muted">Envoie un message dans la conversation enregistrée.</p>{t}</div>
<div class="card zone-danger"><h2>Désactiver et effacer le jeton</h2><p class="muted">Un dernier message signale la désactivation.</p>{x}</div>""".format(
            t=form("telegram-tester", csrf, '<button>Envoyer un message de test</button>'),
            x=form("telegram-effacer", csrf, '<div class="savebar"><div class="mdp"><label for="mdp-x">Mot de passe de l’interface</label>'
                   '<input type="password" id="mdp-x" name="mot_de_passe" autocomplete="current-password" required></div>'
                   '<div class="btns"><button class="danger">Désactiver les alertes</button></div></div>'))
    return '<div class="etroit">{}{}{}</div>'.format(aide, principal, autres)


def description_planning(p):
    h = p.get("heure", "")
    if p.get("frequence") == "quotidien":
        return "chaque jour à {}".format(h)
    if p.get("frequence") == "mensuel":
        return "le {} de chaque mois à {}".format(p.get("jour_mois", 1), h)
    return "chaque {} à {}".format(dict(JOURS_FR).get(p.get("jour"), "lundi"), h)


def r_planification(app, csrf, conf, s):
    p = dict(conf["planification"])
    if s:
        p.update({k: s.get(k, p.get(k)) for k in ("frequence", "jour", "jour_mois", "heure", "garder")})
        p["actif"] = s.get("actif") in ("oui", "on")
    prochain = app.donnees.prochain_audit()
    freq = "".join('<option value="{}"{}>{}</option>'.format(v, " selected" if p.get("frequence") == v else "", t)
                   for v, t in (("quotidien", "Chaque jour"), ("hebdomadaire", "Chaque semaine"), ("mensuel", "Chaque mois")))
    jours = "".join('<option value="{}"{}>{}</option>'.format(v, " selected" if p.get("jour") == v else "", t) for v, t in JOURS_FR)
    return form("planification", csrf, """<div class="etroit"><div class="card"><h2>Audit complet automatique</h2>
<p class="etat-ligne">{etat}</p>{actif}
<div class="row2"><div class="champ"><label for="p-frequence">Fréquence</label><select id="p-frequence" name="frequence">{freq}</select></div>
<div class="champ" id="c-jour"><label for="p-jour">Jour</label><select id="p-jour" name="jour">{jours}</select></div>
<div class="champ" id="c-jour-mois"><label for="p-jour-mois">Jour du mois</label><input type="number" id="p-jour-mois" name="jour_mois" min="1" max="28" value="{jm}"></div>
<div class="champ"><label for="p-heure">Heure</label><input type="time" id="p-heure" name="heure" value="{h}" required></div></div>
<p class="hint">Un délai aléatoire de 20 minutes au plus est ajouté. Si le serveur était éteint à l’heure prévue, l’audit est lancé au démarrage suivant.
Un audit complet prend quelques minutes et sollicite les disques (Lynis, Trivy, scan du réseau).</p></div>
<div class="card"><h2>Conservation des rapports</h2>{garder}</div>{b}</div>""".format(
        etat=('<span class="pastille ok">Planifié : {}</span>{}'.format(esc(description_planning(conf["planification"])),
              ' <span class="muted">prochain audit le {}</span>'.format(esc(prochain)) if prochain else "")
              if conf["planification"].get("actif") else '<span class="pastille warn">Aucun audit automatique</span>'),
        actif=case("actif", "Lancer un audit complet automatiquement", p.get("actif")),
        freq=freq, jours=jours, jm=esc(p.get("jour_mois", 1)), h=esc(p.get("heure", "07:20")),
        garder=champ("garder", "Nombre de rapports conservés", p.get("garder", 60),
                     "De 5 à 500. Les plus anciens sont supprimés après chaque audit ; l’historique et l’évolution des notes portent sur ceux qui restent.",
                     "number", ' min="5" max="500" class="court" required'),
        b=barre_enregistrer()))


def r_interface(app, csrf, conf, s):
    c = app.conf
    duree = (s or {}).get("duree_session_h", c.get("duree_session_h", 12)) if s else c.get("duree_session_h", 12)
    mdp = form("mot-de-passe", csrf, """<div class="card"><h2>Mot de passe de l’interface</h2>
<p class="muted">Toutes les sessions ouvertes sont fermées : reconnectez-vous ensuite avec le nouveau mot de passe.</p>
{a}<div class="row2">{n}{c}</div><div class="savebar"><div class="btns"><button class="primary">Changer le mot de passe</button></div></div></div>""".format(
        a=champ("actuel", "Mot de passe actuel", "", "", "password", ' autocomplete="current-password" required'),
        n=champ("nouveau", "Nouveau mot de passe", "", "12 caractères au moins.", "password", ' autocomplete="new-password" minlength="12" required'),
        c=champ("confirmation", "Confirmation", "", "", "password", ' autocomplete="new-password" minlength="12" required')))
    session = form("interface", csrf, """<div class="card"><h2>Session</h2>{d}{b}</div>""".format(
        d=champ("duree_session_h", "Durée d’une session (heures)", duree, "De 1 à 168 h. Au-delà, le mot de passe est redemandé. L’interface redémarre pour l’appliquer.",
                "number", ' min="1" max="168" class="court" required'),
        b=barre_enregistrer(id_="mdp-s")))
    acces = """<div class="card"><h2>Accès réseau</h2><dl class="kv"><dt>Adresse d’écoute</dt><dd><code>{e}</code>{et}</dd><dt>Port</dt><dd><code>{p}</code></dd>
<dt>HTTPS</dt><dd>{h}</dd></dl>
<p class="hint">Changer l’adresse, le port ou le certificat peut couper l’accès à cette page : faites-le depuis le serveur, par exemple
<code>sudo ./install.sh --port 8765 --ecoute 192.168.1.10</code> (le pare-feu UFW est mis à jour en même temps).</p></div>""".format(
        e=esc(c.get("ecoute", "")), et=" (toutes les interfaces)" if c.get("ecoute") == "0.0.0.0" else "", p=esc(c.get("port", "")),
        h='<span class="pastille ok">Activé</span> certificat auto-signé' if app.tls else '<span class="pastille warn">Désactivé</span> (déconseillé)')
    return '<div class="etroit">{}{}{}</div>'.format(mdp, session, acces)


def r_acceptes(app, csrf):
    acc = app.donnees.acceptes()
    if not acc:
        return ('<div class="card"><p class="muted">Aucun constat accepté. Dans <a href="/constats">Constats</a>, « C’est voulu… » marque un choix assumé : '
                'le constat reste visible, avec votre raison, mais ne compte plus dans la note et ne déclenche plus d’alerte.</p></div>')
    hist = app.donnees.rapports()
    titres = {cle_de(c): c for c in (hist[-1].get("constats", []) if hist else [])}
    secs = hist[-1].get("sections", {}) if hist else {}
    rows = []
    for k, v in sorted(acc.items(), key=lambda kv: -int((kv[1] or {}).get("date", 0))):
        c = titres.get(k)
        titre = fmt(c["titre"]) if c else '<span class="muted">{}</span>'.format(esc(k.split("|", 1)[-1]))
        sec = esc((secs.get(c.get("section", ""), {}) or {}).get("titre", c.get("section", ""))) if c else esc(k.split("|", 1)[0])
        rows.append('<tr><td><b>{t}</b><span class="modele">{s}{abs}</span></td><td class="etat">{r}</td><td>{d}</td><td>{f}</td></tr>'.format(
            t=titre, s=sec, abs="" if c else " · absent du dernier audit", r=esc((v or {}).get("raison", "")),
            d=esc(datetime.fromtimestamp(int((v or {}).get("date", 0))).strftime("%d/%m/%Y")),
            f='<form class="inline" method="post" action="/accepter"><input type="hidden" name="csrf" value="{c}"><input type="hidden" name="cle" value="{k}">'
              '<input type="hidden" name="retirer" value="1"><input type="hidden" name="retour" value="acceptes"><button class="sm">Ne plus accepter</button></form>'.format(
                  c=esc(csrf), k=esc(k))))
    return ('<div class="card"><p class="muted">Ces constats ne comptent plus dans la note ni dans les alertes. Retirez l’acceptation si la situation a changé.</p>'
            '<div class="tw"><table><thead><tr><th>Constat</th><th>Raison</th><th>Depuis le</th><th></th></tr></thead><tbody>{}</tbody></table></div></div>').format("".join(rows))


def r_journal(app):
    j = app.donnees.journal_configuration()
    if not j:
        return '<div class="card"><p class="muted">Aucune modification depuis l’interface pour l’instant. Chaque réglage du serveur modifié ici est noté, et signalé sur Telegram.</p></div>'
    rows = []
    for e in reversed(j[-100:]):
        b = '<span class="badge b-WARN">Refusé</span>' if e.get("refus") else '<span class="badge b-OK">Appliqué</span>' if e.get("ok") else '<span class="badge b-CRIT">Échec</span>'
        rows.append('<tr><td>{d}</td><td class="etat"><b>{l}</b><span class="modele">{c}</span></td><td>{b}</td><td class="etat">{m}</td><td>{p}</td></tr>'.format(
            d=esc(datetime.fromtimestamp(e.get("date", 0)).strftime("%d/%m/%Y %H:%M")), l=esc(e.get("libelle", "")),
            c=esc(", ".join(e.get("changements") or [])), b=b, m=esc(e.get("message", "")), p=esc(e.get("par", ""))))
    return ('<div class="card"><div class="tw"><table><thead><tr><th>Date</th><th>Réglage</th><th>Résultat</th><th>Détail</th><th>Depuis</th></tr></thead>'
            '<tbody>{}</tbody></table></div><p class="hint">Les secrets (jeton, clé API, mot de passe) ne sont jamais notés.</p></div>').format("".join(rows))


SOUS_TITRES = {
    "seuils": "Niveaux d’alerte des contrôles de santé (températures, usure, remplissage…)",
    "controles": "Ce que l’audit teste sur le réseau : services publiés et réseau local",
    "sauvegardes": "Les sauvegardes dont l’audit vérifie la fraîcheur",
    "opnsense": "Lecture de la configuration du routeur par son API (lecture seule)",
    "telegram": "Prévenu sur votre téléphone quand quelque chose change",
    "planification": "Audits automatiques et conservation des rapports",
    "interface": "Mot de passe, session et accès à cette interface",
    "acceptes": "Les écarts que vous avez déclarés volontaires",
    "journal": "Les réglages du serveur modifiés depuis cette interface",
}


def page_reglages(app, csrf, nonce, onglet="seuils", q=None, erreurs=None, saisie=None, erreur_config="", hote=""):
    q = q or {}
    conf = app.donnees.configuration()
    corps = [onglets(onglet, conf)]
    if onglet == "seuils":
        corps.append(r_seuils(app, csrf, q, erreurs, saisie))
    elif onglet in ("acceptes", "journal"):
        corps.append(r_acceptes(app, csrf) if onglet == "acceptes" else r_journal(app))
    else:
        corps.append(bandeau_config(app, q))
        if erreur_config:
            corps.append('<div class="banner errb"><b>Rien n’a été modifié :</b> {}</div>'.format(esc(erreur_config)))
        if onglet == "interface":
            corps.append(r_interface(app, csrf, conf, saisie))
        elif not conf or app.configurer is None:
            corps.append('<div class="card"><p class="muted">Les réglages du serveur ne sont pas encore lisibles par l’interface : mettez Audite-moi à jour sur le serveur '
                         '(<code>git pull && sudo ./install.sh</code>).</p></div>')
        else:
            s = {k: v for k, v in (saisie or {}).items() if k not in SECRETS_FORM} if saisie else None
            corps.append({"controles": lambda: r_controles(app, csrf, conf, s), "sauvegardes": lambda: r_sauvegardes(app, csrf, conf, s),
                          "opnsense": lambda: r_opnsense(app, csrf, conf, s), "telegram": lambda: r_telegram(app, csrf, conf, s, hote),
                          "planification": lambda: r_planification(app, csrf, conf, s)}[onglet]())
    return coque(app.donnees, csrf, nonce, "reglages", "Réglages", "".join(corps), sous_titre=SOUS_TITRES.get(onglet, ""),
                 titre_onglet="Réglages — " + dict(ONGLETS).get(onglet, ""))


def page_texte(donnees, csrf, nonce, nom, contenu):
    corps = '<div class="card"><pre class="texte">{c}</pre></div>'.format(c=esc(contenu))
    actions = '<a class="btn" href="/rapports/{h}">Version HTML</a><a class="btn" href="/rapports/{t}" download>Télécharger</a>'.format(
        h=esc(nom[:-4] + ".html"), t=esc(nom))
    return coque(donnees, csrf, nonce, "rapport", "Rapport texte", corps, sous_titre=esc(nom), actions=actions)


MESSAGES_CONNEXION = {"redemarre": "L’interface a redémarré pour appliquer vos réglages : reconnectez-vous.",
                      "mdp": "Mot de passe modifié : connectez-vous avec le nouveau mot de passe."}


def page_connexion(erreur, nonce, message=""):
    e = '<div class="banner errb">{}</div>'.format(esc(erreur)) if erreur else ""
    if not e and message in MESSAGES_CONNEXION:
        e = '<div class="banner okb">{}</div>'.format(esc(MESSAGES_CONNEXION[message]))
    corps = """<div class="login"><div class="brand">{logo}<span>Audite-moi</span></div>
{e}<div class="card"><form method="post" action="/connexion"><label for="mdp">Mot de passe</label>
<input id="mdp" name="mot_de_passe" type="password" autocomplete="current-password" autofocus required>
<button class="primary">Se connecter</button></form></div></div>""".format(e=e, logo=LOGO)
    return page("Connexion — Audite-moi", corps, nonce, nu=True)


# -------------------------------------------------------------- serveur HTTP --
class Gestionnaire(http.server.BaseHTTPRequestHandler):
    server_version = "Audite-moi"
    sys_version = ""
    protocol_version = "HTTP/1.1"
    timeout = 30

    # -- outils
    @property
    def app(self):
        return self.server.app

    def log_message(self, fmt_, *args):
        sys.stderr.write("{} {}\n".format(self.client_address[0], fmt_ % args))

    def envoyer(self, code, corps=b"", type_="text/html; charset=utf-8", entetes=None, csp=None, cache="no-store"):
        if isinstance(corps, str):
            corps = corps.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", type_)
        self.send_header("Content-Length", str(len(corps)))
        self.send_header("Cache-Control", cache)
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "same-origin")   # « no-referrer » ferait envoyer « Origin: null »
        self.send_header("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
        self.send_header("Content-Security-Policy", csp or "default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
        for k, v in (entetes or {}).items():
            self.send_header(k, v)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(corps)

    def rediriger(self, cible, entetes=None):
        e = {"Location": cible}
        e.update(entetes or {})
        self.envoyer(303, b"", entetes=e)

    def servir_statique(self, nom):
        """Feuille de style et scripts de l'interface : contenu fixe, sans donnée
        du serveur, donc servi sans session, compressé et mis en cache un an
        (le nom contient l'empreinte du contenu : une mise à jour change l'URL)."""
        f = STATIQUES.get(nom)
        if not f or f["url"] != "/static/" + nom:   # seulement les noms avec empreinte (cache d'un an)
            return self.envoyer(404, b"Introuvable", "text/plain; charset=utf-8")
        if self.headers.get("If-None-Match") == f["etag"]:
            return self.envoyer(304, b"", f["type"], entetes={"ETag": f["etag"]}, cache=CACHE_STATIQUE)
        gz = "gzip" in (self.headers.get("Accept-Encoding") or "")
        entetes = {"ETag": f["etag"], "Vary": "Accept-Encoding"}
        if gz:
            entetes["Content-Encoding"] = "gzip"
        return self.envoyer(200, f["gz"] if gz else f["brut"], f["type"], entetes=entetes, cache=CACHE_STATIQUE)

    def csp_page(self, nonce):
        return ("default-src 'none'; style-src 'self' 'nonce-{n}'; script-src 'self' 'nonce-{n}'; img-src 'self' data:; connect-src 'self'; "
                "form-action 'self'; frame-ancestors 'none'; base-uri 'none'").format(n=nonce)

    def session(self):
        brut = self.headers.get("Cookie", "")
        for part in brut.split(";"):
            k, _, v = part.strip().partition("=")
            if k == COOKIE:
                return self.app.session_valide(v)
        return None

    def lire_formulaire(self):
        """Lit un formulaire borné ; refuse les longueurs ambiguës et les corps tronqués."""
        longueurs = self.headers.get_all("Content-Length", [])
        if len(longueurs) > 1 or self.headers.get("Transfer-Encoding"):
            raise ValueError("en-têtes de longueur ambigus")
        brut = longueurs[0].strip() if longueurs else "0"
        if not brut.isascii() or not brut.isdigit():
            raise ValueError("Content-Length invalide")
        if len(brut) > 10:
            raise OverflowError("requête trop volumineuse")
        n = int(brut)
        if n > 16384:          # le formulaire des sauvegardes compte jusqu'à 30 lignes
            raise OverflowError("requête trop volumineuse")
        contenu = self.rfile.read(n)
        if len(contenu) != n:
            raise ValueError("corps de requête tronqué")
        try:
            champs = urllib.parse.parse_qs(contenu.decode("utf-8", "strict"), max_num_fields=200)
        except (UnicodeDecodeError, ValueError) as exc:
            raise ValueError("formulaire invalide") from exc
        return {k: v[0] for k, v in champs.items()}

    def origine_ok(self):
        orig = self.headers.get("Origin")
        if not orig or orig == "null":
            return orig is None
        try:
            origine = urllib.parse.urlsplit(orig)
            return (origine.scheme in ("http", "https")
                    and origine.netloc.casefold() == self.headers.get("Host", "").casefold()
                    and not origine.path and not origine.query and not origine.fragment
                    and not origine.username and not origine.password)
        except ValueError:
            return False

    # -- routes
    def do_HEAD(self):
        self.do_GET()

    def do_GET(self):
        chemin = urllib.parse.urlsplit(self.path)
        nonce = secrets.token_urlsafe(16)
        if chemin.path.startswith("/static/"):
            return self.servir_statique(chemin.path[len("/static/"):])
        if chemin.path == "/connexion":
            if self.session():
                return self.rediriger("/")
            m = urllib.parse.parse_qs(chemin.query).get("m", [""])[0]
            return self.envoyer(200, page_connexion("", nonce, m), csp=self.csp_page(nonce))
        s = self.session()
        if not s:
            if chemin.path in ("/etat.json", "/materiel.json", "/tendances.json", "/reglages/resultat.json"):
                return self.envoyer(401, b'{"erreur":"non connecte"}', "application/json")
            return self.rediriger("/connexion")
        q = urllib.parse.parse_qs(chemin.query)
        m = q.get("m", [""])[0]
        choix = q.get("rapport", [""])[0]
        if not (NOM_RAPPORT.match(choix) and choix.endswith(".json")):
            choix = ""
        if chemin.path == "/":
            if choix:   # ancien lien « /?rapport=… » : les constats sont sur leur propre page
                return self.rediriger("/constats?rapport=" + urllib.parse.quote(choix))
            return self.envoyer(200, tableau_bord(self.app, s["csrf"], nonce, m), csp=self.csp_page(nonce))
        if chemin.path == "/constats":
            return self.envoyer(200, page_constats(self.app, s["csrf"], nonce, m, choix), csp=self.csp_page(nonce))
        if chemin.path == "/corrections":
            return self.envoyer(200, page_corrections(self.app, s["csrf"], nonce, m), csp=self.csp_page(nonce))
        if chemin.path == "/historique":
            return self.envoyer(200, page_historique(self.app, s["csrf"], nonce), csp=self.csp_page(nonce))
        if chemin.path == "/reglages/resultat.json":
            ident = q.get("id", [""])[0]
            res = self.app.donnees.resultat_configuration()
            fait = bool(ID_DEMANDE.match(ident)) and res.get("id") == ident
            return self.envoyer(200, json.dumps({"fait": fait}), "application/json; charset=utf-8")
        if chemin.path.startswith("/reglages/") and chemin.path[len("/reglages/"):] in dict(ONGLETS):
            onglet = chemin.path[len("/reglages/"):]
            return self.envoyer(200, page_reglages(self.app, s["csrf"], nonce, onglet, q, hote=self.hote()), csp=self.csp_page(nonce))
        if chemin.path == "/etat.json":
            return self.envoyer(200, json.dumps(self.app.donnees.etat()), "application/json; charset=utf-8")
        if chemin.path == "/materiel":
            return self.envoyer(200, page_materiel(self.app, s["csrf"], nonce), csp=self.csp_page(nonce))
        if chemin.path == "/reglages":
            return self.envoyer(200, page_reglages(self.app, s["csrf"], nonce, "seuils", q), csp=self.csp_page(nonce))
        if chemin.path == "/tendances.json":
            try:
                j = int(urllib.parse.parse_qs(chemin.query).get("jours", ["30"])[0])
            except ValueError:
                j = 30
            return self.envoyer(200, json.dumps(self.app.mesures.tendances(j), ensure_ascii=False), "application/json; charset=utf-8")
        if chemin.path == "/materiel.json":
            return self.envoyer(200, json.dumps(dict(self.app.mesures.instantane(), seuils=self.app.seuils.effectifs()), ensure_ascii=False),
                                "application/json; charset=utf-8")
        if chemin.path.startswith("/rapports/"):
            return self.servir_rapport(urllib.parse.unquote(chemin.path[len("/rapports/"):]))
        if chemin.path.startswith("/texte/"):
            nom = urllib.parse.unquote(chemin.path[len("/texte/"):])
            corps = self.lire_rapport(nom) if nom.endswith(".txt") else None
            if corps is None:
                return self.introuvable(nonce)
            return self.envoyer(200, page_texte(self.app.donnees, s["csrf"], nonce, nom, corps.decode("utf-8", "replace")), csp=self.csp_page(nonce))
        return self.introuvable(nonce)

    def introuvable(self, nonce):
        corps = '<div class="login"><div class="brand">{}<span>Audite-moi</span></div><div class="card">Page ou rapport introuvable. <a href="/">Retour au tableau de bord</a></div></div>'.format(LOGO)
        return self.envoyer(404, page("Introuvable — Audite-moi", corps, nonce, nu=True), csp=self.csp_page(nonce))

    def hote(self):
        """Nom et port utilisés par le navigateur (suggestion du lien ajouté aux messages Telegram)."""
        h = self.headers.get("Host", "")
        return h if re.fullmatch(r"[A-Za-z0-9.\-]{1,253}(:[0-9]{1,5})?|\[[0-9A-Fa-f:.]+\](:[0-9]{1,5})?", h) else ""

    def lire_rapport(self, nom):
        if not NOM_RAPPORT.match(nom):
            return None
        base = os.path.realpath(self.app.conf["rapports"])
        f = os.path.realpath(os.path.join(base, nom))
        if os.path.dirname(f) != base or not os.path.isfile(f):
            return None
        with open(f, "rb") as fh:
            return fh.read()

    def servir_rapport(self, nom):
        corps = self.lire_rapport(nom)
        if corps is None:
            return self.introuvable(secrets.token_urlsafe(16))
        ext = nom.rsplit(".", 1)[1]
        types = {"html": "text/html; charset=utf-8", "txt": "text/plain; charset=utf-8", "json": "application/json; charset=utf-8"}
        if ext == "html":   # barre de retour au tableau de bord, collée en haut du rapport
            barre_r = ('<div style="position:sticky;top:0;z-index:50;display:flex;gap:10px;align-items:center;flex-wrap:wrap;padding:9px 20px;'
                       'background:var(--card,#fff);border-bottom:1px solid var(--line,#ddd);font:600 14px system-ui,sans-serif">'
                       '<a href="/" style="color:#fff;background:#2557b8;text-decoration:none;padding:6px 12px;border-radius:8px">← Tableau de bord</a>'
                       '<a href="/texte/{t}" style="color:inherit;text-decoration:none;padding:6px 10px;border:1px solid var(--line,#ddd);border-radius:8px">Version texte</a>'
                       '<span style="color:var(--muted,#666);font-weight:500;font-size:13px">Astuce : cliquez sur les notes ou les compteurs pour filtrer</span></div>'
                       ).format(t=esc(nom[:-5] + ".txt")).encode()
            corps = corps.replace(b"<body>", b"<body>" + barre_r, 1)
        csp = "default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; img-src data:; frame-ancestors 'none'; base-uri 'none'; form-action 'none'"
        return self.envoyer(200, corps, types[ext], csp=csp)

    def accepter(self, form):
        """Marque un constat du dernier rapport comme « voulu » (ou retire cette marque)."""
        cle = form.get("cle", "")
        retour = "/reglages/acceptes?m=" if form.get("retour") == "acceptes" else "/constats?m="
        if form.get("retirer") and cle in self.app.donnees.acceptes():     # possible même si le constat a disparu depuis
            self.app.donnees.modifier_acceptes(cle, None)
            return self.rediriger(retour + "retire")
        hist = self.app.donnees.rapports()
        if not hist or len(cle) > 600 or not any(cle_de(c) == cle for c in hist[-1].get("constats", [])):
            return self.rediriger("/constats?m=corr-invalide")
        if form.get("retirer"):
            return self.rediriger(retour + "retire")
        raison = re.sub(r"\s+", " ", form.get("raison", "")).strip()[:200] or "voulu"
        self.app.donnees.modifier_acceptes(cle, {"raison": raison, "date": int(time.time())})
        return self.rediriger("/constats?m=accepte")

    def corriger(self, chemin, form):
        """Correction en un clic (ou annulation) : mot de passe redemandé, puis demande déposée pour audite-moi-corriger (root)."""
        ip = self.client_address[0]
        if self.app.bloque(ip):
            return self.rediriger("/constats?m=bloque")
        if not verifier(form.get("mot_de_passe", ""), self.app.conf["mot_de_passe"]):
            self.app.echec(ip)
            sys.stderr.write("{} mot de passe incorrect pour une correction\n".format(ip))
            return self.rediriger("/constats?m=mdp")
        d = self.app.donnees
        if d.correction_en_attente() or d.etat()["en_cours"]:
            return self.rediriger("/corrections?m=corr-occupe")
        ident = secrets.token_hex(8)
        if chemin == "/annuler":
            cible = form.get("id", "")
            if not ID_DEMANDE.match(cible) or not any(e.get("id") == cible and e.get("ok") and not e.get("annule") for e in d.corrections()):
                return self.rediriger("/corrections?m=corr-invalide")
            demande = {"id": ident, "annuler": cible, "par": ip}
        else:
            hist = d.rapports()
            if not hist or form.get("rapport") != hist[-1]["_fichier"]:      # uniquement depuis le dernier audit
                return self.rediriger("/constats?m=corr-invalide")
            c = next((c for c in hist[-1].get("constats", []) if cle_de(c) == form.get("cle")), None)
            try:
                i = int(form.get("i", "-1"))
                a = (c.get("actions") or [])[i] if c and i >= 0 else None
            except (ValueError, IndexError):
                a = None
            if not a or a.get("type") not in TYPES_CORRECTION:
                return self.rediriger("/constats?m=corr-invalide")
            demande = {"id": ident, "type": a["type"], "cible": a.get("cible", ""), "par": ip}
        try:
            d.demander_correction(demande)
        except OSError as exc:
            sys.stderr.write("demande de correction impossible : {}\n".format(exc))
            return self.rediriger("/?m=erreur")
        sys.stderr.write("{} correction demandée : {}\n".format(ip, demande.get("type") or "annulation"))
        return self.rediriger("/corrections?m=correction")

    def configurer(self, nom, form, s, nonce):
        """Réglage du serveur : validé ici (mêmes règles que le service root), puis déposé pour audite-moi-configurer."""
        action, onglet, mdp = ACTIONS_CONFIG[nom]
        app, ip = self.app, self.client_address[0]
        mod = app.configurer

        def refus(texte, code=400):
            return self.envoyer(code, page_reglages(app, s["csrf"], nonce, onglet, {}, saisie=form, erreur_config=texte, hote=self.hote()),
                                csp=self.csp_page(nonce))
        if mod is None:
            return refus("module de configuration introuvable : réinstallez Audite-moi.", 500)
        if mdp or nom == "mot-de-passe":
            if app.bloque(ip):
                return refus("trop d’essais de mot de passe : réessayez dans 15 minutes.", 429)
            if not verifier(form.get("actuel" if nom == "mot-de-passe" else "mot_de_passe", ""), app.conf["mot_de_passe"]):
                app.echec(ip)
                sys.stderr.write("{} mot de passe incorrect pour un réglage\n".format(ip))
                return refus("mot de passe incorrect.", 403)
        try:
            if nom == "mot-de-passe":
                nouveau = form.get("nouveau", "")
                if len(nouveau) < 12:
                    raise mod.Refus("le nouveau mot de passe doit compter 12 caractères au moins")
                if nouveau != form.get("confirmation", ""):
                    raise mod.Refus("la confirmation ne correspond pas au nouveau mot de passe")
                valeurs = {"mot_de_passe": hacher(nouveau)}
            else:
                valeurs = valeurs_config(action, form, mod)
        except mod.Refus as exc:
            return refus(str(exc))
        if app.donnees.configuration_en_attente():
            return refus("un autre réglage est en cours d’application : réessayez dans quelques secondes.", 409)
        ident = secrets.token_hex(8)
        try:
            app.donnees.demander_configuration({"id": ident, "action": action, "valeurs": valeurs, "par": ip})
        except OSError as exc:
            sys.stderr.write("demande de réglage impossible : {}\n".format(exc))
            return refus("impossible de déposer la demande (droits du dossier de demandes ?).", 500)
        sys.stderr.write("{} réglage demandé : {}\n".format(ip, nom))
        return self.rediriger("/reglages/{}?attente={}".format(onglet, ident))

    def do_POST(self):
        chemin = urllib.parse.urlsplit(self.path).path
        nonce = secrets.token_urlsafe(16)
        if not self.origine_ok():
            self.close_connection = True
            return self.envoyer(403, b"Origine refusee", "text/plain; charset=utf-8")
        try:
            form = self.lire_formulaire()
        except OverflowError:
            self.close_connection = True
            return self.envoyer(413, b"Requete trop volumineuse", "text/plain; charset=utf-8")
        except ValueError:
            self.close_connection = True
            return self.envoyer(400, b"Formulaire invalide", "text/plain; charset=utf-8")
        if chemin == "/connexion":
            ip = self.client_address[0]
            if self.app.bloque(ip):
                return self.envoyer(429, page_connexion("Trop de tentatives : réessayez dans 15 minutes.", nonce), csp=self.csp_page(nonce))
            if verifier(form.get("mot_de_passe", ""), self.app.conf["mot_de_passe"]):
                jeton = self.app.nouvelle_session()
                attrs = "Path=/; HttpOnly; SameSite=Strict; Max-Age={}".format(int(self.app.conf["duree_session_h"] * 3600))
                if self.app.tls:
                    attrs += "; Secure"
                sys.stderr.write("{} connexion réussie\n".format(ip))
                return self.rediriger("/", {"Set-Cookie": "{}={}; {}".format(COOKIE, jeton, attrs)})
            self.app.echec(ip)
            sys.stderr.write("{} échec de connexion\n".format(ip))
            return self.envoyer(401, page_connexion("Mot de passe incorrect.", nonce), csp=self.csp_page(nonce))
        s = self.session()
        if not s:
            return self.rediriger("/connexion")
        if not hmac.compare_digest(form.get("csrf", ""), s["csrf"]):
            return self.envoyer(403, b"Jeton CSRF invalide : rechargez la page.", "text/plain; charset=utf-8")
        if chemin == "/deconnexion":
            self.app.fermer_session(s["jeton"])
            return self.rediriger("/connexion", {"Set-Cookie": "{}=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0".format(COOKIE)})
        if chemin == "/accepter":
            return self.accepter(form)
        if chemin == "/reglages":
            valeurs, erreurs = self.app.seuils.valider(form)
            if erreurs:
                return self.envoyer(400, page_reglages(self.app, s["csrf"], nonce, "seuils", {}, erreurs, form), csp=self.csp_page(nonce))
            try:
                self.app.seuils.enregistrer(valeurs)
            except OSError as exc:
                sys.stderr.write("seuils non enregistrés : {}\n".format(exc))
                return self.rediriger("/?m=erreur")
            sys.stderr.write("{} seuils modifiés : {}\n".format(self.client_address[0], ", ".join("{}={}".format(k, v) for k, v in sorted(valeurs.items())) or "valeurs par défaut"))
            return self.rediriger("/reglages?m=ok")
        if chemin in ("/corriger", "/annuler"):
            return self.corriger(chemin, form)
        if chemin.startswith("/reglages/") and chemin[len("/reglages/"):] in ACTIONS_CONFIG:
            return self.configurer(chemin[len("/reglages/"):], form, s, nonce)
        if chemin == "/mesurer":
            try:
                self.app.mesures.demander()
            except OSError as exc:
                sys.stderr.write("demande de mesure impossible : {}\n".format(exc))
                return self.envoyer(500, b'{"ok":false}', "application/json")
            return self.envoyer(202, b'{"ok":true}', "application/json")
        if chemin == "/lancer":
            e = self.app.donnees.etat()
            if e["en_cours"] or e["demande"]:
                return self.rediriger("/?m=occupe")
            try:
                self.app.donnees.demander(form.get("mode", "complet"))
            except OSError as exc:
                sys.stderr.write("demande impossible : {}\n".format(exc))
                return self.rediriger("/?m=erreur")
            return self.rediriger("/?m=lance")
        return self.envoyer(404, b"Introuvable", "text/plain; charset=utf-8")


class Application:
    def __init__(self, conf):
        self.conf = conf
        self.donnees = Donnees(conf)
        self.mesures = Mesures(conf)
        self.seuils = Seuils(conf)
        self.configurer = charger_configurer(conf)
        self.tls = bool(conf.get("tls_cert"))
        self._sessions = {}
        self._verrou = threading.Lock()
        self._echecs = self._charger_echecs()

    MAX_SESSIONS = 256
    MAX_IPS_ECHECS = 512
    FENETRE_ECHECS = 900
    MAX_ECHECS = 5

    def _fichier_echecs(self):
        return self.conf.get("fichier_tentatives") or os.path.join(self.conf["reglages"], "tentatives-connexion.json")

    def _charger_echecs(self):
        """Recharge les tentatives récentes afin qu'un redémarrage ne réinitialise pas la protection."""
        try:
            with open(self._fichier_echecs(), encoding="utf-8") as f:
                donnees = json.load(f)
        except FileNotFoundError:
            return {}
        except (OSError, ValueError) as exc:
            sys.stderr.write("limitation des connexions : impossible de lire l'état persistant : {}\n".format(exc))
            return {}
        if not isinstance(donnees, dict):
            return {}
        maintenant = time.time()
        resultat = {}
        for ip, valeurs in donnees.items():
            if not isinstance(ip, str) or not isinstance(valeurs, list):
                continue
            try:
                ipaddress.ip_address(ip)
            except ValueError:
                continue
            recents = [float(v) for v in valeurs
                       if isinstance(v, (int, float)) and not isinstance(v, bool)
                       and maintenant - self.FENETRE_ECHECS < v <= maintenant + 60]
            if recents:
                resultat[ip] = recents[-self.MAX_ECHECS:]
        return dict(sorted(resultat.items(), key=lambda item: item[1][-1], reverse=True)[:self.MAX_IPS_ECHECS])

    def _sauver_echecs(self):
        """Écrit l'état par remplacement atomique ; mkstemp crée un fichier privé (0600)."""
        chemin = self._fichier_echecs()
        dossier = os.path.dirname(chemin) or "."
        fd = None
        temporaire = None
        try:
            fd, temporaire = tempfile.mkstemp(prefix=".tentatives-", dir=dossier)
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                fd = None
                json.dump(self._echecs, f, separators=(",", ":"))
                f.flush()
                os.fsync(f.fileno())
            os.replace(temporaire, chemin)
            temporaire = None
        except OSError as exc:
            sys.stderr.write("limitation des connexions : impossible de persister l'état : {}\n".format(exc))
        finally:
            if fd is not None:
                os.close(fd)
            if temporaire:
                try:
                    os.unlink(temporaire)
                except OSError:
                    pass

    def nouvelle_session(self):
        maintenant = time.time()
        jeton = secrets.token_urlsafe(32)
        with self._verrou:
            self._sessions = {k: v for k, v in self._sessions.items() if v["expire"] > maintenant}
            if len(self._sessions) >= self.MAX_SESSIONS:
                ancien = min(self._sessions, key=lambda k: self._sessions[k]["expire"])
                self._sessions.pop(ancien, None)
            self._sessions[jeton] = {"jeton": jeton, "csrf": secrets.token_urlsafe(24),
                                     "expire": maintenant + self.conf["duree_session_h"] * 3600}
        return jeton

    def session_valide(self, jeton):
        with self._verrou:
            s = self._sessions.get(jeton)
            if s and s["expire"] > time.time():
                return s
            self._sessions.pop(jeton, None)
        return None

    def fermer_session(self, jeton):
        with self._verrou:
            self._sessions.pop(jeton, None)

    def echec(self, ip):
        maintenant = time.time()
        try:
            ip = str(ipaddress.ip_address(ip))
        except ValueError:
            return
        with self._verrou:
            for adresse in list(self._echecs):
                recents = [t for t in self._echecs[adresse] if maintenant - t < self.FENETRE_ECHECS]
                if recents:
                    self._echecs[adresse] = recents
                else:
                    self._echecs.pop(adresse, None)
            if ip not in self._echecs and len(self._echecs) >= self.MAX_IPS_ECHECS:
                plus_ancien = min(self._echecs, key=lambda k: self._echecs[k][-1])
                self._echecs.pop(plus_ancien, None)
            self._echecs.setdefault(ip, []).append(maintenant)
            self._echecs[ip] = self._echecs[ip][-self.MAX_ECHECS:]
            self._sauver_echecs()

    def bloque(self, ip):
        try:
            ip = str(ipaddress.ip_address(ip))
        except ValueError:
            return False
        maintenant = time.time()
        with self._verrou:
            recents = [t for t in self._echecs.get(ip, []) if maintenant - t < self.FENETRE_ECHECS]
            if recents:
                self._echecs[ip] = recents
            else:
                self._echecs.pop(ip, None)
            return len(recents) >= self.MAX_ECHECS


class Serveur(http.server.ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True
    MAX_THREADS = 64

    def __init__(self, *args, **kwargs):
        self._places = threading.BoundedSemaphore(self.MAX_THREADS)
        super().__init__(*args, **kwargs)

    def process_request(self, request, client_address):
        # ThreadingHTTPServer crée normalement un thread sans limite par connexion.
        # Refuser proprement les connexions excédentaires évite l'épuisement mémoire.
        if not self._places.acquire(blocking=False):
            try:
                request.sendall(b"HTTP/1.1 503 Service Unavailable\r\nConnection: close\r\nContent-Length: 0\r\n\r\n")
            except OSError:
                pass
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except Exception:
            self._places.release()
            raise

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            self._places.release()

    def handle_error(self, request, client_address):
        exc = sys.exc_info()[1]
        sys.stderr.write("{} erreur : {}\n".format(client_address[0] if client_address else "?", exc))


def charger_conf(chemin):
    conf = dict(DEFAUTS)
    with open(chemin, encoding="utf-8") as f:
        conf.update(json.load(f))
    if not conf["mot_de_passe"].startswith("pbkdf2_sha256$"):
        sys.exit("Configuration invalide : aucun mot de passe haché dans {} (utilisez --hachage).".format(chemin))
    return conf


def main():
    ap = argparse.ArgumentParser(description="Interface web d'Audite-moi")
    ap.add_argument("--config", default="/etc/audite-moi/web.json")
    ap.add_argument("--hachage", action="store_true", help="hache un mot de passe lu sur l'entrée standard et l'affiche")
    a = ap.parse_args()
    if a.hachage:
        mdp = getpass.getpass("Mot de passe : ") if sys.stdin.isatty() else sys.stdin.readline().rstrip("\n")
        if len(mdp) < 8:
            sys.exit("Mot de passe trop court (8 caractères minimum).")
        print(hacher(mdp))
        return
    conf = charger_conf(a.config)
    app = Application(conf)
    hote = conf["ecoute"]
    Serveur.address_family = socket.AF_INET6 if ":" in hote else socket.AF_INET
    srv = Serveur((hote, int(conf["port"])), Gestionnaire)
    srv.app = app
    app.mesures.demarrer()
    schema = "http"
    if app.tls:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        ctx.load_cert_chain(conf["tls_cert"], conf["tls_cle"])
        srv.socket = ctx.wrap_socket(srv.socket, server_side=True, do_handshake_on_connect=False)
        schema = "https"
    sys.stderr.write("Audite-moi {} : interface disponible sur {}://{}:{}/\n".format(VERSION, schema, hote, conf["port"]))
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
