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
import getpass
import hashlib
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
import time
import urllib.parse
from datetime import datetime

VERSION = "1.0.0"
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
}


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
class Donnees:
    def __init__(self, conf):
        self.conf = conf

    def rapports(self):
        """Résumés des rapports JSON, du plus ancien au plus récent."""
        dossier = self.conf["rapports"]
        res = []
        try:
            noms = os.listdir(dossier)
        except OSError:
            return res
        for nom in noms:
            if not (NOM_RAPPORT.match(nom) and nom.endswith(".json")):
                continue
            try:
                with open(os.path.join(dossier, nom), encoding="utf-8") as f:
                    d = json.load(f)
                d["_fichier"] = nom
                res.append(d)
            except (OSError, ValueError):
                continue
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


# ------------------------------------------------------------------ gabarits --
CSS = """
:root{--bg:#f4f5f7;--card:#fff;--ink:#1b1f27;--muted:#5d6675;--line:#e3e6eb;--soft:#f0f2f5;--accent:#2f5fd0;--accent-ink:#fff;
--crit:#c4352f;--crit-bg:#fdecea;--warn:#a35f00;--warn-bg:#fff3dd;--ok:#1d7a4c;--ok-bg:#e4f4ea;--info:#3461c1;--info-bg:#e9effc;
--s1:#2a78d6;--s2:#eb6834;--grid:#e8eaee;--mono:ui-monospace,SFMono-Regular,Menlo,Consolas,"Liberation Mono",monospace}
@media (prefers-color-scheme:dark){:root{--bg:#0f1216;--card:#171b21;--ink:#e7eaee;--muted:#9aa3af;--line:#29303a;--soft:#1e232b;--accent:#5b86f0;
--crit:#ff7b72;--crit-bg:#3a1d1d;--warn:#f2b24c;--warn-bg:#382a12;--ok:#4cc38a;--ok-bg:#13301f;--info:#86a8ff;--info-bg:#1a2540;
--s1:#3987e5;--s2:#d95926;--grid:#262c35}}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--ink);font:15px/1.55 system-ui,-apple-system,"Segoe UI",Roboto,Ubuntu,"Helvetica Neue",Arial,sans-serif}
a{color:var(--accent)}
.wrap{max-width:1180px;margin:0 auto;padding:22px 20px 60px}
.bar{display:flex;align-items:center;justify-content:space-between;gap:16px;flex-wrap:wrap;margin-bottom:18px}
.brand{display:flex;align-items:center;gap:10px;font-weight:750;font-size:18px}
.logo{width:30px;height:30px;border-radius:8px;background:var(--accent);display:grid;place-items:center;color:#fff;font-size:15px}
.host{color:var(--muted);font-weight:500;font-size:14px}
.actions{display:flex;gap:8px;flex-wrap:wrap;align-items:center}
button,.btn{font:inherit;font-size:14px;font-weight:600;border-radius:9px;padding:8px 14px;border:1px solid var(--line);background:var(--card);color:var(--ink);cursor:pointer;text-decoration:none;display:inline-block}
button.primary{background:var(--accent);border-color:var(--accent);color:var(--accent-ink)}
button:disabled{opacity:.5;cursor:not-allowed}
button:hover:not(:disabled),.btn:hover{filter:brightness(1.06)}
form.inline{display:inline}
.card{background:var(--card);border:1px solid var(--line);border-radius:14px;padding:18px 20px;margin:0 0 18px}
h2{font-size:18px;margin:0 0 12px;display:flex;gap:10px;align-items:baseline;flex-wrap:wrap}
h2 .mini{margin-left:auto;font-size:12.5px;color:var(--muted);font-weight:500}
.banner{border-radius:12px;padding:12px 16px;margin:0 0 18px;border:1px solid var(--line);background:var(--card)}
.banner.run{border-left:4px solid var(--info)}.banner.okb{border-left:4px solid var(--ok)}.banner.warnb{border-left:4px solid var(--warn)}
.banner pre{margin:10px 0 0;max-height:240px;overflow:auto;background:var(--soft);border-radius:8px;padding:10px;font:12px/1.45 var(--mono);white-space:pre-wrap}
.spin{display:inline-block;width:12px;height:12px;border:2px solid var(--info);border-right-color:transparent;border-radius:50%;animation:r 1s linear infinite;margin-right:8px;vertical-align:-1px}
@keyframes r{to{transform:rotate(360deg)}}
@media (prefers-reduced-motion:reduce){.spin{animation:none}}
.hero{display:grid;grid-template-columns:repeat(2,minmax(0,1fr)) repeat(4,minmax(0,1fr));gap:12px;margin-bottom:18px}
.tile{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:12px 16px}
.tile .l{color:var(--muted);font-size:12px;text-transform:uppercase;letter-spacing:.06em;font-weight:650}
.tile .v{font-size:28px;font-weight:750;line-height:1.25}
.tile .v small{font-size:13px;color:var(--muted);font-weight:500}
.score{display:flex;align-items:center;gap:12px}
.grade{font-size:24px;font-weight:800;width:44px;height:44px;border-radius:10px;display:grid;place-items:center;color:#fff;flex:none}
.g-A{background:#1d7a4c}.g-B{background:#4c8a2a}.g-C{background:#a35f00}.g-D{background:#c4561c}.g-E{background:#c4352f}
.kpi{border-left:4px solid var(--c)}.k-CRIT{--c:var(--crit)}.k-WARN{--c:var(--warn)}.k-OK{--c:var(--ok)}.k-INFO{--c:var(--info)}
.meta{color:var(--muted);font-size:13.5px;margin:-4px 0 16px}
.links{display:flex;gap:8px;flex-wrap:wrap;margin-top:12px}
.badge{display:inline-block;min-width:78px;text-align:center;font-size:11px;font-weight:750;padding:3px 8px;border-radius:999px;text-transform:uppercase;letter-spacing:.04em}
.b-CRIT{background:var(--crit-bg);color:var(--crit)}.b-WARN{background:var(--warn-bg);color:var(--warn)}
ol.plan{list-style:none;margin:0;padding:0}
ol.plan li{display:grid;grid-template-columns:92px 1fr;gap:8px;padding:10px 0;border-top:1px solid var(--line)}
ol.plan li:first-child{border-top:0}
.sec{font-size:12px;color:var(--muted);margin-right:6px}
.ttl{font-weight:600}
.fix{margin-top:5px;font-size:13.5px;padding:6px 10px;border-left:3px solid var(--info);background:var(--soft);border-radius:0 6px 6px 0;overflow-wrap:anywhere}
.fix::before{content:"À faire : ";font-weight:650}
details.d{margin-top:4px}details.d summary{cursor:pointer;color:var(--muted);font-size:13px}
.det{color:var(--muted);font-size:13.5px;white-space:pre-wrap;overflow-wrap:anywhere}
code{font-family:var(--mono);font-size:12.5px;background:var(--soft);padding:1px 5px;border-radius:4px}
.fix code{background:var(--card)}
table{border-collapse:collapse;width:100%;font-size:14px}
th{text-align:left;font-size:12px;color:var(--muted);text-transform:uppercase;letter-spacing:.05em;padding:6px 8px;border-bottom:1px solid var(--line);white-space:nowrap}
td{padding:8px;border-bottom:1px solid var(--line);white-space:nowrap}
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
.login{max-width:380px;margin:12vh auto 0}
.login .brand{margin-bottom:14px}.login button{width:100%}
.login input{width:100%;font:inherit;padding:10px 12px;border-radius:9px;border:1px solid var(--line);background:var(--soft);color:var(--ink);margin:6px 0 14px}
.err{color:var(--crit);font-weight:600;margin:0 0 10px}
footer{color:var(--muted);font-size:12.5px;text-align:center;margin-top:24px}
@media (max-width:900px){.hero{grid-template-columns:repeat(2,minmax(0,1fr))}}
@media (max-width:620px){ol.plan li{grid-template-columns:1fr}}
"""

GRADE = lambda s: "A" if s >= 90 else "B" if s >= 75 else "C" if s >= 60 else "D" if s >= 40 else "E"
NIV_FR = {"CRIT": "Critique", "WARN": "Attention"}


def esc(s):
    return html.escape(str(s), quote=True)


def fmt(s):
    """Texte → HTML : échappement, `code` → <code>, sauts de ligne conservés."""
    s = esc(s or "")
    s = re.sub(r"`([^`]+)`", r"<code>\1</code>", s)
    return s.replace("\n", "<br>")


def page(titre, corps, nonce):
    return """<!DOCTYPE html>
<html lang="fr"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex"><title>{t}</title>
<link rel="icon" href="data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 16 16'%3E%3Crect width='16' height='16' rx='4' fill='%232f5fd0'/%3E%3Cpath d='M4 8.5l2.5 2.5L12 5' stroke='white' stroke-width='2' fill='none'/%3E%3C/svg%3E">
<style nonce="{n}">{css}</style></head><body><div class="wrap">{c}</div></body></html>""".format(t=esc(titre), n=nonce, css=CSS, c=corps)


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


def tableau_bord(donnees, csrf, nonce, message):
    hist = donnees.rapports()
    etat = donnees.etat()
    occupe = etat["en_cours"] or etat["demande"]
    der = hist[-1] if hist else None
    hote = der.get("hote", "") if der else socket.gethostname()
    out = []
    dis = " disabled" if occupe else ""
    out.append("""<div class="bar"><div class="brand"><span class="logo">✓</span>Audite-moi <span class="host">{h}</span></div>
<div class="actions">
<form class="inline" method="post" action="/lancer"><input type="hidden" name="csrf" value="{c}"><input type="hidden" name="mode" value="complet"><button class="primary"{d}>Lancer un audit complet</button></form>
<form class="inline" method="post" action="/lancer"><input type="hidden" name="csrf" value="{c}"><input type="hidden" name="mode" value="rapide"><button{d}>Audit rapide</button></form>
<form class="inline" method="post" action="/deconnexion"><input type="hidden" name="csrf" value="{c}"><button>Se déconnecter</button></form>
</div></div>""".format(h=esc(hote), c=esc(csrf), d=dis))

    msgs = {"lance": ("okb", "Demande enregistrée : l’audit démarre dans quelques secondes."),
            "occupe": ("warnb", "Un audit est déjà en cours ou en attente."),
            "erreur": ("warnb", "Impossible d’enregistrer la demande (droits du dossier de demandes ?).")}
    if etat["en_cours"]:
        depuis = int((time.time() - (etat["depuis"] or time.time())) // 60)
        out.append('<div class="banner run" id="etat"><span class="spin"></span><b>Audit {m} en cours</b> depuis {d} min — la page se mettra à jour à la fin.<pre id="journal">{j}</pre></div>'
                   .format(m=esc(etat["mode"] or ""), d=depuis, j=esc(etat["journal"])))
    elif etat["bloque"]:
        out.append('<div class="banner warnb"><b>La demande d’audit n’a pas été prise en charge.</b> Vérifiez sur le serveur : <code>systemctl status audite-moi.path audite-moi.service</code></div>')
    elif etat["demande"]:
        out.append('<div class="banner run" id="etat"><span class="spin"></span>Demande enregistrée, démarrage imminent…</div>')
    elif message in msgs:
        out.append('<div class="banner {}">{}</div>'.format(*msgs[message]))

    if not der:
        out.append('<div class="card"><h2>Aucun rapport pour l’instant</h2><p class="empty">Lancez un premier audit avec le bouton ci-dessus (un audit complet prend quelques minutes).</p></div>')
    else:
        n, c = der["notes"], der["compteurs"]
        out.append('<div class="meta">Dernier audit : {d} · {m} · {os} · durée {s} s</div>'.format(
            d=esc(der.get("date", "")), m="mode " + esc(der.get("mode", "")), os=esc(der.get("os", "")), s=esc(der.get("duree_s", "?"))))
        tiles = []
        for lib, k in (("Santé", "sante"), ("Sécurité", "securite")):
            tiles.append('<div class="tile score"><span class="grade g-{g}">{g}</span><div><div class="l">{l}</div><div class="v">{v}<small> / 100</small></div></div></div>'
                         .format(g=esc(n[k]["lettre"]), l=lib, v=esc(n[k]["score"])))
        for k, lib in (("CRIT", "critiques"), ("WARN", "avertissements"), ("OK", "contrôles OK"), ("INFO", "informations")):
            tiles.append('<div class="tile kpi k-{k}"><div class="v">{v}</div><div class="l">{l}</div></div>'.format(k=k, v=esc(c.get(k, 0)), l=lib))
        out.append('<div class="hero">{}</div>'.format("".join(tiles)))
        f = der["fichiers"]
        out.append('<div class="links"><a class="btn" href="/rapports/{h}">Ouvrir le rapport complet</a><a class="btn" href="/rapports/{t}">Version texte</a><a class="btn" href="/rapports/{j}">JSON</a></div>'
                   .format(h=esc(f["html"]), t=esc(f["txt"]), j=esc(f["json"])))
        out[-1] = '<div class="card"><h2>Rapport du {}</h2>{}</div>'.format(esc(der.get("date", "")), out[-1])

        secs = der.get("sections", {})
        items = [x for lvl in ("CRIT", "WARN") for x in der.get("constats", []) if x.get("niveau") == lvl]
        lis = []
        for x in items:
            det = '<details class="d"><summary>Détail</summary><div class="det">{}</div></details>'.format(fmt(x["detail"])) if x.get("detail") else ""
            fx = '<div class="fix">{}</div>'.format(fmt(x["correctif"])) if x.get("correctif") else ""
            lis.append('<li><div><span class="badge b-{n}">{nf}</span></div><div><span class="sec">{s}</span><span class="ttl">{t}</span>{fx}{det}</div></li>'.format(
                n=x["niveau"], nf=NIV_FR[x["niveau"]], s=esc(secs.get(x["section"], {}).get("court") or secs.get(x["section"], {}).get("titre", x["section"])), t=fmt(x["titre"]), fx=fx, det=det))
        out.append('<div class="card"><h2>Plan d’action <span class="mini">{} point(s), du plus urgent au moins urgent</span></h2>{}</div>'.format(
            len(items), '<ol class="plan">{}</ol>'.format("".join(lis)) if lis else '<p class="empty">Rien à corriger : tout est au vert.</p>'))

    out.append('<div class="card"><h2>Évolution des notes</h2>{}</div>'.format(graphique(hist, nonce)))

    if hist:
        rows = []
        for d in reversed(hist[-60:]):
            n, c, f = d["notes"], d["compteurs"], d["fichiers"]
            rows.append("<tr><td>{date}</td><td>{mode}</td><td><span class='pill'><i class='g-{gs}'>{gs}</i>{s}</span></td><td><span class='pill'><i class='g-{gc}'>{gc}</i>{c}</span></td>"
                        "<td class='num'>{cr}</td><td class='num'>{w}</td><td><a href='/rapports/{h}'>HTML</a> · <a href='/rapports/{t}'>texte</a></td></tr>".format(
                            date=esc(d.get("date", "")), mode=esc(d.get("mode", "")), gs=esc(n["sante"]["lettre"]), s=esc(n["sante"]["score"]),
                            gc=esc(n["securite"]["lettre"]), c=esc(n["securite"]["score"]), cr=esc(c.get("CRIT", 0)), w=esc(c.get("WARN", 0)),
                            h=esc(f["html"]), t=esc(f["txt"])))
        out.append('<div class="card"><h2>Historique <span class="mini">{} rapport(s)</span></h2><div class="tw"><table><thead><tr><th>Date</th><th>Mode</th><th>Santé</th><th>Sécurité</th>'
                   '<th>Critiques</th><th>Avert.</th><th>Rapport</th></tr></thead><tbody>{}</tbody></table></div></div>'.format(len(hist), "".join(rows)))

    prochain = donnees.prochain_audit()
    out.append('<footer>Audite-moi {v}{p} · <a href="https://github.com/oliv2776/Audite-moi">GitHub</a></footer>'.format(
        v=VERSION, p=" · prochain audit automatique : " + esc(prochain) if prochain else ""))
    if occupe:
        out.append("""<script nonce="{n}">(function(){{var j=document.getElementById('journal');
setInterval(function(){{fetch('/etat.json',{{credentials:'same-origin'}}).then(function(r){{return r.json();}}).then(function(e){{
if(!e.en_cours&&!e.demande){{location.href='/';return;}} if(j&&e.journal){{j.textContent=e.journal;j.scrollTop=j.scrollHeight;}}
if(!j&&e.en_cours){{location.reload();}}}}).catch(function(){{}});}},3000);}})();</script>""".format(n=nonce))
    return page("Audite-moi — " + hote, "".join(out), nonce)


def page_connexion(erreur, nonce):
    e = '<p class="err">{}</p>'.format(esc(erreur)) if erreur else ""
    corps = """<div class="login card"><div class="brand"><span class="logo">✓</span>Audite-moi</div>
{e}<form method="post" action="/connexion"><label for="mdp">Mot de passe</label>
<input id="mdp" name="mot_de_passe" type="password" autocomplete="current-password" autofocus required>
<button class="primary">Se connecter</button></form></div>""".format(e=e)
    return page("Audite-moi — connexion", corps, nonce)


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

    def envoyer(self, code, corps=b"", type_="text/html; charset=utf-8", entetes=None, csp=None):
        if isinstance(corps, str):
            corps = corps.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", type_)
        self.send_header("Content-Length", str(len(corps)))
        self.send_header("Cache-Control", "no-store")
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

    def csp_page(self, nonce):
        return ("default-src 'none'; style-src 'nonce-{n}'; script-src 'nonce-{n}'; img-src 'self' data:; connect-src 'self'; "
                "form-action 'self'; frame-ancestors 'none'; base-uri 'none'").format(n=nonce)

    def session(self):
        brut = self.headers.get("Cookie", "")
        for part in brut.split(";"):
            k, _, v = part.strip().partition("=")
            if k == COOKIE:
                return self.app.session_valide(v)
        return None

    def lire_formulaire(self):
        try:
            n = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            n = 0
        if n > 4096:
            return None
        return {k: v[0] for k, v in urllib.parse.parse_qs(self.rfile.read(n).decode("utf-8", "replace")).items()}

    def origine_ok(self):
        orig = self.headers.get("Origin")
        if not orig or orig == "null":
            return orig is None
        return urllib.parse.urlsplit(orig).netloc == self.headers.get("Host", "")

    # -- routes
    def do_HEAD(self):
        self.do_GET()

    def do_GET(self):
        chemin = urllib.parse.urlsplit(self.path)
        nonce = secrets.token_urlsafe(16)
        if chemin.path == "/connexion":
            if self.session():
                return self.rediriger("/")
            return self.envoyer(200, page_connexion("", nonce), csp=self.csp_page(nonce))
        s = self.session()
        if not s:
            if chemin.path == "/etat.json":
                return self.envoyer(401, b'{"erreur":"non connecte"}', "application/json")
            return self.rediriger("/connexion")
        if chemin.path == "/":
            msg = urllib.parse.parse_qs(chemin.query).get("m", [""])[0]
            return self.envoyer(200, tableau_bord(self.app.donnees, s["csrf"], nonce, msg), csp=self.csp_page(nonce))
        if chemin.path == "/etat.json":
            return self.envoyer(200, json.dumps(self.app.donnees.etat()), "application/json; charset=utf-8")
        if chemin.path.startswith("/rapports/"):
            return self.servir_rapport(urllib.parse.unquote(chemin.path[len("/rapports/"):]))
        return self.envoyer(404, page("Introuvable", '<div class="card">Page introuvable. <a href="/">Retour</a></div>', nonce), csp=self.csp_page(nonce))

    def servir_rapport(self, nom):
        if not NOM_RAPPORT.match(nom):
            return self.envoyer(404, b"Rapport introuvable", "text/plain; charset=utf-8")
        base = os.path.realpath(self.app.conf["rapports"])
        f = os.path.realpath(os.path.join(base, nom))
        if os.path.dirname(f) != base or not os.path.isfile(f):
            return self.envoyer(404, b"Rapport introuvable", "text/plain; charset=utf-8")
        with open(f, "rb") as fh:
            corps = fh.read()
        types = {"html": "text/html; charset=utf-8", "txt": "text/plain; charset=utf-8", "json": "application/json; charset=utf-8"}
        csp = "default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; img-src data:; frame-ancestors 'none'; base-uri 'none'; form-action 'none'"
        return self.envoyer(200, corps, types[nom.rsplit(".", 1)[1]], csp=csp)

    def do_POST(self):
        chemin = urllib.parse.urlsplit(self.path).path
        nonce = secrets.token_urlsafe(16)
        if not self.origine_ok():
            return self.envoyer(403, b"Origine refusee", "text/plain; charset=utf-8")
        form = self.lire_formulaire()
        if form is None:
            return self.envoyer(413, b"Requete trop volumineuse", "text/plain; charset=utf-8")
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
        self.tls = bool(conf.get("tls_cert"))
        self._sessions = {}
        self._echecs = {}
        self._verrou = threading.Lock()

    def nouvelle_session(self):
        jeton = secrets.token_urlsafe(32)
        with self._verrou:
            self._sessions[jeton] = {"jeton": jeton, "csrf": secrets.token_urlsafe(24),
                                     "expire": time.time() + self.conf["duree_session_h"] * 3600}
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
        with self._verrou:
            self._echecs.setdefault(ip, []).append(time.time())

    def bloque(self, ip):
        with self._verrou:
            recents = [t for t in self._echecs.get(ip, []) if time.time() - t < 900]
            self._echecs[ip] = recents
            return len(recents) >= 5


class Serveur(http.server.ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

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
