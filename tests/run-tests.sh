#!/usr/bin/env bash
# Tests d'Audite-moi sur un « faux NAS » : les commandes système (zpool, docker,
# smartctl, journalctl…) sont remplacées par des simulations (tests/mock/bin) et
# des données d'exemple (tests/fixtures). Aucun accès réel au système audité.
#
#   sudo tests/run-tests.sh            # scénario complet simulé
#   sudo tests/run-tests.sh --reel     # + exécution réelle sur cette machine (lecture seule)
set -u
ROOT=$(cd "$(dirname "$0")/.." && pwd)
SCRIPT=$ROOT/audite-moi.sh
((EUID == 0)) || exec sudo -E bash "$0" "$@"

TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
fail=0
ok()  { printf '  \e[32m✔\e[0m %s\n' "$1"; }
ko()  { printf '  \e[31m✘\e[0m %s\n' "$1"; fail=1; }

# --- Faux sysfs : iGPU Intel (renderD128) + carte AMD (renderD129), disques -----
S=$TMP/sys
mkdir -p "$S/drivers/i915" "$S/drivers/amdgpu" "$S/pci/0000:00:02.0" "$S/pci/0000:03:00.0/hwmon/hwmon5" "$S/drm" "$TMP/dri"
echo 0x8086 > "$S/pci/0000:00:02.0/vendor"; ln -s ../../drivers/i915 "$S/pci/0000:00:02.0/driver"
echo 0x1002 > "$S/pci/0000:03:00.0/vendor"; ln -s ../../drivers/amdgpu "$S/pci/0000:03:00.0/driver"
echo 7 > "$S/pci/0000:03:00.0/gpu_busy_percent"
echo 1073741824 > "$S/pci/0000:03:00.0/mem_info_vram_used"; echo 8573157376 > "$S/pci/0000:03:00.0/mem_info_vram_total"
H=$S/pci/0000:03:00.0/hwmon/hwmon5
echo 52000 > "$H/temp1_input"; echo edge > "$H/temp1_label"
echo 61000 > "$H/temp2_input"; echo junction > "$H/temp2_label"
echo 28000000 > "$H/power1_average"
for n in renderD128:0000:00:02.0 renderD129:0000:03:00.0; do
  mkdir -p "$S/drm/${n%%:*}"; ln -s "../../pci/${n#*:}" "$S/drm/${n%%:*}/device"; touch "$TMP/dri/${n%%:*}"
done
for d in sda:0 sdb:0 sdc:1 sdd:1 sde:1 nvme0n1:0; do mkdir -p "$S/block/${d%%:*}/queue"; echo "${d#*:}" > "$S/block/${d%%:*}/queue/rotational"; done
printf 'x x x\nname type data\nsize 4 12884901888\nc_min 4 1073741824\nc_max 4 16777216000\nhits 4 98765432\nmisses 4 1234567\n' > "$TMP/arcstats"

export AUDITE_MOI_FIX=$ROOT/tests/fixtures AUDITE_MOI_DRI_DIR=$TMP/dri AUDITE_MOI_DRM_CLASS=$S/drm \
       AUDITE_MOI_ARCSTATS=$TMP/arcstats AUDITE_MOI_SYS_BLOCK=$S/block AUDITE_MOI_SMB_CONF=$ROOT/tests/fixtures/smb.conf

echo "▶ Scénario simulé (NAS ZFS + Docker + iGPU Intel + carte AMD + tunnel Cloudflare)"
OUT=$TMP/rapports
PATH="$ROOT/tests/mock/bin:$PATH" bash "$SCRIPT" -o "$OUT" --no-color --keep 5 > "$TMP/sortie.txt" 2> "$TMP/erreurs.txt"
rc=$?
[[ $rc == 2 ]] && ok "code de sortie 2 (problèmes critiques détectés)" || ko "code de sortie attendu 2, obtenu $rc"
if [[ -s $TMP/erreurs.txt ]]; then ko "messages d'erreur inattendus :"; sed 's/^/      /' "$TMP/erreurs.txt" | head -20; else ok "aucune erreur sur la sortie d'erreur"; fi
J=$(ls "$OUT"/rapport-*.json 2>/dev/null | head -n 1)
for f in html txt json; do ls "$OUT"/rapport-*."$f" >/dev/null 2>&1 && ok "rapport .$f généré" || ko "rapport .$f absent"; done
jq -e . "$J" >/dev/null 2>&1 && ok "JSON valide" || ko "JSON invalide"
perms=$(stat -c %a "$J" 2>/dev/null); [[ $perms == 600 ]] && ok "rapport en mode 600" || ko "droits du rapport : $perms"
grep -q 'TresSecret123' "$OUT"/rapport-* && ko "un secret apparaît dans le rapport" || ok "secrets masqués dans les rapports"
grep -q 'eyJhIjoiMTIz' "$OUT"/rapport-* && ko "le jeton du tunnel apparaît dans le rapport" || ok "jeton du tunnel absent du rapport"

expect() {   # expect NIVEAU "motif dans le titre"
  if jq -e --arg l "$1" --arg t "$2" '.constats[] | select(.niveau == $l and (.titre | contains($t)))' "$J" >/dev/null; then ok "[$1] $2"
  else ko "constat attendu absent : [$1] $2"; fi
}
expect WARN "Pool rapide rempli à 83"
expect WARN "Pool stockage : erreurs d'entrées/sorties"
expect WARN "le dernier scrub a réparé"
expect WARN "Pool stockage : dernier scrub il y a"
expect INFO "nouvelles fonctionnalités ZFS"
expect WARN "Pool rapide (SSD) : aucun TRIM"
expect WARN "Pool rapide : aucun snapshot"
expect OK   "Pool stockage : 52 snapshots"
expect WARN "Disque /dev/sdd"
expect OK   "5 disque(s) en bonne santé SMART"
expect WARN "Erreurs matérielles ou système"
expect OK   "Espace disque suffisant"
expect WARN "OOM killer"
expect OK   "iGPU Intel opérationnel"
expect OK   "GPU AMD opérationnel"
expect OK   "VA-API (AMD) : encodage matériel disponible"
expect OK   "Conteneur jellyfin : accès GPU configuré"
expect OK   "Conteneur tdarr : accès GPU configuré"
expect OK   "Tunnel « cloudflared » connecté"
expect WARN "cloudflared « cloudflared » obsolète"
expect WARN "service(s) injoignable(s)"
expect INFO "Protection Cloudflare Access à confirmer : films.exemple.fr"
expect INFO "jellyfin : aussi accessible directement"
expect WARN "Docker contourne UFW"
expect WARN "Services sensibles accessibles depuis le réseau"
expect WARN "Conteneur tdarr privilégié"
expect WARN "Conteneur portainer : socket Docker monté"
expect WARN "Image de nextcloud construite il y a"
expect INFO "Secrets en clair"
expect WARN "Conteneur sauvegarde-photos arrêté en erreur"
expect WARN "Conteneur(s) proche(s) de leur limite mémoire"
expect CRIT "SSH exposé à Internet avec authentification par mot de passe"
expect WARN "mise(s) à jour de sécurité en attente"
expect WARN "Partages Samba accessibles sans mot de passe"
expect WARN "sharenfs=on"
expect WARN "La box redirige des ports vers ce serveur (UPnP)"
expect WARN "Service(s) systemd en échec"
expect WARN "Aucun outil de sauvegarde détecté"
expect OK   "Onduleur eaton en ligne"
expect INFO "Indice de durcissement Lynis : 64/100"
expect WARN "Image exposée nextcloud:29-apache"

echo "▶ Contrôles du rapport HTML"
Hf=$(ls "$OUT"/rapport-*.html | head -n 1)
grep -q '<section class="card" id="plan">' "$Hf" && ok "plan d'action présent" || ko "plan d'action absent"
grep -q '<code>sudo zpool scrub stockage</code>' "$Hf" && ok "commandes mises en forme" || ko "mise en forme des commandes"
python3 - "$Hf" <<'PY' && ok "HTML bien formé (balises équilibrées)" || ko "HTML mal formé"
import sys, html.parser
class P(html.parser.HTMLParser):
    void = {"meta", "br", "input", "link", "img", "hr"}
    def __init__(s): super().__init__(); s.stack = []; s.err = []
    def handle_starttag(s, t, a):
        if t not in s.void: s.stack.append(t)
    def handle_endtag(s, t):
        if t in s.void: return
        if not s.stack or s.stack[-1] != t: s.err.append((t, s.stack[-3:])); return
        s.stack.pop()
p = P(); p.feed(open(sys.argv[1], encoding="utf-8").read())
sys.exit(1 if p.err or p.stack else 0)
PY

echo "▶ Conservation des rapports (--keep)"
for i in 1 2 3 4 5 6; do touch "$OUT/rapport-nas-demo-2025010$i-1200".{html,txt,json}; done
PATH="$ROOT/tests/mock/bin:$PATH" bash "$SCRIPT" -o "$OUT" --no-color --quick --keep 3 >/dev/null 2>&1
n=$(ls "$OUT"/rapport-*-[0-9]*.html | wc -l)
[[ $n == 3 ]] && ok "seuls les 3 rapports les plus récents sont conservés" || ko "$n rapports conservés au lieu de 3"

echo "▶ Interface web"
if python3 "$ROOT/tests/test_web.py" > "$TMP/web.txt" 2>&1; then ok "tests de l'interface web ($(grep -oE 'Ran [0-9]+ tests' "$TMP/web.txt"))"
else ko "tests de l'interface web"; tail -n 25 "$TMP/web.txt"; fi
for f in "$ROOT"/install.sh "$ROOT"/uninstall.sh "$ROOT"/systemd/audite-moi-run "$SCRIPT"; do bash -n "$f" || ko "syntaxe : $f"; done
if command -v shellcheck >/dev/null; then
  shellcheck -S warning "$SCRIPT" "$ROOT/install.sh" "$ROOT/uninstall.sh" "$ROOT/systemd/audite-moi-run" && ok "shellcheck sans avertissement" || ko "shellcheck"
fi

if [[ ${1:-} == --reel ]]; then
  echo "▶ Exécution réelle sur cette machine (sans simulation)"
  bash "$SCRIPT" -o "$TMP/reel" --no-color --quick > "$TMP/reel.txt" 2> "$TMP/reel.err"
  rc=$?
  ((rc <= 2)) && ok "exécution réelle terminée (code $rc)" || ko "exécution réelle : code $rc"
  [[ -s $TMP/reel.err ]] && { ko "erreurs :"; head -20 "$TMP/reel.err"; } || ok "aucune erreur sur la sortie d'erreur"
fi

[[ -n ${GARDER:-} ]] && { cp -r "$OUT" "$GARDER"; echo "Rapports copiés dans $GARDER"; }
echo
if ((fail)); then echo "Des tests ont échoué."; exit 1; fi
echo "Tous les tests sont passés."
