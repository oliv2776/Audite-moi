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
cat > "$TMP/audit.conf" <<'EOC'
# configuration de test
EXTERNE=oui
DOMAINES_EXTRA="nc.exemple.fr direct.exemple.fr"
OPNSENSE_URL=https://192.168.1.1/
OPNSENSE_KEY=clef-api
OPNSENSE_SECRET="secret+/="
SCAN_RESEAU=oui
EOC
chmod 644 "$TMP/audit.conf"
mkdir -p "$OUT" && printf '00:0d:b9:11:22:33\t192.168.1.1\trouteur.maison\tPC Engines\n' > "$OUT/.inventaire-reseau"
PATH="$ROOT/tests/mock/bin:$PATH" bash "$SCRIPT" -o "$OUT" --config "$TMP/audit.conf" --no-color --keep 5 > "$TMP/sortie.txt" 2> "$TMP/erreurs.txt"
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
expect WARN "Entrée en double dans /etc/fstab (mnt-data.mount"
expect WARN "OOM killer"
expect OK   "iGPU Intel opérationnel"
expect OK   "GPU AMD opérationnel"
expect OK   "VA-API (AMD) : encodage matériel disponible"
jq -e '.constats[] | select(.titre | contains("Erreurs du pilote AMD"))' "$J" >/dev/null && ko "fausse alerte « Erreurs du pilote AMD »" || ok "pas de fausse alerte sur le firmware AMD"
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
# Vu d'Internet
expect OK   "cloud.exemple.fr protégé par Cloudflare Access"
expect CRIT "direct.exemple.fr pointe directement sur votre box"
expect CRIT "films.exemple.fr expose un fichier sensible : /.git/HEAD"
expect CRIT "Stash est accessible sans mot de passe depuis Internet"
expect WARN "Nextcloud 29.0.3 : correctifs disponibles (29.0.16)"
expect WARN "Votre IP personnelle est publiée dans le DNS (maison.exemple.fr"
expect INFO "films.exemple.fr accepte TLS 1.0/1.1"
# Applications
expect CRIT "Nextcloud : compte(s) administrateur sans double authentification : admin"
expect WARN "Nextcloud : 2 lien(s) de partage public(s) sans mot de passe"
expect WARN "Nextcloud ne voit pas les vraies adresses IP"
expect WARN "Nextcloud : mode debug activé"
expect WARN "Nextcloud signale des erreurs de configuration"
expect CRIT "Stash (stash) n'a ni identifiant ni mot de passe"
expect WARN "Stash a détecté un accès depuis Internet"
# OPNsense
expect WARN "audit.conf est lisible par d'autres comptes"
expect WARN "OPNsense 25.7.3 : mises à jour disponibles"
expect CRIT "Port 2222/tcp ouvert sur Internet → 192.168.1.10:22 (ce NAS) (SSH)"
expect WARN "Port 32400/tcp ouvert sur Internet"
expect CRIT "Le routeur lui-même est accessible depuis Internet (port 443)"
expect INFO "Port VPN ouvert sur le WAN : udp 51820"
expect WARN "UPnP activé sur le routeur"
expect WARN "SSH d'OPNsense : connexion root autorisée"
jq -e '.constats[] | select(.titre | contains("8080/tcp"))' "$J" >/dev/null && ko "une redirection désactivée est signalée" || ok "redirection désactivée ignorée"
# Réseau local
expect INFO "Réseaux trop grands ignorés : 10.30.0.0/16"
expect INFO "4 appareil(s) trouvé(s) sur 192.168.1.0/24 192.168.20.0/24"
expect CRIT "API Docker sans TLS ouverte sur le réseau : 192.168.1.30"
expect WARN "Services risqués sur d'autres appareils du réseau"
expect INFO "Nouveaux appareils depuis le dernier scan : 3"
grep -qE 'SECRETHASH|SECRETWG|secret\+/=' "$OUT"/rapport-* && ko "un secret d'OPNsense apparaît dans le rapport" || ok "aucun secret d'OPNsense dans les rapports"

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

echo "▶ Relevé des disques et des pools (page Matériel)"
M=$TMP/mesures.json; touch "$TMP/dem-mesurer"
releve() { PATH="$ROOT/tests/mock/bin:$PATH" python3 "$ROOT/systemd/audite-moi-mesures" --sortie "$M" --demande "$TMP/dem-mesurer" --groupe root; }
verifie() {   # verifie "description" 'expression jq'
  if jq -e "$2" "$M" >/dev/null 2>&1; then ok "$1"; else ko "$1"; fi
}
releve && ok "relevé produit" || ko "le relevé a échoué"
[[ -e $TMP/dem-mesurer ]] && ko "la demande de mesure n'a pas été effacée" || ok "demande de mesure effacée (pas de boucle)"
[[ $(stat -c %a "$M") == 640 ]] && ok "relevé en mode 640" || ko "droits du relevé : $(stat -c %a "$M")"
verifie "pool rapide : SSD en miroir, 83 % rempli" '.pools[] | select(.nom == "rapide" and .type == "SSD" and .disposition == "mirror" and .remplissage == 83)'
verifie "pool stockage : HDD en RAIDZ1, espace utilisable" '.pools[] | select(.nom == "stockage" and .type == "HDD" and .disposition == "raidz1" and .libre == 10557207691264)'
verifie "jeux de données sans les couches Docker" '[.pools[] | select(.nom == "rapide") | .jeux[].nom] == ["nextcloud", "docker"]'
verifie "nvme0 : cache du pool stockage" '.disques[] | select(.nom == "nvme0" and .role == "cache" and .pool == "stockage" and .usure == 4)'
verifie "sdd à surveiller (secteurs réalloués, CRC en hausse, erreurs ZFS)" '.disques[] | select(.nom == "sdd" and .etat == "attention" and (.raisons | length) == 3)'
verifie "SSD : usure lue (sda 9 %)" '.disques[] | select(.nom == "sda" and .etat == "ok" and .usure == 9)'
jq '(.disques[] | select(.nom == "sdd") | .crc_hausse) = 1000' "$M" > "$M.t" && mv "$M.t" "$M"
releve; verifie "erreurs CRC anciennes et stables : simple note" '.disques[] | select(.nom == "sdd" and (.note | test("stables")) and (.raisons | length) == 2)'
AUDITE_MOI_VEILLE=sdc releve
verifie "disque en veille : pas réveillé, dernières valeurs gardées" '.disques[] | select(.nom == "sdc" and .veille == true and .temperature == 38 and .etat == "veille")'

echo "▶ Interface web"
if python3 "$ROOT/tests/test_web.py" > "$TMP/web.txt" 2>&1; then ok "tests de l'interface web ($(grep -oE 'Ran [0-9]+ tests' "$TMP/web.txt"))"
else ko "tests de l'interface web"; tail -n 25 "$TMP/web.txt"; fi
for f in "$ROOT"/install.sh "$ROOT"/uninstall.sh "$ROOT"/systemd/audite-moi-run "$SCRIPT"; do bash -n "$f" || ko "syntaxe : $f"; done
python3 -c "import ast,sys; [ast.parse(open(f).read(), f) for f in sys.argv[1:]]" "$ROOT/systemd/audite-moi-mesures" "$ROOT/web/audite-moi-web.py" && ok "syntaxe Python" || ko "syntaxe Python"
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
