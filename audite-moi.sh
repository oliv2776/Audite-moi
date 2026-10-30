#!/usr/bin/env bash
# shellcheck disable=SC1112,SC2155,SC2174,SC2034  # (SC2034 : champs lus mais volontairement ignorés)
# =============================================================================
#  Audite-moi — bilan de santé et audit de sécurité d'un NAS Ubuntu
#               (pools ZFS, Docker, GPU / transcodage, tunnels Cloudflare)
#
#  Utilisation : sudo ./audite-moi.sh [options]          (aide : --help)
#
#  • Lecture seule : rien n'est modifié sur le système, sauf si vous demandez
#    explicitement --install-deps ou --apt-update.
#  • Produit un rapport HTML (à ouvrir dans un navigateur), un rapport texte et
#    un résumé JSON (utilisé par l'interface web). Ils décrivent en détail votre
#    serveur et ses faiblesses : ils ne sont lisibles que par vous.
#  • Code de sortie : 0 = rien à signaler, 1 = avertissements,
#    2 = problèmes critiques, 3 = erreur d'exécution.
#
#  https://github.com/oliv2776/Audite-moi
# =============================================================================

VERSION="1.1.0"
PROG=${0##*/}
NL=$'\n'
TAB=$'\t'
US=$'\x1f'      # séparateur de champs interne (contrairement à la tabulation, ne fusionne pas les champs vides)
RS=$'\x1e'

if locale -a 2>/dev/null | grep -qiE '^c\.utf-?8$'; then export LC_ALL=C.UTF-8; else export LC_ALL=C; fi
umask 077

SHARED_DIR=/var/lib/audite-moi/rapports   # dossier commun créé par install.sh (interface web)
SHARED_GROUP=audite-moi

# ------------------------------------------------------------------- options --
CONF_FILE=/etc/audite-moi/audit.conf
OUTDIR="" OUTGROUP="" KEEP=0 QUICK=0 NO_WAKE=0 APT_UPDATE=0 INSTALL_DEPS=0 USE_COLOR=1

usage() {
  cat <<EOF
$PROG $VERSION — bilan de santé et audit de sécurité d'un NAS Ubuntu
(pools ZFS, Docker, GPU / transcodage, tunnels Cloudflare)

Utilisation : sudo $PROG [options]

  -o, --output DIR   dossier des rapports (défaut : $SHARED_DIR si
                     l'interface web est installée, sinon ~/audite-moi de
                     l'utilisateur qui lance sudo)
  -q, --quick        mode rapide : sans Lynis, Trivy, rkhunter, scan du réseau
                     local, recherche des fichiers SUID ni vérifications à
                     l'intérieur des conteneurs
      --no-wake      ne réveille pas les disques en veille pour lire SMART
      --apt-update   rafraîchit la liste des paquets (apt-get update) avant l'audit
      --install-deps installe les outils utiles : jq, smartmontools, lynis,
                     vainfo, pciutils, curl, nmap (+ intel-gpu-tools si iGPU Intel)
      --group GROUPE rend les rapports lisibles par ce groupe (droits 640)
      --keep N       ne conserve que les N rapports les plus récents
      --config FICHIER  réglages des modules réseau (défaut : $CONF_FILE) :
                     test depuis Internet, clé API OPNsense, scan du réseau local
      --no-color     sortie sans couleurs
  -h, --help         affiche cette aide

Rien n'est modifié sur le système (hors --install-deps et --apt-update).
Code de sortie : 0 = RAS, 1 = avertissements, 2 = critiques, 3 = erreur.
EOF
}

while (($#)); do
  case $1 in
    -o|--output)
      [[ -n ${2:-} ]] || { echo "L'option $1 attend un dossier." >&2; exit 3; }
      OUTDIR=$2; shift 2 ;;
    --output=*)     OUTDIR=${1#*=}; shift ;;
    --group)        [[ -n ${2:-} ]] || { echo "L'option --group attend un nom de groupe." >&2; exit 3; }
                    OUTGROUP=$2; shift 2 ;;
    --keep)         [[ ${2:-} =~ ^[0-9]+$ ]] || { echo "L'option --keep attend un nombre." >&2; exit 3; }
                    KEEP=$2; shift 2 ;;
    --config)       [[ -n ${2:-} ]] || { echo "L'option --config attend un fichier." >&2; exit 3; }
                    CONF_FILE=$2; shift 2 ;;
    -q|--quick)     QUICK=1; shift ;;
    --no-wake)      NO_WAKE=1; shift ;;
    --apt-update)   APT_UPDATE=1; shift ;;
    --install-deps) INSTALL_DEPS=1; shift ;;
    --no-color)     USE_COLOR=0; shift ;;
    -h|--help)      usage; exit 0 ;;
    -V|--version)   echo "$VERSION"; exit 0 ;;
    *) echo "Option inconnue : $1" >&2; usage >&2; exit 3 ;;
  esac
done

[[ -t 1 ]] || USE_COLOR=0
if ((USE_COLOR)); then
  C_R=$'\e[1;31m' C_Y=$'\e[1;33m' C_G=$'\e[32m' C_B=$'\e[36m' C_D=$'\e[2m' C_BOLD=$'\e[1m' C_0=$'\e[0m'
else
  C_R="" C_Y="" C_G="" C_B="" C_D="" C_BOLD="" C_0=""
fi

if ((EUID != 0)); then
  echo "Ce script doit être lancé en root (lecture de SMART, ZFS, Docker, /etc/shadow…) :" >&2
  echo "  sudo $0 $*" >&2
  exit 3
fi

# Chemins système (surchargeables par variables d'environnement, utile pour les tests)
DRI_DIR=${AUDITE_MOI_DRI_DIR:-/dev/dri}
DRM_CLASS=${AUDITE_MOI_DRM_CLASS:-/sys/class/drm}
ARCSTATS=${AUDITE_MOI_ARCSTATS:-/proc/spl/kstat/zfs/arcstats}
SMB_CONF=${AUDITE_MOI_SMB_CONF:-/etc/samba/smb.conf}
SYS_BLOCK=${AUDITE_MOI_SYS_BLOCK:-/sys/block}

WORK=$(mktemp -d "${TMPDIR:-/tmp}/audite-moi.XXXXXX") || { echo "mktemp a échoué" >&2; exit 3; }
trap 'rm -rf "$WORK"' EXIT
trap 'echo >&2; echo "Interrompu." >&2; exit 130' INT TERM

# -------------------------------------------------------------------- outils --
have()   { command -v "$1" >/dev/null 2>&1; }
tmo()    { local t=$1; shift; timeout -k 5 "$t" "$@"; }
isint()  { [[ ${1:-} =~ ^-?[0-9]+$ ]]; }
note()   { printf '  %s%s%s\n' "$C_D" "$*" "$C_0"; }
nlines() { grep -c . <<< "${1:-}"; }
NOW=$(date +%s)
days_ago() { local t; t=$(date -d "$1" +%s 2>/dev/null) || return 1; echo $(( (NOW - t) / 86400 )); }
hbytes() {
  if isint "${1:-}"; then numfmt --to=iec-i --suffix=o --format='%.1f' "$1" 2>/dev/null || printf '%s o' "$1"
  else printf '%s' "${1:--}"; fi
}
join_list() { local sep=$1 out="" x; shift; for x in "$@"; do [[ -n $x ]] && out+="${out:+$sep}$x"; done; printf '%s' "$out"; }
sev()   { case $1 in CRIT) echo 3 ;; WARN) echo 2 ;; INFO) echo 1 ;; *) echo 0 ;; esac; }
worst() { if (( $(sev "$1") >= $(sev "$2") )); then echo "$1"; else echo "$2"; fi; }
kv()    { awk -v k="$2" '$1 == k { $1 = ""; sub(/^ /, ""); print; exit }' <<< "$1"; }
is_private_ip() {
  local ip=${1,,} o
  case $ip in
    10.*|192.168.*|127.*|169.254.*|::1|fe80:*|fc*|fd*) return 0 ;;
    172.*) o=${ip#172.}; o=${o%%.*}; isint "$o" && ((o >= 16 && o <= 31)) && return 0 ;;
    100.*) o=${ip#100.}; o=${o%%.*}; isint "$o" && ((o >= 64 && o <= 127)) && return 0 ;;
  esac
  return 1
}
# Première adresse IP de chaque ligne de journal (IPv4 ou IPv6)
extract_ip() {
  awk '{ for (i = 1; i <= NF; i++) { f = $i; sub(/^rhost=/, "", f)
         if (f ~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/ || (f ~ /^[0-9a-fA-F:]+$/ && f ~ /:.*:/ && f !~ /^[0-9]+:[0-9]+:[0-9]+$/)) { print f; break } } }'
}
# Masque les secrets (jetons, mots de passe) dans les données brutes du rapport
sanitize() {
  sed -E \
    -e 's/(eyJ[A-Za-z0-9_-]{6})[A-Za-z0-9_=.+\/-]{20,}/\1…[masqué]/g' \
    -e 's/((pass(word|wd)?|secret|token|api[_-]?key|private[_-]?key)[A-Za-z0-9_]*["'\'']?[[:space:]]*[=:][[:space:]]*["'\'']?)[^[:space:]"'\'',;}]+/\1***/Ig'
}

# ---------------------------------------------------------------- résultats --
declare -a R_SEC=() R_LVL=() R_TTL=() R_MSG=() R_FIX=()   # constats
declare -a T_SEC=() T_TTL=() T_FILE=()                    # tableaux
declare -a X_SEC=() X_TTL=() X_FILE=()                    # données brutes
CUR="" SEC_N=0

SEC_ORDER=(systeme materiel disques zfs docker gpu reseau sauvegardes cloudflare exposition applis opnsense lan maj comptes ssh parefeu dockersec fichiers noyau journaux outils)
declare -A SEC_TITLE=(
  [systeme]="Système" [materiel]="Matériel : processeur, mémoire, températures, onduleur"
  [disques]="Disques (SMART)" [zfs]="Pools ZFS" [docker]="Docker : état des conteneurs"
  [gpu]="GPU et transcodage" [reseau]="Réseau" [sauvegardes]="Sauvegardes et snapshots"
  [cloudflare]="Exposition Internet : tunnels Cloudflare" [exposition]="Vu d'Internet : services publiés"
  [applis]="Applications exposées : Nextcloud et Stash" [opnsense]="Routeur OPNsense" [lan]="Réseau local (scan)"
  [maj]="Mises à jour"
  [comptes]="Comptes et privilèges" [ssh]="SSH" [parefeu]="Pare-feu et services réseau"
  [dockersec]="Sécurité Docker" [fichiers]="Fichiers, permissions et intégrité"
  [noyau]="Noyau et durcissement" [journaux]="Journaux et détection d'intrusion"
  [outils]="Analyses complémentaires (Lynis, Trivy, rkhunter)"
)
declare -A SEC_SHORT=(
  [systeme]="Système" [materiel]="Matériel" [disques]="Disques" [zfs]="ZFS" [docker]="Docker"
  [gpu]="GPU" [reseau]="Réseau" [sauvegardes]="Sauvegardes" [cloudflare]="Cloudflare"
  [exposition]="Vu d'Internet" [applis]="Applications" [opnsense]="OPNsense" [lan]="Réseau local" [maj]="Mises à jour" [comptes]="Comptes" [ssh]="SSH" [parefeu]="Pare-feu"
  [dockersec]="Sécurité Docker" [fichiers]="Fichiers" [noyau]="Noyau" [journaux]="Journaux" [outils]="Analyses"
)
declare -A SEC_CAT=(
  [systeme]=sante [materiel]=sante [disques]=sante [zfs]=sante [docker]=sante [gpu]=sante
  [reseau]=sante [sauvegardes]=sante [cloudflare]=secu [exposition]=secu [applis]=secu [opnsense]=secu [lan]=secu [maj]=secu [comptes]=secu [ssh]=secu
  [parefeu]=secu [dockersec]=secu [fichiers]=secu [noyau]=secu [journaux]=secu [outils]=secu
)
declare -A LVL_FR=([CRIT]="Critique" [WARN]="Attention" [OK]="OK" [INFO]="Info")

section() {
  CUR=$1; SEC_N=$((SEC_N + 1))
  printf '\n%s[%d/%d] %s%s\n' "$C_BOLD" "$SEC_N" "${#SEC_ORDER[@]}" "${SEC_TITLE[$1]}" "$C_0"
}

add() {   # add NIVEAU "titre" ["détail"] ["correctif"]   (le texte entre `…` est affiché comme du code)
  local lvl=$1 ttl=$2 msg=${3:-} fix=${4:-} c tag first
  R_SEC+=("$CUR"); R_LVL+=("$lvl"); R_TTL+=("$ttl"); R_MSG+=("$msg"); R_FIX+=("$fix")
  case $lvl in
    CRIT) c=$C_R tag="CRIT" ;; WARN) c=$C_Y tag="WARN" ;; OK) c=$C_G tag=" OK " ;; *) c=$C_B tag="INFO" ;;
  esac
  first=${msg%%"$NL"*}
  ((${#first} > 100)) && first="${first:0:97}…"
  if [[ -n $first ]]; then printf '  %s[%s]%s %s %s— %s%s\n' "$c" "$tag" "$C_0" "$ttl" "$C_D" "$first" "$C_0"
  else printf '  %s[%s]%s %s\n' "$c" "$tag" "$C_0" "$ttl"; fi
}
ok()   { add OK   "$@"; }
info() { add INFO "$@"; }
warn() { add WARN "$@"; }
crit() { add CRIT "$@"; }

cap_file() {   # limite la taille des données brutes
  local f=$1 max=${2:-400} n
  n=$(wc -l < "$f")
  if ((n > max)); then
    { head -n $((max / 2)) "$f"; echo "[… $((n - max)) lignes masquées …]"; tail -n $((max / 2)) "$f"; } > "$f.cut" && mv "$f.cut" "$f"
  fi
}
tbl() {   # tbl "titre" < TSV (1re ligne = en-têtes ; cellule « @OK|@WARN|@CRIT|@INFO texte » = colorée)
  local f="$WORK/t${#T_FILE[@]}.tsv"
  sanitize > "$f"
  (( $(wc -l < "$f") >= 2 )) || return 0
  T_SEC+=("$CUR"); T_TTL+=("$1"); T_FILE+=("$f")
}
raw() {   # raw "titre" ["contenu"]   (sinon lit l'entrée standard)
  local f="$WORK/x${#X_FILE[@]}.txt"
  if (($# >= 2)); then printf '%s\n' "$2" | sanitize > "$f"; else sanitize > "$f"; fi
  grep -q '[^[:space:]]' "$f" 2>/dev/null || return 0
  cap_file "$f"
  X_SEC+=("$CUR"); X_TTL+=("$1"); X_FILE+=("$f")
}
rawcmd() {   # rawcmd "titre" commande args…
  local t=$1; shift
  raw "$t" < <(printf '$ %s\n' "$*"; tmo 60 "$@" 2>&1)
}

# ------------------------------------------------------- informations hôte --
HOST=$(hostname -s 2>/dev/null || hostname)
# shellcheck disable=SC1091
OS_PRETTY=$(. /etc/os-release 2>/dev/null; echo "${PRETTY_NAME:-inconnu}")
# shellcheck disable=SC1091
OS_ID=$(. /etc/os-release 2>/dev/null; echo "${ID:-}")
# shellcheck disable=SC1091
OS_VER=$(. /etc/os-release 2>/dev/null; echo "${VERSION_ID:-}")
# shellcheck disable=SC1091
OS_CODE=$(. /etc/os-release 2>/dev/null; echo "${VERSION_CODENAME:-${UBUNTU_CODENAME:-}}")
KERNEL=$(uname -r)
ARCH=$(uname -m)
CPU_MODEL=$(awk -F': *' '/^model name/ {print $2; exit}' /proc/cpuinfo 2>/dev/null)
NCPU=$(nproc 2>/dev/null || echo 1)
MEM_TOTAL=$(awk '/^MemTotal:/ {printf "%.0f", $2 * 1024}' /proc/meminfo 2>/dev/null)
DATE_FILE=$(date +%Y%m%d-%H%M)
DATE_HUMAN=$(date '+%d/%m/%Y à %H:%M')
START=$NOW

# Variables partagées entre sections
declare -A DISK_POOL=() POOL_MEDIA=() POOL_NVME=() SNAP_COUNT=() SNAP_LAST=()
declare -A EXPOSED=() REACHABLE=() PORTMAP=() CNAMES=() CF_NETMODE=() VIA_PORT=()
declare -a POOLS=() ZFS_MOUNTS=() INGRESS=() PERM_BAD=()
DOCKER_OK=0 SSH_EXPOSED=0 SSH_PASS=0 REBOOT_REQ=0 CF_FOUND=0 CF_NETS="" IPV6_GLOBAL="" TRIM_SCHED=""
ARC_SIZE=0 ARC_MIN=0 ARC_MAX=0 ARC_HITS=0 ARC_MISS=0
INSPECT="$WORK/inspect.json"
echo '[]' > "$INSPECT"

# ------------------------------------------------- dépendances et sortie --
install_pkgs() {
  (($#)) || return 0
  echo "Installation : $*"
  DEBIAN_FRONTEND=noninteractive apt-get update -qq >/dev/null 2>&1
  DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --no-install-recommends "$@" \
    || echo "  (certains paquets n'ont pas pu être installés)" >&2
}

check_deps() {
  local -a pk=()
  if ((INSTALL_DEPS)); then
    have jq       || pk+=(jq)
    have smartctl || pk+=(smartmontools)
    have lynis    || pk+=(lynis)
    have lspci    || pk+=(pciutils)
    have vainfo   || pk+=(vainfo)
    have curl     || pk+=(curl)
    have nmap     || pk+=(nmap)
    have python3  || pk+=(python3)
    if have lspci && lspci 2>/dev/null | grep -Ei 'vga|display|3d' | grep -qi intel && ! have intel_gpu_top; then
      pk+=(intel-gpu-tools)
    fi
    install_pkgs "${pk[@]}"
  elif ! have jq && [[ -t 0 ]]; then
    local a
    read -r -p "jq est nécessaire à ce script. L'installer maintenant (apt) ? [O/n] " a
    [[ $a =~ ^[nN] ]] || install_pkgs jq
  fi
  have jq || { echo "jq est indispensable : sudo apt install jq   (ou relancez avec --install-deps)" >&2; exit 3; }
}

REPORT_OWNER=""
setup_output() {
  if [[ -z $OUTDIR && -d $SHARED_DIR ]]; then
    OUTDIR=$SHARED_DIR
    [[ -z $OUTGROUP ]] && getent group "$SHARED_GROUP" >/dev/null && OUTGROUP=$SHARED_GROUP
  fi
  if [[ -n ${SUDO_USER:-} && $SUDO_USER != root && $OUTDIR != "$SHARED_DIR" ]]; then
    REPORT_OWNER=$SUDO_USER
  fi
  if [[ -z $OUTDIR ]]; then
    local home=""
    [[ -n $REPORT_OWNER ]] && home=$(getent passwd "$REPORT_OWNER" | cut -d: -f6)
    if [[ -n $home && -d $home ]]; then OUTDIR="$home/audite-moi"; else OUTDIR=/var/log/audite-moi; REPORT_OWNER=""; fi
  fi
  if [[ ! -d $OUTDIR ]]; then
    mkdir -p -m 700 "$OUTDIR" || { echo "Impossible de créer $OUTDIR" >&2; exit 3; }
    [[ -n $REPORT_OWNER ]] && chown "$REPORT_OWNER": "$OUTDIR"
  fi
  [[ -w $OUTDIR ]] || { echo "Dossier non accessible en écriture : $OUTDIR" >&2; exit 3; }
  if [[ -n $OUTGROUP ]] && ! getent group "$OUTGROUP" >/dev/null; then
    echo "Groupe inconnu : $OUTGROUP" >&2; exit 3
  fi
}

# -------------------------------------------------------------- préparation --
read_arc() {
  [[ -r $ARCSTATS ]] || return 0
  read -r ARC_SIZE ARC_MIN ARC_MAX ARC_HITS ARC_MISS < <(awk '
    $1 == "size" {s = $3} $1 == "c_min" {n = $3} $1 == "c_max" {m = $3} $1 == "hits" {h = $3} $1 == "misses" {x = $3}
    END {printf "%.0f %.0f %.0f %.0f %.0f\n", s, n, m, h, x}' "$ARCSTATS")
}

zfs_prep() {   # pools, disques membres et type de support (SSD/HDD)
  have zpool || return 0
  mapfile -t POOLS < <(tmo 30 zpool list -H -o name 2>/dev/null)
  local p line dev disk sect rot nrot nssd nnv
  local re_sect=$'^\t(logs|cache|spares|special|dedup)[[:space:]]*$'
  for p in "${POOLS[@]}"; do
    nrot=0 nssd=0 nnv=0 sect=""
    while IFS= read -r line; do
      if [[ $line =~ $re_sect ]]; then sect=${BASH_REMATCH[1]}; continue; fi
      if [[ $line == $'\t'"$p "* || $line == $'\t'"$p"$'\t'* ]]; then sect=data; continue; fi
      [[ -n $sect && $line =~ ^[[:space:]]+(/dev/[^[:space:]]+) ]] || continue
      dev=${BASH_REMATCH[1]}
      disk=$(lsblk -nlspo NAME,TYPE "$dev" 2>/dev/null | awk '$2 == "disk" {print $1; exit}')
      disk=${disk#/dev/}; [[ -n $disk ]] || disk=${dev##*/}
      if [[ $sect == data ]]; then
        DISK_POOL[$disk]=$p
        rot=$(cat "$SYS_BLOCK/$disk/queue/rotational" 2>/dev/null)
        if [[ $rot == 1 ]]; then nrot=$((nrot + 1)); else nssd=$((nssd + 1)); fi
        [[ $disk == nvme* ]] && nnv=$((nnv + 1))
      else
        DISK_POOL[$disk]="$p ($sect)"
      fi
    done < <(tmo 30 zpool status -LP "$p" 2>/dev/null)
    if ((nrot && nssd)); then POOL_MEDIA[$p]="mixte HDD/SSD"
    elif ((nssd)); then POOL_MEDIA[$p]=SSD
    elif ((nrot)); then POOL_MEDIA[$p]=HDD
    else POOL_MEDIA[$p]="?"; fi
    ((nssd > 0 && nnv == nssd && nrot == 0)) && POOL_NVME[$p]=1
  done
}

# ============================================================== SECTIONS ====

check_systeme() {
  section systeme
  local up; up=$(cut -d. -f1 /proc/uptime 2>/dev/null); isint "$up" || up=0
  info "Système" "$OS_PRETTY — noyau $KERNEL ($ARCH) — en marche depuis $((up / 86400)) j $(((up % 86400) / 3600)) h"

  if [[ -f /var/run/reboot-required ]]; then
    REBOOT_REQ=1
    local pk; pk=$(sort -u /var/run/reboot-required.pkgs 2>/dev/null | tr '\n' ' ')
    warn "Redémarrage nécessaire" "Des mises à jour (noyau, bibliothèques…) ne seront actives qu'après un redémarrage.${pk:+ Paquets : $pk}" \
      "Planifiez \`sudo reboot\` — vérifiez d'abord dans la section « Noyau » que les modules ZFS/GPU sont prêts pour le nouveau noyau"
  else
    ok "Aucun redémarrage en attente"
  fi

  if have systemctl; then
    local failed; failed=$(systemctl --failed --no-legend --plain 2>/dev/null | awk '{for (i = 1; i <= NF; i++) if ($i ~ /\./) {print $i; break}}')
    if [[ -n $failed ]]; then
      warn "Service(s) systemd en échec : $(tr '\n' ' ' <<< "$failed")" "$(systemctl --failed --no-legend --plain 2>/dev/null)" \
        "\`systemctl status <service>\` et \`journalctl -u <service> -b\` ; une fois réglé : \`sudo systemctl reset-failed\`"
    else
      ok "Aucun service systemd en échec"
    fi
  fi

  if have timedatectl; then
    case $(timedatectl show -p NTPSynchronized --value 2>/dev/null) in
      yes) ok "Horloge synchronisée (NTP)" ;;
      no)  warn "Horloge non synchronisée" "Une horloge fausse perturbe les journaux, les certificats TLS et les tâches planifiées." \
             "\`sudo timedatectl set-ntp true\` puis \`timedatectl timesync-status\`" ;;
    esac
  fi

  # Espace disque hors ZFS (racine, /boot, /boot/efi…)
  local -a rows=()
  local fs typ size used avail pct mnt lvl nbad=0
  while read -r fs typ size used avail pct mnt; do
    pct=${pct%\%}
    isint "$pct" && isint "$avail" || continue
    lvl=OK; ((pct >= 85)) && lvl=WARN; ((pct >= 95)) && lvl=CRIT
    if [[ $lvl != OK ]]; then
      nbad=$((nbad + 1))
      add "$lvl" "Espace disque : $mnt rempli à $pct %" "$fs ($typ) — reste $(hbytes $((avail * 1024)))." \
        "Repérez les gros dossiers : \`sudo du -xh --max-depth=2 $mnt | sort -h | tail -20\` ; pour /boot : \`sudo apt autoremove --purge\`"
    fi
    rows+=("$mnt$TAB$fs$TAB$typ$TAB$(hbytes $((size * 1024)))$TAB$(hbytes $((avail * 1024)))$TAB@$lvl $pct %")
  done < <(df -PT -x tmpfs -x devtmpfs -x squashfs -x overlay -x zfs -x efivarfs -x nsfs -x fuse.snapfuse 2>/dev/null | tail -n +2)
  local ino; ino=$(df -Pi -x tmpfs -x devtmpfs -x squashfs -x overlay -x zfs -x efivarfs -x nsfs 2>/dev/null \
    | awk 'NR > 1 {u = $5; sub(/%/, "", u); if (u + 0 >= 90) print $6 " (" $5 ")"}')
  if [[ -n $ino ]]; then
    nbad=$((nbad + 1))
    warn "Inodes presque épuisés" "$ino" "Trop de petits fichiers (caches, journaux) : repérez le dossier en cause avec \`sudo du -x --inodes --max-depth=2 / | sort -n | tail\`"
  fi
  ((nbad == 0 && ${#rows[@]} > 0)) && ok "Espace disque suffisant (systèmes de fichiers hors ZFS)"
  ((${#rows[@]})) && tbl "Systèmes de fichiers hors ZFS" < <(printf 'Point de montage\tPériphérique\tType\tTaille\tLibre\tUtilisation\n'; printf '%s\n' "${rows[@]}")

  if have journalctl; then
    local ju; ju=$(journalctl --disk-usage 2>/dev/null | grep -oE '[0-9.]+[KMGT]?B?' | head -n 1)
    [[ -n $ju ]] && info "Taille des journaux systemd : $ju"
    local kerr; kerr=$(tmo 30 journalctl -k -p err --since "24 hours ago" --no-pager -q 2>/dev/null)
    local pat='I/O error|blk_update_request|Buffer I/O error|critical medium error|ata[0-9.]+: (exception|failed command|SError)|nvme[0-9]+.*(timeout|Abort|reset|controller is down)|EXT4-fs error|XFS .*(error|corrupt)|Hardware Error|Machine check|mce: |soft lockup|hung_task|blocked for more than|BUG:|Oops'
    local hits; hits=$(grep -E "$pat" <<< "$kerr" | tail -n 12)
    local fst; fst=$(grep -oE "Duplicate entry in '/etc/fstab'|Failed to create unit file '[^']+'" <<< "$kerr" | grep -oE "/run/systemd/generator/[^']+" | sort -u | sed 's|.*/||' | tr '\n' ' ')
    [[ -n $fst ]] && warn "Entrée en double dans /etc/fstab ($fst)" "systemd signale le même point de montage deux fois (à chaque rechargement) : au démarrage, le montage peut échouer ou masquer l'autre entrée." \
      "Repérez le doublon : \`grep -v '^#' /etc/fstab\`, supprimez une des deux lignes (gardez celle avec UUID=…), puis \`sudo systemctl daemon-reload && sudo mount -a\`"
    if [[ -n $hits ]]; then
      warn "Erreurs matérielles ou système dans le journal du noyau (24 h)" "$hits" \
        "Croisez avec la section « Disques (SMART) » ; détail : \`journalctl -k -p err --since '24 hours ago'\`"
    elif [[ -n $kerr ]]; then
      info "$(nlines "$kerr") message(s) d'erreur du noyau (24 h)" "$(tail -n 5 <<< "$kerr")"
    else
      ok "Aucune erreur dans le journal du noyau (24 h)"
    fi
    raw "Erreurs du noyau (24 h)" "$kerr"
  fi
}

check_materiel() {
  section materiel
  info "Processeur" "${CPU_MODEL:-inconnu} — $NCPU cœurs logiques"

  local l1 l5 l15 ratio
  read -r l1 l5 l15 _ < /proc/loadavg
  ratio=$(awk -v l="$l15" -v n="$NCPU" 'BEGIN {printf "%.2f", l / n}')
  if awk -v r="$ratio" 'BEGIN {exit !(r > 2)}'; then
    warn "Charge système très élevée" "Charge moyenne (1/5/15 min) : $l1 / $l5 / $l15 pour $NCPU cœurs." \
      "Identifiez les processus : \`top\` ou \`htop\` (un transcodage logiciel ou un scrub peuvent l'expliquer)"
  elif awk -v r="$ratio" 'BEGIN {exit !(r > 1)}'; then
    info "Charge système élevée" "Charge moyenne : $l1 / $l5 / $l15 pour $NCPU cœurs."
  else
    ok "Charge système normale" "Charge moyenne : $l1 / $l5 / $l15 pour $NCPU cœurs."
  fi
  if have vmstat; then
    local wa; wa=$(vmstat 1 2 2>/dev/null | tail -n 1 | awk '{print $16}')
    isint "$wa" && ((wa >= 20)) && warn "Attente d'entrées/sorties élevée ($wa %)" "Le processeur attend souvent les disques." "\`sudo iotop -o\` ou \`zpool iostat -v 2\`"
  fi

  # Mémoire (le cache ARC de ZFS apparaît comme « utilisé » mais se libère à la demande)
  local mt ma st sf
  mt=$(awk '/^MemTotal:/ {printf "%.0f", $2 * 1024}' /proc/meminfo)
  ma=$(awk '/^MemAvailable:/ {printf "%.0f", $2 * 1024}' /proc/meminfo)
  st=$(awk '/^SwapTotal:/ {printf "%.0f", $2 * 1024}' /proc/meminfo)
  sf=$(awk '/^SwapFree:/ {printf "%.0f", $2 * 1024}' /proc/meminfo)
  if isint "$mt" && ((mt > 0)) && isint "$ma"; then
    local reclaim=$(( ARC_SIZE > ARC_MIN ? ARC_SIZE - ARC_MIN : 0 ))
    local eff=$(( ma + reclaim )); ((eff > mt)) && eff=$mt
    local pct=$(( 100 - eff * 100 / mt ))
    local msg="Utilisée : $(hbytes $((mt - ma))) sur $(hbytes "$mt")"
    ((ARC_SIZE > 0)) && msg+=" (dont cache ZFS ARC : $(hbytes "$ARC_SIZE"), libérable à la demande)"
    msg+="${NL}Pression mémoire réelle (hors cache libérable) : $pct %"
    if ((pct >= 95)); then
      crit "Mémoire saturée ($pct %)" "$msg" "Repérez les conteneurs gourmands (\`docker stats\`), limitez l'ARC (\`zfs_arc_max\`) ou ajoutez de la RAM"
    elif ((pct >= 90)); then
      warn "Mémoire presque saturée ($pct %)" "$msg" "Repérez les conteneurs gourmands (\`docker stats\`) et fixez-leur une limite mémoire"
    else
      ok "Mémoire : pression de $pct %" "$msg"
    fi
  fi
  if isint "$st" && ((st > 0)); then
    local sp=$(( (st - sf) * 100 / st ))
    if ((sp >= 80)); then
      warn "Swap utilisé à $sp %" "$(hbytes $((st - sf))) sur $(hbytes "$st") : le serveur manque de mémoire." "Identifiez les processus gourmands : \`sudo smem -rs swap\` ou \`top\` (tri par mémoire)"
    else
      info "Swap utilisé à $sp %" "$(hbytes $((st - sf))) sur $(hbytes "$st")"
    fi
  else
    info "Pas de swap configuré" "Sans swap, un pic de mémoire déclenche directement l'OOM killer."
  fi
  if have journalctl; then
    local oom; oom=$(tmo 30 journalctl -k --since "7 days ago" --no-pager -q 2>/dev/null | grep -E 'Out of memory|oom-kill|invoked oom-killer')
    if [[ -n $oom ]]; then
      local victims; victims=$(grep -oE 'Killed process [0-9]+ \([^)]+\)' <<< "$oom" | sed -E 's/.*\((.*)\)/\1/' | sort | uniq -c | sort -rn | awk '{printf "%s (%d×) ", $2, $1}')
      warn "Manque de mémoire : l'OOM killer est intervenu (7 jours)" "Processus tués : ${victims:-voir le journal du noyau}" \
        "Fixez une limite mémoire aux conteneurs gourmands (\`mem_limit\`), réduisez \`zfs_arc_max\` ou ajoutez de la RAM"
    fi
  fi

  # Températures (capteurs hwmon)
  local -a rows=()
  local h name t lbl v cr cpu=-1
  for h in /sys/class/hwmon/hwmon*; do
    [[ -r $h/name ]] || continue
    name=$(cat "$h/name" 2>/dev/null)
    for t in "$h"/temp*_input; do
      [[ -r $t ]] || continue
      v=$(cat "$t" 2>/dev/null); isint "$v" || continue; v=$((v / 1000))
      lbl=$(cat "${t%_input}_label" 2>/dev/null) || lbl=${t##*/}; lbl=${lbl%_input}
      cr=$(cat "${t%_input}_crit" 2>/dev/null); if isint "$cr"; then cr="$((cr / 1000)) °C"; else cr=""; fi
      rows+=("$name$TAB$lbl$TAB$v °C$TAB$cr")
      case $name in coretemp|k10temp|zenpower|cpu_thermal) ((v > cpu)) && cpu=$v ;; esac
    done
  done
  if ((cpu < 0)); then
    local z
    for z in /sys/class/thermal/thermal_zone*; do
      [[ $(cat "$z/type" 2>/dev/null) == x86_pkg_temp ]] || continue
      v=$(cat "$z/temp" 2>/dev/null); isint "$v" && ((v / 1000 > cpu)) && cpu=$((v / 1000))
    done
  fi
  if ((cpu >= 90)); then
    crit "Processeur très chaud : $cpu °C" "Risque de bridage et d'usure prématurée." "Vérifiez ventilateurs, poussière et pâte thermique ; un transcodage logiciel prolongé chauffe beaucoup le CPU"
  elif ((cpu >= 80)); then
    warn "Processeur chaud : $cpu °C" "Normal pendant un transcodage intensif, anormal au repos." "Vérifiez la ventilation du boîtier"
  elif ((cpu >= 0)); then
    ok "Température du processeur : $cpu °C"
  else
    info "Température du processeur non disponible" "Aucun capteur coretemp/k10temp trouvé." "Installez \`lm-sensors\` puis \`sudo sensors-detect\`"
  fi
  ((${#rows[@]})) && tbl "Capteurs de température" < <(printf 'Capteur\tSonde\tTempérature\tSeuil critique\n'; printf '%s\n' "${rows[@]}")

  # Mémoire ECC
  if compgen -G "/sys/devices/system/edac/mc/mc*" >/dev/null; then
    local ce ue
    ce=$(cat /sys/devices/system/edac/mc/mc*/ce_count 2>/dev/null | awk '{s += $1} END {print s + 0}')
    ue=$(cat /sys/devices/system/edac/mc/mc*/ue_count 2>/dev/null | awk '{s += $1} END {print s + 0}')
    if ((ue > 0)); then
      crit "Erreurs mémoire ECC non corrigibles : $ue" "Une barrette est défaillante : risque de corruption de données." "Identifiez la barrette : \`grep . /sys/devices/system/edac/mc/mc*/dimm*/dimm_ue_count\`, puis remplacez-la"
    elif ((ce > 0)); then
      warn "Erreurs mémoire ECC corrigées : $ce" "L'ECC a corrigé des erreurs : une barrette commence peut-être à faiblir." "Identifiez-la : \`grep . /sys/devices/system/edac/mc/mc*/dimm*/dimm_ce_count\`"
    else
      ok "Mémoire ECC : aucune erreur"
    fi
  else
    info "Pas de surveillance ECC (EDAC)" "Mémoire non-ECC ou pilote EDAC non chargé."
  fi

  # Onduleur
  if have upsc; then
    local u d s c r found=0
    for u in $(tmo 10 upsc -l 2>/dev/null); do
      found=1
      d=$(tmo 10 upsc "$u" 2>/dev/null)
      s=$(awk -F': ' '$1 == "ups.status" {print $2}' <<< "$d")
      c=$(awk -F': ' '$1 == "battery.charge" {print $2}' <<< "$d")
      r=$(awk -F': ' '$1 == "battery.runtime" {print $2}' <<< "$d"); r=${r%.*}; isint "$r" || r=0
      local m="État : ${s:-?}, charge : ${c:-?} %, autonomie : $((r / 60)) min"
      case " $s " in
        *" LB "*) crit "Onduleur $u : batterie faible" "$m" "Le NAS doit s'arrêter proprement : vérifiez la configuration de NUT (upsmon)" ;;
        *" OB "*) warn "Onduleur $u : sur batterie (coupure secteur)" "$m" ;;
        *" RB "*) warn "Onduleur $u : batterie à remplacer" "$m" "Commandez une batterie de remplacement" ;;
        *" OL "*) ok "Onduleur $u en ligne" "$m" ;;
        *) info "Onduleur $u" "$m" ;;
      esac
    done
    ((found)) || info "NUT installé mais aucun onduleur déclaré" "" "Déclarez l'onduleur dans /etc/nut/ups.conf"
  elif have apcaccess; then
    local a s; a=$(tmo 10 apcaccess status 2>/dev/null)
    s=$(awk -F': ' '/^STATUS/ {gsub(/ +$/, "", $2); print $2}' <<< "$a")
    case $s in
      ONLINE*) ok "Onduleur en ligne (apcupsd)" "$(grep -E '^(BCHARGE|TIMELEFT)' <<< "$a" | tr -s ' ' | tr '\n' ' ')" ;;
      ONBATT*) warn "Onduleur sur batterie (apcupsd)" "$(grep -E '^(BCHARGE|TIMELEFT)' <<< "$a" | tr -s ' ' | tr '\n' ' ')" ;;
      *) info "Onduleur (apcupsd) : ${s:-état inconnu}" ;;
    esac
  else
    info "Aucun onduleur supervisé" "Ni NUT ni apcupsd n'est installé." \
      "Avec un onduleur USB, NUT (\`sudo apt install nut\`) permet d'arrêter proprement le NAS avant l'épuisement de la batterie"
  fi
}

JQ_SMART='
def attr($id): ((.ata_smart_attributes.table // []) | map(select(.id == $id)) | first);
def rawv($id): (attr($id) | if . == null then "" else (.raw.value | tostring) end);
def normv($id): (attr($id) | if . == null then null else .value end);
def st: ((.ata_smart_self_test_log.standard.table // .nvme_self_test_log.table // [])[0]);
[ (.model_name // .scsi_model_name // .model_family // "?"),
  (.serial_number // "?"),
  (.device.protocol // "?"),
  ((.rotation_rate // "") | tostring),
  ((.user_capacity.bytes // .nvme_total_capacity // "") | tostring),
  (if (.smart_status.passed | type) == "boolean" then (.smart_status.passed | tostring) else "" end),
  ((.temperature.current // "") | tostring),
  ((.power_on_time.hours // "") | tostring),
  ((.smartctl.exit_status // "") | tostring),
  rawv(5), rawv(197), rawv(198), rawv(199), rawv(187),
  ([normv(177), normv(231), normv(233), normv(202)] | map(select(type == "number" and . <= 100))
     | if length > 0 then (min | tostring) else "" end),
  (if .nvme_smart_health_information_log == null then "" else ((.nvme_smart_health_information_log.critical_warning // 0) | tostring) end),
  ((.nvme_smart_health_information_log.percentage_used // "") | tostring),
  ((.nvme_smart_health_information_log.available_spare // "") | tostring),
  ((.nvme_smart_health_information_log.available_spare_threshold // "") | tostring),
  ((.nvme_smart_health_information_log.media_errors // "") | tostring),
  (st | if . == null then ""
        elif (.status.passed | type) == "boolean" then (.status.passed | tostring)
        elif (.self_test_result.value | type) == "number" then ((.self_test_result.value == 0) | tostring)
        else "?" end),
  (st | if . == null then "" else ((.lifetime_hours // .power_on_hours // "") | tostring) end),
  (st | if . == null then "" else (.status.string // .self_test_result.string // "") end),
  ([.smartctl.messages[]?.string] | join(" ")),
  ((.scsi_grown_defect_list // "") | tostring)
] | map(tostring | gsub("[\n\u001f]"; " ")) | join("\u001f")'

check_disques() {
  section disques
  if ! have smartctl; then
    warn "smartmontools n'est pas installé" "Impossible de lire l'état SMART des disques : une panne annoncée passerait inaperçue." \
      "\`sudo apt install --no-install-recommends smartmontools\` (ou relancez avec --install-deps)"
    return
  fi
  local -a devs=()
  mapfile -t devs < <(tmo 60 smartctl -j --scan-open 2>/dev/null | jq -r '.devices[]? | "\(.name)\u001f\(.type // "auto")"' 2>/dev/null)
  if ((${#devs[@]} == 0)); then
    mapfile -t devs < <(lsblk -dnpo NAME,TYPE 2>/dev/null | awk '$2 == "disk" && $1 !~ /\/(loop|zram|ram|sr|fd|nbd)/ {printf "%s%cauto\n", $1, 31}')
  fi
  if ((${#devs[@]} == 0)); then info "Aucun disque détecté par smartctl"; return; fi
  note "Lecture SMART de ${#devs[@]} disque(s)…"

  local -a rows=() okd=() notest=() oldtest=()
  local e
  for e in "${devs[@]}"; do
    local dev=${e%%"$US"*} typ=${e#*"$US"}
    local j="$WORK/smart_${dev//\//_}.json"
    local -a extra=(); ((NO_WAKE)) && extra=(-n standby)
    tmo 90 smartctl -j -a "${extra[@]}" -d "$typ" "$dev" > "$j" 2>/dev/null
    local bname=${dev##*/}; [[ $bname =~ ^nvme[0-9]+$ ]] && bname="${bname}n1"
    local pool=${DISK_POOL[$bname]:-—}
    if ! jq -e . "$j" >/dev/null 2>&1; then
      info "$dev : lecture SMART impossible" "smartctl n'a rien renvoyé d'exploitable." "\`sudo smartctl -a $dev\` (un pont USB peut nécessiter \`-d sat\`)"
      continue
    fi
    local model serial proto rot cap passed temp poh ex realloc pend offu crc repu wear nvcw nvused nvspare nvthr nvmedia stpass sth ststr msgs grown
    IFS=$US read -r model serial proto rot cap passed temp poh ex realloc pend offu crc repu wear nvcw nvused nvspare nvthr nvmedia stpass sth ststr msgs grown \
      < <(jq -r "$JQ_SMART" "$j")

    if [[ ${msgs,,} == *standby* ]]; then
      info "$dev en veille : non interrogé" "Option --no-wake : le disque n'a pas été réveillé."
      rows+=("$dev$TAB$model$TAB$serial$TAB—$TAB$(hbytes "$cap")$TAB$pool$TAB@INFO en veille$TAB$TAB$TAB$TAB$TAB$TAB")
      continue
    fi
    local kind
    case $proto in
      NVMe) kind=NVMe ;;
      ATA)
        if [[ $rot == 0 ]]; then kind=SSD
        elif isint "$rot"; then kind="HDD $rot tr/min"
        elif [[ $(cat "$SYS_BLOCK/$bname/queue/rotational" 2>/dev/null) == 0 ]]; then kind=SSD
        else kind=HDD; fi ;;
      SCSI) kind=SAS/SCSI ;;
      *) kind=$proto ;;
    esac
    if [[ -z $passed ]]; then
      [[ -n $msgs ]] || msgs="Le disque ne renvoie pas d'état SMART (pont USB, contrôleur RAID ?)."
      info "$dev ($model) : SMART indisponible" "$msgs" "Essayez \`sudo smartctl -d sat -a $dev\`"
      rows+=("$dev$TAB$model$TAB$serial$TAB$kind$TAB$(hbytes "$cap")$TAB$pool$TAB@INFO indisponible$TAB$TAB$TAB$TAB$TAB$TAB")
      continue
    fi

    local lvl=OK cablefix=0
    local -a iss=()
    [[ $passed == false ]] && { lvl=CRIT; iss+=("auto-diagnostic SMART en ÉCHEC"); }
    if isint "$ex"; then
      ((ex & 8))  && { lvl=CRIT; iss+=("le disque annonce une défaillance"); }
      ((ex & 16)) && { lvl=CRIT; iss+=("attribut(s) de pré-défaillance sous le seuil"); }
      ((ex & 32)) && { lvl=$(worst "$lvl" WARN); iss+=("attribut(s) passé(s) sous le seuil par le passé"); }
      [[ $proto == ATA ]] && ((ex & 64)) && { lvl=$(worst "$lvl" WARN); iss+=("journal d'erreurs SMART non vide (\`smartctl -l error $dev\`)"); }
      ((ex & 128)) && { lvl=$(worst "$lvl" WARN); iss+=("erreurs dans le journal des auto-tests"); }
    fi
    if isint "$realloc" && ((realloc > 0)); then
      if ((realloc >= 100)); then lvl=CRIT; else lvl=$(worst "$lvl" WARN); fi; iss+=("$realloc secteur(s) réalloué(s)")
    fi
    if isint "$pend" && ((pend > 0)); then
      if ((pend >= 10)); then lvl=CRIT; else lvl=$(worst "$lvl" WARN); fi; iss+=("$pend secteur(s) illisible(s) en attente")
    fi
    if isint "$offu" && ((offu > 0)); then
      if ((offu >= 10)); then lvl=CRIT; else lvl=$(worst "$lvl" WARN); fi; iss+=("$offu secteur(s) irrécupérable(s)")
    fi
    if isint "$repu" && ((repu > 0)); then lvl=$(worst "$lvl" WARN); iss+=("$repu erreur(s) non corrigée(s) signalée(s)"); fi
    if isint "$crc" && ((crc > 0)); then lvl=$(worst "$lvl" WARN); iss+=("$crc erreur(s) CRC de liaison"); cablefix=1; fi
    if isint "$grown" && ((grown > 0)); then lvl=$(worst "$lvl" WARN); iss+=("$grown défaut(s) acquis"); fi
    local tw=50 tc=60
    case $kind in SSD) tw=60 tc=70 ;; NVMe) tw=70 tc=80 ;; esac
    if isint "$temp"; then
      if ((temp >= tc)); then lvl=CRIT; iss+=("température $temp °C")
      elif ((temp >= tw)); then lvl=$(worst "$lvl" WARN); iss+=("température élevée ($temp °C)"); fi
    fi
    local wear_disp=""
    if isint "$wear"; then
      wear_disp="$wear % restant"
      if ((wear <= 10)); then lvl=CRIT; iss+=("usure : ~$wear % de durée de vie restante")
      elif ((wear <= 20)); then lvl=$(worst "$lvl" WARN); iss+=("usure : ~$wear % de durée de vie restante"); fi
    fi
    if isint "$nvused"; then
      wear_disp="$nvused % utilisé"
      if ((nvused >= 90)); then lvl=CRIT; iss+=("usure NVMe : $nvused % de l'endurance consommée")
      elif ((nvused >= 80)); then lvl=$(worst "$lvl" WARN); iss+=("usure NVMe : $nvused % de l'endurance consommée"); fi
    fi
    if isint "$nvcw" && ((nvcw != 0)); then lvl=CRIT; iss+=("avertissement critique NVMe ($(printf '0x%02x' "$nvcw"))"); fi
    if isint "$nvspare" && isint "$nvthr" && ((nvspare < nvthr)); then lvl=CRIT; iss+=("réserve NVMe épuisée ($nvspare % < $nvthr %)"); fi
    if isint "$nvmedia" && ((nvmedia > 0)); then lvl=$(worst "$lvl" WARN); iss+=("$nvmedia erreur(s) média NVMe"); fi

    local st_disp="aucun" age=""
    if [[ -n $stpass ]]; then
      if isint "$poh" && isint "$sth"; then
        # sur les disques ATA, l'heure du test est stockée sur 16 bits
        if ((poh > 65535)); then age=$(( ((poh - sth) % 65536 + 65536) % 65536 )); else age=$((poh - sth)); fi
        ((age < 0)) && age=""
      fi
      st_disp="${ststr:-?}"
      [[ -n $age ]] && st_disp+=", il y a $((age / 24)) j"
      [[ $stpass == false ]] && { lvl=CRIT; iss+=("dernier auto-test en échec ($ststr)"); }
      [[ -n $age ]] && ((age > 24 * 35)) && oldtest+=("$dev ($((age / 24)) j)")
    else
      notest+=("$dev")
    fi

    if [[ $lvl == OK ]]; then
      okd+=("$dev")
    else
      local fix pz=""
      [[ $pool != "—" ]] && pz=" (pool ${pool%% *} : \`sudo zpool replace ${pool%% *} <ancien> <nouveau>\`)"
      if [[ $lvl == CRIT ]]; then
        fix="Vérifiez vos sauvegardes et prévoyez le remplacement du disque$pz ; test long : \`sudo smartctl -t long $dev\`"
      elif ((cablefix)) && ((${#iss[@]} == 1)); then
        fix="Erreurs de transmission, pas forcément le disque : changez le câble SATA ou vérifiez le fond de panier, puis surveillez si le compteur augmente"
      else
        fix="Surveillez l'évolution en relançant l'audit ; test long : \`sudo smartctl -t long $dev\`"
      fi
      add "$lvl" "Disque $dev ($model) : $(join_list ', ' "${iss[@]}")" "$kind, $(hbytes "$cap"), pool : $pool, n° de série $serial" "$fix"
    fi
    local cell
    case $lvl in OK) cell="@OK OK" ;; WARN) cell="@WARN à surveiller" ;; *) cell="@CRIT DÉFAILLANT" ;; esac
    rows+=("$dev$TAB$model$TAB$serial$TAB$kind$TAB$(hbytes "$cap")$TAB$pool$TAB$cell$TAB${temp:+$temp °C}$TAB$poh$TAB${realloc:--} / ${pend:--} / ${offu:--}$TAB${crc:--}$TAB${wear_disp:--}$TAB$st_disp")
  done

  ((${#okd[@]})) && ok "${#okd[@]} disque(s) en bonne santé SMART" "$(join_list ', ' "${okd[@]}")"
  local sched=0
  grep -qsE '^[[:space:]]*[^#[:space:]].*[[:space:]]-s[[:space:]]' /etc/smartd.conf && sched=1
  if ((${#notest[@]} || ${#oldtest[@]})) || ((!sched)); then
    local m=""
    ((${#notest[@]})) && m+="Jamais testé : $(join_list ', ' "${notest[@]}"). "
    ((${#oldtest[@]})) && m+="Dernier test ancien : $(join_list ', ' "${oldtest[@]}"). "
    ((sched)) || m+="Aucun auto-test planifié dans /etc/smartd.conf."
    info "Auto-tests SMART à planifier" "$m" \
      "Dans /etc/smartd.conf, ajoutez à la ligne DEVICESCAN : \`-s (S/../.././02|L/../01/./03)\` (test court chaque nuit à 2 h, long le 1er du mois à 3 h), puis \`sudo systemctl restart smartmontools\`"
  else
    ok "Auto-tests SMART planifiés et récents"
  fi
  if systemctl is-active --quiet smartmontools 2>/dev/null || systemctl is-active --quiet smartd 2>/dev/null; then
    ok "Surveillance continue smartd active"
  else
    warn "smartd n'est pas actif" "Les disques ne sont surveillés qu'au lancement de cet audit." "\`sudo systemctl enable --now smartmontools\`"
  fi
  tbl "Disques" < <(printf 'Disque\tModèle\tN° de série\tType\tCapacité\tPool ZFS\tSMART\tTemp.\tHeures\tRéalloués / en attente / irrécup.\tCRC\tUsure\tDernier auto-test\n'; printf '%s\n' "${rows[@]}")
}

check_zfs() {
  section zfs
  if ! have zpool; then info "ZFS n'est pas installé" "La commande zpool est introuvable."; return; fi
  local v; v=$(zfs version 2>/dev/null | tr '\n' ' ')
  [[ -n $v ]] && info "Version d'OpenZFS" "$v"
  if ((${#POOLS[@]} == 0)); then
    crit "Aucun pool ZFS importé" "Aucun pool n'est importé : les données des pools ne sont pas accessibles." \
      "\`sudo zpool import\` pour lister les pools disponibles, puis \`sudo zpool import <nom>\`"
    return
  fi
  local timers; timers=$(systemctl list-timers --all --no-legend 2>/dev/null)
  local -a sched=()
  grep -qsE '^[^#]*scrub' /etc/cron.d/zfsutils-linux && sched+=("cron zfsutils-linux (mensuel)")
  grep -qiE 'zfs-scrub' <<< "$timers" && sched+=("timer systemd zfs-scrub")
  grep -rqsE '^[^#]*zpool[[:space:]]+scrub' /etc/crontab /etc/cron.d /var/spool/cron/crontabs && sched+=("crontab")
  grep -qsE '^[^#]*trim' /etc/cron.d/zfsutils-linux && TRIM_SCHED="cron zfsutils-linux"
  grep -qiE 'zfs-trim' <<< "$timers" && TRIM_SCHED="timer systemd zfs-trim"

  local -a prow=()
  local p
  for p in "${POOLS[@]}"; do
    local size alloc free frag cap health dedup
    IFS=$'\t' read -r size alloc free frag cap health dedup < <(tmo 30 zpool list -H -p -o size,alloc,free,frag,cap,health,dedupratio "$p" 2>/dev/null)
    cap=${cap%\%}; frag=${frag%\%}
    local media=${POOL_MEDIA[$p]:-?}
    local st; st=$(tmo 30 zpool status -p "$p" 2>&1)
    raw "zpool status $p" "$st"
    local bad stx act
    bad=$(awk '/^config:/ {c = 1; next} /^errors:/ {c = 0} c && NF >= 2 && $2 ~ /^(DEGRADED|FAULTED|UNAVAIL|REMOVED|OFFLINE)$/ {printf "%s : %s\n", $1, $2}' <<< "$st")
    stx=$(awk '/^ *status:/ {s = 1; sub(/^ *status: */, ""); print; next} /^ *(action|see|scan|config|remove):/ {s = 0} s {sub(/^[ \t]+/, ""); print}' <<< "$st" | tr '\n' ' ')
    act=$(awk '/^ *action:/ {s = 1; sub(/^ *action: */, ""); print; next} /^ *(see|scan|config|status):/ {s = 0} s {sub(/^[ \t]+/, ""); print}' <<< "$st" | tr '\n' ' ')
    case $health in
      ONLINE) ;;
      DEGRADED)
        crit "Pool $p DÉGRADÉ" "La redondance est réduite : une panne supplémentaire peut entraîner une perte de données.${bad:+$NL$bad}${stx:+$NL$stx}" \
          "Identifiez le disque en cause (\`zpool status -v $p\`), remplacez-le puis \`sudo zpool replace $p <ancien> <nouveau>\`" ;;
      *)
        crit "Pool $p : état ${health:-inconnu}" "${bad}${stx:+$NL$stx}" "${act:-\`zpool status -v $p\`}" ;;
    esac
    local caplvl=OK
    if isint "$cap"; then ((cap >= 80)) && caplvl=WARN; ((cap >= 90)) && caplvl=CRIT; fi
    local capmsg="$(hbytes "$alloc") utilisés sur $(hbytes "$size") — libre : $(hbytes "$free"), fragmentation de l'espace libre : ${frag} %"
    case $caplvl in
      OK)   [[ $health == ONLINE ]] && ok "Pool $p ($media) : en ligne, rempli à $cap %" "$capmsg" ;;
      WARN) warn "Pool $p rempli à $cap %" "$capmsg. Au-delà de 80 %, les performances de ZFS se dégradent." \
              "Faites le ménage (les snapshots retiennent de l'espace : \`zfs list -t snapshot -o name,used -s used -r $p | tail\`) ou agrandissez le pool" ;;
      CRIT) crit "Pool $p presque plein ($cap %)" "$capmsg. Au-delà de 90 %, ZFS devient très lent et peut manquer d'espace." \
              "Libérez de l'espace en urgence (snapshots, fichiers volumineux) ou ajoutez un vdev" ;;
    esac
    local errs; errs=$(awk '/^config:/ {c = 1; next} /^errors:/ {c = 0}
      c && NF >= 5 && $3 ~ /^[0-9]+$/ && $4 ~ /^[0-9]+$/ && $5 ~ /^[0-9]+$/ && ($3 + $4 + $5) > 0 {printf "%s : lecture %s, écriture %s, checksum %s\n", $1, $3, $4, $5}' <<< "$st")
    local feat=0; [[ $stx == *feature* ]] && feat=1
    if [[ -n $errs ]]; then
      local emsg=$errs; ((feat)) || emsg+="${stx:+$NL$stx}"
      warn "Pool $p : erreurs d'entrées/sorties sur des périphériques" "$emsg" \
        "Vérifiez les câbles et l'état SMART des disques concernés, puis \`sudo zpool clear $p\` ; si les erreurs reviennent, remplacez le disque"
    fi
    if [[ $health == ONLINE && -n $stx ]]; then
      if ((feat)); then
        info "Pool $p : nouvelles fonctionnalités ZFS disponibles" "$stx" \
          "\`sudo zpool upgrade $p\` — irréversible : le pool ne sera plus importable par une version plus ancienne d'OpenZFS"
      elif [[ -z $errs ]]; then
        warn "Pool $p : message d'état ZFS" "$stx" "$act"
      fi
    fi
    local el; el=$(grep -m1 '^errors:' <<< "$st")
    if [[ -n $el && $el != *"No known data errors"* ]]; then
      crit "Pool $p : erreurs de données permanentes" "$el" \
        "\`zpool status -v $p\` liste les fichiers corrompus : restaurez-les depuis une sauvegarde, puis \`sudo zpool clear $p\` et lancez un scrub"
    fi

    local scan; scan=$(awk '/^ *scan:/ {sub(/^ *scan: */, ""); print; exit}' <<< "$st")
    local scrub_disp="?"
    case $scan in
      "scrub repaired"*)
        local when=${scan##* on } d rep nerr
        d=$(days_ago "$when"); rep=$(awk '{print $3}' <<< "$scan")
        nerr=$(grep -oE 'with [0-9]+ errors' <<< "$scan" | grep -oE '[0-9]+')
        if [[ -z $d ]]; then
          info "Pool $p : dernier scrub" "$scan"
        elif ((d > 40)); then
          warn "Pool $p : dernier scrub il y a $d jours" "Un scrub mensuel détecte et corrige la corruption silencieuse avant qu'elle ne devienne irréparable." \
            "\`sudo zpool scrub $p\`, puis vérifiez la planification des scrubs"
          scrub_disp="@WARN il y a $d j"
        else
          ok "Pool $p : dernier scrub il y a $d jour(s)" "Réparé : $rep, erreurs : ${nerr:-0}"
          scrub_disp="@OK il y a $d j"
        fi
        if [[ $rep != 0B && $rep != 0 ]] || ((${nerr:-0} > 0)); then
          warn "Pool $p : le dernier scrub a réparé des données" "Réparé : $rep, erreurs : ${nerr:-0}. Signe possible d'un disque ou d'un câble défaillant." \
            "Consultez la section « Disques (SMART) » et \`zpool status -v $p\`"
        fi ;;
      "scrub in progress"*)
        info "Pool $p : scrub en cours" "$(grep -oE '[0-9.]+% done.*' <<< "$st" | head -n 1)"; scrub_disp="@INFO en cours" ;;
      "resilver in progress"*)
        warn "Pool $p : reconstruction (resilver) en cours" "$(grep -oE '[0-9.]+% done.*' <<< "$st" | head -n 1)" \
          "Évitez de solliciter le pool et ne retirez aucun disque avant la fin"; scrub_disp="@WARN resilver" ;;
      "resilvered"*)
        info "Pool $p : dernier resilver" "$scan — la date du dernier scrub n'est plus affichée après un resilver." ;;
      "none requested"*|"")
        warn "Pool $p : aucun scrub n'a jamais été lancé" "Le scrub vérifie toutes les données et répare la corruption silencieuse." "\`sudo zpool scrub $p\`"
        scrub_disp="@WARN jamais" ;;
      *cancel*)
        warn "Pool $p : le dernier scrub a été annulé" "$scan" "\`sudo zpool scrub $p\`"; scrub_disp="@WARN annulé" ;;
      *) info "Pool $p : scrub" "$scan" ;;
    esac

    if [[ $media == SSD ]]; then
      local at ptrim
      at=$(zpool get -H -o value autotrim "$p" 2>/dev/null)
      ptrim=$(zfs get -H -o value org.debian:periodic-trim "$p" 2>/dev/null)
      if [[ $at == on ]]; then
        ok "Pool $p (SSD) : TRIM automatique actif"
      elif [[ -n $TRIM_SCHED ]] && { [[ $ptrim == enable ]] || [[ -n ${POOL_NVME[$p]:-} && $ptrim != disable ]]; }; then
        ok "Pool $p (SSD) : TRIM périodique planifié" "$TRIM_SCHED"
      else
        warn "Pool $p (SSD) : aucun TRIM" "Sans TRIM, les SSD perdent en performances et s'usent davantage. (Le TRIM mensuel d'Ubuntu ne traite par défaut que les pools 100 % NVMe.)" \
          "\`sudo zpool set autotrim=on $p\` (ou un TRIM mensuel : \`sudo zfs set org.debian:periodic-trim=enable $p\`)"
      fi
    fi
    prow+=("$p$TAB$media$TAB@$( [[ $health == ONLINE ]] && echo OK || echo CRIT) $health$TAB$(hbytes "$size")$TAB$(hbytes "$alloc")$TAB$(hbytes "$free")$TAB@$caplvl $cap %$TAB$frag %$TAB$scrub_disp")
  done
  tbl "Pools" < <(printf 'Pool\tSupport\tÉtat\tTaille\tUtilisé\tLibre\tRemplissage\tFragmentation\tDernier scrub\n'; printf '%s\n' "${prow[@]}")

  if ((${#sched[@]})); then
    ok "Scrubs planifiés" "$(join_list ', ' "${sched[@]}")"
  else
    warn "Aucun scrub planifié" "Sans scrub régulier, la corruption silencieuse n'est détectée qu'à la lecture des fichiers." \
      "Ubuntu fournit /etc/cron.d/zfsutils-linux (paquet zfsutils-linux) ; sinon ajoutez par ex. \`0 2 1 * * root /usr/sbin/zpool scrub <pool>\` dans /etc/cron.d/"
  fi

  if systemctl is-active --quiet zfs-zed 2>/dev/null; then
    local notif; notif=$(grep -E '^[[:space:]]*(ZED_EMAIL_ADDR|ZED_NTFY_TOPIC|ZED_SLACK_WEBHOOK_URL|ZED_PUSHBULLET_ACCESS_TOKEN|ZED_PUSHOVER_TOKEN|ZED_GOTIFY_URL)=' /etc/zfs/zed.d/zed.rc 2>/dev/null | cut -d= -f1 | tr '\n' ' ')
    if [[ -n $notif ]]; then
      ok "ZED (démon d'événements ZFS) actif, notifications configurées" "$notif"
      [[ $notif == *ZED_EMAIL_ADDR* ]] && ! have sendmail && warn "ZED envoie ses alertes par e-mail mais aucun serveur de messagerie n'est installé" \
        "Les e-mails d'alerte ne partiront jamais." "Installez et configurez un relais SMTP léger : \`sudo apt install msmtp-mta\`"
    else
      warn "ZED actif mais aucune notification configurée" "En cas de panne de disque, personne ne sera prévenu." \
        "Dans /etc/zfs/zed.d/zed.rc, renseignez \`ZED_EMAIL_ADDR\` (avec un relais SMTP, ex. msmtp) ou, selon votre version, \`ZED_NTFY_TOPIC\` / \`ZED_SLACK_WEBHOOK_URL\`, puis \`sudo systemctl restart zfs-zed\`"
    fi
  else
    warn "ZED (zfs-zed) inactif" "Aucune réaction ni alerte automatique en cas de défaillance d'un disque." "\`sudo systemctl enable --now zfs-zed\`"
  fi

  if ((ARC_SIZE > 0)); then
    local hr; hr=$(awk -v h="$ARC_HITS" -v m="$ARC_MISS" 'BEGIN {if (h + m > 0) printf "%.1f", h * 100 / (h + m); else print "?"}')
    info "Cache ARC" "Taille : $(hbytes "$ARC_SIZE") (min $(hbytes "$ARC_MIN"), max $(hbytes "$ARC_MAX")) — taux de succès depuis le démarrage : $hr %"
  fi

  local snapf="$WORK/snapshots.tsv"
  tmo 120 zfs list -H -p -t snapshot -o name,creation 2>/dev/null > "$snapf"
  for p in "${POOLS[@]}"; do
    read -r "SNAP_COUNT[$p]" "SNAP_LAST[$p]" < <(awk -F'\t' -v p="$p" 'index($1, p "@") == 1 || index($1, p "/") == 1 {n++; if ($2 + 0 > m) m = $2 + 0} END {printf "%d %.0f\n", n, m}' "$snapf")
  done

  local enc nt ne
  enc=$(tmo 60 zfs get -H -o name,value -t filesystem,volume encryption 2>/dev/null | grep -vE '/[0-9a-f]{64}')
  nt=$(nlines "$enc"); ne=$(awk -F'\t' '$2 != "off" && $2 != "-"' <<< "$enc" | grep -c .)
  if ((ne > 0)); then
    ok "Chiffrement ZFS natif : $ne dataset(s) chiffré(s) sur $nt"
  elif ((nt > 0)); then
    info "Aucun dataset chiffré" "En cas de vol ou de renvoi d'un disque en SAV, les données qu'il contient sont lisibles." \
      "Le chiffrement natif ne s'active qu'à la création d'un dataset (\`zfs create -o encryption=on -o keyformat=passphrase …\`), puis copie des données"
  fi
  tbl "Datasets" < <(printf 'Dataset\tUtilisé\tDisponible\tRéférencé\tCompression\tChiffrement\tPoint de montage\n'
    tmo 60 zfs list -H -p -t filesystem,volume -o name,used,avail,refer,compressratio,encryption,mountpoint 2>/dev/null \
      | grep -vE '/[0-9a-f]{64}(-init)?[[:space:]]' | head -n 150 \
      | numfmt --to=iec-i --suffix=o --format='%.1f' --field=2-4 -d "$TAB" --invalid=ignore 2>/dev/null)
  mapfile -t ZFS_MOUNTS < <(tmo 60 zfs list -H -o mountpoint,mounted -t filesystem 2>/dev/null | awk -F'\t' '$2 == "yes" && $1 ~ /^\// {print $1}' | grep -vE '/[0-9a-f]{64}' | head -n 200)
}

check_docker() {
  section docker
  if ! have docker; then info "Docker n'est pas installé"; return; fi
  if ! tmo 20 docker info >/dev/null 2>&1; then
    crit "Le démon Docker ne répond pas" "$(tmo 10 docker info 2>&1 | tail -n 3)" "\`sudo systemctl status docker\` puis \`sudo journalctl -u docker -n 50\`"
    return
  fi
  DOCKER_OK=1
  local dver ddrv droot dlog dcg
  IFS='|' read -r dver ddrv droot dlog dcg < <(tmo 20 docker info --format '{{.ServerVersion}}|{{.Driver}}|{{.DockerRootDir}}|{{.LoggingDriver}}|{{.CgroupVersion}}' 2>/dev/null)
  info "Docker ${dver:-?}" "Stockage : ${ddrv:-?} (${droot:-?}), journalisation : ${dlog:-?}, cgroups v${dcg:-?}"
  local ids; ids=$(tmo 30 docker ps -aq --no-trunc 2>/dev/null)
  if [[ -z $ids ]]; then info "Aucun conteneur"; return; fi
  # shellcheck disable=SC2086
  tmo 60 docker inspect $ids > "$INSPECT" 2>/dev/null
  jq -e 'type == "array"' "$INSPECT" >/dev/null 2>&1 || echo '[]' > "$INSPECT"

  local k v
  while IFS= read -r k; do [[ -n $k ]] && CNAMES[$k]=1; done < <(jq -r '.[] | .Name | ltrimstr("/")' "$INSPECT")
  while IFS=$US read -r k v; do [[ -n $k ]] && PORTMAP[$k]=$v; done < <(jq -r '.[] | select(.State.Status == "running") | (.Name | ltrimstr("/")) as $n
    | (.NetworkSettings.Ports // {}) | to_entries[] | select(.value != null) | .value[] | "\(.HostPort)\u001f\($n)"' "$INSPECT")

  local -a rows=() stopped=() norestart=()
  local nrun=0 name image status code health rc policy started oom proj
  while IFS=$US read -r name image status code health rc policy started oom proj; do
    local since="-" d cell
    if [[ $status == running ]] && d=$(days_ago "$started"); then since="$d j"; fi
    cell="@OK $status"
    case $status in
      running)
        nrun=$((nrun + 1))
        if [[ $health == unhealthy ]]; then
          cell="@WARN en marche (unhealthy)"
          warn "Conteneur $name : test de santé en échec" "Le conteneur tourne mais son healthcheck échoue." \
            "\`docker inspect --format '{{json .State.Health}}' $name\` et \`docker logs --tail 100 $name\`"
        fi
        if isint "$rc" && ((rc >= 5)); then
          cell="@WARN en marche"
          warn "Conteneur $name : $rc redémarrages" "Le conteneur a planté et redémarré $rc fois." "\`docker logs --tail 100 $name\`"
        fi
        [[ $policy == no || -z $policy ]] && norestart+=("$name") ;;
      restarting)
        cell="@CRIT redémarre en boucle"
        crit "Conteneur $name en boucle de redémarrage" "Il plante dès son démarrage (code de sortie $code)." "\`docker logs --tail 100 $name\`" ;;
      exited|dead)
        if [[ $oom == true ]]; then
          cell="@WARN arrêté (mémoire)"
          warn "Conteneur $name tué par manque de mémoire" "Le noyau l'a arrêté faute de RAM (code $code)." "Augmentez sa limite mémoire ou réduisez la charge (\`docker stats\`)"
        elif [[ $code != 0 && $code != 137 && $code != 143 ]]; then
          cell="@WARN arrêté (code $code)"
          warn "Conteneur $name arrêté en erreur (code $code)" "" "\`docker logs --tail 100 $name\`"
        else
          cell="@INFO arrêté"; stopped+=("$name")
        fi ;;
      *) cell="@INFO $status"; stopped+=("$name ($status)") ;;
    esac
    rows+=("$name$TAB$image$TAB$cell$TAB${health:--}$TAB$rc$TAB$policy$TAB$since$TAB${proj:--}")
  done < <(jq -r '.[] | [(.Name | ltrimstr("/")), (.Config.Image // ""), .State.Status, (.State.ExitCode | tostring), (.State.Health.Status // ""),
      ((.RestartCount // 0) | tostring), (.HostConfig.RestartPolicy.Name // ""), (.State.StartedAt // ""), ((.State.OOMKilled // false) | tostring),
      ((.Config.Labels // {})["com.docker.compose.project"] // "")] | join("\u001f")' "$INSPECT")

  ok "$nrun conteneur(s) en fonctionnement" "$( ((${#stopped[@]})) && echo "Arrêtés : $(join_list ', ' "${stopped[@]}")")"
  ((${#norestart[@]})) && info "Conteneurs sans redémarrage automatique" "Ils ne repartiront pas après un redémarrage du serveur : $(join_list ', ' "${norestart[@]}")." \
    "Ajoutez \`restart: unless-stopped\` dans leur docker-compose"
  tbl "Conteneurs" < <(printf 'Nom\tImage\tÉtat\tSanté\tRedémarrages\tPolitique\tDémarré depuis\tProjet compose\n'; printf '%s\n' "${rows[@]}")

  local stats; stats=$(tmo 45 docker stats --no-stream --format '{{.Name}}|{{.CPUPerc}}|{{.MemUsage}}|{{.MemPerc}}|{{.NetIO}}|{{.BlockIO}}|{{.PIDs}}' 2>/dev/null)
  if [[ -n $stats ]]; then
    tbl "Consommation instantanée des conteneurs" < <(printf 'Conteneur\tCPU\tMémoire\tMémoire %%\tRéseau E/S\tDisque E/S\tProcessus\n'; tr '|' '\t' <<< "$stats")
    local hi; hi=$(awk -F'|' '{p = $4; sub(/%/, "", p); if (p + 0 >= 90) print $1 " (" $4 " de sa limite)"}' <<< "$stats")
    [[ -n $hi ]] && warn "Conteneur(s) proche(s) de leur limite mémoire" "$hi" "Augmentez la limite (\`mem_limit\`) ou cherchez une fuite mémoire"
  fi

  local sdf; sdf=$(tmo 60 docker system df --format '{{.Type}}|{{.TotalCount}}|{{.Active}}|{{.Size}}|{{.Reclaimable}}' 2>/dev/null)
  if [[ -n $sdf ]]; then
    tbl "Espace disque utilisé par Docker" < <(printf 'Type\tTotal\tActifs\tTaille\tRécupérable\n'; tr '|' '\t' <<< "$sdf")
    local rec; rec=$(awk -F'|' '$1 == "Images" || $1 == "Build Cache" {print $1 " : " $5}' <<< "$sdf" | paste -sd ';' | sed 's/;/ ; /g')
    [[ -n $rec ]] && info "Espace Docker récupérable" "$rec" "\`docker image prune -a\` (supprime les images inutilisées) et \`docker builder prune\`"
  fi

  local nolim big
  nolim=$(jq -r '.[] | select(.HostConfig.LogConfig.Type == "json-file" and (((.HostConfig.LogConfig.Config // {})["max-size"] // "") == "")) | .Name | ltrimstr("/")' "$INSPECT" | paste -sd ' ')
  big=$(find "${droot:-/var/lib/docker}/containers" -name '*-json.log' -size +500M -printf '%s %h\n' 2>/dev/null | sort -rn | head -n 5 \
    | while read -r sz dir; do printf '%s : %s\n' "$(jq -r --arg id "${dir##*/}" '.[] | select(.Id == $id) | .Name | ltrimstr("/")' "$INSPECT")" "$(hbytes "$sz")"; done)
  [[ -n $big ]] && warn "Journaux de conteneurs volumineux" "$big" "Configurez la rotation (voir ci-dessous), puis recréez les conteneurs (\`docker compose up -d --force-recreate\`)"
  if [[ -n $nolim ]]; then
    info "Journaux Docker sans rotation : $nolim" "Ces journaux grossissent indéfiniment." \
      "Dans /etc/docker/daemon.json : \`\"log-driver\": \"local\"\` (ou \`\"log-opts\": {\"max-size\": \"10m\", \"max-file\": \"3\"}\`), \`sudo systemctl restart docker\`, puis recréez les conteneurs"
  else
    ok "Rotation des journaux Docker configurée"
  fi
}

gpu_vainfo() {   # gpu_vainfo nœud libellé
  local node=$1 label=$2
  if ! have vainfo; then
    info "vainfo non installé" "Impossible de vérifier depuis l'hôte les profils d'encodage VA-API ($label)." "\`sudo apt install vainfo\`"
    return
  fi
  local vi enc drvl
  vi=$(tmo 20 vainfo --display drm --device "$DRI_DIR/$node" 2>&1)
  raw "vainfo ($node, $label)" "$vi"
  enc=$(grep -E 'VAEntrypointEnc' <<< "$vi" | sed -E 's/^[[:space:]]*VAProfile([A-Za-z0-9_]+).*/\1/' | sort -u | tr '\n' ' ')
  drvl=$(grep -m1 -i 'driver version' <<< "$vi" | sed -E 's/.*[Dd]river version: *//')
  if [[ -n $enc ]]; then
    ok "VA-API ($label) : encodage matériel disponible" "Pilote : ${drvl:-?}${NL}Profils d'encodage : $enc"
  else
    info "VA-API ($label) : aucun profil d'encodage depuis l'hôte" "$(grep -iE 'error|failed|libva|driver' <<< "$vi" | head -n 3)" \
      "Sans importance si seul le conteneur transcode (il embarque souvent ses propres pilotes). Sinon : \`sudo apt install mesa-va-drivers\` (AMD) ou \`intel-media-va-driver-non-free\` (Intel)"
  fi
}

check_gpu() {
  section gpu
  local -a gpus=()
  have lspci && mapfile -t gpus < <(lspci -nn 2>/dev/null | grep -Ei 'vga compatible|3d controller|display controller')
  local has_intel=0 has_nv=0 has_amd=0 g
  for g in "${gpus[@]}"; do
    [[ $g == *Intel* ]] && has_intel=1
    [[ $g == *NVIDIA* ]] && has_nv=1
    [[ $g == *"Advanced Micro Devices"* || $g == *"[AMD/ATI]"* || $g == *"ATI Technologies"* ]] && has_amd=1
  done
  if ((!has_intel)) && [[ ${CPU_MODEL:-} =~ Intel.*Core.*-[0-9]{4,5}([A-Z]*) ]] && [[ ${BASH_REMATCH[1]} != *F* ]]; then
    info "iGPU Intel du processeur non visible" "Le processeur (${CPU_MODEL}) possède un iGPU (Quick Sync), mais il n'apparaît pas : il est probablement désactivé dans le BIOS parce qu'une carte graphique est installée." \
      "Dans le BIOS : activez « iGPU Multi-Monitor » (ou « Internal Graphics : Enabled »), redémarrez, puis vérifiez \`ls /dev/dri\` (un nœud renderD de plus)"
  fi
  if ((${#gpus[@]})); then
    info "Processeur(s) graphique(s) détecté(s)" "$(printf '%s\n' "${gpus[@]}" | sed -E 's/^[^ ]+ [^:]+: //')"
  else
    info "Aucun GPU détecté" "lspci ne liste aucun contrôleur graphique$(have lspci || echo ' (pciutils non installé)')."
  fi

  # Nœuds de rendu /dev/dri : à quel GPU correspond chacun ?
  local -a drows=()
  local -A NODE_DRV=() NODE_VEND=() NODE_DEV=()
  local n b drv pci vend vname desc
  for n in "$DRI_DIR"/renderD*; do
    [[ -e $n ]] || continue
    b=${n##*/}
    drv=$(readlink -f "$DRM_CLASS/$b/device/driver" 2>/dev/null); drv=${drv##*/}
    pci=$(readlink -f "$DRM_CLASS/$b/device" 2>/dev/null); pci=${pci##*/}
    vend=$(cat "$DRM_CLASS/$b/device/vendor" 2>/dev/null)
    case $vend in 0x8086) vname=Intel ;; 0x10de) vname=NVIDIA ;; 0x1002) vname=AMD ;; *) vname="?" ;; esac
    NODE_DRV[$b]=$drv; NODE_VEND[$b]=$vname; NODE_DEV[$b]="$DRM_CLASS/$b/device"
    desc=""; [[ -n $pci ]] && have lspci && desc=$(lspci -s "$pci" 2>/dev/null | sed -E 's/^[^ ]+ [^:]+: //')
    drows+=("$b$TAB$vname$TAB${drv:-?}$TAB${pci:-?}$TAB$(stat -c '%A %U:%G' "$n" 2>/dev/null)$TAB$desc")
  done
  ((${#drows[@]})) && tbl "Nœuds de rendu (/dev/dri)" < <(printf 'Nœud\tFabricant\tPilote\tAdresse PCI\tDroits\tPériphérique\n'; printf '%s\n' "${drows[@]}")
  local klog; klog=$( { journalctl -k -b --no-pager -q 2>/dev/null || dmesg 2>/dev/null; } )

  if ((has_intel)); then
    local inode=""
    for b in "${!NODE_VEND[@]}"; do [[ ${NODE_VEND[$b]} == Intel ]] && inode=$b; done
    if [[ -z $inode ]]; then
      warn "iGPU Intel présent mais inutilisable (aucun nœud /dev/dri)" "Le pilote i915/xe n'est pas chargé : Quick Sync est indisponible." \
        "\`lsmod | grep -E 'i915|xe'\` et \`journalctl -k | grep -iE 'i915|xe'\` ; vérifiez que l'iGPU est activé dans le BIOS (même avec une carte graphique) et que linux-firmware est à jour"
    else
      ok "iGPU Intel opérationnel (pilote ${NODE_DRV[$inode]:-?}, $DRI_DIR/$inode)"
      gpu_vainfo "$inode" "Intel Quick Sync"
      local guc; guc=$(grep -iE '\b(guc|huc)\b' <<< "$klog" | sed -E 's/.*\] //' | tail -n 6)
      if grep -qiE '(guc|huc).*(fail|error|not (loaded|authenticated))' <<< "$guc"; then
        warn "Firmware GuC/HuC Intel en erreur" "$guc" "Mettez à jour \`linux-firmware\` ; HuC est requis pour l'encodage basse consommation (Low-Power) sur certaines générations"
      elif [[ -n $guc ]]; then
        info "Firmware GuC/HuC Intel" "$guc"
      fi
      ((QUICK)) || ! have intel_gpu_top || raw "intel_gpu_top (échantillon de 3 s)" "$(tmo 4 intel_gpu_top -l -s 1000 2>&1 | head -n 8)"
    fi
  fi

  if ((has_amd)); then
    local -a anodes=()
    for b in "${!NODE_VEND[@]}"; do [[ ${NODE_VEND[$b]} == AMD ]] && anodes+=("$b"); done
    if ((${#anodes[@]} == 0)); then
      warn "GPU AMD présent mais inutilisable (aucun nœud /dev/dri)" "Le pilote amdgpu (ou radeon) n'est pas chargé : pas d'accélération matérielle." \
        "\`journalctl -k | grep -iE 'amdgpu|radeon'\` ; installez ou mettez à jour \`linux-firmware\` (les cartes récentes exigent un firmware et parfois un noyau HWE récents)"
    fi
    local a dev busy vu vt temps tlvl tedge pw
    for a in "${anodes[@]}"; do
      dev=${NODE_DEV[$a]}
      if [[ ${NODE_DRV[$a]} == radeon ]]; then
        info "GPU AMD sur l'ancien pilote « radeon » ($DRI_DIR/$a)" "Les cartes GCN 1.0/1.1 (Radeon HD 7000, R7/R9 200…) fonctionnent mieux avec amdgpu, qui gère aussi l'encodage VCE." \
          "Si votre carte est GCN 1.x : ajoutez \`radeon.si_support=0 amdgpu.si_support=1\` (ou \`radeon.cik_support=0 amdgpu.cik_support=1\`) à GRUB_CMDLINE_LINUX_DEFAULT, \`sudo update-grub\`, redémarrez"
      fi
      busy=$(cat "$dev/gpu_busy_percent" 2>/dev/null)
      vu=$(cat "$dev/mem_info_vram_used" 2>/dev/null); vt=$(cat "$dev/mem_info_vram_total" 2>/dev/null)
      temps="" tedge=-1 pw=""
      local hm t lbl val
      for hm in "$dev"/hwmon/hwmon*; do
        [[ -d $hm ]] || continue
        for t in "$hm"/temp*_input; do
          [[ -r $t ]] || continue
          val=$(cat "$t" 2>/dev/null); isint "$val" || continue; val=$((val / 1000))
          lbl=$(cat "${t%_input}_label" 2>/dev/null) || lbl=temp
          temps+="$lbl $val °C, "
          [[ $lbl == edge || $tedge -lt 0 ]] && tedge=$val
        done
        pw=$(cat "$hm/power1_average" 2>/dev/null || cat "$hm/power1_input" 2>/dev/null)
        isint "$pw" && pw="$((pw / 1000000)) W" || pw=""
      done
      local msg="Pilote ${NODE_DRV[$a]:-?} ($DRI_DIR/$a)"
      [[ -n $temps ]] && msg+="${NL}Températures : ${temps%, }"
      isint "$busy" && msg+="${NL}Charge : $busy %"
      isint "$vu" && isint "$vt" && ((vt > 0)) && msg+=", mémoire vidéo : $(hbytes "$vu") / $(hbytes "$vt")"
      [[ -n $pw ]] && msg+=", consommation : $pw"
      tlvl=OK
      ((tedge >= 85)) && tlvl=WARN; ((tedge >= 95)) && tlvl=CRIT
      case $tlvl in
        OK)   ok "GPU AMD opérationnel" "$msg" ;;
        WARN) warn "GPU AMD chaud ($tedge °C)" "$msg" "Vérifiez la ventilation du boîtier et l'encrassement du radiateur de la carte" ;;
        CRIT) crit "GPU AMD en surchauffe ($tedge °C)" "$msg" "Vérifiez immédiatement les ventilateurs de la carte graphique" ;;
      esac
      gpu_vainfo "$a" "AMD"
    done
    local afw; afw=$(grep -iE 'amdgpu|radeon' <<< "$klog" | grep -iE 'fail|error|timeout|test failed|hang|gpu reset' | grep -viE 'loaded|version|will use|successfully' | tail -n 6)
    [[ -n $afw ]] && warn "Erreurs du pilote AMD dans le journal du noyau" "$afw" "Mettez à jour \`linux-firmware\` et le noyau (HWE) ; détail : \`journalctl -k -b | grep -i amdgpu\`"
    ((QUICK)) || ! have radeontop || raw "radeontop (échantillon)" "$(tmo 5 radeontop -d - -l 2 2>&1 | tail -n 2)"
  fi

  if ((has_nv)); then
    if have nvidia-smi; then
      local q; q=$(tmo 20 nvidia-smi --query-gpu=index,name,driver_version,pstate,temperature.gpu,utilization.gpu,memory.used,memory.total,power.draw,encoder.stats.sessionCount,persistence_mode --format=csv,noheader,nounits 2>&1)
      if [[ $q == *"NVIDIA-SMI has failed"* || $q == *"couldn't communicate"* || -z $q ]]; then
        crit "Pilote NVIDIA inopérant" "$(head -n 2 <<< "$q")" \
          "Souvent après une mise à jour du noyau : vérifiez \`dkms status\` et \`lsmod | grep nvidia\`, réinstallez le module pour $KERNEL (\`sudo dkms autoinstall\`) puis redémarrez"
      else
        local idx gname gdrv pst temp util mu mt2 pwr encs pers
        while IFS=',' read -r idx gname gdrv pst temp util mu mt2 pwr encs pers; do
          temp=${temp// /}; local lv=OK
          isint "$temp" && ((temp >= 80)) && lv=WARN; isint "$temp" && ((temp >= 90)) && lv=CRIT
          add "$lv" "GPU NVIDIA$idx :${gname}" "Pilote${gdrv}, $temp °C, charge${util} %, mémoire vidéo${mu} /${mt2} Mio,${pwr} W, état${pst}, sessions NVENC actives :${encs}, mode persistance :${pers}"
        done <<< "$q"
        rawcmd "nvidia-smi" nvidia-smi
      fi
      local xid; xid=$(tmo 30 journalctl -k --since "7 days ago" --no-pager -q 2>/dev/null | grep -E 'NVRM: Xid' | tail -n 5)
      [[ -n $xid ]] && warn "Erreurs GPU NVIDIA (Xid) sur 7 jours" "$xid" "Xid 79 = GPU « tombé du bus » (alimentation, PCIe) ; Xid 13/31/43 = erreurs applicatives"
      if ((DOCKER_OK)) && ! have nvidia-ctk && ! have nvidia-container-cli; then
        warn "NVIDIA Container Toolkit absent" "Les conteneurs ne peuvent pas utiliser le GPU NVIDIA." \
          "Installez nvidia-container-toolkit puis \`sudo nvidia-ctk runtime configure --runtime=docker && sudo systemctl restart docker\`"
      fi
    else
      warn "Carte NVIDIA détectée mais pilote absent" "nvidia-smi est introuvable : NVENC/NVDEC indisponibles." "\`sudo ubuntu-drivers install --gpgpu\`"
    fi
  fi

  # Conteneurs ayant accès aux GPU (transcodage)
  ((DOCKER_OK)) || return 0
  local found=0 cname cstate cpriv dri nv caps cuser cgroups
  while IFS=$US read -r cname cstate cpriv dri nv caps cuser cgroups; do
    found=1
    local -a acc=() see=()
    if [[ -n $dri ]]; then
      acc+=("DRM : $dri")
      for b in "${!NODE_VEND[@]}"; do
        if [[ " $dri " == *" $DRI_DIR "* || " $dri " == *" /dev/dri "* || " $dri " == *"/$b "* ]]; then see+=("${NODE_VEND[$b]} ($b)"); fi
      done
    fi
    [[ $nv == true ]] && acc+=("NVIDIA (capacités : ${caps:-par défaut})")
    local msg="Accès : $(join_list ' ; ' "${acc[@]}")"
    ((${#see[@]})) && msg+="${NL}GPU joignables : $(join_list ', ' "${see[@]}")"
    if ((has_amd)) && [[ -n $dri ]] && [[ " ${see[*]} " != *AMD* ]] && ((${#drows[@]})); then
      msg+="${NL}La carte AMD n'est pas transmise à ce conteneur."
    fi
    if [[ $cstate == running ]] && ((!QUICK)) && [[ -n $dri ]]; then
      local inside; inside=$(tmo 15 docker exec "$cname" ls /dev/dri 2>/dev/null | tr '\n' ' ')
      if [[ -n $inside ]]; then msg+="${NL}Vu dans le conteneur : /dev/dri → $inside"; else msg+="${NL}Impossible de lister /dev/dri dans le conteneur."; fi
    fi
    ok "Conteneur $cname : accès GPU configuré" "$msg"
    if [[ $nv == true && $caps != *video* && $caps != *all* ]]; then
      warn "Conteneur $cname : NVENC/NVDEC probablement indisponibles" "Le GPU NVIDIA est attribué sans la capacité « video »." \
        "Ajoutez \`NVIDIA_DRIVER_CAPABILITIES=compute,video,utility\` (ou \`all\`) à l'environnement du conteneur"
    fi
    if [[ -n $dri && -n $cuser && $cuser != 0* && $cuser != root* && $cgroups != *render* && $cgroups != *video* && ! $cgroups =~ [0-9] ]]; then
      info "Conteneur $cname : utilisateur « $cuser » sans groupe render" "Un utilisateur non root doit appartenir au groupe propriétaire de /dev/dri/renderD* pour l'utiliser." \
        "Dans le compose : \`group_add: [\"$(stat -c %g "$(compgen -G "$DRI_DIR/renderD*" | head -n 1)" 2>/dev/null || echo render)\"]\`"
    fi
  done < <(jq -r '.[] |
      ([.HostConfig.Devices[]?.PathOnHost | select(test("^/dev/dri"))] | join(" ")) as $dri |
      ([.HostConfig.DeviceRequests[]? | select((.Driver // "") == "nvidia" or (((.Capabilities // []) | flatten | index("gpu")) != null))] | length > 0) as $req |
      (($req or (.HostConfig.Runtime == "nvidia")) | tostring) as $nv |
      (((.Config.Env // []) | map(select(startswith("NVIDIA_DRIVER_CAPABILITIES="))) | first // "") | ltrimstr("NVIDIA_DRIVER_CAPABILITIES=")) as $capenv |
      ([.HostConfig.DeviceRequests[]?.Capabilities[]?[]?] | join(",")) as $capreq |
      select($dri != "" or $nv == "true") |
      [(.Name | ltrimstr("/")), .State.Status, (.HostConfig.Privileged | tostring), $dri, $nv,
       ($capenv + (if $capreq != "" then " [" + $capreq + "]" else "" end)), (.Config.User // ""),
       ((.HostConfig.GroupAdd // []) | join(","))] | join("\u001f")' "$INSPECT")
  if ((!found)); then
    local priv; priv=$(jq -r '.[] | select(.HostConfig.Privileged == true) | .Name | ltrimstr("/")' "$INSPECT" | paste -sd ' ')
    if [[ -n $priv ]]; then
      info "Aucun GPU attribué explicitement à un conteneur" "Les conteneurs privilégiés ($priv) voient implicitement tous les GPU (voir la section « Sécurité Docker »)." \
        "Préférez \`devices: [\"/dev/dri:/dev/dri\"]\` à \`privileged: true\` pour le transcodage"
    else
      warn "Aucun conteneur n'a accès au GPU" "Votre conteneur de compression vidéo n'a ni /dev/dri ni GPU attribué : l'encodage se fait probablement sur le processeur." \
        "Dans le docker-compose du conteneur : \`devices: [\"/dev/dri:/dev/dri\"]\` (iGPU + carte AMD)"
    fi
  fi
}

check_reseau() {
  section reseau
  if have ip; then
    rawcmd "Adresses IP" ip -br addr
    rawcmd "Routes" ip route
  fi
  local -a rows=()
  local i n st sp dup mtu rxe txe rxd rxp
  for i in /sys/class/net/*; do
    [[ -e $i/device ]] || continue
    n=${i##*/}
    st=$(cat "$i/operstate" 2>/dev/null); sp=$(cat "$i/speed" 2>/dev/null); dup=$(cat "$i/duplex" 2>/dev/null); mtu=$(cat "$i/mtu" 2>/dev/null)
    rxe=$(cat "$i/statistics/rx_errors" 2>/dev/null); txe=$(cat "$i/statistics/tx_errors" 2>/dev/null)
    rxd=$(cat "$i/statistics/rx_dropped" 2>/dev/null); rxp=$(cat "$i/statistics/rx_packets" 2>/dev/null)
    if [[ $st == up && ! -d $i/wireless ]] && isint "$sp" && ((sp > 0 && sp < 1000)); then
      warn "Interface $n négociée à $sp Mb/s" "Un NAS devrait être relié à 1 Gb/s ou plus : câble, port du switch ou de la box à vérifier." \
        "Essayez un autre câble (catégorie 5e ou mieux) et un autre port ; \`sudo ethtool $n\`"
    fi
    if isint "$rxp" && ((rxp > 10000)) && isint "$rxe" && isint "$txe" && (( (rxe + txe) * 1000 / rxp > 1 )); then
      warn "Interface $n : erreurs de transmission" "$rxe erreurs en réception, $txe en émission pour $rxp paquets." "Câble ou port défectueux probable"
    fi
    rows+=("$n$TAB$( [[ $st == up ]] && echo "@OK up" || echo "@INFO $st")$TAB$( isint "$sp" && ((sp > 0)) && echo "$sp Mb/s" || echo "-")$TAB${dup:--}$TAB$mtu$TAB${rxe:-0} / ${txe:-0}$TAB${rxd:-0}")
  done
  ((${#rows[@]})) && tbl "Interfaces physiques" < <(printf 'Interface\tÉtat\tVitesse\tDuplex\tMTU\tErreurs RX / TX\tPaquets RX rejetés\n'; printf '%s\n' "${rows[@]}")

  local gw=""
  have ip && gw=$(ip route show default 2>/dev/null | awk '/default/ {print $3; exit}')
  if have ip && [[ -z $gw ]]; then
    warn "Aucune route par défaut" "Le serveur ne peut pas joindre Internet (tunnels, mises à jour)." "Vérifiez la configuration réseau (\`/etc/netplan/\`)"
  elif [[ -n $gw ]] && have ping; then
    if ping -c 2 -W 2 "$gw" >/dev/null 2>&1; then ok "Passerelle $gw joignable"; else info "La passerelle $gw ne répond pas au ping" "Certaines box filtrent l'ICMP."; fi
  fi
  if getent ahosts cloudflare.com >/dev/null 2>&1; then
    ok "Résolution DNS fonctionnelle"
  else
    warn "Résolution DNS en échec" "Les tunnels Cloudflare et les mises à jour ne peuvent pas fonctionner." "\`resolvectl status\` et vérifiez les serveurs DNS de \`/etc/netplan/\`"
  fi
  if have ping; then
    if ping -c 2 -W 3 1.1.1.1 >/dev/null 2>&1; then ok "Accès Internet (ping 1.1.1.1)"; else info "Pas de réponse au ping de 1.1.1.1" "L'ICMP sortant est peut-être filtré."; fi
  fi
  if have ip; then
    IPV6_GLOBAL=$(ip -6 addr show scope global 2>/dev/null | awk '/inet6/ {print $2}' | grep -viE '^f[cd]' | tr '\n' ' ')
    [[ -n $IPV6_GLOBAL ]] && info "Adresse(s) IPv6 publique(s) : $IPV6_GLOBAL" "Avec IPv6, le serveur peut être joignable directement depuis Internet si la box ne filtre pas les connexions entrantes." \
      "Vérifiez que le pare-feu IPv6 de votre box bloque les connexions entrantes"
  fi
}

check_sauvegardes() {
  section sauvegardes
  local p n last age
  if ((${#POOLS[@]})); then
    for p in "${POOLS[@]}"; do
      n=${SNAP_COUNT[$p]:-0}; last=${SNAP_LAST[$p]:-0}
      if ((n == 0)); then
        if have sanoid; then
          warn "Pool $p : aucun snapshot" "sanoid est installé mais ne crée aucun snapshot de ce pool : sans snapshots, un fichier supprimé ou chiffré par un rançongiciel est définitivement perdu." \
            "Déclarez le pool dans /etc/sanoid/sanoid.conf (section \`[$p]\` avec \`use_template = production\`, \`recursive = yes\`), puis \`sudo systemctl enable --now sanoid.timer\`"
        else
          warn "Pool $p : aucun snapshot" "Sans snapshots, un fichier supprimé ou chiffré par un rançongiciel est définitivement perdu." \
            "Installez sanoid (\`sudo apt install sanoid\`) et configurez /etc/sanoid/sanoid.conf (ex. : 24 horaires, 30 quotidiens, 6 mensuels)"
        fi
      else
        age=$(( (NOW - last) / 3600 ))
        if ((age > 48)); then
          warn "Pool $p : dernier snapshot il y a $((age / 24)) jours" "$n snapshots au total : la création automatique semble arrêtée." \
            "Vérifiez l'outil de snapshots (\`systemctl list-timers | grep -Ei 'sanoid|snap'\`, cron zfs-auto-snapshot)"
        else
          ok "Pool $p : $n snapshots, dernier il y a $age h"
        fi
      fi
    done
    local used; used=$(tmo 60 zfs list -H -p -t filesystem,volume -o name,usedbysnapshots 2>/dev/null \
      | awk -F'\t' '{split($1, a, "/"); s[a[1]] += $2} END {for (k in s) printf "%s\t%.0f\n", k, s[k]}' \
      | numfmt --to=iec-i --suffix=o --format='%.1f' --field=2 -d "$TAB" 2>/dev/null | tr '\t' ' ' | paste -sd ';' | sed 's/;/ ; /g')
    [[ -n $used ]] && info "Espace occupé par les snapshots" "$used"
  fi
  local -a tools=() bk=()
  have sanoid && tools+=(sanoid)
  { [[ -f /etc/cron.d/zfs-auto-snapshot ]] || have zfs-auto-snapshot; } && tools+=(zfs-auto-snapshot)
  local b
  for b in zrepl znapzend pyznap; do have "$b" && tools+=("$b"); done
  ((${#tools[@]})) && info "Outils de snapshots détectés : $(join_list ', ' "${tools[@]}")"

  for b in restic borg borgmatic kopia rclone syncoid duplicity rsnapshot proxmox-backup-client; do have "$b" && bk+=("$b"); done
  if ((DOCKER_OK)); then
    local cb; cb=$(jq -r '.[] | select((.Config.Image // "") | test("duplicati|restic|borg|kopia|backrest|urbackup|rclone|duplicacy|rsnapshot|zrepl|proxmox-backup"; "i")) | "\(.Name | ltrimstr("/")) (\(.Config.Image))"' "$INSPECT" | paste -sd ',' | sed 's/,/, /g')
    [[ -n $cb ]] && bk+=("conteneurs : $cb")
  fi
  local plan; plan=$( { grep -rhsE 'restic|borg|kopia|rclone|syncoid|zfs send|rsync' /etc/crontab /etc/cron.d /var/spool/cron/crontabs 2>/dev/null | grep -v '^[[:space:]]*#'
                        systemctl list-timers --all --no-legend 2>/dev/null | grep -Ei 'restic|borg|kopia|rclone|syncoid|backup|sauvegarde' | grep -v 'dpkg-db-backup'; } | head -n 5)
  if [[ -n $plan || -n ${cb:-} ]]; then
    ok "Sauvegardes planifiées détectées" "$(join_list ' ; ' "${bk[@]}")${plan:+$NL$plan}"
    info "Pensez à tester une restauration" "Une sauvegarde n'est fiable que si sa restauration a été testée ; gardez une copie hors site (règle 3-2-1)."
  elif ((${#bk[@]})); then
    warn "Outils de sauvegarde installés mais rien de planifié" "Installé(s) : $(join_list ', ' "${bk[@]}"), mais aucune tâche planifiée (cron ou minuteur systemd) ne les utilise." \
      "Planifiez la sauvegarde, par ex. dans /etc/cron.d/sauvegarde : \`30 3 * * * root /usr/sbin/syncoid -r <pool>/<dataset> <destination>\`"
  else
    warn "Aucun outil de sauvegarde détecté" "La redondance ZFS (miroir, RAIDZ) protège d'une panne de disque, pas d'une suppression, d'un rançongiciel, d'un incendie ou d'une erreur de manipulation. Règle 3-2-1 : 3 copies, 2 supports, 1 hors site." \
      "Par exemple \`syncoid\` (paquet sanoid) vers un autre pool ou serveur, ou restic/kopia vers un stockage distant chiffré"
  fi
}

# ------------------------------------------------- tunnels Cloudflare -----
CF_META_RE='Updated to new configuration|Starting metrics server|Version [0-9]|version=[0-9]|outdated|Registered tunnel connection|Unregistered tunnel connection|Connection terminated|Lost connection|Retrying connection|Serve tunnel error|Starting tunnel'

cf_get() {   # cf_get <pid|""> <url>  → corps, saut de ligne, code HTTP
  local pid=$1 url=$2
  have curl || return 1
  if [[ -n $pid && $pid != 0 ]] && have nsenter; then
    tmo 10 nsenter -t "$pid" -n -- curl -sS -m 5 -w '\n%{http_code}' "$url" 2>/dev/null
  else
    tmo 10 curl -sS -m 5 -w '\n%{http_code}' "$url" 2>/dev/null
  fi
}

cf_analyse() {   # cf_analyse nom méta récent pid type(docker|host) référence
  local name=$1 meta=$2 recent=$3 pid=$4 kind=$5 ref=$6
  local ver logcmd upd
  ver=$(grep -oE '(Version|version)[ =]"?[0-9]{4}\.[0-9]+\.[0-9]+' "$meta" | tail -n 1 | grep -oE '[0-9]{4}\.[0-9]+\.[0-9]+')
  if [[ $kind == docker ]]; then
    logcmd="docker logs --since 24h $name"
    upd="Dans le dossier du projet : \`docker compose pull && docker compose up -d\` (ou \`docker pull cloudflare/cloudflared:latest\` puis recréez le conteneur)"
  else
    logcmd="journalctl -u $ref --since '24 hours ago'"
    upd="\`sudo apt update && sudo apt install --only-upgrade cloudflared\`"
  fi

  # État de la connexion : point de contrôle /ready du serveur de métriques
  local maddr; maddr=$(grep -oE 'Starting metrics server on [^ ]+' "$meta" | tail -n 1 | awk '{print $5}'); maddr=${maddr%/metrics}
  local -a cands=()
  if [[ -n $maddr ]]; then
    local mh=${maddr%:*} mp=${maddr##*:}
    case $mh in ""|0.0.0.0|"[::]"|"::"|localhost) mh=127.0.0.1 ;; esac
    cands+=("$mh:$mp")
  fi
  cands+=(127.0.0.1:20241 127.0.0.1:20242 127.0.0.1:20243 127.0.0.1:20244 127.0.0.1:20245)
  local a out code="" body rdy="" raddr="" cpid=""
  [[ $kind == docker ]] && cpid=$pid
  for a in "${cands[@]}"; do
    out=$(cf_get "$cpid" "http://$a/ready") || continue
    code=${out##*"$NL"}; body=${out%"$NL"*}
    [[ $code =~ ^[0-9]{3}$ && $code != 000 ]] || continue
    raddr=$a; rdy=$(jq -r '.readyConnections // empty' <<< "$body" 2>/dev/null); break
  done
  local locs; locs=$(grep -hoE 'location=[A-Za-z0-9]+' "$meta" "$recent" 2>/dev/null | tail -n 8 | cut -d= -f2 | sort -u | tr '\n' ' ')
  if [[ -n $raddr ]]; then
    if isint "$rdy" && ((rdy > 0)); then
      ok "Tunnel « $name » connecté" "$rdy connexion(s) active(s) vers Cloudflare${locs:+ (centres : ${locs% })}"
    else
      crit "Tunnel « $name » non connecté" "Le point de contrôle /ready répond HTTP $code (connexions prêtes : ${rdy:-0}) : les services publiés sont injoignables." \
        "Consultez \`$logcmd\` ; cloudflared doit pouvoir sortir vers Internet sur le port 7844 (UDP pour QUIC, TCP en repli)"
    fi
    local m v2
    m=$(cf_get "$cpid" "http://$raddr/metrics"); m=${m%"$NL"*}
    v2=$(grep -oE 'build_info\{[^}]*\}' <<< "$m" | grep -oE '[{,]version="[^"]+"' | head -n 1 | cut -d'"' -f2)
    [[ -n $v2 ]] && ver=$v2
  else
    local lreg ldown
    lreg=$(grep -n 'Registered tunnel connection' "$meta" | tail -n 1 | cut -d: -f1)
    ldown=$(grep -nE 'Unregistered tunnel connection|Connection terminated|Lost connection|Retrying connection|Serve tunnel error' "$meta" | tail -n 1 | cut -d: -f1)
    if [[ -n $lreg ]] && { [[ -z $ldown ]] || ((lreg > ldown)); }; then
      info "Tunnel « $name » : connecté d'après ses journaux" "Métriques inaccessibles : vérification indirecte${locs:+ (centres : ${locs% })}."
    elif [[ -n $ldown ]]; then
      warn "Tunnel « $name » : déconnexions récentes" "$(sed -n "${ldown}p" "$meta" | cut -c1-250)" "\`$logcmd\` ; vérifiez l'accès sortant (port 7844)"
    else
      info "État du tunnel « $name » indéterminé" "Ni métriques accessibles, ni événement de connexion dans les journaux."
    fi
  fi

  if [[ -z $ver ]]; then
    if [[ $kind == docker ]] && ((!QUICK)); then
      ver=$(tmo 15 docker exec "$ref" cloudflared --version 2>/dev/null | grep -oE '[0-9]{4}\.[0-9]+\.[0-9]+' | head -n 1)
    elif [[ $kind == host ]] && have cloudflared; then
      ver=$(cloudflared --version 2>/dev/null | grep -oE '[0-9]{4}\.[0-9]+\.[0-9]+' | head -n 1)
    fi
  fi
  local warned=0
  if [[ $ver =~ ^([0-9]{4})\.([0-9]+)\. ]]; then
    local age=$(( ($(date +%Y) * 12 + 10#$(date +%m)) - (BASH_REMATCH[1] * 12 + 10#${BASH_REMATCH[2]}) ))
    if ((age >= 12)); then
      warned=1
      warn "cloudflared « $name » obsolète (version $ver, ~$age mois)" "Cloudflare ne prend en charge que les versions de cloudflared publiées depuis moins d'un an." "$upd"
    elif ((age >= 6)); then
      info "cloudflared « $name » : version $ver (~$age mois)" "Une version plus récente est probablement disponible." "$upd"
    else
      ok "cloudflared « $name » récent (version $ver)"
    fi
  else
    info "Version de cloudflared « $name » inconnue"
  fi
  local outd; outd=$(grep -i 'outdated' "$meta" | tail -n 1 | sed -E 's/^[^ ]+ +[A-Z]{3} +//')
  [[ -n $outd ]] && ((!warned)) && info "cloudflared « $name » signale une mise à jour" "$outd" "$upd"

  local nerr origins
  nerr=$(grep -c ' ERR ' "$recent")
  origins=$(grep ' ERR ' "$recent" | grep -oE 'originService=[^ ]+' | sort | uniq -c | sort -rn | head -n 5 | awk '{sub(/originService=/, "", $2); printf "%s (%d erreur(s))\n", $2, $1}')
  if [[ -n $origins ]]; then
    warn "Tunnel « $name » : service(s) injoignable(s) (24 h)" "cloudflared n'a pas pu joindre :$NL$origins" \
      "Vérifiez que ces conteneurs tournent et partagent un réseau Docker avec cloudflared (\`docker network inspect <réseau>\`)"
  elif ((nerr > 20)); then
    warn "Tunnel « $name » : $nerr erreurs en 24 h" "$(grep ' ERR ' "$recent" | tail -n 3 | cut -c1-300)" "\`$logcmd\`"
  elif ((nerr > 0)); then
    info "Tunnel « $name » : $nerr erreur(s) en 24 h" "$(grep ' ERR ' "$recent" | tail -n 3 | cut -c1-300)"
  else
    ok "Tunnel « $name » : aucune erreur en 24 h"
  fi
  raw "Journal cloudflared « $name » (24 h, extrait)" "$(tail -n 60 "$recent")"

  # Routage (ingress) des tunnels gérés depuis le tableau de bord : journalisé au démarrage
  local cl; cl=$(grep 'Updated to new configuration' "$meta" | tail -n 1)
  if [[ -n $cl ]]; then
    local js; js=$(sed -E 's/.*config="(.*)" version=[0-9]+.*/\1/' <<< "$cl" | sed -e 's/\\"/"/g' -e 's/\\\\/\\/g')
    if jq -e '.ingress' >/dev/null 2>&1 <<< "$js"; then
      local h s pa ac
      while IFS=$US read -r h s pa ac; do INGRESS+=("$h$US$s$US$pa$US$ac$US$name"); done < <(jq -r '.ingress[]? | [(.hostname // "*"), (.service // ""), (.path // ""), ((.originRequest.access.required // false) | tostring)] | join("\u001f")' <<< "$js")
      [[ $(jq -r '."warp-routing".enabled // false' <<< "$js") == true ]] && info "Tunnel « $name » : routage WARP activé" \
        "Le tunnel donne accès à votre réseau privé aux appareils WARP autorisés de votre organisation Zero Trust." "Vérifiez les règles (Zero Trust > Networks) ou désactivez-le s'il ne sert pas"
      local notls; notls=$(jq -r '.ingress[]? | select(.originRequest.noTLSVerify == true) | .hostname // "*"' <<< "$js" | tr '\n' ' ')
      [[ -n $notls ]] && info "Vérification TLS vers l'origine désactivée : $notls" "noTLSVerify=true : acceptable pour un service local en HTTPS auto-signé."
    fi
  fi
}

cf_parse_local() {   # cf_parse_local fichier-config nom
  local f=$1 name=$2 h s
  while IFS=$US read -r h s; do INGRESS+=("${h}${US}${s}${US}${US}false${US}${name}"); done < <(awk '
    /^[[:space:]]*#/ {next}
    /^[[:space:]]*-[[:space:]]*hostname:/ {h = $0; sub(/.*hostname:[[:space:]]*/, "", h); gsub(/["\047]/, "", h); sub(/[[:space:]]+#.*/, "", h); next}
    /^[[:space:]]*-?[[:space:]]*service:/ {s = $0; sub(/.*service:[[:space:]]*/, "", s); gsub(/["\047]/, "", s); sub(/[[:space:]]+#.*/, "", s); printf "%s%c%s\n", (h == "" ? "*" : h), 31, s; h = ""}' "$f")
  local d x m
  d=$(dirname "$f")
  for x in "$d"/*.json "$d"/cert.pem; do
    [[ -f $x ]] || continue
    m=$(stat -c '%a' "$x")
    (( 8#$m & 8#044 )) && warn "Identifiants cloudflared lisibles par d'autres : $x ($m)" "Ce fichier permet de faire tourner le tunnel (et cert.pem de gérer tunnels et DNS de la zone)." \
      "Restreignez-le : \`sudo chmod 600 $x\` (en le donnant à l'utilisateur du conteneur avec \`chown\` si besoin)"
  done
  [[ -f $d/cert.pem ]] && info "Certificat d'origine cloudflared présent ($d/cert.pem)" "Il permet de créer ou supprimer des tunnels et des enregistrements DNS : inutile pour faire tourner un tunnel existant." \
    "Conservez-le hors du serveur si vous n'en avez pas besoin"
}

cf_local_config() {   # chemin, côté hôte, du config.yml d'un conteneur cloudflared
  local id=$1 c src dst cpath
  cpath=$(jq -r --arg id "$id" '.[] | select(.Id == $id) | (.Args // []) as $a
    | ([range(0; $a | length) as $i | if $a[$i] == "--config" then $a[$i + 1] elif ($a[$i] | startswith("--config=")) then ($a[$i] | ltrimstr("--config=")) else empty end] | first) // ""' "$INSPECT")
  local -a cands=()
  [[ -n $cpath ]] && cands+=("$cpath")
  cands+=(/etc/cloudflared/config.yml /etc/cloudflared/config.yaml /home/nonroot/.cloudflared/config.yml /home/nonroot/.cloudflared/config.yaml /root/.cloudflared/config.yml)
  for c in "${cands[@]}"; do
    while IFS=$US read -r src dst; do
      [[ $c == "$dst"/* || $c == "$dst" ]] || continue
      local hp="$src${c#"$dst"}"
      [[ -f $hp ]] && { echo "$hp"; return; }
    done < <(jq -r --arg id "$id" '.[] | select(.Id == $id) | .Mounts[]? | [.Source, .Destination] | join("\u001f")' "$INSPECT")
  done
}

cf_docker() {
  local id=$1 name=$2 net=$3 pid=$4 state=$5
  local meta="$WORK/cf_${name}_meta.log" recent="$WORK/cf_${name}_24h.log"
  if [[ $state != running ]]; then
    crit "Tunnel cloudflared « $name » arrêté" "État du conteneur : $state. Les services publiés via ce tunnel sont injoignables depuis Internet." \
      "\`docker start $name\` puis \`docker logs --tail 50 $name\`"
  fi
  tmo 120 docker logs "$id" 2>&1 | grep -E "$CF_META_RE" | tail -n 400 > "$meta"
  tmo 60 docker logs --since 24h "$id" 2>&1 | tail -n 20000 > "$recent"
  CF_NETMODE[$name]=$net
  local pol; pol=$(jq -r --arg id "$id" '.[] | select(.Id == $id) | .HostConfig.RestartPolicy.Name // ""' "$INSPECT")
  if [[ -z $pol || $pol == no ]]; then
    warn "Tunnel « $name » sans redémarrage automatique" "Le conteneur cloudflared a été lancé sans politique de redémarrage : après un redémarrage du NAS ou de Docker, vos services ne seront plus joignables depuis Internet." \
      "Immédiatement : \`docker update --restart unless-stopped $name\` ; idéalement, décrivez le tunnel dans un docker-compose avec \`restart: unless-stopped\`"
  fi
  CF_NETS+=" $(jq -r --arg id "$id" '.[] | select(.Id == $id) | (.NetworkSettings.Networks // {}) | keys[]' "$INSPECT" | tr '\n' ' ')"
  cf_analyse "$name" "$meta" "$recent" "$pid" docker "$id"
  local tok; tok=$(jq -r --arg id "$id" '.[] | select(.Id == $id)
    | ((((.Config.Env // []) | map(select(startswith("TUNNEL_TOKEN="))) | length) > 0) or (((.Args // []) | map(select(startswith("--token"))) | length) > 0))' "$INSPECT")
  [[ $tok == true ]] && info "Tunnel « $name » : jeton dans la configuration du conteneur" \
    "Le jeton est lisible via \`docker inspect\` par tout membre du groupe docker, et dans votre fichier compose ou .env." \
    "Réservez le groupe docker aux administrateurs et protégez le fichier (\`chmod 600\`) ; en cas de doute, régénérez le jeton (Zero Trust > Networks > Tunnels)"
  local cfg; cfg=$(cf_local_config "$id")
  [[ -n $cfg ]] && cf_parse_local "$cfg" "$name"
}

cf_host() {
  local unit=$1 pid=$2 name
  name=${unit%.service}; [[ -n $name ]] || name=cloudflared
  local meta="$WORK/cf_host_meta.log" recent="$WORK/cf_host_24h.log"
  : > "$meta"; : > "$recent"
  if [[ -n $unit ]]; then
    systemctl is-active --quiet "$unit" || crit "Service $unit arrêté" "Les services publiés via ce tunnel sont injoignables depuis Internet." "\`sudo systemctl start $unit\` puis \`journalctl -u $unit -n 50\`"
    tmo 60 journalctl -u "$unit" --no-pager -q -o cat 2>/dev/null | grep -E "$CF_META_RE" | tail -n 400 > "$meta"
    tmo 60 journalctl -u "$unit" --since "24 hours ago" --no-pager -q -o cat 2>/dev/null | tail -n 20000 > "$recent"
  fi
  CF_NETMODE[$name]=host
  cf_analyse "$name" "$meta" "$recent" "$pid" host "$unit"
  if [[ -n $unit ]]; then
    local fp; fp=$(systemctl show -p FragmentPath --value "$unit" 2>/dev/null)
    if [[ -f $fp ]] && grep -qE -- '--token|TUNNEL_TOKEN' "$fp"; then
      local m; m=$(stat -c '%a' "$fp")
      (( 8#$m & 8#004 )) && warn "Jeton du tunnel lisible par tous ($fp, droits $m)" "Tout utilisateur local peut le lire et faire tourner un connecteur sur votre tunnel." \
        "\`sudo chmod 600 $fp && sudo systemctl daemon-reload\`"
    fi
  fi
  local c
  for c in /etc/cloudflared/config.yml /etc/cloudflared/config.yaml /root/.cloudflared/config.yml; do
    [[ -f $c ]] && { cf_parse_local "$c" "$name"; break; }
  done
}

cf_exposure() {
  local -A IDX=()
  local k v
  while IFS=$US read -r k v; do [[ -n $k ]] && IDX[$k]=$v; done < <(jq -r '.[] | (.Name | ltrimstr("/")) as $n
    | ([$n, ((.Config.Labels // {})["com.docker.compose.service"] // empty)]
       + [((.NetworkSettings.Networks // {}) | to_entries[] | .value | ((.Aliases // []) + (.DNSNames // []) + [(.IPAddress // "")])[])]
       | map(select(. != null and . != "")) | unique)[] | "\(.)\u001f\($n)"' "$INSPECT")
  local myips; myips=" 127.0.0.1 localhost ::1 host.docker.internal $(hostname -I 2>/dev/null) "
  local -a irows=()
  local r h s pa ac tn host port scheme tgt nm
  for r in "${INGRESS[@]}"; do
    IFS=$US read -r h s pa ac tn <<< "$r"
    tgt="" host=""
    if [[ $s =~ ^([a-z0-9+.-]+)://\[?([^]/:]+)\]?(:([0-9]+))? ]]; then
      scheme=${BASH_REMATCH[1]} host=${BASH_REMATCH[2]} port=${BASH_REMATCH[4]}
      if [[ -z $port ]]; then case $scheme in https) port=443 ;; http) port=80 ;; ssh) port=22 ;; rdp) port=3389 ;; esac; fi
      nm=${CF_NETMODE[$tn]:-}
      if [[ -n ${IDX[$host]:-} ]]; then
        tgt=${IDX[$host]}
      elif [[ $myips == *" $host "* ]]; then
        if [[ $nm == container:* ]]; then
          tgt=$(jq -r --arg c "${nm#container:}" '.[] | select(.Id == $c or (.Name | ltrimstr("/")) == $c) | .Name | ltrimstr("/")' "$INSPECT")
        elif [[ $nm == host || ( $host != 127.0.0.1 && $host != localhost && $host != ::1 ) ]]; then
          tgt=${PORTMAP[$port]:-"hôte, port $port"}
        else
          tgt="? (localhost dans le conteneur cloudflared)"
        fi
      else
        tgt="externe : $host"
      fi
    else
      [[ $h == "*" && $s == http_status:* ]] && continue   # règle par défaut normale
      tgt="—"
    fi
    if [[ $h == "*" ]]; then
      warn "Tunnel « $tn » : la règle par défaut mène à un service ($s)" "Tout nom d'hôte pointant vers ce tunnel atteindra ce service." "Terminez la liste des routes par \`service: http_status:404\`"
    fi
    if [[ -n $tgt && -n ${CNAMES[$tgt]:-} && $h != "*" ]]; then
      [[ ", ${EXPOSED[$tgt]:-}, " == *", $h, "* ]] || EXPOSED[$tgt]+="${EXPOSED[$tgt]:+, }$h"
      [[ $myips == *" ${host:-?} "* && ${PORTMAP[$port]:-} == "$tgt" ]] && VIA_PORT[$tgt]+=" $port "
    fi
    irows+=("$h$TAB$s${pa:+ (chemin $pa)}$TAB${tgt:-—}$TAB$( [[ $ac == true ]] && echo "@OK exigé par le tunnel" || echo "@INFO à vérifier côté Cloudflare")$TAB$tn")
  done
  if ((${#irows[@]})); then
    tbl "Services publiés via les tunnels" < <(printf "Nom d'hôte public\tService d'origine\tConteneur\tCloudflare Access\tTunnel\n"; printf '%s\n' "${irows[@]}")
    local -a hosts=()
    for k in "${!EXPOSED[@]}"; do hosts+=("${EXPOSED[$k]} → $k"); done
    info "${#EXPOSED[@]} conteneur(s) publié(s) sur Internet (${#irows[@]} route(s))" "$(printf '%s\n' "${hosts[@]}")"
    local noacc=""
    for r in "${INGRESS[@]}"; do IFS=$US read -r h s pa ac tn <<< "$r"; [[ $h != "*" && $ac != true && " $noacc" != *" $h "* ]] && noacc+="$h "; done
    if [[ -n $noacc ]]; then
      info "Protection Cloudflare Access à confirmer : $noacc" "Le serveur ne voit pas les applications Access configurées dans le tableau de bord Cloudflare." \
        "Zero Trust > Access > Applications : protégez chaque nom d'hôte (connexion + MFA), ou activez « Protect with Access » dans la route publique du tunnel"
    else
      ok "Cloudflare Access exigé au niveau du tunnel pour tous les noms d'hôte"
    fi
  elif ((CF_FOUND)); then
    local reach c
    reach=$(jq -r --arg nets "$CF_NETS" '($nets | split(" ") | map(select(. != "" and . != "host" and . != "none"))) as $cf
      | .[] | select(.State.Status == "running") | (.Name | ltrimstr("/")) as $n
      | select(((.NetworkSettings.Networks // {}) | keys) as $k | ($cf | any(. as $x | ($k | index($x)) != null)))
      | select(((.Config.Image // "") + $n) | test("cloudflared") | not) | $n' "$INSPECT" | sort -u)
    for c in $reach; do REACHABLE[$c]=1; done
    local rmsg="Les routes sont gérées dans le tableau de bord Cloudflare et n'apparaissent pas dans les journaux conservés."
    [[ -n $reach ]] && rmsg+=" Conteneurs joignables par le tunnel (réseau Docker partagé) : $(tr '\n' ' ' <<< "$reach")"
    info "Routage des tunnels non visible depuis le serveur" "$rmsg" \
      "Redémarrez le conteneur cloudflared (il journalise ses routes au démarrage), puis relancez l'audit"
  fi
  local pp
  for c in "${!EXPOSED[@]}"; do
    pp=$(jq -r --arg n "$c" '.[] | select((.Name | ltrimstr("/")) == $n) | (.NetworkSettings.Ports // {}) | to_entries[] | select(.value != null)
      | .value[] | select((.HostIp // "") == "" or .HostIp == "0.0.0.0" or .HostIp == "::") | .HostPort' "$INSPECT" | sort -un | tr '\n' ' ')
    local x restants=""
    for x in $pp; do [[ ${VIA_PORT[$c]:-} == *" $x "* ]] || restants+="$x "; done
    pp=$restants
    [[ -n $pp ]] && info "$c : aussi accessible directement (port ${pp% })" \
      "En plus du tunnel, ce service est joignable sans passer par Cloudflare (ni Access, ni WAF) depuis tout le réseau local — et depuis Internet si la box redirige ce port ou via IPv6. Normal si vous l'utilisez en local." \
      "Sinon, supprimez \`ports:\` (cloudflared passe par le réseau Docker) ou limitez à \`127.0.0.1:PORT:PORT\`"
  done
}

check_cloudflare() {
  section cloudflare
  if ((DOCKER_OK)); then
    local cid cname cnet cpid cstate
    while IFS=$US read -r cid cname cnet cpid cstate; do
      CF_FOUND=1
      cf_docker "$cid" "$cname" "$cnet" "$cpid" "$cstate"
    done < <(jq -r '.[] | select(((.Config.Image // "") + " " + (.Path // "") + " " + ((.Args // []) | join(" "))) | test("cloudflared"))
      | [.Id, (.Name | ltrimstr("/")), (.HostConfig.NetworkMode // ""), ((.State.Pid // 0) | tostring), .State.Status] | join("\u001f")' "$INSPECT")
  fi
  local -a hostpids=()
  local p unit
  for p in $(pgrep -x cloudflared 2>/dev/null); do
    grep -qE 'docker|containerd|libpod|kubepods' "/proc/$p/cgroup" 2>/dev/null || hostpids+=("$p")
  done
  unit=$(systemctl list-unit-files --type=service --no-legend 'cloudflared*' 2>/dev/null | awk '{print $1}' | grep -v update | head -n 1)
  if ((${#hostpids[@]})) || [[ -n $unit ]]; then
    CF_FOUND=1
    cf_host "$unit" "${hostpids[0]:-}"
  fi
  if ((!CF_FOUND)); then
    info "Aucun tunnel cloudflared détecté" "Ni conteneur ni service cloudflared sur cet hôte." "Si vos tunnels tournent sur une autre machine, auditez-la aussi"
    return
  fi
  cf_exposure
}

# ------------------------------------------------- configuration (audit.conf) --
declare -A CFG=()
charger_conf() {
  [[ -f $CONF_FILE ]] || return 0
  local line k v
  while IFS= read -r line || [[ -n $line ]]; do
    [[ $line =~ ^[[:space:]]*([A-Z_]+)[[:space:]]*=[[:space:]]*(.*)$ ]] || continue
    k=${BASH_REMATCH[1]}; v=${BASH_REMATCH[2]}
    v=${v%"${v##*[![:space:]]}"}
    [[ $v == \"*\" || $v == \'*\' ]] && v=${v:1:${#v}-2}
    CFG[$k]=$v
  done < "$CONF_FILE"
}
cfg() { printf '%s' "${CFG[$1]:-${2:-}}"; }
oui() { [[ ${1,,} =~ ^(oui|o|yes|y|1|true|on)$ ]]; }

# Requête HTTP(S) : corps dans $1, en-têtes dans $1.h ; affiche « code url_de_redirection »
http_get() {   # http_get fichier url [options curl…]
  local f=$1 url=$2; shift 2
  tmo 25 curl -sS -m 20 -A "Audite-moi/$VERSION" -o "$f" -D "$f.h" -w '%{http_code} %{redirect_url}' "$@" "$url" 2>/dev/null || echo "000 "
}
en_plage() {   # en_plage IP CIDR… → vrai si l'IP appartient à l'une des plages
  python3 -c 'import ipaddress,sys
ip = ipaddress.ip_address(sys.argv[1])
sys.exit(0 if any(ip in ipaddress.ip_network(n, strict=False) for n in sys.argv[2:]) else 1)' "$@" 2>/dev/null
}
DNS_MODE=doh
doh() {   # doh nom A|AAAA → adresses publiques (DNS de Cloudflare en HTTPS : les surcharges DNS locales d'OPNsense sont ignorées)
  local t=1; [[ $2 == AAAA ]] && t=28
  case $DNS_MODE in
    doh) tmo 12 curl -sS -m 10 -H 'accept: application/dns-json' "https://cloudflare-dns.com/dns-query?name=$1&type=$2" 2>/dev/null \
           | jq -r --argjson t "$t" '.Answer[]? | select(.type == $t) | .data' 2>/dev/null ;;
    dig) tmo 12 dig +short +time=5 "@1.1.1.1" "$1" "$2" 2>/dev/null | grep -E '^[0-9a-fA-F.:]+$' ;;
    *)   [[ $2 == A ]] && getent ahostsv4 "$1" 2>/dev/null | awk '{print $1}' | sort -u ;;
  esac
}
derniere_version() {   # derniere_version dépôt-github [majeure] → dernière version publiée (de la majeure)
  tmo 20 curl -sS -m 15 "https://api.github.com/repos/$1/releases?per_page=60" 2>/dev/null \
    | jq -r --arg m "${2:-}" '[.[]? | select(.prerelease == false and .draft == false) | .tag_name | ltrimstr("v")
        | select(test("^[0-9]+\\.[0-9]+\\.[0-9]+$")) | select($m == "" or startswith($m + "."))]
        | sort_by(split(".") | map(tonumber)) | last // empty' 2>/dev/null
}
version_lt() { [[ $1 != "$2" && $(printf '%s\n%s\n' "$1" "$2" | sort -V | head -n 1) == "$1" ]]; }

CF_V4=(173.245.48.0/20 103.21.244.0/22 103.22.200.0/22 103.31.4.0/22 141.101.64.0/18 108.162.192.0/18 190.93.240.0/20 188.114.96.0/20
       197.234.240.0/22 198.41.128.0/17 162.158.0.0/15 104.16.0.0/13 104.24.0.0/14 172.64.0.0/13 131.0.72.0/22)
NC_PUBLIC=0 PUB_IP=""

check_exposition() {
  section exposition
  if ! oui "$(cfg EXTERNE oui)"; then info "Test depuis Internet désactivé (EXTERNE=non dans audit.conf)"; return; fi
  if ! have curl; then info "curl absent : test depuis Internet impossible" "" "\`sudo apt install curl\`"; return; fi
  local -a hotes=()
  local r h
  for r in "${INGRESS[@]}"; do h=${r%%"$US"*}; [[ $h == "*" || $h == \** ]] || hotes+=("$h"); done
  for h in $(cfg DOMAINES_EXTRA); do hotes+=("$h"); done
  mapfile -t hotes < <(printf '%s\n' "${hotes[@]}" | grep . | sort -u)
  if ((${#hotes[@]} == 0)); then
    info "Aucun nom d'hôte public à tester" "Les routes des tunnels ne sont pas visibles et DOMAINES_EXTRA est vide." "Ajoutez vos noms d'hôte dans /etc/audite-moi/audit.conf : \`DOMAINES_EXTRA=\"nextcloud.exemple.fr stash.exemple.fr\"\`"
    return
  fi
  note "Test depuis Internet de ${#hotes[@]} nom(s) d'hôte…"
  local m
  for m in doh dig local; do
    [[ $m == dig ]] && ! have dig && continue
    DNS_MODE=$m; [[ -n $(doh cloudflare.com A) ]] && break
    DNS_MODE=""
  done
  if [[ -z $DNS_MODE ]]; then
    info "Test depuis Internet impossible" "Le serveur n'arrive pas à interroger le DNS public : pas d'accès à Internet, ou sorties filtrées." "Vérifiez que le NAS peut joindre https://cloudflare-dns.com (port 443)"
    return
  fi
  [[ $DNS_MODE == local ]] && note "DNS public injoignable en HTTPS : résolution par le DNS local (les surcharges d'OPNsense peuvent fausser le résultat)."
  local live; live=$(tmo 10 curl -sS -m 8 https://www.cloudflare.com/ips-v4 2>/dev/null | grep -E '^[0-9.]+/[0-9]+$')
  [[ -n $live ]] && mapfile -t CF_V4 <<< "$live"
  PUB_IP=$(tmo 10 curl -sS -m 8 https://1.1.1.1/cdn-cgi/trace 2>/dev/null | awk -F= '$1 == "ip" {print $2}')
  [[ -n $PUB_IP ]] && info "Adresse IP publique de la maison : $PUB_IP" "Telle que vue depuis Internet (via Cloudflare)."

  local -a rows=()
  for h in "${hotes[@]}"; do expo_hote "$h"; done
  tbl "Ce qu'un visiteur voit depuis Internet" < <(printf "Nom d'hôte\tAdresses publiques\tProtection\tApplication\tAuthentification\tHSTS\n"; printf '%s\n' "${rows[@]}")

  # IP personnelle publiée dans le DNS (conteneur de DNS dynamique, enregistrements non proxifiés)
  local -a noms=()
  if ((DOCKER_OK)); then
    mapfile -t noms < <(jq -r '.[] | select((.Config.Image // "") | test("ddns|ddclient"; "i")) | (.Config.Env // []) as $e
      | ([$e[] | select(startswith("ZONE=") or startswith("DOMAINS=") or startswith("DOMAIN="))] | map(split("=")[1]) | join(",")) as $z
      | ([$e[] | select(startswith("SUBDOMAIN="))] | map(split("=")[1]) | first // "") as $s
      | ($z | split(",")[] | select(. != "") | if $s != "" then $s + "." + . else . end)' "$INSPECT" 2>/dev/null | sort -u)
  fi
  local n ip
  for n in "${noms[@]}"; do
    for ip in $(doh "$n" A); do
      if [[ -n $PUB_IP && $ip == "$PUB_IP" ]]; then
        warn "Votre IP personnelle est publiée dans le DNS ($n → $ip)" "Ce nom n'est pas protégé par le proxy Cloudflare (nuage gris) : n'importe qui peut trouver l'adresse de votre box et y chercher des ports ouverts, sans passer par Cloudflare." \
          "Si ce nom ne sert qu'à vous (VPN…), gardez-le mais vérifiez qu'aucun port inutile n'est redirigé sur OPNsense ; sinon, activez le proxy (nuage orange, \`PROXIED=true\` dans cloudflare-ddns) ou supprimez l'enregistrement"
      fi
    done
  done
}

expo_hote() {   # appelée par check_exposition (alimente « rows »)
  local h=$1 ips ips6 ip cf=0 hors=() a
  ips=$(doh "$h" A); ips6=$(doh "$h" AAAA)
  if [[ -z $ips$ips6 ]]; then
    warn "$h ne résout pas dans le DNS public" "Le nom n'existe pas (ou plus) côté Internet." "Vérifiez l'enregistrement DNS dans Cloudflare"
    rows+=("$h$TAB@WARN aucune$TAB$TAB$TAB$TAB"); return
  fi
  for ip in $ips; do
    if en_plage "$ip" "${CF_V4[@]}"; then cf=1
    else hors+=("$ip"); fi
  done
  local direct=""
  if ((${#hors[@]})); then
    if [[ -n $PUB_IP && " ${hors[*]} " == *" $PUB_IP "* ]]; then
      crit "$h pointe directement sur votre box ($PUB_IP)" "Ce nom contourne Cloudflare : ni tunnel, ni Access, ni WAF. Les visiteurs arrivent sur les ports redirigés par OPNsense." \
        "Dans Cloudflare > DNS, activez le proxy (nuage orange) pour ce nom ou remplacez-le par la route publique du tunnel"
      direct=1
    else
      info "$h résout hors de Cloudflare : ${hors[*]}" "Service hébergé ailleurs, ou enregistrement non proxifié."
    fi
  fi
  ((cf)) || { rows+=("$h$TAB$(tr '\n' ' ' <<< "$ips")$TAB${direct:+@CRIT direct}$TAB$TAB$TAB"); return; }
  a=$(head -n 1 <<< "$ips")
  local f="$WORK/web_${h//[^A-Za-z0-9]/_}" res code loc
  res=$(http_get "$f" "https://$h/" --resolve "$h:443:$a")
  code=${res%% *}; loc=${res#* }
  if [[ $code == 000 ]]; then
    warn "$h injoignable depuis Internet" "Pas de réponse HTTPS via Cloudflare." "Vérifiez le tunnel et la route publique dans Cloudflare Zero Trust"
    rows+=("$h$TAB$a$TAB@WARN injoignable$TAB$TAB$TAB"); return
  fi
  local hsts="non"; grep -qi '^strict-transport-security:' "$f.h" && hsts="oui"
  if [[ $loc == *cloudflareaccess.com* || $loc == */cdn-cgi/access/* ]]; then
    ok "$h protégé par Cloudflare Access" "Les visiteurs doivent s'authentifier auprès de Cloudflare avant d'atteindre l'application."
    rows+=("$h$TAB$a$TAB@OK Cloudflare Access$TAB(masquée)$TAB@OK avant l'application$TAB$hsts"); return
  fi
  local appli="inconnue" auth="?"
  if grep -qi '^cf-mitigated: *challenge' "$f.h"; then
    info "$h : Cloudflare présente un défi anti-robot" "Le test automatique ne voit pas l'application (Bot Fight Mode ou règle WAF) : les contrôles de cette application sont incomplets. Un vrai attaquant peut parfois contourner ce défi."
    rows+=("$h$TAB$a$TAB@OK défi Cloudflare$TAB?$TAB?$TAB$hsts"); return
  fi
  # Nextcloud ?
  local st; st=$(tmo 20 curl -sS -m 15 --resolve "$h:443:$a" "https://$h/status.php" 2>/dev/null)
  if jq -e '.installed != null and (.versionstring // .version) != null' >/dev/null 2>&1 <<< "$st"; then
    local v; v=$(jq -r '.versionstring // .version' <<< "$st")
    appli="Nextcloud $v"; auth="@OK page de connexion"; NC_PUBLIC=1
    expo_nextcloud "$h" "$a" "$v"
  else
    # Stash ? (son API GraphQL répond à cette requête si aucun identifiant n'est défini)
    local g gc gb
    g=$(tmo 20 curl -sS -m 15 --resolve "$h:443:$a" -H 'Content-Type: application/json' -X POST -d '{"query":"{ version { version } }"}' -w '\n%{http_code}' "https://$h/graphql" 2>/dev/null)
    gc=${g##*"$NL"} gb=${g%"$NL"*}
    if jq -e '.data.version.version' >/dev/null 2>&1 <<< "$gb"; then
      appli="Stash $(jq -r '.data.version.version' <<< "$gb")"; auth="@CRIT aucune"
      crit "Stash est accessible sans mot de passe depuis Internet ($h)" "N'importe qui peut parcourir, télécharger ou supprimer votre bibliothèque : l'API répond sans authentification." \
        "Immédiatement : Stash > Paramètres > Sécurité, définissez un identifiant et un mot de passe ; puis protégez $h par Cloudflare Access (Zero Trust > Access > Applications)"
    elif [[ $h == *stash* || $loc == */login?returnURL=* ]] || grep -qi '<title>Stash' "$f" 2>/dev/null; then
      appli="Stash"
      if [[ $gc == 401 || $gc == 403 || $code == 30* ]]; then
        auth="@OK identifiant exigé"; ok "Stash exige un identifiant ($h)" "L'API refuse les requêtes anonymes (HTTP $gc)."
      else
        auth="@INFO indéterminée"; info "Authentification de Stash indéterminée ($h)" "Réponse de l'API : HTTP $gc."
      fi
    else
      case $code in
        401|403) auth="@OK refus anonyme (HTTP $code)" ;;
        30*) auth="@INFO redirige vers ${loc:0:60}" ;;
        200) auth="@INFO page publique"
             info "$h : page accessible sans Cloudflare Access" "Vérifiez que l'application exige une connexion forte, ou ajoutez Cloudflare Access." ;;
        *) auth="HTTP $code" ;;
      esac
    fi
  fi
  # Fichiers qui ne devraient jamais être publics
  local p body c
  for p in /.git/HEAD /.env /.git/config /server-status /phpinfo.php /backup.zip /.DS_Store; do
    c=$(http_get "$f.p" "https://$h$p" --resolve "$h:443:$a"); c=${c%% *}
    [[ $c == 200 ]] || continue
    body=$(head -c 300 "$f.p" 2>/dev/null)
    if [[ ($p == /.git/HEAD && $body == ref:*) || ($p == /.git/config && $body == *"[core]"*) || ($p == /.env && $body =~ ^[A-Z_]+= ) || ($p == /server-status && $body == *"Apache Server Status"*) || ($p == /phpinfo.php && $body == *"phpinfo"*) || ($p == /backup.zip && $body == PK*) ]]; then
      crit "$h expose un fichier sensible : $p" "Ce fichier est téléchargeable par n'importe qui et peut contenir des mots de passe ou le code source." "Bloquez ce chemin dans l'application ou par une règle WAF Cloudflare, et changez les secrets qu'il contient"
    fi
  done
  [[ $hsts == non ]] && info "$h : en-tête HSTS absent" "Sans HSTS, un navigateur peut être piégé sur une connexion non chiffrée (Wi-Fi public)." "Cloudflare > SSL/TLS > Edge Certificates > HTTP Strict Transport Security (HSTS)"
  local c80; c80=$(http_get "$f.80" "http://$h/" --resolve "$h:80:$a"); c80=${c80%% *}
  [[ $c80 == 200 ]] && info "$h répond en HTTP non chiffré" "La page est servie sans redirection vers HTTPS." "Cloudflare > SSL/TLS > Edge Certificates > Always Use HTTPS"
  if tmo 15 curl -sS -m 10 -o /dev/null --tlsv1.0 --tls-max 1.1 --ciphers 'DEFAULT:@SECLEVEL=0' --resolve "$h:443:$a" "https://$h/" 2>/dev/null; then
    info "$h accepte TLS 1.0/1.1 (protocoles obsolètes)" "" "Cloudflare > SSL/TLS > Edge Certificates > Minimum TLS Version : TLS 1.2"
  fi
  rows+=("$h$TAB$(tr '\n' ' ' <<< "$ips")$TAB@INFO Cloudflare, sans Access$TAB$appli$TAB$auth$TAB$hsts")
}

expo_nextcloud() {   # expo_nextcloud hôte ip version
  local h=$1 a=$2 v=$3 f="$WORK/nc_${1//[^A-Za-z0-9]/_}" c
  c=$(http_get "$f" "https://$h/data/.ocdata" --resolve "$h:443:$a"); c=${c%% *}
  [[ $c == 200 ]] && (( $(stat -c %s "$f" 2>/dev/null || echo 0) < 64 )) && ! grep -qi '<html' "$f" && crit "Nextcloud ($h) : dossier de données accessible depuis Internet" "Le fichier /data/.ocdata est téléchargeable : tous les fichiers des utilisateurs le sont probablement aussi." \
    "Déplacez le dossier de données hors de la racine web ou bloquez /data (configuration du serveur web)"
  local maj=${v%%.*}
  [[ $maj =~ ^[0-9]+$ ]] || { info "Version de Nextcloud ($h) : ${v:-inconnue}"; return; }
  local latest_all latest_maj
  latest_all=$(derniere_version nextcloud/server); latest_maj=$(derniere_version nextcloud/server "$maj")
  if [[ -z $latest_all ]]; then
    info "Nextcloud $v ($h)" "Impossible de joindre GitHub pour comparer avec la dernière version."
  elif ((maj < ${latest_all%%.*} - 2)); then
    crit "Nextcloud $v n'est plus maintenu ($h)" "Dernière version : $latest_all. Votre version majeure ne reçoit plus de correctifs de sécurité." \
      "Mettez à jour (Nextcloud AIO : interface d'administration AIO → « Arrêter les conteneurs » puis « Démarrer et mettre à jour »)"
  elif [[ -n $latest_maj ]] && version_lt "$v" "$latest_maj"; then
    warn "Nextcloud $v : correctifs disponibles ($latest_maj) ($h)" "Les versions correctives contiennent souvent des correctifs de sécurité. Dernière version tous canaux : $latest_all." \
      "Mettez à jour (Nextcloud AIO : interface d'administration AIO → « Arrêter les conteneurs » puis « Démarrer et mettre à jour »)"
  else
    ok "Nextcloud $v à jour ($h)" "Dernière version : $latest_all."
  fi
  info "Scan de sécurité officiel de Nextcloud" "Nextcloud propose un scanner externe gratuit qui teste votre instance depuis Internet." "Ouvrez https://scan.nextcloud.com et saisissez https://$h"
}

# ------------------------------------------------ applications exposées --
occ_nc() { tmo 90 docker exec -u www-data "$NC_C" php /var/www/html/occ --no-interaction "$@" 2>/dev/null; }
occ_lsio() { tmo 90 docker exec "$NC_C" occ --no-interaction "$@" 2>/dev/null; }
OCC=occ_nc NC_C=""

check_applis() {
  section applis
  if ((!DOCKER_OK)); then info "Docker absent ou inaccessible : section ignorée"; return; fi
  local nc stc found=0
  nc=$(jq -r '.[] | select(.State.Status == "running") | select((.Config.Image // "") | test("aio-nextcloud|(^|/)nextcloud:|^nextcloud$|linuxserver/nextcloud")) | .Name | ltrimstr("/")' "$INSPECT" | head -n 1)
  stc=$(jq -r '.[] | select(.State.Status == "running") | select((.Config.Image // "") | test("stashapp/stash")) | .Name | ltrimstr("/")' "$INSPECT" | head -n 1)
  [[ -n $nc ]] && { found=1; audit_nextcloud "$nc"; }
  [[ -n $stc ]] && { found=1; audit_stash "$stc"; }
  ((found)) || info "Ni Nextcloud ni Stash détecté dans les conteneurs"
}

audit_nextcloud() {
  NC_C=$1
  local stj
  stj=$(occ_nc status --output=json)
  if ! jq -e .installed >/dev/null 2>&1 <<< "$stj"; then OCC=occ_lsio; stj=$(occ_lsio status --output=json); fi
  if ! jq -e .installed >/dev/null 2>&1 <<< "$stj"; then
    info "Nextcloud ($NC_C) : commande occ inaccessible" "Impossible d'interroger Nextcloud de l'intérieur." "Vérifiez : \`docker exec -u www-data $NC_C php occ status\`"
    return
  fi
  local exposed=0 k
  ((NC_PUBLIC)) && exposed=1
  [[ -n ${REACHABLE[$NC_C]:-} ]] && exposed=1
  for k in "${!EXPOSED[@]}"; do [[ $k == "$NC_C" || $k == *nextcloud* ]] && exposed=1; done
  local ver; ver=$(jq -r '.versionstring // .version' <<< "$stj")
  [[ $(jq -r '.maintenance' <<< "$stj") == true ]] && warn "Nextcloud en mode maintenance" "Les utilisateurs ne peuvent pas se connecter." "\`docker exec -u www-data $NC_C php occ maintenance:mode --off\`"
  info "Nextcloud $ver (conteneur $NC_C)$( ((exposed)) && echo ' — exposé sur Internet')"

  # Double authentification
  local enforce admins u st2 no2fa=() t
  enforce=$($OCC twofactorauth:enforce)
  admins=$($OCC group:list --output=json | jq -r '.admin[]?' 2>/dev/null)
  for u in $admins; do
    st2=$($OCC twofactorauth:state "$u")
    [[ $st2 == *"is enabled"* ]] || no2fa+=("$u")
  done
  local lvl=WARN; ((exposed)) && lvl=CRIT
  if [[ $enforce == *"is enforced"* && $enforce != *"not enforced"* ]]; then
    ok "Nextcloud : double authentification obligatoire" "$enforce"
  elif ((${#no2fa[@]})); then
    add "$lvl" "Nextcloud : compte(s) administrateur sans double authentification : $(join_list ', ' "${no2fa[@]}")" \
      "Un mot de passe administrateur deviné ou volé (fuite, hameçonnage) donne accès à tous les fichiers de tous les utilisateurs. Administrateurs : $(tr '\n' ' ' <<< "$admins")— gardez-en le moins possible et utilisez un compte ordinaire au quotidien." \
      "Activez l'application « Two-Factor TOTP Provider » (\`docker exec -u www-data $NC_C php occ app:enable twofactor_totp\`), configurez-la pour chaque admin (Paramètres personnels > Sécurité), puis imposez-la : Paramètres d'administration > Sécurité > « Imposer l'authentification à deux facteurs »"
  elif [[ -n $admins ]]; then
    ok "Nextcloud : administrateurs protégés par double authentification" "$(tr '\n' ' ' <<< "$admins")"
  fi

  # Liens de partage publics
  local lp ep
  lp=$($OCC config:app:get core shareapi_enforce_links_password); ep=$($OCC config:app:get core shareapi_enforce_expire_date)
  local sh sherr=""; sh=$(nc_partages)
  if [[ $sh == ERR"$US"* ]]; then sherr=${sh#ERR"$US"}; sh=""; fi
  if [[ -n $sh ]]; then
    local ntot npw nexp nw liste
    ntot=$(nlines "$sh"); npw=$(awk -F'\t' '$2 == 1' <<< "$sh" | grep -c .); nexp=$(awk -F'\t' '$3 == 1' <<< "$sh" | grep -c .)
    nw=$(awk -F'\t' '($4 % 32) >= 4' <<< "$sh" | grep -c .)
    liste=$(awk -F'\t' '$2 == 1 {printf "%s : %s%s\n", $6, $5, (($4 % 32) >= 4 ? " (dépôt/écriture autorisés)" : "")}' <<< "$sh" | head -n 15)
    if ((npw > 0)); then
      add "$( ((exposed)) && echo WARN || echo INFO)" "Nextcloud : $npw lien(s) de partage public(s) sans mot de passe" \
        "Quiconque obtient le lien (courriel transféré, historique, capture d'écran) accède aux fichiers. Liens sans date d'expiration : $nexp sur $ntot ; liens permettant le dépôt ou la modification : $nw.$NL$liste" \
        "Revoyez ces partages (Fichiers > Partages) ; imposez mot de passe et expiration : Paramètres d'administration > Partage > « Imposer la protection par mot de passe » et « Imposer une date d'expiration »"
    else
      ok "Nextcloud : tous les liens publics ($ntot) sont protégés par mot de passe" "Liens sans date d'expiration : $nexp."
    fi
    raw "Nextcloud : liens de partage publics (type, sans mot de passe, sans expiration, droits, chemin, propriétaire)" "$sh"
  elif [[ -n $sherr ]]; then
    info "Nextcloud : liens de partage non vérifiés" "$sherr"
  else
    ok "Nextcloud : aucun lien de partage public"
  fi
  if [[ $lp != yes ]]; then
    info "Nextcloud : mot de passe non imposé sur les nouveaux liens publics" "" "Paramètres d'administration > Partage > « Imposer la protection par mot de passe »"
  fi
  [[ $ep != yes ]] && info "Nextcloud : pas d'expiration imposée sur les liens publics" "" "Paramètres d'administration > Partage > « Imposer une date d'expiration »"

  # Avertissements de sécurité et de configuration de Nextcloud lui-même
  local sc; sc=$($OCC setupchecks --output=json)
  if jq -e 'type == "object"' >/dev/null 2>&1 <<< "$sc"; then
    local err wrn
    err=$(jq -r '[to_entries[] | .key as $c | .value | to_entries[] | select(.value.severity == "error") | "\($c) — \(.value.name) : \(.value.description // "" | gsub("<[^>]*>"; "") | gsub("\\s+"; " ") | .[0:220])"] | .[]' <<< "$sc" 2>/dev/null)
    wrn=$(jq -r '[to_entries[] | .key as $c | .value | to_entries[] | select(.value.severity == "warning") | "\($c) — \(.value.name) : \(.value.description // "" | gsub("<[^>]*>"; "") | gsub("\\s+"; " ") | .[0:220])"] | .[]' <<< "$sc" 2>/dev/null)
    [[ -n $err ]] && warn "Nextcloud signale des erreurs de configuration" "$err" "Détail : Paramètres d'administration > Vue d'ensemble"
    [[ -n $wrn ]] && info "Nextcloud : avertissements de configuration ($(nlines "$wrn"))" "$wrn" "Détail : Paramètres d'administration > Vue d'ensemble"
    [[ -z $err$wrn ]] && ok "Nextcloud : aucun avertissement dans les vérifications d'administration"
  fi

  # Protection contre le brute-force : Nextcloud voit-il les vraies adresses ?
  [[ $($OCC config:system:get auth.bruteforce.protection.enabled) == false ]] && warn "Nextcloud : protection contre le brute-force désactivée" "" "Retirez \`'auth.bruteforce.protection.enabled' => false\` de config.php"
  [[ $($OCC config:system:get debug) == true ]] && warn "Nextcloud : mode debug activé" "Le mode debug affiche des détails internes aux visiteurs et ralentit Nextcloud." "\`docker exec -u www-data $NC_C php occ config:system:set debug --value=false --type=boolean\`"
  local logf dd; logf=$($OCC config:system:get logfile); dd=$($OCC config:system:get datadirectory)
  [[ -n $logf ]] || logf="$dd/nextcloud.log"
  local addrs; addrs=$(tmo 30 docker exec "$NC_C" tail -n 4000 "$logf" 2>/dev/null | jq -r '.remoteAddr // empty' 2>/dev/null | grep -vE '^(--|)$')
  if (( $(nlines "$addrs") >= 20 )); then
    local npub=0 a
    while read -r a; do is_private_ip "$a" || npub=$((npub + 1)); done < <(sort -u <<< "$addrs")
    if ((npub == 0 && exposed)); then
      warn "Nextcloud ne voit pas les vraies adresses IP des visiteurs" "Toutes les requêtes semblent venir du réseau local (le tunnel) : la protection anti-brute-force ne peut ni identifier ni ralentir un attaquant, et risque de bloquer tout le monde à la fois." \
        "Déclarez le proxy de confiance : \`docker exec -u www-data $NC_C php occ config:system:set trusted_proxies 0 --value=<IP du proxy/tunnel>\` et \`... config:system:set forwarded_for_headers 0 --value=HTTP_X_FORWARDED_FOR\` (avec Nextcloud AIO, voir la documentation « reverse proxy » d'AIO)"
    elif ((npub > 0)); then
      ok "Nextcloud voit les vraies adresses IP des visiteurs" "$npub adresse(s) publique(s) distincte(s) dans le journal récent."
    fi
  fi
  local upd; upd=$($OCC app:update --showonly | grep -i 'new version' | head -n 20)
  [[ -n $upd ]] && info "Nextcloud : $(nlines "$upd") application(s) à mettre à jour" "$upd" "Paramètres d'administration > Applications > « Tout mettre à jour »"
}

nc_partages() {   # liens publics : type, sans_mdp(1/0), sans_expiration(1/0), droits, chemin, propriétaire
  local dbtype dbname dbhost dbuser dbpass pre hostp port dbc q
  dbtype=$($OCC config:system:get dbtype); dbname=$($OCC config:system:get dbname); dbhost=$($OCC config:system:get dbhost)
  dbuser=$($OCC config:system:get dbuser); dbpass=$($OCC config:system:get dbpassword); pre=$($OCC config:system:get dbtableprefix)
  pre=${pre:-oc_}
  [[ $pre =~ ^[A-Za-z0-9_]+$ ]] || { printf 'ERR%s%s' "$US" "Préfixe de tables inattendu."; return; }
  hostp=${dbhost%%:*}; port=""; [[ $dbhost == *:* ]] && port=${dbhost##*:}
  if [[ -z $hostp || $hostp == localhost || $hostp == 127.0.0.1 ]]; then dbc=$NC_C
  else dbc=$(jq -r --arg h "$hostp" '.[] | select(.State.Status == "running") | select(((.Name | ltrimstr("/")) == $h) or ([(.NetworkSettings.Networks // {})[] | (.Aliases // [])[], (.DNSNames // [])[]] | index($h))) | .Name | ltrimstr("/")' "$INSPECT" | head -n 1); fi
  [[ -n $dbc ]] || { printf 'ERR%s%s' "$US" "Conteneur de la base de données introuvable ($dbhost)."; return; }
  q="SELECT share_type, CASE WHEN password IS NULL OR password = '' THEN 1 ELSE 0 END, CASE WHEN expiration IS NULL THEN 1 ELSE 0 END, permissions, file_target, uid_owner FROM ${pre}share WHERE share_type IN (3,4)"
  local out rc
  case $dbtype in
    pgsql)
      out=$(printf '%s\n' "$dbpass" | tmo 60 docker exec -i "$dbc" sh -c 'read -r PGPASSWORD; export PGPASSWORD; psql -h 127.0.0.1 ${1:+-p "$1"} -U "$2" -d "$3" -tA -F "	" -c "$4"' sh "$port" "$dbuser" "$dbname" "$q" 2>&1); rc=$? ;;
    mysql)
      out=$(printf '%s\n' "$dbpass" | tmo 60 docker exec -i "$dbc" sh -c 'read -r MYSQL_PWD; export MYSQL_PWD; c=mysql; command -v mariadb >/dev/null && c=mariadb; $c -h 127.0.0.1 ${1:+-P "$1"} -u "$2" -N -B -e "$4" "$3"' sh "$port" "$dbuser" "$dbname" "$q" 2>&1); rc=$? ;;
    *) printf 'ERR%s%s' "$US" "Base $dbtype non prise en charge."; return ;;
  esac
  if ((rc != 0)); then printf 'ERR%s%s' "$US" "Requête impossible : $(head -n 1 <<< "$out" | cut -c1-160)"; return; fi
  grep -E '^[34]	' <<< "$out"
}

audit_stash() {
  local c=$1 path y
  path=$(jq -r --arg n "$c" '.[] | select((.Name | ltrimstr("/")) == $n) | (.Config.Env // [])[] | select(startswith("STASH_CONFIG_FILE=")) | split("=")[1]' "$INSPECT" | head -n 1)
  for p in "$path" /root/.stash/config.yml /config/config.yml /home/stash/.stash/config.yml; do
    [[ -n $p ]] || continue
    y=$(tmo 20 docker exec "$c" cat "$p" 2>/dev/null) && [[ -n $y ]] && { path=$p; break; }
  done
  if [[ -z $y ]]; then info "Stash ($c) : configuration illisible" "Impossible de lire config.yml dans le conteneur."; return; fi
  local user dang trip exposed=0
  [[ -n ${EXPOSED[$c]:-}${REACHABLE[$c]:-} ]] && exposed=1
  user=$(awk -F': *' '$1 == "username" {print $2}' <<< "$y" | tr -d "\"'")
  dang=$(awk -F': *' '$1 == "dangerous_allow_public_without_auth" {print $2}' <<< "$y")
  trip=$(awk -F': *' '$1 == "security_tripwire_accessed_from_public_internet" {print $2}' <<< "$y" | tr -d "\"'")
  if [[ -z $user ]]; then
    add "$( ((exposed)) && echo CRIT || echo WARN)" "Stash ($c) n'a ni identifiant ni mot de passe" \
      "Sans identifiants, toute personne qui atteint Stash (via le tunnel$( ((exposed)) && echo " : ${EXPOSED[$c]:-}") ou le réseau local) a un accès complet. Derrière cloudflared, les visites semblent venir du réseau local : la protection intégrée de Stash contre l'accès depuis Internet ne se déclenche pas." \
      "Stash > Paramètres > Sécurité : définissez identifiant et mot de passe ; ajoutez Cloudflare Access devant le nom d'hôte"
  else
    ok "Stash ($c) protégé par identifiant (« $user »)"
  fi
  [[ $dang == true ]] && crit "Stash : accès public sans authentification explicitement autorisé" "dangerous_allow_public_without_auth: true dans $path" "Mettez cette option à false et définissez des identifiants"
  [[ -n $trip ]] && warn "Stash a détecté un accès depuis Internet sans authentification" "security_tripwire_accessed_from_public_internet : $trip" "Définissez des identifiants, puis retirez cette ligne de $path et redémarrez Stash"
}

# ------------------------------------------------------------- OPNsense --
opn_py() {   # analyse de config.xml : lignes F (constat), N (réseau), T (table) ; n'affiche jamais de secret
  cat <<'PY'
import sys, ipaddress, xml.etree.ElementTree as ET
US = "\x1f"
root = ET.parse(sys.argv[1]).getroot()
nas_ips = set(sys.argv[2].split())
def F(lvl, ttl, msg="", fix=""): print(US.join(["F", lvl, ttl, msg.replace("\n", "\\n"), fix]))
def T(tab, *cells): print(US.join(["T", tab, "\t".join(str(c) for c in cells)]))
def tx(e, p, d=""):
    x = e.find(p) if e is not None else None
    return (x.text or "").strip() if x is not None and x.text else d
def present(e, p): return e is not None and e.find(p) is not None

# Interfaces et réseaux
names = {}
T("Interfaces du routeur", "Interface", "Nom interne", "Adresse", "Active")
itfs = root.find("interfaces")
for i in (list(itfs) if itfs is not None else []):
    descr = tx(i, "descr") or i.tag.upper()
    names[i.tag] = descr
    ip, sn = tx(i, "ipaddr"), tx(i, "subnet")
    T("Interfaces du routeur", descr, i.tag, f"{ip}/{sn}" if ip and sn else (ip or "-"), "oui" if present(i, "enable") else "non")
    if ip and sn and ip[0].isdigit() and i.tag != "wan":
        try:
            net = ipaddress.ip_interface(f"{ip}/{sn}").network
            if net.is_private: print(US.join(["N", str(net)]))
        except ValueError: pass
def nom(itf): return ", ".join(names.get(x, x) for x in itf.split(",")) if itf else "?"

# Redirections de ports (NAT)
RISQUE = {"22": "SSH", "23": "Telnet", "3389": "RDP", "445": "SMB", "139": "SMB", "5900": "VNC", "21": "FTP", "3306": "MySQL", "5432": "PostgreSQL",
          "6379": "Redis", "2375": "API Docker", "9000": "Portainer", "9090": "Cockpit", "8765": "Audite-moi", "80": "HTTP", "8080": "HTTP"}
fw = []
T("Redirections de ports (NAT)", "Interface", "Protocole", "Port externe", "Destination interne", "Source autorisée", "Description", "État")
for n in root.findall("./nat/rule"):
    off = present(n, "disabled")
    itf, proto = tx(n, "interface"), tx(n, "protocol", "tcp")
    dport = tx(n, "destination/port", "*")
    tgt, lport = tx(n, "target"), tx(n, "local-port", dport)
    src = "toutes" if present(n, "source/any") else (tx(n, "source/address") or tx(n, "source/network") or "?")
    descr = tx(n, "descr")
    T("Redirections de ports (NAT)", nom(itf), proto, dport, f"{tgt}:{lport}", src, descr, "désactivée" if off else "@WARN active")
    if off: continue
    fw.append(dport)
    risk = RISQUE.get(lport) or RISQUE.get(dport)
    cible = " (ce NAS)" if tgt in nas_ips else ""
    if src == "toutes":
        lvl = "CRIT" if risk and risk not in ("HTTP",) else "WARN"
        F(lvl, f"Port {dport}/{proto} ouvert sur Internet → {tgt}:{lport}{cible}" + (f" ({risk})" if risk else ""),
          f"Redirection active sur {nom(itf)}{(' — ' + descr) if descr else ''}. Ce service est directement attaquable depuis Internet, sans Cloudflare.",
          "Si l'accès distant passe par les tunnels Cloudflare ou un VPN, supprimez cette redirection (Pare-feu > NAT > Redirection de port) ; sinon limitez la source autorisée")
    else:
        F("INFO", f"Port {dport}/{proto} redirigé vers {tgt}:{lport}{cible}, source limitée à {src}", descr)
nat_out = [x for x in root.findall("./nat/onetoone") if not present(x, "disabled")]
if nat_out:
    F("WARN", f"{len(nat_out)} règle(s) NAT 1:1", "Une adresse publique est entièrement associée à une machine interne.", "Vérifiez qu'elles sont toujours nécessaires (Pare-feu > NAT > One-to-One)")
if not fw:
    F("OK", "Aucune redirection de port vers le réseau local", "Rien n'est ouvert directement depuis Internet : l'accès distant passe uniquement par les tunnels.")

# Règles d'entrée côté WAN (règles classiques et nouvelles règles)
wan_pass = []
for r in root.findall("./filter/rule"):
    if present(r, "disabled") or tx(r, "type", "pass") != "pass" or present(r, "associated-rule-id"): continue
    itf = tx(r, "interface")
    if "wan" not in itf.split(","): continue
    src = "toutes" if present(r, "source/any") else (tx(r, "source/address") or tx(r, "source/network") or "?")
    dst = "toutes" if present(r, "destination/any") else (tx(r, "destination/network") or tx(r, "destination/address") or "?")
    wan_pass.append((tx(r, "protocol", "any"), src, dst, tx(r, "destination/port", "*"), tx(r, "descr")))
mvc = root.find("./OPNsense/Firewall/Filter/rules")
for r in (list(mvc) if mvc is not None else []):
    if tx(r, "enabled", "1") != "1" or tx(r, "action", "pass") != "pass": continue
    if "wan" not in tx(r, "interface").split(","): continue
    wan_pass.append((tx(r, "protocol", "any"), tx(r, "source_net", "any"), tx(r, "destination_net", "any"), tx(r, "destination_port", "*"), tx(r, "description")))
VPN = {"51820": "WireGuard", "1194": "OpenVPN", "500": "IPsec", "4500": "IPsec"}
admin_ports = {tx(root, "./system/webgui/port") or ("80" if tx(root, "./system/webgui/protocol") == "http" else "443"), "22", "80", "443"}
for proto, src, dst, port, descr in wan_pass:
    ouvert = src in ("toutes", "any")
    self_dst = dst in ("(self)", "wanip", "wan", "toutes", "any")
    if ouvert and self_dst and (port in admin_ports or port == "*"):
        F("CRIT", f"Le routeur lui-même est accessible depuis Internet (port {port})", f"Règle WAN : {proto} de {src} vers {dst}:{port} {descr}".strip(),
          "Supprimez cette règle : l'administration d'OPNsense ne doit être accessible que depuis le réseau local ou un VPN")
    elif port in VPN:
        F("INFO", f"Port VPN ouvert sur le WAN : {proto} {port} ({VPN[port]})", f"Source : {src}. {descr}".strip())
    else:
        F("WARN" if ouvert else "INFO", f"Règle WAN autorisant l'entrée : {proto} vers {dst}:{port}", f"Source : {src}. {descr}".strip(),
          "Vérifiez qu'elle est nécessaire (Pare-feu > Règles > WAN)")

# Interface d'administration, SSH, comptes
wg = root.find("./system/webgui")
if tx(wg, "protocol", "https") == "http":
    F("WARN", "Interface d'administration d'OPNsense en HTTP", "Le mot de passe administrateur circule en clair sur le réseau.", "Système > Paramètres > Administration : protocole HTTPS")
if present(root, "./system/ssh/enabled") or tx(root, "./system/ssh/enabled") == "enabled":
    if present(root, "./system/ssh/permitrootlogin"):
        F("WARN", "SSH d'OPNsense : connexion root autorisée", "", "Système > Paramètres > Administration > Secure Shell : décochez « Permit root user login » et utilisez un compte dédié")
    if present(root, "./system/ssh/passwordauth"):
        F("INFO", "SSH d'OPNsense : authentification par mot de passe autorisée", "", "Préférez les clés SSH (décochez « Permit password login »)")
totp = {tx(a, "name") for a in root.findall("./system/authserver") if tx(a, "type") == "totp"}
modes = set(filter(None, tx(wg, "authmode").split(",")))
if not (modes & totp):
    F("INFO", "Connexion à OPNsense sans double authentification", "Un mot de passe administrateur volé suffit pour prendre la main sur le routeur.",
      "Système > Accès > Serveurs : ajoutez un serveur « Local + Timebased One Time Password », générez une graine OTP pour chaque utilisateur (Système > Accès > Utilisateurs), puis choisissez ce serveur dans Système > Paramètres > Administration > Authentification")

# UPnP, IDS, DNS
upnp_on = False
for el in root.iter():
    if "upnp" in el.tag.lower():
        for ch in el.iter():
            if ch.tag.lower() == "enable" and (ch.text or "").strip().lower() in ("1", "on", "yes", "enabled"): upnp_on = True
F("WARN" if upnp_on else "OK", "UPnP activé sur le routeur" if upnp_on else "UPnP désactivé sur le routeur",
  "N'importe quel appareil du réseau (console, objet connecté… ou logiciel malveillant) peut ouvrir lui-même des ports sur Internet." if upnp_on else "",
  "Services > UPnP : désactivez-le, ou limitez-le aux appareils qui en ont besoin (règles d'autorisation)" if upnp_on else "")
if tx(root, "./OPNsense/IDS/general/enabled") == "1":
    F("OK", "Détection d'intrusion (Suricata) active", "")
else:
    F("INFO", "Détection d'intrusion (Suricata) inactive", "Optionnel sur un réseau domestique.", "Services > Intrusion Detection, ou le plugin os-crowdsec")
opn = root.find("OPNsense")
if opn is not None and any(c.tag.lower() == "crowdsec" for c in opn): F("OK", "CrowdSec présent sur le routeur", "Blocage collaboratif des adresses malveillantes.")
PY
}
OPN_NETS=""
opn_api() {   # opn_api chemin fichier → code HTTP (identifiants passés par l'entrée standard, pas sur la ligne de commande)
  local -a k=(); oui "$(cfg OPNSENSE_VERIFIER_TLS non)" || k=(-k)
  printf 'user = "%s:%s"\n' "$(cfg OPNSENSE_KEY)" "$(cfg OPNSENSE_SECRET)" \
    | tmo 40 curl -sS -m 30 "${k[@]}" -K - -o "$2" -w '%{http_code}' "$(cfg OPNSENSE_URL)$1" 2>/dev/null || echo 000
}

check_opnsense() {
  section opnsense
  local url; url=$(cfg OPNSENSE_URL)
  if [[ -z $url || -z $(cfg OPNSENSE_KEY) ]]; then
    info "Audit d'OPNsense non configuré" "Audite-moi peut lire la configuration du routeur (redirections de ports, règles, UPnP, mises à jour) avec une clé API." \
      "Sur le NAS : \`sudo ./install.sh --configurer-opnsense\` (voir le README pour créer la clé dans OPNsense)"
    return
  fi
  have curl || { info "curl absent : audit d'OPNsense impossible"; return; }
  url=${url%/}; CFG[OPNSENSE_URL]=$url
  local m; m=$(stat -c %a "$CONF_FILE" 2>/dev/null)
  [[ -n $m && ${m: -2} != 00 ]] && warn "$CONF_FILE est lisible par d'autres comptes (droits $m)" "Ce fichier contient la clé API d'OPNsense." "\`sudo chmod 600 $CONF_FILE\`"
  local fw="$WORK/opn_fw.json" code
  code=$(opn_api /api/core/firmware/status "$fw")
  case $code in
    200) ;;
    401) warn "OPNsense refuse la clé API (HTTP 401)" "Clé ou secret incorrect." "Vérifiez OPNSENSE_KEY et OPNSENSE_SECRET dans $CONF_FILE"; return ;;
    000) warn "OPNsense injoignable ($url)" "Pas de réponse de l'API." "Vérifiez OPNSENSE_URL (ex. https://10.10.1.1) et que le NAS peut joindre l'interface d'administration"; return ;;
    *) info "OPNsense : état des mises à jour illisible (HTTP $code)" "" "Ajoutez le privilège « System: Firmware » à l'utilisateur de la clé API" ;;
  esac
  if [[ $code == 200 ]]; then
    local pv st msg
    pv=$(jq -r '.product_version // .product.product_version // empty' "$fw" 2>/dev/null)
    st=$(jq -r '.status // empty' "$fw" 2>/dev/null); msg=$(jq -r '.status_msg // empty' "$fw" 2>/dev/null)
    case $st in
      update|upgrade) warn "OPNsense ${pv:+$pv }: mises à jour disponibles" "${msg:-Des mises à jour du routeur attendent.}" "OPNsense > Système > Firmware > Mises à jour" ;;
      none|"") ok "OPNsense ${pv:+$pv }: aucune mise à jour en attente" "${msg:-Dernière vérification faite par le routeur.}" ;;
      *) info "OPNsense ${pv:+$pv }: état du firmware « $st »" "$msg" ;;
    esac
  fi
  local xml="$WORK/opn_config.xml"
  code=$(opn_api /api/core/backup/download/this "$xml")
  if [[ $code != 200 ]] || ! grep -q '<opnsense>' "$xml" 2>/dev/null; then
    info "OPNsense : configuration illisible (HTTP $code)" "Sans la configuration, les redirections de ports et les règles ne peuvent pas être vérifiées." \
      "Ajoutez le privilège « Diagnostics: Backup & Restore » (ou « System: Configuration: Backups ») à l'utilisateur de la clé API (voir README)"
    rm -f "$xml"; return
  fi
  local -A TB=()
  local -a TORD=()
  local kind a b c d
  while IFS=$US read -r kind a b c d; do
    case $kind in
      F) add "$a" "$b" "${c//\\n/$NL}" "$d" ;;
      N) OPN_NETS+="$a " ;;
      T) [[ -n ${TB[$a]:-} ]] || { TB[$a]="$WORK/opn_t_${#TB[@]}.tsv"; TORD+=("$a"); }; printf '%s\n' "$b" >> "${TB[$a]}" ;;
    esac
  done < <(opn_py > "$WORK/opn.py"; python3 -I "$WORK/opn.py" "$xml" "$(hostname -I 2>/dev/null)")
  local t
  for t in "${TORD[@]}"; do tbl "$t" < "${TB[$t]}"; done
  rm -f "$xml"
}

# ------------------------------------------------------ scan du réseau local --
nmap_py() {   # résultat XML de nmap → IP, nom, MAC, fabricant, ports ouverts
  cat <<'PY'
import sys, xml.etree.ElementTree as ET
for h in ET.parse(sys.argv[1]).getroot().findall("host"):
    s = h.find("status")
    if s is None or s.get("state") != "up": continue
    ip = mac = vendor = ""
    for a in h.findall("address"):
        if a.get("addrtype") == "ipv4": ip = a.get("addr")
        elif a.get("addrtype") == "mac": mac, vendor = a.get("addr"), a.get("vendor", "")
    hn = h.find("hostnames/hostname"); name = hn.get("name") if hn is not None else ""
    ports = []
    for p in h.findall("ports/port"):
        st = p.find("state")
        if st is None or st.get("state") != "open": continue
        sv = p.find("service")
        ports.append(p.get("portid") + "/" + p.get("protocol") + ((" " + sv.get("name")) if sv is not None and sv.get("name") else ""))
    print("\x1f".join([ip, name, mac, vendor, ", ".join(ports)]))
PY
}
check_lan() {
  section lan
  if ! oui "$(cfg SCAN_RESEAU oui)"; then info "Scan du réseau désactivé (SCAN_RESEAU=non dans audit.conf)"; return; fi
  if ((QUICK)); then info "Scan du réseau non exécuté (mode rapide)"; return; fi
  if ! have nmap; then info "nmap non installé : scan du réseau impossible" "" "\`sudo apt install nmap\`"; return; fi
  local cibles; cibles=$(cfg SCAN_RESEAUX)
  local origine="audit.conf (SCAN_RESEAUX)"
  if [[ -z $cibles && -n $OPN_NETS ]]; then cibles=$OPN_NETS; origine="interfaces d'OPNsense"; fi
  if [[ -z $cibles ]]; then
    origine="réseaux du NAS"
    cibles=$(ip -o -f inet addr show 2>/dev/null | awk '$2 !~ /^(lo|docker|br-|veth|virbr|tailscale|wg|tun)/ {print $4}' \
      | while read -r c; do python3 -c 'import ipaddress,sys; n=ipaddress.ip_interface(sys.argv[1]).network; print(n) if n.is_private else None' "$c" 2>/dev/null; done | sort -u | tr '\n' ' ')
  fi
  local -a ok_c=() trop=()
  local c
  for c in $cibles; do
    if [[ $c =~ /([0-9]+)$ ]] && ((BASH_REMATCH[1] < 22)); then trop+=("$c"); else ok_c+=("$c"); fi
  done
  ((${#trop[@]})) && info "Réseaux trop grands ignorés : ${trop[*]}" "Le scan est limité aux réseaux de 1 024 adresses au plus." "Indiquez des sous-réseaux plus précis dans SCAN_RESEAUX (audit.conf)"
  if ((${#ok_c[@]} == 0)); then info "Aucun réseau à scanner" "" "Renseignez SCAN_RESEAUX dans /etc/audite-moi/audit.conf"; return; fi
  note "Scan nmap de ${ok_c[*]} (quelques minutes)…"
  local x="$WORK/nmap.xml"
  tmo 1800 nmap -T4 --top-ports 200 --open --host-timeout 120s -oX "$x" "${ok_c[@]}" >/dev/null 2>&1
  [[ -s $x ]] || { warn "Le scan nmap a échoué" "" "Lancez-le à la main : \`sudo nmap -T4 --top-ports 200 --open ${ok_c[*]}\`"; return; }
  local res; res=$(nmap_py > "$WORK/nmap.py"; python3 -I "$WORK/nmap.py" "$x")
  local n; n=$(nlines "$res")
  info "$n appareil(s) trouvé(s) sur ${ok_c[*]}" "Réseaux pris dans : $origine. Le scan montre ce que le NAS peut joindre : un appareil d'un autre sous-réseau peut voir autre chose selon les règles d'OPNsense."
  local -A RISK=([23]="Telnet (non chiffré)" [21]="FTP (non chiffré)" [2375]="API Docker sans TLS" [3389]="Bureau à distance (RDP)" [5900]="VNC"
    [6379]="Redis" [27017]="MongoDB" [9200]="Elasticsearch" [11211]="Memcached" [3306]="MySQL/MariaDB" [5432]="PostgreSQL" [1883]="MQTT non chiffré" [554]="flux vidéo RTSP (caméra)")
  local -a rows=() risq=() crit2375=() pl=()
  local ip name mac vendor ports p num me
  local myips=" $(hostname -I 2>/dev/null) "
  while IFS=$US read -r ip name mac vendor ports; do
    [[ -n $ip ]] || continue
    me=""; [[ $myips == *" $ip "* ]] && me=" (ce NAS)"
    rows+=("$ip$TAB${name:--}$me$TAB${mac:--}$TAB${vendor:--}$TAB${ports:--}")
    [[ -n $me ]] && continue
    IFS=',' read -r -a pl <<< "$ports"
    for p in "${pl[@]}"; do
      p=${p# }; num=${p%%/*}
      [[ -n ${RISK[$num]:-} ]] || continue
      if [[ $num == 2375 ]]; then crit2375+=("$ip${name:+ ($name)}"); else risq+=("$ip${name:+ ($name)} : $num — ${RISK[$num]}"); fi
    done
  done <<< "$res"
  ((${#crit2375[@]})) && crit "API Docker sans TLS ouverte sur le réseau : $(join_list ', ' "${crit2375[@]}")" "Quiconque atteint ce port prend le contrôle total de la machine." "Désactivez l'écoute TCP de Docker sur cette machine (-H tcp://…)"
  if ((${#risq[@]})); then
    warn "Services risqués sur d'autres appareils du réseau" "$(printf '%s\n' "${risq[@]}")" \
      "Désactivez ces services s'ils ne servent pas, changez les mots de passe par défaut, et isolez caméras et objets connectés dans un VLAN séparé (OPNsense)"
  else
    ok "Aucun service particulièrement risqué (Telnet, FTP, RDP, VNC, bases de données…) sur les autres appareils"
  fi
  tbl "Appareils du réseau local" < <(printf 'Adresse IP\tNom\tAdresse MAC\tFabricant\tPorts ouverts\n'; printf '%s\n' "${rows[@]}" | sort -t. -k1,1n -k2,2n -k3,3n -k4,4n)
  # Nouveaux appareils depuis le dernier scan
  local inv="$OUTDIR/.inventaire-reseau" nouveaux=""
  local actuel; actuel=$(awk -F"$US" '{print ($3 != "" ? tolower($3) : $1) "\t" $1 "\t" $2 "\t" $4}' <<< "$res" | sort -u)
  if [[ -f $inv ]]; then
    nouveaux=$(awk -F'\t' 'NR == FNR {vu[$1] = 1; next} !($1 in vu) {printf "%s%s%s%s\n", $2, ($3 != "" ? " (" $3 ")" : ""), ($1 != $2 ? " — " $1 : ""), ($4 != "" ? " — " $4 : "")}' "$inv" - <<< "$actuel")
    if [[ -n $nouveaux ]]; then
      info "Nouveaux appareils depuis le dernier scan : $(nlines "$nouveaux")" "$nouveaux" "Vérifiez que vous les reconnaissez (adresse MAC et fabricant) ; un appareil inconnu peut signaler un intrus sur le Wi-Fi"
    else
      ok "Aucun nouvel appareil depuis le dernier scan"
    fi
  fi
  printf '%s\n' "$actuel" > "$inv"
  [[ -n $OUTGROUP ]] && chgrp "$OUTGROUP" "$inv" 2>/dev/null && chmod 640 "$inv"
}

check_maj() {
  section maj
  if ! have apt-get; then info "Gestionnaire apt absent"; return; fi
  if ((APT_UPDATE)); then
    note "apt-get update…"
    tmo 300 apt-get update -qq >/dev/null 2>&1 || warn "apt-get update a échoué" "La liste des paquets n'a pas pu être rafraîchie." "\`sudo apt-get update\` pour voir l'erreur"
  fi
  local stamp; stamp=$(find /var/lib/apt/lists -maxdepth 1 -name '*Release' -printf '%T@\n' 2>/dev/null | sort -n | tail -n 1); stamp=${stamp%.*}
  if isint "$stamp"; then
    local d=$(( (NOW - stamp) / 86400 ))
    ((d > 7)) && warn "Liste des paquets non rafraîchie depuis $d jours" "Les mises à jour en attente ci-dessous sont peut-être sous-estimées." \
      "Relancez l'audit avec \`--apt-update\` ; vérifiez que \`apt-daily.timer\` est actif"
  fi
  local up nall nsec secpk
  up=$(tmo 120 apt list --upgradable 2>/dev/null | grep '/')
  nall=$(nlines "$up"); nsec=$(grep -c -- '-security' <<< "$up")
  secpk=$(grep -- '-security' <<< "$up" | cut -d/ -f1 | head -n 25 | tr '\n' ' ')
  if ((nsec > 0)); then
    warn "$nsec mise(s) à jour de sécurité en attente" "Paquets : $secpk" "\`sudo apt update && sudo apt full-upgrade\`"
  fi
  if ((nall > nsec)); then
    info "$((nall - nsec)) autre(s) mise(s) à jour disponible(s)" "" "\`sudo apt update && sudo apt full-upgrade\`"
  elif ((nall == 0)); then
    ok "Tous les paquets sont à jour"
  fi
  raw "Paquets pouvant être mis à jour" "$up"
  local held; held=$(apt-mark showhold 2>/dev/null | tr '\n' ' ')
  [[ -n $held ]] && info "Paquets bloqués (non mis à jour) : $held" "" "\`sudo apt-mark unhold <paquet>\` si le blocage n'est plus utile"

  local uu; uu=$(apt-config dump 2>/dev/null | awk -F'"' '/^APT::Periodic::Unattended-Upgrade / {print $2}')
  if dpkg -s unattended-upgrades >/dev/null 2>&1 && [[ $uu == 1 ]]; then
    local last=""; [[ -f /var/log/unattended-upgrades/unattended-upgrades.log ]] && last=$(date -r /var/log/unattended-upgrades/unattended-upgrades.log '+%d/%m/%Y')
    ok "Mises à jour de sécurité automatiques actives" "unattended-upgrades${last:+, dernière exécution le $last}. Par défaut, seules les mises à jour de sécurité d'Ubuntu sont automatiques (ni Docker CE, ni les images des conteneurs)."
  else
    warn "Mises à jour de sécurité automatiques désactivées" "Les failles corrigées par Ubuntu ne sont appliquées que lorsque vous y pensez." \
      "\`sudo apt install unattended-upgrades && sudo dpkg-reconfigure -plow unattended-upgrades\`"
  fi

  if [[ $OS_ID == ubuntu ]]; then
    local eol="" csv=/usr/share/distro-info/ubuntu.csv
    [[ -r $csv ]] && eol=$(awk -F, -v s="$OS_CODE" '$3 == s {print ($7 != "" ? $7 : $6)}' "$csv")
    if [[ -z $eol ]]; then case $OS_VER in 20.04) eol=2025-05-31 ;; 22.04) eol=2027-06-01 ;; 24.04) eol=2029-05-31 ;; esac; fi
    if [[ -n $eol ]]; then
      local ets dleft; ets=$(date -d "$eol" +%s 2>/dev/null)
      if isint "$ets"; then
        dleft=$(( (ets - NOW) / 86400 ))
        local pro_esm=""
        have pro && pro_esm=$(pro status --format json 2>/dev/null | jq -r 'select(.attached == true) | .services[]? | select(.name == "esm-infra") | .status' 2>/dev/null)
        if ((dleft < 0)); then
          if [[ $pro_esm == enabled ]]; then
            info "Ubuntu $OS_VER : support standard terminé, couvert par ESM (Ubuntu Pro)"
          else
            crit "Ubuntu $OS_VER n'est plus maintenue depuis $((-dleft)) jours" "Plus aucun correctif de sécurité gratuit pour les paquets de base." \
              "Mettez à niveau (\`sudo do-release-upgrade\`) ou activez Ubuntu Pro (gratuit jusqu'à 5 machines) : \`sudo pro attach\`"
          fi
        elif ((dleft < 180)); then
          warn "Fin du support d'Ubuntu $OS_VER dans $dleft jours" "Après cette date, plus de correctifs de sécurité gratuits." "Planifiez la mise à niveau (\`sudo do-release-upgrade\`) ou Ubuntu Pro"
        else
          ok "Ubuntu $OS_VER maintenue jusqu'au $(date -d "$eol" +%d/%m/%Y)"
        fi
      fi
    fi
  fi
}

check_comptes() {
  section comptes
  local u0 empty
  u0=$(awk -F: '$3 == 0 && $1 != "root" {print $1}' /etc/passwd | tr '\n' ' ')
  if [[ -n $u0 ]]; then
    crit "Comptes avec l'UID 0 (super-utilisateur) autres que root : $u0" "Ces comptes ont tous les pouvoirs : souvent la trace d'une compromission." "Vérifiez leur origine, puis supprimez-les (\`sudo userdel <compte>\`)"
  else
    ok "Seul root possède l'UID 0"
  fi
  empty=$(awk -F: '$2 == "" {print $1}' /etc/shadow 2>/dev/null | tr '\n' ' ')
  if [[ -n $empty ]]; then
    crit "Comptes sans mot de passe : $empty" "N'importe qui peut s'y connecter localement." "\`sudo passwd -l <compte>\` (verrouiller) ou définissez un mot de passe"
  else
    ok "Aucun compte sans mot de passe"
  fi

  local -a rows=()
  local u x uid gid gecos home shell pw pws grps
  while IFS=: read -r u x uid gid gecos home shell; do
    [[ $shell =~ (nologin|false|sync|shutdown|halt)$ ]] && continue
    ((uid == 0 || (uid >= 1000 && uid != 65534))) || continue
    pw=$(awk -F: -v u="$u" '$1 == u {print $2}' /etc/shadow 2>/dev/null)
    case $pw in '') pws="@CRIT vide" ;; '!'*|'*'*) pws="verrouillé" ;; *) pws="défini" ;; esac
    grps=$(id -nG "$u" 2>/dev/null | tr ' ' '\n' | grep -xE 'sudo|admin|wheel|docker|lxd|adm|disk' | tr '\n' ' ')
    rows+=("$u$TAB$uid$TAB$shell$TAB$pws$TAB${grps:--}$TAB$home")
  done < /etc/passwd
  tbl "Comptes avec un shell de connexion" < <(printf 'Compte\tUID\tShell\tMot de passe\tGroupes sensibles\tDossier\n'; printf '%s\n' "${rows[@]}")

  local sudoers dk lxd
  sudoers=$(getent group sudo admin wheel 2>/dev/null | cut -d: -f4 | tr ',' '\n' | grep -v '^$' | sort -u | tr '\n' ' ')
  info "Administrateurs (groupe sudo)" "${sudoers:-aucun}"
  dk=$(getent group docker | cut -d: -f4 | tr ',' ' ')
  [[ -n $dk ]] && info "Membres du groupe docker : $dk" "Appartenir au groupe docker équivaut à être root (montage de / dans un conteneur, lecture des secrets…)." \
    "Réservez ce groupe aux administrateurs : \`sudo gpasswd -d <utilisateur> docker\`"
  lxd=$(getent group lxd | cut -d: -f4 | tr ',' ' ')
  [[ -n $lxd ]] && info "Membres du groupe lxd : $lxd" "Le groupe lxd équivaut lui aussi à root." "\`sudo gpasswd -d <utilisateur> lxd\` si LXD n'est pas utilisé"

  local np; np=$(grep -hsE '^[^#]*NOPASSWD' /etc/sudoers /etc/sudoers.d/* 2>/dev/null)
  [[ -n $np ]] && warn "Règles sudo sans mot de passe (NOPASSWD)" "$np" \
    "Si ce n'est pas indispensable, retirez NOPASSWD (\`sudo visudo -f <fichier>\`) : un compte compromis deviendrait root sans obstacle"

  # Clés SSH autorisées
  local -a krows=() kbad=() krecent=()
  local kf fp m km
  while IFS=: read -r u x uid gid gecos home shell; do
    [[ -n $home && -d $home ]] || continue
    for kf in "$home/.ssh/authorized_keys" "$home/.ssh/authorized_keys2"; do
      [[ -f $kf ]] || continue
      m=$(stat -c '%a %U' "$kf")
      (( 8#${m%% *} & 8#022 )) && kbad+=("$kf : droits ${m%% *} (modifiable par d'autres)")
      [[ ${m#* } != "$u" && ${m#* } != root ]] && kbad+=("$kf : appartient à ${m#* }")
      km=$(stat -c %Y "$kf"); (( (NOW - km) < 7 * 86400 )) && krecent+=("$u ($(date -d "@$km" '+%d/%m %H:%M'))")
      while IFS= read -r fp; do
        [[ -n $fp ]] || continue
        local bits=${fp%% *} typ=${fp##* } cmt
        cmt=$(awk '{$1 = ""; $2 = ""; $NF = ""; sub(/^ +/, ""); print}' <<< "$fp")
        local lv="@OK"
        [[ $typ == "(DSA)" ]] && { lv="@WARN"; kbad+=("$u : clé DSA obsolète ($cmt)"); }
        [[ $typ == "(RSA)" ]] && isint "$bits" && ((bits < 2048)) && { lv="@WARN"; kbad+=("$u : clé RSA de $bits bits ($cmt)"); }
        krows+=("$u$TAB$lv ${typ//[()]/}$TAB$bits$TAB${cmt:--}$TAB${kf#"$home"/}")
      done < <(ssh-keygen -lf "$kf" 2>/dev/null)
    done
  done < /etc/passwd
  ((${#krows[@]})) && tbl "Clés SSH autorisées" < <(printf 'Compte\tType\tBits\tCommentaire\tFichier\n'; printf '%s\n' "${krows[@]}")
  ((${#kbad[@]})) && warn "Clés SSH autorisées à corriger" "$(printf '%s\n' "${kbad[@]}")" \
    "Remplacez les clés faibles par des clés ed25519 (\`ssh-keygen -t ed25519\`) ; droits : \`chmod 700 ~/.ssh && chmod 600 ~/.ssh/authorized_keys\`"
  ((${#krecent[@]})) && info "authorized_keys modifié ces 7 derniers jours : $(join_list ', ' "${krecent[@]}")" "Vérifiez que ces ajouts viennent bien de vous."
  rawcmd "Utilisateurs connectés" who
}

check_ssh() {
  section ssh
  local sshd; sshd=$(command -v sshd 2>/dev/null || echo /usr/sbin/sshd)
  if [[ ! -x $sshd ]]; then info "Serveur SSH non installé"; return; fi
  local active=0
  { systemctl is-active --quiet ssh 2>/dev/null || systemctl is-active --quiet ssh.socket 2>/dev/null || systemctl is-active --quiet sshd 2>/dev/null; } && active=1
  local T; T=$(tmo 15 "$sshd" -T 2>&1)
  if ! grep -q '^port ' <<< "$T"; then
    warn "Configuration SSH illisible ou invalide" "$(head -n 3 <<< "$T")" "\`sudo sshd -t\` pour localiser l'erreur"
    return
  fi
  local prl pa kbd pep x11 mat port lad au ag ciph macs kex usepam
  prl=$(kv "$T" permitrootlogin); pa=$(kv "$T" passwordauthentication)
  kbd=$(kv "$T" kbdinteractiveauthentication); [[ -n $kbd ]] || kbd=$(kv "$T" challengeresponseauthentication)
  pep=$(kv "$T" permitemptypasswords); x11=$(kv "$T" x11forwarding); mat=$(kv "$T" maxauthtries)
  port=$(awk '$1 == "port" {print $2}' <<< "$T" | tr '\n' ' '); lad=$(awk '$1 == "listenaddress" {print $2}' <<< "$T" | tr '\n' ' ')
  au=$(kv "$T" allowusers); ag=$(kv "$T" allowgroups)
  ciph=$(kv "$T" ciphers); macs=$(kv "$T" macs); kex=$(kv "$T" kexalgorithms); usepam=$(kv "$T" usepam)
  [[ $pa == yes ]] && SSH_PASS=1
  [[ $kbd == yes && $usepam == yes ]] && SSH_PASS=1
  info "Serveur SSH $( ((active)) && echo actif || echo installé mais inactif)" "Port(s) : ${port% } — écoute : ${lad% }"

  # Journaux d'authentification (7 jours)
  local lf="$WORK/ssh.log"
  have journalctl && tmo 60 journalctl --since "7 days ago" --no-pager -q -o short-iso -t sshd -t sshd-session > "$lf" 2>/dev/null
  [[ -s $lf ]] || cat /var/log/auth.log.1 /var/log/auth.log 2>/dev/null | grep -E 'sshd(-session)?\[' > "$lf"
  local fails nfail ipc acc
  fails=$(grep -E 'Failed (password|publickey|keyboard)|Invalid user|Connection closed by (authenticating|invalid) user|Disconnected from (authenticating|invalid) user|maximum authentication attempts' "$lf")
  nfail=$(nlines "$fails")
  ipc=$(extract_ip <<< "$fails" | sort | uniq -c | sort -rn)
  local -a pub=() accpub=()
  local cnt ip n uu meth
  while read -r cnt ip; do [[ -n $ip ]] || continue; is_private_ip "$ip" || pub+=("$ip ($cnt)"); done <<< "$ipc"
  acc=$(grep -E 'Accepted (password|publickey|keyboard-interactive/pam|hostbased|gssapi-with-mic) for' "$lf" \
    | awk '{for (i = 1; i <= NF; i++) if ($i == "Accepted") {print $(i + 3) "\t" $(i + 5) "\t" $(i + 1); break}}' | sort | uniq -c | sort -rn)
  while read -r n uu ip meth; do [[ -n $ip ]] || continue; is_private_ip "$ip" || accpub+=("$uu depuis $ip ($meth, ${n}×)"); done <<< "$acc"
  ((${#pub[@]})) && SSH_EXPOSED=1

  case $prl in
    yes) add "$( ((SSH_EXPOSED)) && echo CRIT || echo WARN)" "Connexion SSH directe en root autorisée" "PermitRootLogin yes : il suffit de deviner le mot de passe de root." \
           "Dans /etc/ssh/sshd_config.d/99-durcissement.conf : \`PermitRootLogin no\`, puis \`sudo systemctl reload ssh\`" ;;
    prohibit-password|without-password)
         info "Root autorisé en SSH par clé uniquement" "PermitRootLogin $prl" "Préférez \`PermitRootLogin no\` et l'utilisation de sudo" ;;
    no)  ok "Connexion SSH en root interdite" ;;
    *)   info "PermitRootLogin : ${prl:-?}" ;;
  esac
  local me=${SUDO_USER:-<utilisateur>}
  if ((SSH_PASS)); then
    if ((SSH_EXPOSED)); then
      crit "SSH exposé à Internet avec authentification par mot de passe" "$nfail tentatives échouées en 7 jours, dont depuis ${#pub[@]} adresse(s) IP publique(s)." \
        "1) Installez votre clé (\`ssh-copy-id $me@$HOST\`) et testez-la ; 2) mettez \`PasswordAuthentication no\` et \`KbdInteractiveAuthentication no\` dans /etc/ssh/sshd_config.d/99-durcissement.conf ; 3) \`sudo systemctl reload ssh\` ; 4) supprimez la redirection du port SSH sur la box"
    else
      warn "Authentification SSH par mot de passe autorisée" "PasswordAuthentication=$pa, KbdInteractiveAuthentication=$kbd (PAM : $usepam). Les clés SSH sont bien plus sûres." \
        "Après avoir installé et testé votre clé (\`ssh-copy-id $me@$HOST\`) : \`PasswordAuthentication no\` dans /etc/ssh/sshd_config.d/99-durcissement.conf, puis \`sudo systemctl reload ssh\`"
    fi
  else
    ok "Authentification SSH par clé uniquement"
  fi
  [[ $pep == yes ]] && crit "SSH accepte les mots de passe vides" "PermitEmptyPasswords yes" "\`PermitEmptyPasswords no\`"
  [[ $x11 == yes ]] && info "Redirection X11 activée" "Inutile sur un serveur sans écran." "\`X11Forwarding no\`"
  isint "$mat" && ((mat > 4)) && info "MaxAuthTries = $mat" "Nombre d'essais par connexion élevé." "\`MaxAuthTries 3\`"
  [[ -z $au && -z $ag ]] && info "Aucune restriction AllowUsers / AllowGroups" "Tout compte disposant d'un shell peut tenter de se connecter." "\`AllowUsers $me\`"
  local weak=""
  grep -qE '(cbc|arcfour|3des|blowfish|cast128)' <<< "$ciph" && weak+="chiffrements : $ciph$NL"
  grep -qE '(hmac-md5|-96)' <<< "$macs" && weak+="MAC : $macs$NL"
  grep -qE '(diffie-hellman-group1-sha1|diffie-hellman-group-exchange-sha1)' <<< "$kex" && weak+="échanges de clés : $kex"
  [[ -n $weak ]] && warn "Algorithmes SSH obsolètes acceptés" "$weak" "Retirez les directives Ciphers / MACs / KexAlgorithms personnalisées pour revenir aux valeurs sûres par défaut d'OpenSSH"

  if ((${#pub[@]})); then
    ((SSH_PASS)) || warn "SSH joignable depuis Internet" "$nfail tentatives échouées en 7 jours depuis ${#pub[@]} adresse(s) IP publique(s), par ex. : $(join_list ', ' "${pub[@]:0:8}")." \
      "Supprimez la redirection du port SSH sur la box ; pour l'accès à distance, utilisez un VPN (WireGuard, Tailscale) ou Cloudflare Access"
  elif ((nfail > 0)); then
    info "$nfail tentative(s) SSH échouée(s) en 7 jours, depuis le réseau local" "$(head -n 5 <<< "$ipc")"
  else
    ok "Aucune tentative de connexion SSH échouée (7 jours)"
  fi
  ((${#accpub[@]})) && warn "Connexions SSH réussies depuis Internet (7 jours)" "$(printf '%s\n' "${accpub[@]}")" \
    "Vérifiez qu'il s'agit bien de vous ; sinon changez immédiatement mots de passe et clés, et examinez \`last -i\`"
  [[ -n $acc ]] && raw "Connexions SSH réussies (7 jours) : nombre, compte, IP, méthode" "$acc"
  [[ -n $ipc ]] && raw "Échecs SSH par adresse IP (7 jours)" "$(head -n 30 <<< "$ipc")"

  # Protection contre le brute-force
  local prot=""
  if systemctl is-active --quiet fail2ban 2>/dev/null; then
    prot=fail2ban
    local jails sj banned total
    jails=$(tmo 10 fail2ban-client status 2>/dev/null | awk -F':[[:space:]]*' '/Jail list/ {print $2}')
    sj=$(tmo 10 fail2ban-client status sshd 2>/dev/null)
    banned=$(awk -F':[[:space:]]*' '/Currently banned/ {print $2}' <<< "$sj"); total=$(awk -F':[[:space:]]*' '/Total banned/ {print $2}' <<< "$sj")
    if [[ $jails == *sshd* ]]; then
      ok "fail2ban actif (prison sshd)" "Prisons : $jails — IP bannies actuellement : ${banned:-0}, au total : ${total:-0}"
    else
      warn "fail2ban actif mais sans prison sshd" "Prisons : ${jails:-aucune}" "Créez /etc/fail2ban/jail.local avec une section \`[sshd]\` et \`enabled = true\`"
    fi
  fi
  if systemctl is-active --quiet crowdsec 2>/dev/null; then
    prot+=" crowdsec"
    if have cscli && [[ -z $(tmo 10 cscli bouncers list -o raw 2>/dev/null | tail -n +2) ]]; then
      warn "CrowdSec détecte mais ne bloque rien" "Aucun « bouncer » n'est enregistré." "\`sudo apt install crowdsec-firewall-bouncer-iptables\`"
    else
      ok "CrowdSec actif"
    fi
  elif ((DOCKER_OK)) && jq -e '.[] | select(.State.Status == "running" and ((.Config.Image // "") | test("crowdsec")))' "$INSPECT" >/dev/null 2>&1; then
    prot+=" crowdsec(conteneur)"; ok "CrowdSec actif (conteneur)"
  fi
  if [[ -z $prot ]]; then
    if ((SSH_PASS)); then
      warn "Aucune protection contre les attaques par force brute" "Ni fail2ban ni CrowdSec, alors que les mots de passe sont acceptés en SSH." "\`sudo apt install fail2ban\` (la prison sshd est active par défaut sur Ubuntu)"
    else
      info "Ni fail2ban ni CrowdSec" "Peu critique tant que l'authentification SSH par mot de passe est désactivée."
    fi
  fi
}

check_parefeu() {
  section parefeu
  local ufw_on=0
  if have ufw; then
    local us; us=$(tmo 15 ufw status verbose 2>/dev/null)
    if grep -q '^Status: active' <<< "$us"; then
      ufw_on=1
      local def; def=$(grep -m1 '^Default:' <<< "$us")
      if [[ $def == *"deny (incoming)"* || $def == *"reject (incoming)"* ]]; then
        ok "Pare-feu UFW actif" "$def"
      else
        warn "UFW actif mais les connexions entrantes sont autorisées par défaut" "$def" "\`sudo ufw default deny incoming\` (après avoir autorisé SSH et vos partages depuis le réseau local)"
      fi
      if grep -qE '^IPV6=no' /etc/default/ufw 2>/dev/null && [[ -n $IPV6_GLOBAL ]]; then
        warn "UFW ne filtre pas l'IPv6" "IPV6=no dans /etc/default/ufw alors que le serveur a une adresse IPv6 publique." "Mettez \`IPV6=yes\` dans /etc/default/ufw, puis \`sudo ufw reload\`"
      fi
      raw "ufw status verbose" "$us"
    fi
  fi
  if ((!ufw_on)); then
    local pol nr
    pol=$(tmo 10 iptables -S INPUT 2>/dev/null | head -n 1); nr=$(tmo 10 iptables -S INPUT 2>/dev/null | grep -c '^-A')
    if [[ $pol == "-P INPUT DROP" ]] || ((nr > 0)); then
      info "Pare-feu iptables/nftables personnalisé" "Politique : ${pol#-P INPUT } — $nr règle(s) INPUT."
    else
      warn "Aucun pare-feu actif sur le serveur" "UFW est inactif et la chaîne INPUT accepte tout : le serveur repose entièrement sur la box." \
        "Exemple (adaptez votre réseau local) : \`sudo ufw default deny incoming && sudo ufw allow from 192.168.1.0/24 && sudo ufw enable\` — gardez une session SSH ouverte pendant le test"
    fi
  fi

  local pubs=""
  if ((DOCKER_OK)); then
    pubs=$(jq -r '.[] | select(.State.Status == "running") | (.Name | ltrimstr("/")) as $n | (.NetworkSettings.Ports // {}) | to_entries[] | select(.value != null)
      | .key as $k | .value[] | select((.HostIp // "") == "" or .HostIp == "0.0.0.0" or .HostIp == "::") | "\($n)\u001f\(.HostPort)\u001f\($k)"' "$INSPECT" | sort -u)
    if [[ -n $pubs ]]; then
      local list; list=$(awk -F"$US" '{a[$1] = a[$1] (a[$1] ? ", " : "") $2 "→" $3} END {for (k in a) print k " : " a[k]}' <<< "$pubs" | sort)
      if ((ufw_on)); then
        warn "Docker contourne UFW : $(nlines "$pubs") port(s) publié(s) sur toutes les interfaces" "Docker insère ses propres règles iptables : ces ports restent accessibles même si UFW les bloque.$NL$list" \
          "Pour chaque service : liez le port à une adresse précise (\`127.0.0.1:8080:80\` ou \`192.168.1.10:8080:80\`), supprimez les \`ports:\` inutiles (cloudflared passe par le réseau Docker) ou filtrez dans la chaîne \`DOCKER-USER\` (outil ufw-docker)"
      else
        info "Ports Docker publiés sur toutes les interfaces" "$list" "Liez-les à l'adresse du réseau local ou à 127.0.0.1 si l'accès réseau n'est pas nécessaire"
      fi
      local du; du=$(tmo 10 iptables -S DOCKER-USER 2>/dev/null | grep -vE '^-N DOCKER-USER$|^-A DOCKER-USER -j RETURN$')
      [[ -n $du ]] && info "Règles de filtrage DOCKER-USER présentes" "$du"
    fi
  fi

  local -A RISK=([21]="FTP (non chiffré)" [23]="Telnet (non chiffré)" [69]="TFTP" [512]="rexec" [513]="rlogin" [514]="rsh"
    [2375]="API Docker sans TLS" [3306]="MySQL/MariaDB" [5432]="PostgreSQL" [6379]="Redis" [27017]="MongoDB" [9200]="Elasticsearch"
    [11211]="Memcached" [5984]="CouchDB" [8086]="InfluxDB" [5900]="VNC" [3389]="RDP")
  local -A ADMIN=([9000]="Portainer" [9443]="Portainer" [9090]="Cockpit" [10000]="Webmin" [81]="Nginx Proxy Manager" [19999]="Netdata"
    [61208]="Glances" [8384]="Syncthing" [8765]="Audite-moi")
  local -a rows=() risky=() admin=()
  local proto state rq sq loc peer proc addr port expo who
  if have ss; then
    while read -r proto state rq sq loc peer proc; do
      [[ -n $loc ]] || continue
      port=${loc##*:}; addr=${loc%:*}; addr=${addr%%%*}
      case $addr in 127.*|"[::1]"|::1) continue ;; esac
      case $addr in 0.0.0.0|"*"|"[::]"|::) expo="toutes les interfaces" ;; *) expo=$addr ;; esac
      who=$(grep -oE '"[^"]+"' <<< "$proc" | head -n 1 | tr -d '"')
      [[ $who == docker-proxy && -n ${PORTMAP[$port]:-} ]] && who="docker-proxy → ${PORTMAP[$port]}"
      rows+=("$proto$TAB$port$TAB$expo$TAB${who:-?}")
      [[ -n ${RISK[$port]:-} ]] && risky+=("$port ${RISK[$port]} — ${who:-?} ($expo)")
      [[ -n ${ADMIN[$port]:-} ]] && admin+=("$port ${ADMIN[$port]} (${who:-?})")
    done < <(ss -H -tulpn 2>/dev/null)
  fi
  if [[ -n $pubs ]]; then
    local cn hp cp cpn
    while IFS=$US read -r cn hp cp; do
      cpn=${cp%/*}
      [[ -n ${RISK[$hp]:-} ]] && risky+=("$hp ${RISK[$hp]} — conteneur $cn (toutes les interfaces)")
      [[ -z ${RISK[$hp]:-} && -n ${RISK[$cpn]:-} ]] && risky+=("$hp ${RISK[$cpn]} — conteneur $cn (toutes les interfaces)")
      [[ -n ${ADMIN[$hp]:-} ]] && admin+=("$hp ${ADMIN[$hp]} (conteneur $cn)")
    done <<< "$pubs"
  fi
  if ((${#risky[@]})); then
    local rl rl2
    rl=$(printf '%s\n' "${risky[@]}" | sort -u -t' ' -k1,1n -k2)
    if grep -q '^2375 ' <<< "$rl"; then
      crit "API Docker accessible sans TLS sur le réseau" "$(grep '^2375 ' <<< "$rl")" "Retirez \`-H tcp://0.0.0.0:2375\` de la configuration de Docker : quiconque atteint ce port est root sur le serveur"
    fi
    rl2=$(grep -v '^2375 ' <<< "$rl")
    [[ -n $rl2 ]] && warn "Services sensibles accessibles depuis le réseau" "$rl2" \
      "Bases de données et protocoles non chiffrés ne devraient écouter que sur 127.0.0.1 ou le réseau Docker interne : supprimez la publication du port (\`ports:\`) ou liez-la à \`127.0.0.1\`"
  else
    ok "Aucun service sensible (base de données, Telnet, FTP…) exposé sur le réseau"
  fi
  ((${#admin[@]})) && info "Interfaces d'administration accessibles sur le réseau local" "$(printf '%s\n' "${admin[@]}" | sort -u)" \
    "Ne les publiez jamais via un tunnel sans Cloudflare Access ; activez leur authentification forte"
  ((${#rows[@]})) && tbl "Ports en écoute (hors boucle locale)" < <(printf 'Proto\tPort\tAdresse\tProcessus\n'; printf '%s\n' "${rows[@]}" | sort -t "$TAB" -k2,2n -u)

  if have testparm && [[ -f $SMB_CONF ]]; then
    local tp minp guests
    tp=$(tmo 20 testparm -s "$SMB_CONF" 2>/dev/null)
    minp=$(awk -F'=' 'tolower($1) ~ /^[[:space:]]*(server min protocol|min protocol)[[:space:]]*$/ {gsub(/[[:space:]]/, "", $2); print toupper($2)}' <<< "$tp" | head -n 1)
    if [[ $minp == NT1 || $minp == LANMAN* || $minp == CORE* ]]; then
      crit "Samba accepte SMB1" "server min protocol = $minp : protocole obsolète et vulnérable (WannaCry)." "Retirez cette ligne de /etc/samba/smb.conf (défaut : SMB2), puis \`sudo systemctl restart smbd\`"
    fi
    guests=$(awk '/^\[/ {s = $0} tolower($0) ~ /^[[:space:]]*(guest ok|public)[[:space:]]*=[[:space:]]*yes/ {print s}' <<< "$tp" | sort -u | tr '\n' ' ')
    if [[ -n $guests ]]; then
      warn "Partages Samba accessibles sans mot de passe : $guests" "Tout appareil du réseau local (y compris un objet connecté compromis) peut y accéder." \
        "Mettez \`guest ok = no\` et utilisez des comptes Samba (\`sudo smbpasswd -a <utilisateur>\`)"
    elif [[ $minp != NT1 && $minp != LANMAN* && $minp != CORE* ]]; then
      ok "Samba : aucun partage invité, SMB1 désactivé"
    fi
    raw "Configuration Samba effective (testparm -s)" "$tp"
  fi
  if [[ -s /etc/exports ]]; then
    local ex; ex=$(grep -vE '^[[:space:]]*(#|$)' /etc/exports)
    if [[ -n $ex ]]; then
      grep -q 'no_root_squash' <<< "$ex" && warn "Export NFS avec no_root_squash" "$ex" "Remplacez par \`root_squash\` : sinon le root d'un client devient root sur vos fichiers"
      grep -qE '[[:space:]]\*\(|[[:space:]]\(' <<< "$ex" && warn "Export NFS ouvert à toutes les adresses" "$ex" "Restreignez à votre réseau : \`/chemin 192.168.1.0/24(rw,sync,root_squash)\`"
      raw "/etc/exports" "$ex"
    fi
  fi
  if have zfs; then
    local sn; sn=$(tmo 30 zfs get -H -o name,value,source sharenfs 2>/dev/null | awk -F'\t' '$2 != "off" && $3 ~ /local|received/ {print $1 " : sharenfs=" $2}')
    if [[ -n $sn ]]; then
      if grep -qE 'sharenfs=on$' <<< "$sn"; then
        warn "Dataset(s) partagé(s) en NFS avec tout le réseau (sharenfs=on)" "$sn" "Restreignez : \`sudo zfs set sharenfs='rw=@192.168.1.0/24' <dataset>\`"
      else
        info "Datasets partagés en NFS (propriété sharenfs)" "$sn"
      fi
    fi
  fi
  if have upnpc; then
    local upn mine myips; upn=$(tmo 20 upnpc -l 2>/dev/null); myips=" $(hostname -I 2>/dev/null) "
    mine=$(grep -E '^[[:space:]]*[0-9]+[[:space:]]+(TCP|UDP)[[:space:]]+[0-9]+->[0-9.]+:[0-9]+' <<< "$upn" | while read -r _ pr map rest; do
      local tip=${map#*->}; tip=${tip%:*}; [[ $myips == *" $tip "* ]] && echo "$pr $map $rest"; done)
    if [[ -n $mine ]]; then
      warn "La box redirige des ports vers ce serveur (UPnP)" "$mine" "Désactivez UPnP sur la box (ou dans l'application qui l'utilise) : ces ports sont ouverts sur Internet"
    elif grep -qi 'ExternalIPAddress' <<< "$upn"; then
      ok "Aucune redirection UPnP vers ce serveur"
    fi
  fi
  local -a extra=()
  local svc
  for svc in avahi-daemon cups cups-browsed rpcbind telnet.socket vsftpd proftpd snmpd; do systemctl is-active --quiet "$svc" 2>/dev/null && extra+=("$svc"); done
  ((${#extra[@]})) && info "Services réseau actifs à vérifier : $(join_list ', ' "${extra[@]}")" "Désactivez ceux qui ne servent pas (moins de surface d'attaque)." "\`sudo systemctl disable --now <service>\`"
}

check_dockersec() {
  section dockersec
  if ((!DOCKER_OK)); then info "Docker absent ou inaccessible : section ignorée"; return; fi
  local sock=/var/run/docker.sock
  if [[ -S $sock ]]; then
    local sm mode; sm=$(stat -Lc '%a %U:%G' "$sock"); mode=${sm%% *}
    if (( 8#$mode & 8#006 )); then
      crit "Socket Docker accessible à tous ($sm)" "N'importe quel utilisateur local peut piloter Docker, donc devenir root." "\`sudo chmod 660 $sock\` et vérifiez docker.socket"
    else
      ok "Socket Docker protégé ($sm)"
    fi
  fi
  local tcp; tcp=$( { systemctl cat docker 2>/dev/null; cat /etc/docker/daemon.json 2>/dev/null; } | grep -oE 'tcp://[^" ]+' | sort -u | tr '\n' ' ')
  if [[ -n $tcp ]]; then
    if [[ $tcp == *":2375"* ]] || ! { grep -qs '"tlsverify"[[:space:]]*:[[:space:]]*true' /etc/docker/daemon.json || systemctl cat docker 2>/dev/null | grep -q -- '--tlsverify'; }; then
      crit "API Docker exposée en TCP sans TLS ($tcp)" "Quiconque atteint ce port obtient un accès root à l'hôte (cible classique des botnets de minage)." \
        "Retirez l'option \`-H tcp://…\` (daemon.json ou service docker) ou activez le TLS mutuel (\`--tlsverify\`)"
    else
      info "API Docker en TCP avec TLS ($tcp)"
    fi
  fi
  local so; so=$(tmo 15 docker info --format '{{json .SecurityOptions}}' 2>/dev/null)
  if [[ $so == *seccomp* ]]; then ok "Profils de sécurité Docker actifs" "$so"; else warn "Seccomp désactivé pour Docker" "$so" "Retirez \`seccomp-profile: unconfined\` de daemon.json"; fi
  [[ $so == *apparmor* ]] || info "AppArmor non utilisé par Docker" "$so"
  [[ $so == *rootless* ]] && ok "Docker en mode rootless"
  [[ $so == *userns* ]] && ok "Remappage des utilisateurs (userns-remap) actif"
  local dj=/etc/docker/daemon.json
  if [[ -s $dj ]] && ! jq -e . "$dj" >/dev/null 2>&1; then
    warn "daemon.json invalide" "/etc/docker/daemon.json n'est pas un JSON valide : Docker refusera de redémarrer." "\`sudo jq . /etc/docker/daemon.json\` pour localiser l'erreur"
  elif [[ -s $dj ]]; then
    tbl "Réglages du démon Docker (daemon.json)" < <(printf 'Paramètre\tValeur\tRecommandation\n'
      jq -r '[["icc", (.icc // "défaut (true)"), "false : les conteneurs du réseau bridge par défaut ne se parlent plus"],
              ["no-new-privileges", (."no-new-privileges" // "défaut (false)"), "true : bloque l’élévation de privilèges dans les conteneurs"],
              ["userns-remap", (."userns-remap" // "non"), "default : root du conteneur ≠ root de l’hôte (attention aux volumes)"],
              ["live-restore", (."live-restore" // "défaut (false)"), "true : les conteneurs survivent au redémarrage du démon"],
              ["log-driver", (."log-driver" // "défaut (json-file)"), "local, ou json-file avec max-size"]][] | map(tostring) | join("\t")' "$dj")
  fi

  # Posture de chaque conteneur en fonctionnement
  local -A IMG_AGE=()
  local iids iid created dd
  iids=$(jq -r '.[] | select(.State.Status == "running") | .Image' "$INSPECT" | sort -u)
  # shellcheck disable=SC2086
  while IFS='|' read -r iid created; do
    dd=$(days_ago "$created") || continue
    ((dd >= 0 && dd < 15000)) && IMG_AGE[$iid]=$dd
  done < <( [[ -n $iids ]] && tmo 30 docker image inspect --format '{{.Id}}|{{.Created}}' $iids 2>/dev/null)

  local -a rows=() secrets=() oldimg=()
  local n img priv user net pidm ipcm caps secopt ro mem sockm sens envsec haspuid imgid restart
  while IFS=$US read -r n img priv user net pidm ipcm caps secopt ro mem sockm sens envsec haspuid imgid restart; do
    local isexp=0 expo="—" lvl
    if [[ -n ${EXPOSED[$n]:-} ]]; then isexp=1; expo="@INFO Internet (${EXPOSED[$n]})"
    elif [[ -n ${REACHABLE[$n]:-} ]]; then isexp=1; expo="@INFO via le tunnel ?"; fi
    local where; ((isexp)) && where=" (exposé sur Internet)" || where=""
    if [[ $priv == true ]]; then
      lvl=WARN; ((isexp)) && lvl=CRIT
      add "$lvl" "Conteneur $n privilégié$where" "privileged: true donne au conteneur un accès quasi total à l'hôte : sa compromission = celle du serveur." \
        "Retirez \`privileged: true\` ; pour le GPU, \`devices: [\"/dev/dri:/dev/dri\"]\` suffit ; n'ajoutez que les capacités utiles (\`cap_add\`)"
    fi
    if [[ -n $sockm ]]; then
      lvl=WARN; ((isexp)) && lvl=CRIT
      add "$lvl" "Conteneur $n : socket Docker monté ($sockm)$where" "Accès au socket Docker = contrôle total de l'hôte. Le montage en lecture seule (:ro) ne protège pas l'API." \
        "$( [[ $img == nextcloud/all-in-one* ]] && echo "Indispensable au fonctionnement de Nextcloud AIO : gardez son interface (port 8080) inaccessible depuis Internet" || echo "Si l'outil en a vraiment besoin, passez par un proxy limitant les appels autorisés (ex. tecnativa/docker-socket-proxy)")"
    fi
    if [[ $net == host ]]; then
      if ((isexp)); then warn "Conteneur $n en réseau « host »$where" "Aucune isolation réseau : il voit et peut écouter sur toutes les interfaces de l'hôte." "Utilisez un réseau bridge et publiez uniquement les ports nécessaires"
      else info "Conteneur $n en réseau « host »" "Pas d'isolation réseau (parfois nécessaire pour la découverte DLNA/mDNS)."; fi
    fi
    [[ $pidm == host ]] && warn "Conteneur $n partage l'espace de processus de l'hôte (pid: host)" "Il voit et peut signaler tous les processus du serveur." "Retirez \`pid: host\` si ce n'est pas indispensable"
    if [[ ,$caps, =~ ,(CAP_)?(SYS_ADMIN|ALL|SYS_MODULE|SYS_RAWIO|SYS_PTRACE|DAC_READ_SEARCH|BPF), ]] && [[ $img == *aio-collabora* ]]; then
      info "Conteneur $n : capacités étendues ($caps)" "Requises par Collabora (Nextcloud AIO) pour isoler chaque document : c'est la configuration prévue." ""
    elif [[ ,$caps, =~ ,(CAP_)?(SYS_ADMIN|ALL|SYS_MODULE|SYS_RAWIO|SYS_PTRACE|DAC_READ_SEARCH|BPF), ]]; then
      warn "Conteneur $n : capacités dangereuses ($caps)" "Ces capacités permettent souvent de s'échapper du conteneur." "Retirez-les de \`cap_add\` si possible"
    fi
    [[ $secopt == *unconfined* ]] && warn "Conteneur $n : confinement désactivé ($secopt)" "Seccomp ou AppArmor est désactivé pour ce conteneur." "Retirez \`seccomp:unconfined\` / \`apparmor:unconfined\` de \`security_opt\`"
    if [[ -n $sens ]]; then
      local smsg=$sens
      if [[ ", $sens" == *", /→"*"(rw)"* || $sens == *"/etc→"*"(rw)"* || $sens == *"/root→"*"(rw)"* ]]; then
        if [[ $user == root ]]; then lvl=CRIT; smsg+="${NL}Le conteneur tourne en root : il peut modifier n'importe quel fichier du serveur."
        else lvl=WARN; smsg+="${NL}Le conteneur tourne sous l'utilisateur $user : il peut lire presque tout le serveur et modifier tout ce qui appartient à cet utilisateur."; fi
      else lvl=WARN; fi
      add "$lvl" "Conteneur $n : montage sensible de l'hôte" "$smsg" "Ne montez que les dossiers utiles (ex. \`/hddPool/partage:/srv\` au lieu de \`/\`), en lecture seule (\`:ro\`) quand c'est possible"
    fi
    if ((isexp)) && [[ $user == root && $haspuid != true ]]; then
      info "Conteneur $n (exposé) fonctionne en root" "L'application tourne en root dans le conteneur : une faille donne davantage de prise." "Si l'image le permet : \`user: \"1000:1000\"\` dans le compose"
    fi
    [[ -n $envsec ]] && secrets+=("$n : ${envsec//,/, }")
    local age=${IMG_AGE[$imgid]:-} agec="?"
    if isint "$age"; then
      agec="$age j"
      if ((isexp && age > 180)); then
        agec="@WARN $age j"
        local maj="Dans le dossier du projet : \`docker compose pull && docker compose up -d\` ; un outil comme diun peut vous prévenir des nouvelles versions"
        [[ $img == *nextcloud-releases/aio-* ]] && maj="Conteneur géré par Nextcloud AIO : mettez à jour depuis son interface (port 8080 de l'hôte) → « Arrêter les conteneurs », puis « Démarrer et mettre à jour ». Si rien ne se met à jour, mettez d'abord à jour le conteneur maître (nextcloud-aio-mastercontainer)"
        warn "Image de $n construite il y a $age jours$where" "Service exposé : ses failles connues restent ouvertes tant que l'image n'est pas mise à jour (vérifiez qu'une version plus récente existe)." "$maj"
      elif ((age > 365)); then
        agec="@INFO $age j"; oldimg+=("$n ($age j)")
      fi
    fi
    local nnp="non"; [[ $secopt == *no-new-privileges* ]] && nnp="oui"
    local memc="aucune"; isint "$mem" && ((mem > 0)) && memc=$(hbytes "$mem")
    rows+=("$n$TAB$expo$TAB$( [[ $priv == true ]] && echo "@WARN oui" || echo non)$TAB$( [[ -n $sockm ]] && echo "@WARN $sockm" || echo non)$TAB${net:--}$TAB$( [[ $user == root ]] && echo "root" || echo "${user:-?}")$TAB${caps:--}$TAB$( [[ -n $sens ]] && echo "@WARN oui" || echo non)$TAB$nnp$TAB$memc$TAB$agec")
  done < <(jq -r '
    def isroot: (. == "" or . == "0" or . == "root" or startswith("0:") or startswith("root:"));
    .[] | select(.State.Status == "running") | (.Name | ltrimstr("/")) as $n | ((.Config.Env // []) | map(split("=")[0])) as $env |
    [ $n, (.Config.Image // ""), (.HostConfig.Privileged | tostring),
      ((.Config.User // "") | if isroot then "root" else . end),
      (.HostConfig.NetworkMode // ""), (.HostConfig.PidMode // ""), (.HostConfig.IpcMode // ""),
      ((.HostConfig.CapAdd // []) | join(",")), ((.HostConfig.SecurityOpt // []) | join(",")),
      (.HostConfig.ReadonlyRootfs | tostring), ((.HostConfig.Memory // 0) | tostring),
      ([.Mounts[]? | select((.Source // "") | test("(^|/)docker\\.sock$")) | (if .RW then "rw" else "ro" end)] | join(",")),
      ([.Mounts[]? | select(.Type == "bind") | select(.Source as $s | (["/","/etc","/root","/boot","/usr","/lib","/bin","/sbin","/var","/var/lib","/var/lib/docker","/proc","/sys","/dev","/home","/run","/var/run"] | index($s)) != null)
        | "\(.Source)→\(.Destination)" + (if .RW then " (rw)" else " (ro)" end)] | join(", ")),
      ($env | map(select(test("PASS|SECRET|TOKEN|API_?KEY|PRIVATE_?KEY|CREDENTIAL"; "i") and (test("_FILE$") | not))) | unique | join(",")),
      (($env | map(select(test("^(PUID|PGID|UID|GID|USER_ID|GROUP_ID|APP_UID|RUN_AS_USER)$"; "i"))) | length > 0) | tostring),
      (.Image // ""), (.HostConfig.RestartPolicy.Name // "")
    ] | map(tostring) | join("\u001f")' "$INSPECT")
  ((${#secrets[@]})) && info "Secrets en clair dans les variables d'environnement" "$(printf '%s\n' "${secrets[@]}")$NL(valeurs masquées ; elles sont lisibles via \`docker inspect\` par tout membre du groupe docker)" \
    "Quand l'image le permet, utilisez les secrets Docker Compose (\`secrets:\` + variables \`*_FILE\`) et protégez les fichiers .env (\`chmod 600\`)"
  ((${#oldimg[@]})) && info "Images de plus d'un an" "$(join_list ', ' "${oldimg[@]}")" "\`docker compose pull && docker compose up -d\` dans le dossier de chaque projet"
  ((${#rows[@]})) && tbl "Posture de sécurité des conteneurs" < <(printf 'Conteneur\tExposition\tPrivilégié\tSocket Docker\tRéseau\tUtilisateur\tCapacités ajoutées\tMontages sensibles\tno-new-privileges\tLimite RAM\tÂge de l’image\n'; printf '%s\n' "${rows[@]}")

  # Fichiers compose et .env lisibles par tous et contenant des secrets
  local -a weak=()
  local f m
  while IFS= read -r f; do
    [[ -f $f ]] || continue
    m=$(stat -c '%a' "$f")
    (( 8#$m & 8#004 )) && grep -qiE '(password|passwd|secret|token|api[_-]?key)[[:space:]]*[:=]' "$f" && weak+=("$f ($m)")
  done < <( { jq -r '.[] | (.Config.Labels // {}) | (.["com.docker.compose.project.config_files"] // empty) | split(",")[]' "$INSPECT"
              jq -r '.[] | (.Config.Labels // {}) | (.["com.docker.compose.project.working_dir"] // empty) | . + "/.env"' "$INSPECT"; } | sort -u)
  if ((${#weak[@]})); then
    warn "Fichiers compose/.env contenant des secrets lisibles par tous" "$(printf '%s\n' "${weak[@]}")" "\`chmod 600 <fichier>\` (ou 640 avec un groupe d'administration)"
  fi
}

chkperm() {
  local f=$1 max=$2 m
  [[ -e $f ]] || return 0
  m=$(stat -c '%a' "$f" 2>/dev/null) || return 0
  if (( (8#$m & ~8#$max) & 8#7777 )); then PERM_BAD+=("$f : $m (attendu $max au plus)"); fi
}

check_fichiers() {
  section fichiers
  PERM_BAD=()
  local f
  chkperm /etc/passwd 644; chkperm /etc/group 644; chkperm /etc/shadow 640; chkperm /etc/gshadow 640
  chkperm /etc/sudoers 440
  for f in /etc/sudoers.d/*; do [[ -f $f ]] && chkperm "$f" 440; done
  chkperm /etc/ssh/sshd_config 644
  for f in /etc/ssh/sshd_config.d/*; do [[ -f $f ]] && chkperm "$f" 644; done
  for f in /etc/ssh/ssh_host_*_key; do [[ -f $f ]] && chkperm "$f" 600; done
  chkperm /root 700; chkperm /etc/crontab 644
  for f in /etc/cron.d/*; do [[ -f $f ]] && chkperm "$f" 644; done
  chkperm /etc/docker/daemon.json 644
  if ((${#PERM_BAD[@]})); then
    warn "Fichiers sensibles avec des droits trop larges" "$(printf '%s\n' "${PERM_BAD[@]}")" "Corrigez avec \`sudo chmod <droits attendus> <fichier>\`"
  else
    ok "Droits des fichiers système sensibles corrects"
  fi

  local ww; ww=$(tmo 120 find /etc /usr /boot /opt /var/spool/cron -xdev -type f -perm -0002 2>/dev/null | head -n 30)
  [[ -n $ww ]] && warn "Fichiers système modifiables par tous" "$ww" "\`sudo chmod o-w <fichier>\`, et cherchez qui les a modifiés"
  if ((!QUICK)); then
    note "Recherche des dossiers ouverts à tous et des fichiers SUID…"
    local wd; wd=$(tmo 180 find / -xdev \( -path /proc -o -path /sys -o -path /dev -o -path /run -o -path /tmp -o -path /var/tmp -o -path /snap -o -path /var/snap -o -path /var/lib/docker -o -path /var/lib/containerd \) -prune \
      -o -type d -perm -0002 ! -perm -1000 -print 2>/dev/null | head -n 30)
    [[ -n $wd ]] && warn "Dossiers modifiables par tous sans « sticky bit »" "$wd" "\`sudo chmod o-w <dossier>\` (ou \`sudo chmod +t <dossier>\` s'il doit rester partagé)"
    check_suid
  fi

  local -a zw=() hr=() pk=()
  local m
  for f in "${ZFS_MOUNTS[@]}"; do [[ -d $f ]] || continue; m=$(stat -c '%a' "$f"); (( 8#$m & 8#002 )) && zw+=("$f ($m)"); done
  ((${#zw[@]})) && warn "Dossiers de données ZFS modifiables par tous" "$(printf '%s\n' "${zw[@]}")" \
    "Préférez un groupe dédié : \`sudo chgrp -R partage <dossier> && sudo chmod 2775 <dossier>\`"
  for f in /home/*/; do [[ -d $f ]] || continue; m=$(stat -c '%a' "$f"); (( 8#$m & 8#005 )) && hr+=("${f%/} ($m)"); done
  ((${#hr[@]})) && info "Dossiers personnels lisibles par les autres utilisateurs" "$(join_list ', ' "${hr[@]}")" "\`sudo chmod 750 /home/<utilisateur>\`"
  while IFS= read -r f; do m=$(stat -c '%a' "$f"); (( 8#$m & 8#077 )) && pk+=("$f ($m)"); done < <(find /root/.ssh /home/*/.ssh -maxdepth 1 -type f -name 'id_*' ! -name '*.pub' 2>/dev/null)
  ((${#pk[@]})) && warn "Clés SSH privées lisibles par d'autres" "$(printf '%s\n' "${pk[@]}")" "\`chmod 600 <clé>\`"

  # Intégrité des paquets critiques (fichiers modifiés hors du gestionnaire de paquets)
  local p vout=""
  for p in openssh-server openssh-client sudo passwd login util-linux coreutils procps iproute2 findutils bash libpam-modules libpam-runtime cron systemd docker-ce docker.io containerd.io; do
    dpkg -s "$p" >/dev/null 2>&1 || continue
    vout+=$(tmo 60 dpkg -V "$p" 2>/dev/null | awk -v p="$p" '$2 != "c" && substr($1, 3, 1) == "5" {print p " : " $NF}')
    vout+=$NL
  done
  vout=$(grep . <<< "$vout")
  if [[ -n $vout ]]; then
    crit "Fichiers système modifiés hors du gestionnaire de paquets" "$vout" \
      "Si ce n'est pas une modification volontaire, réinstallez le paquet (\`sudo apt install --reinstall <paquet>\`) et suspectez une compromission"
  else
    ok "Intégrité des binaires critiques vérifiée (dpkg --verify)"
  fi
}

check_suid() {
  local -a suid=() unowned=() retry=()
  mapfile -t suid < <(tmo 180 find / -xdev \( -path /proc -o -path /sys -o -path /dev -o -path /run -o -path /snap -o -path /var/snap -o -path /var/lib/docker -o -path /var/lib/containerd -o -path /var/lib/lxd \) -prune \
    -o -type f \( -perm -4000 -o -perm -2000 \) -print 2>/dev/null)
  ((${#suid[@]})) || return 0
  local owned f alt
  owned=$(dpkg -S "${suid[@]}" 2>/dev/null | grep -oE ': /.*$' | cut -c3-)
  for f in "${suid[@]}"; do grep -qxF "$f" <<< "$owned" || retry+=("$f"); done
  if ((${#retry[@]})); then
    local -a alts=()
    for f in "${retry[@]}"; do alts+=("${f#/usr}"); done
    local owned2; owned2=$(dpkg -S "${alts[@]}" 2>/dev/null | grep -oE ': /.*$' | cut -c3-)
    for f in "${retry[@]}"; do alt=${f#/usr}; grep -qxF "$alt" <<< "$owned2" || unowned+=("$f"); done
  fi
  if ((${#unowned[@]})); then
    warn "Fichiers SUID/SGID n'appartenant à aucun paquet" "$(printf '%s\n' "${unowned[@]}")" \
      "Vérifiez leur origine ; si inconnus, retirez le bit SUID (\`sudo chmod u-s,g-s <fichier>\`) et enquêtez"
  else
    ok "${#suid[@]} fichiers SUID/SGID, tous issus de paquets officiels"
  fi
  raw "Fichiers SUID/SGID" "$(printf '%s\n' "${suid[@]}")"
}

check_noyau() {
  section noyau
  local -a kvers=() newer=() missing=()
  local f
  for f in /boot/vmlinuz-*; do [[ -e $f ]] && kvers+=("${f#/boot/vmlinuz-}"); done
  ((${#kvers[@]})) && mapfile -t kvers < <(printf '%s\n' "${kvers[@]}" | sort -V)
  for f in "${kvers[@]}"; do
    [[ $f != "$KERNEL" && $(printf '%s\n%s\n' "$KERNEL" "$f" | sort -V | tail -n 1) == "$f" ]] && newer+=("$f")
  done
  if ((${#newer[@]})); then
    local nw=${newer[${#newer[@]} - 1]}
    if ((REBOOT_REQ)); then
      info "Noyau $nw installé, $KERNEL en cours d'exécution" "Il sera utilisé au prochain redémarrage (voir « Redémarrage nécessaire »)."
    else
      warn "Noyau $nw installé mais non utilisé" "Le noyau en cours ($KERNEL) ne bénéficie pas des derniers correctifs de sécurité." "Redémarrez après avoir vérifié les modules ci-dessous"
    fi
  else
    ok "Le noyau en cours est le plus récent installé ($KERNEL)"
  fi
  local loaded mod kv; loaded=$(lsmod 2>/dev/null | awk 'NR > 1 {print $1}')
  for mod in zfs nvidia; do
    grep -qx "$mod" <<< "$loaded" || continue
    for kv in "${newer[@]}"; do modinfo -k "$kv" -F version "$mod" >/dev/null 2>&1 || missing+=("$mod pour $kv"); done
  done
  if ((${#missing[@]})); then
    local what=""
    [[ ${missing[*]} == *zfs* ]] && what="les pools ZFS ne seront pas importés"
    [[ ${missing[*]} == *nvidia* ]] && what+="${what:+ et }le GPU NVIDIA sera inutilisable"
    crit "Modules absents pour le prochain noyau : $(join_list ', ' "${missing[@]}")" "Au prochain redémarrage, $what." \
      "NE REDÉMARREZ PAS avant correction : \`dkms status\`, puis \`sudo dkms autoinstall -k <noyau>\` (modules DKMS) ; pour ZFS sous Ubuntu : \`sudo apt install --reinstall linux-modules-<noyau>\`"
  elif ((${#newer[@]})) && grep -qxE 'zfs|nvidia' <<< "$loaded"; then
    ok "Modules ZFS/GPU prêts pour le noyau ${newer[${#newer[@]} - 1]}"
  fi
  if have dkms; then
    local ds dbad; ds=$(tmo 30 dkms status 2>&1)
    dbad=$(grep -vE ': installed$|^[[:space:]]*$' <<< "$ds")
    [[ -n $dbad ]] && warn "Modules DKMS non installés ou en erreur" "$dbad" "\`sudo dkms autoinstall\`, puis consultez /var/lib/dkms/<module>/<version>/build/make.log"
    raw "dkms status" "$ds"
  fi

  local vd=/sys/devices/system/cpu/vulnerabilities
  if [[ -d $vd ]]; then
    local vul fix; vul=$(grep -H . "$vd"/* 2>/dev/null | sed "s|^$vd/||" | grep -E ':Vulnerable')
    if [[ -n $vul ]]; then
      if grep -q 'microcode' <<< "$vul"; then fix="Installez le microcode du processeur (\`sudo apt install intel-microcode\` ou \`amd64-microcode\`) puis redémarrez"
      else fix="Vérifiez que le noyau est à jour et que les protections ne sont pas désactivées (\`mitigations=off\` dans /proc/cmdline)"; fi
      warn "Vulnérabilités du processeur non atténuées" "$vul" "$fix"
    else
      ok "Vulnérabilités matérielles du processeur atténuées"
    fi
    raw "Vulnérabilités du processeur" "$(grep -H . "$vd"/* 2>/dev/null | sed "s|^$vd/||")"
  fi
  grep -qw 'mitigations=off' /proc/cmdline 2>/dev/null && warn "Protections CPU désactivées (mitigations=off)" "$(cat /proc/cmdline)" \
    "Retirez \`mitigations=off\` de GRUB_CMDLINE_LINUX_DEFAULT (/etc/default/grub), puis \`sudo update-grub\`"

  local vendor mcpkg=""
  vendor=$(awk -F': *' '/^vendor_id/ {print $2; exit}' /proc/cpuinfo)
  [[ $vendor == GenuineIntel ]] && mcpkg=intel-microcode
  [[ $vendor == AuthenticAMD ]] && mcpkg=amd64-microcode
  if [[ -n $mcpkg ]] && ! grep -qw hypervisor /proc/cpuinfo; then
    if dpkg -s "$mcpkg" >/dev/null 2>&1; then
      ok "Microcode du processeur installé ($mcpkg)" "Révision : $(awk -F': *' '/^microcode/ {print $2; exit}' /proc/cpuinfo)"
    else
      warn "Microcode du processeur non installé" "Les correctifs de sécurité du processeur ($mcpkg) ne sont pas chargés au démarrage." "\`sudo apt install $mcpkg\` puis redémarrez"
    fi
  fi

  local -a sys=(
    "kernel.randomize_va_space|2|WARN|ge|Randomisation de l'espace d'adressage (ASLR)"
    "fs.protected_hardlinks|1|WARN|eq|Protection des liens physiques"
    "fs.protected_symlinks|1|WARN|eq|Protection des liens symboliques"
    "fs.protected_fifos|1|INFO|ge|Protection des FIFO dans les dossiers partagés"
    "fs.protected_regular|1|INFO|ge|Protection des fichiers dans les dossiers partagés"
    "fs.suid_dumpable|0|INFO|eq|Pas de vidage mémoire des programmes SUID"
    "kernel.kptr_restrict|1|INFO|ge|Masquage des adresses du noyau"
    "kernel.dmesg_restrict|1|INFO|eq|dmesg réservé à root"
    "kernel.yama.ptrace_scope|1|INFO|ge|Restriction de ptrace"
    "kernel.unprivileged_bpf_disabled|1|INFO|ge|eBPF non privilégié désactivé"
    "net.ipv4.tcp_syncookies|1|INFO|eq|Protection contre l'inondation SYN"
    "net.ipv4.conf.all.accept_redirects|0|INFO|eq|Redirections ICMP refusées (IPv4)"
    "net.ipv6.conf.all.accept_redirects|0|INFO|eq|Redirections ICMP refusées (IPv6)"
    "net.ipv4.conf.all.accept_source_route|0|INFO|eq|Routage par la source refusé"
    "net.ipv4.icmp_echo_ignore_broadcasts|1|INFO|eq|Pings en broadcast ignorés"
  )
  local -a rows=() bad=()
  local e k want lv how desc cur st nok=0
  for e in "${sys[@]}"; do
    IFS='|' read -r k want lv how desc <<< "$e"
    cur=$(sysctl -n "$k" 2>/dev/null) || continue
    st=$lv
    if [[ $how == ge ]]; then
      isint "$cur" && ((cur >= want)) && st=OK
    elif [[ $cur == "$want" ]]; then
      st=OK
    fi
    [[ $st == OK ]] && nok=$((nok + 1))
    [[ $st == WARN ]] && bad+=("$k = $cur (recommandé : $want)")
    rows+=("$k$TAB$desc$TAB$cur$TAB$want$TAB@$st $( [[ $st == OK ]] && echo conforme || echo 'à durcir')")
  done
  if ((${#bad[@]})); then
    warn "Paramètres de sécurité du noyau affaiblis" "$(printf '%s\n' "${bad[@]}")" "Ajoutez-les dans /etc/sysctl.d/99-durcissement.conf, puis \`sudo sysctl --system\`"
  fi
  ((${#rows[@]})) && info "$nok/${#rows[@]} paramètres sysctl de sécurité conformes" "Les écarts « Info » sont des durcissements optionnels (voir le tableau)." \
    "Pour les appliquer : /etc/sysctl.d/99-durcissement.conf puis \`sudo sysctl --system\`"
  ((${#rows[@]})) && tbl "Paramètres sysctl de sécurité" < <(printf 'Paramètre\tRôle\tValeur\tRecommandé\tÉtat\n'; printf '%s\n' "${rows[@]}")

  if have aa-status; then
    if aa-status --enabled 2>/dev/null; then
      ok "AppArmor actif" "$(aa-status 2>/dev/null | grep -E 'profiles are (loaded|in enforce mode)' | tr '\n' ' ')"
    else
      warn "AppArmor désactivé" "Les profils de confinement (dont celui des conteneurs Docker) ne s'appliquent pas." \
        "Vérifiez que \`apparmor=0\` n'est pas dans /proc/cmdline, puis \`sudo systemctl enable --now apparmor\`"
    fi
  elif [[ -r /sys/module/apparmor/parameters/enabled ]]; then
    if [[ $(cat /sys/module/apparmor/parameters/enabled) == Y ]]; then ok "AppArmor actif"; else warn "AppArmor désactivé" "" "\`sudo systemctl enable --now apparmor\`"; fi
  fi
  have mokutil && info "Secure Boot : $(mokutil --sb-state 2>&1 | head -n 1)"
}

check_journaux() {
  section journaux
  if [[ -d /var/log/journal ]]; then
    ok "Journal systemd persistant (conservé après redémarrage)"
  else
    info "Journal systemd non persistant" "Les journaux sont perdus à chaque redémarrage : difficile d'enquêter après un incident." \
      "\`sudo mkdir -p /var/log/journal && sudo systemd-tmpfiles --create --prefix /var/log/journal && sudo systemctl restart systemd-journald\`"
  fi
  if have journalctl; then
    local sj nsudo sfail acct
    sj=$(tmo 30 journalctl -t sudo --since "7 days ago" --no-pager -q -o short-iso 2>/dev/null)
    nsudo=$(grep -c 'COMMAND=' <<< "$sj")
    sfail=$(grep -E 'authentication failure|incorrect password attempt|NOT in sudoers|user NOT authorized' <<< "$sj" | tail -n 10)
    if [[ -n $sfail ]]; then
      warn "Échecs d'authentification sudo (7 jours)" "$sfail" "Vérifiez qu'il s'agit bien de vous (faute de frappe) ; sinon, un compte local est peut-être compromis"
    else
      ok "Aucun échec sudo (7 jours)" "$nsudo commande(s) sudo exécutée(s)."
    fi
    acct=$(tmo 30 journalctl --since "30 days ago" --no-pager -q -o short-iso -t useradd -t userdel -t usermod -t groupadd -t gpasswd -t passwd -t chpasswd 2>/dev/null | tail -n 15)
    [[ -n $acct ]] && info "Modifications de comptes ou de groupes (30 jours)" "$acct" "Vérifiez que chaque changement est de votre fait"
  fi
  if systemctl is-active --quiet auditd 2>/dev/null; then
    ok "auditd actif (journalisation fine des accès)"
  else
    info "auditd non installé" "Utile pour tracer finement les accès et modifications des fichiers sensibles." "\`sudo apt install auditd\`"
  fi

  local susp="" dele="" p exe comm
  for p in /proc/[0-9]*; do
    exe=$(readlink "$p/exe" 2>/dev/null) || continue
    case $exe in
      /tmp/*|/dev/shm/*|/var/tmp/*|/run/shm/*) comm=$(cat "$p/comm" 2>/dev/null); susp+="PID ${p#/proc/} : $exe ($comm)$NL" ;;
    esac
    [[ $exe == *" (deleted)" && $exe != /memfd:* ]] && dele+="$(cat "$p/comm" 2>/dev/null)$NL"
  done
  [[ -n $susp ]] && warn "Processus exécutés depuis un dossier temporaire" "$susp" \
    "Signe classique de logiciel malveillant : examinez-les (\`sudo ls -l /proc/<PID>/exe\`, \`sudo cat /proc/<PID>/cmdline | tr '\\\\0' ' '\`) avant tout redémarrage"
  if [[ -n $dele ]]; then
    info "Processus utilisant des programmes remplacés par une mise à jour" "$(sort -u <<< "$dele" | grep . | head -n 15 | tr '\n' ' ')" \
      "Redémarrez les services concernés (\`sudo needrestart\`) ou le serveur"
  fi
  local mine; mine=$(ps -eo pid,user,comm,args 2>/dev/null | grep -Ei 'xmrig|kinsing|kdevtmpfsi|minerd|cpuminer|nicehash|c3pool|moneroocean|stratum\+tcp' | grep -v grep)
  if [[ -n $mine ]]; then
    crit "Processus de minage de cryptomonnaie détecté" "$mine" "Machine probablement compromise (souvent via une API Docker ou un service exposé) : isolez-la du réseau et enquêtez"
  else
    ok "Aucun processus suspect connu (mineurs, exécution depuis /tmp)"
  fi
  raw "Processus les plus gourmands en CPU" "$(ps -eo pid,user,pcpu,pmem,etime,comm --sort=-pcpu 2>/dev/null | head -n 15)"
  have last && rawcmd "Dernières connexions" last -n 20 -i -w
  have lastb && rawcmd "Dernières connexions échouées" lastb -n 20 -i -w
}

check_outils() {
  section outils
  if have lynis; then
    if ((QUICK)); then
      info "Lynis non exécuté (mode rapide)"
    else
      note "Lynis : audit en cours (1 à 3 minutes)…"
      local lr="$WORK/lynis-report.dat" ll="$WORK/lynis.log"
      tmo 900 lynis audit system --quick --no-colors --quiet --logfile "$ll" --report-file "$lr" > "$WORK/lynis.out" 2>&1
      if [[ -s $lr ]]; then
        local hi lw ns lvl=INFO
        hi=$(awk -F= '/^hardening_index=/ {print $2}' "$lr")
        lw=$(awk '/^warning\[\]=/ {sub(/^warning\[\]=/, ""); print}' "$lr" | awk -F'|' '{print $1 " : " $2}')
        ns=$(grep -c '^suggestion\[\]=' "$lr")
        if isint "$hi"; then ((hi >= 75)) && lvl=OK; ((hi < 60)) && lvl=WARN; fi
        add "$lvl" "Indice de durcissement Lynis : ${hi:-?}/100" "$ns suggestion(s), $(nlines "$lw") avertissement(s)." "Détail d'un test : \`sudo lynis show details <ID>\`"
        [[ -n $lw ]] && warn "Avertissements Lynis" "$lw" "Détail : \`sudo lynis show details <ID>\`"
        tbl "Suggestions de Lynis" < <(printf 'Test\tSuggestion\tDétail\n'; awk '/^suggestion\[\]=/ {sub(/^suggestion\[\]=/, ""); print}' "$lr" | awk -F'|' '{print $1 "\t" $2 "\t" $3}' | head -n 80)
      else
        warn "Lynis n'a pas produit de rapport" "$(tail -n 5 "$WORK/lynis.out")"
      fi
    fi
  else
    info "Lynis non installé" "Lynis complète cet audit avec environ 300 tests de durcissement." "\`sudo apt install lynis\` (ou relancez avec --install-deps)"
  fi

  if have trivy && ((DOCKER_OK)); then
    if ((QUICK)); then
      info "Trivy non exécuté (mode rapide)"
    else
      local -a imgs=() trows=()
      local img out c h tc=0 nexp
      mapfile -t imgs < <(jq -r '.[] | select(.State.Status == "running") | .Config.Image' "$INSPECT" | sort -u)
      note "Trivy : analyse de ${#imgs[@]} image(s)…"
      for img in "${imgs[@]}"; do
        out=$(tmo 600 trivy image --quiet --scanners vuln --ignore-unfixed --severity HIGH,CRITICAL --format json "$img" 2>/dev/null) || continue
        c=$(jq '[.Results[]?.Vulnerabilities[]? | select(.Severity == "CRITICAL")] | length' <<< "$out" 2>/dev/null)
        h=$(jq '[.Results[]?.Vulnerabilities[]? | select(.Severity == "HIGH")] | length' <<< "$out" 2>/dev/null)
        isint "$c" || continue
        tc=$((tc + c))
        nexp=$(jq -r --arg i "$img" '.[] | select(.Config.Image == $i) | .Name | ltrimstr("/")' "$INSPECT" | while read -r x; do [[ -n ${EXPOSED[$x]:-}${REACHABLE[$x]:-} ]] && echo "$x"; done | head -n 1)
        trows+=("$img$TAB$( ((c > 0)) && echo "@WARN $c" || echo "@OK 0")$TAB$h$TAB${nexp:+Internet ($nexp)}")
        ((c > 0)) && [[ -n $nexp ]] && warn "Image exposée $img : $c vulnérabilité(s) critique(s) corrigeable(s)" "Conteneur $nexp, publié sur Internet." "Mettez l'image à jour : \`docker compose pull && docker compose up -d\`"
      done
      ((${#trows[@]})) && tbl "Vulnérabilités des images (Trivy, corrigeables uniquement)" < <(printf 'Image\tCritiques\tÉlevées\tExposition\n'; printf '%s\n' "${trows[@]}")
      ((tc == 0 && ${#trows[@]} > 0)) && ok "Aucune vulnérabilité critique corrigeable dans les images en service"
    fi
  elif ((DOCKER_OK)); then
    info "Trivy non installé" "Trivy recherche les vulnérabilités connues dans les images Docker." "Installation : https://trivy.dev (dépôt APT d'Aqua Security)"
  fi

  if have rkhunter && ((!QUICK)); then
    note "rkhunter…"
    local rk; rk=$(tmo 900 rkhunter --check --sk --nocolors --rwo 2>/dev/null)
    if [[ -n $rk ]]; then
      warn "Avertissements rkhunter" "$(head -n 15 <<< "$rk")" "rkhunter produit des faux positifs : vérifiez chaque point (\`sudo less /var/log/rkhunter.log\`)"
    else
      ok "rkhunter : aucun avertissement"
    fi
  fi
}

# ================================================================ RAPPORTS ==
count_lvl() {   # count_lvl NIVEAU [catégorie]
  local n=0 i
  for i in "${!R_LVL[@]}"; do
    [[ ${R_LVL[i]} == "$1" ]] || continue
    [[ -z ${2:-} || ${SEC_CAT[${R_SEC[i]}]} == "$2" ]] && n=$((n + 1))
  done
  echo "$n"
}
score() { awk -v c="$(count_lvl CRIT "$1")" -v w="$(count_lvl WARN "$1")" 'BEGIN {printf "%d", 100 * (0.75 ^ c) * (0.96 ^ w) + 0.5}'; }
grade() { local s=$1; if ((s >= 90)); then echo A; elif ((s >= 75)); then echo B; elif ((s >= 60)); then echo C; elif ((s >= 40)); then echo D; else echo E; fi; }

has_content() {
  local s=$1 x
  for x in "${R_SEC[@]}" "${T_SEC[@]}" "${X_SEC[@]}"; do [[ $x == "$s" ]] && return 0; done
  return 1
}
sec_worst() {
  local s=$1 w=OK i
  for i in "${!R_SEC[@]}"; do [[ ${R_SEC[i]} == "$s" ]] && w=$(worst "$w" "${R_LVL[i]}"); done
  [[ $w == INFO ]] && w=OK
  echo "$w"
}

esc() {   # échappement HTML (les remplacements sont entre guillemets : sûr avec bash ≥ 5.2)
  local s=$1 a='&amp;' l='&lt;' g='&gt;' q='&quot;'
  s=${s//&/"$a"}; s=${s//</"$l"}; s=${s//>/"$g"}; s=${s//\"/"$q"}
  printf '%s' "$s"
}
html_esc() { sed -e 's/&/\&amp;/g' -e 's/</\&lt;/g' -e 's/>/\&gt;/g'; }
fmt_to() {   # REPLY ← texte échappé, `code` → <code>, sauts de ligne → <br>
  local s=$1 a='&amp;' l='&lt;' g='&gt;' out="" i
  s=${s//&/"$a"}; s=${s//</"$l"}; s=${s//>/"$g"}
  local -a segs=()
  IFS='`' read -r -d '' -a segs <<< "$s"
  for ((i = 0; i < ${#segs[@]}; i++)); do
    if ((i % 2)); then out+="<code>${segs[i]}</code>"; else out+=${segs[i]}; fi
  done
  out=${out%"$NL"}
  REPLY=${out//"$NL"/<br>}
}

CSS=$(cat <<'EOF'
:root{--bg:#f4f5f7;--card:#fff;--ink:#1b1f27;--muted:#5d6675;--line:#e3e6eb;--soft:#f0f2f5;
--crit:#c4352f;--crit-bg:#fdecea;--warn:#a35f00;--warn-bg:#fff3dd;--ok:#1d7a4c;--ok-bg:#e4f4ea;--info:#3461c1;--info-bg:#e9effc;
--mono:ui-monospace,SFMono-Regular,Menlo,Consolas,"Liberation Mono",monospace}
@media (prefers-color-scheme:dark){:root{--bg:#0f1216;--card:#171b21;--ink:#e7eaee;--muted:#9aa3af;--line:#29303a;--soft:#1e232b;
--crit:#ff7b72;--crit-bg:#3a1d1d;--warn:#f2b24c;--warn-bg:#382a12;--ok:#4cc38a;--ok-bg:#13301f;--info:#86a8ff;--info-bg:#1a2540}}
*{box-sizing:border-box}html{scroll-behavior:smooth}
body{margin:0;background:var(--bg);color:var(--ink);font:15px/1.55 system-ui,-apple-system,"Segoe UI",Roboto,Ubuntu,"Helvetica Neue",Arial,sans-serif}
.wrap{max-width:1180px;margin:0 auto;padding:28px 20px 60px}
header.top{display:flex;flex-wrap:wrap;justify-content:space-between;gap:20px;align-items:flex-end;margin-bottom:18px}
.eyebrow{text-transform:uppercase;letter-spacing:.08em;font-size:12px;color:var(--muted);font-weight:650}
h1{margin:2px 0 6px;font-size:30px;line-height:1.15}
.meta{color:var(--muted);font-size:13.5px}
.scores{display:flex;gap:12px;flex-wrap:wrap}
.score{display:flex;align-items:center;gap:12px;background:var(--card);border:1px solid var(--line);border-radius:12px;padding:10px 16px 10px 10px}
.grade{font-size:26px;font-weight:800;width:46px;height:46px;border-radius:10px;display:grid;place-items:center;color:#fff}
.g-A{background:#1d7a4c}.g-B{background:#4c8a2a}.g-C{background:#a35f00}.g-D{background:#c4561c}.g-E{background:#c4352f}
.sl{font-size:12px;color:var(--muted);text-transform:uppercase;letter-spacing:.06em;font-weight:650}
.sv{font-size:20px;font-weight:750}.sv small{font-size:12px;color:var(--muted);font-weight:500}
.kpis{display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin:0 0 20px}
.kpi{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:12px 16px;border-left:4px solid var(--c)}
.kpi .n{font-size:28px;font-weight:750;display:block;line-height:1.2}
.kpi .l{color:var(--muted);font-size:13px}
.k-CRIT{--c:var(--crit)}.k-WARN{--c:var(--warn)}.k-OK{--c:var(--ok)}.k-INFO{--c:var(--info)}
.card{background:var(--card);border:1px solid var(--line);border-radius:14px;padding:18px 20px;margin:0 0 18px;scroll-margin-top:12px}
h2{font-size:19px;margin:0 0 12px;display:flex;align-items:center;gap:10px;flex-wrap:wrap}
h3{font-size:12.5px;margin:20px 0 8px;color:var(--muted);text-transform:uppercase;letter-spacing:.05em}
.cat{font-size:11px;font-weight:650;text-transform:uppercase;letter-spacing:.06em;padding:2px 8px;border-radius:999px;background:var(--soft);color:var(--muted)}
.mini{margin-left:auto;font-size:12.5px;font-weight:500;color:var(--muted)}
.badge{display:inline-block;min-width:78px;text-align:center;font-size:11px;font-weight:750;padding:3px 8px;border-radius:999px;text-transform:uppercase;letter-spacing:.04em}
.b-CRIT{background:var(--crit-bg);color:var(--crit)}.b-WARN{background:var(--warn-bg);color:var(--warn)}
.b-OK{background:var(--ok-bg);color:var(--ok)}.b-INFO{background:var(--info-bg);color:var(--info)}
table{border-collapse:collapse;width:100%}
table.findings td{padding:9px 8px;border-top:1px solid var(--line);vertical-align:top}
table.findings tr:first-child td{border-top:0}
table.findings td:first-child{width:96px;padding-top:11px}
.ttl{font-weight:600}
.msg{color:var(--muted);font-size:14px;margin-top:2px;overflow-wrap:anywhere}
.fix{margin-top:6px;font-size:13.5px;padding:6px 10px;border-left:3px solid var(--info);background:var(--soft);border-radius:0 6px 6px 0;overflow-wrap:anywhere}
.fix::before{content:"À faire : ";font-weight:650}
code{font-family:var(--mono);font-size:12.5px;background:var(--soft);padding:1px 5px;border-radius:4px}
.fix code{background:var(--card)}
.tw{overflow-x:auto;border:1px solid var(--line);border-radius:10px}
table.data{font-size:13px}
table.data th{text-align:left;background:var(--soft);padding:7px 10px;font-weight:650;white-space:nowrap}
table.data td{padding:6px 10px;border-top:1px solid var(--line);vertical-align:top;white-space:nowrap}
table.data td.w{white-space:normal;min-width:280px}
.dot{display:inline-block;width:8px;height:8px;border-radius:50%;margin-right:6px;background:var(--c,var(--muted));vertical-align:1px}
.c-CRIT{--c:var(--crit);color:var(--crit);font-weight:650}.c-WARN{--c:var(--warn);color:var(--warn);font-weight:650}.c-OK{--c:var(--ok)}.c-INFO{--c:var(--info)}
details{margin-top:10px;border:1px solid var(--line);border-radius:10px;background:var(--soft)}
summary{cursor:pointer;padding:8px 12px;font-size:13px;color:var(--muted)}
pre{margin:0;padding:12px;font-family:var(--mono);font-size:12px;line-height:1.45;overflow:auto;max-height:520px;white-space:pre;border-top:1px solid var(--line);background:var(--card);border-radius:0 0 10px 10px}
.toolbar{display:flex;justify-content:space-between;align-items:center;gap:12px;flex-wrap:wrap;margin:0 0 14px}
nav.toc{display:flex;flex-wrap:wrap;gap:6px}
nav.toc a{font-size:13px;text-decoration:none;color:var(--ink);background:var(--card);border:1px solid var(--line);border-radius:999px;padding:4px 11px}
nav.toc a:hover{border-color:var(--muted)}
nav.toc .dot{font-weight:400}
.toggle{font-size:13px;color:var(--muted);display:flex;gap:6px;align-items:center;cursor:pointer;white-space:nowrap}
button.score,button.kpi{font:inherit;color:inherit;text-align:left;cursor:pointer}button.kpi{width:100%}
button.score:hover,button.kpi:hover{border-color:var(--muted)}
button.score[aria-pressed=true],button.kpi[aria-pressed=true]{outline:2px solid var(--info);outline-offset:1px}
.kpi .hint,.score .hint{display:block;font-size:11.5px;color:var(--muted);margin-top:2px}
.filtre{display:flex;align-items:center;gap:10px;flex-wrap:wrap;background:var(--info-bg);color:var(--ink);border-radius:10px;padding:8px 12px;margin:0 0 14px;font-size:14px}
.filtre button{font:inherit;font-size:13px;font-weight:600;border:1px solid var(--line);background:var(--card);color:var(--ink);border-radius:8px;padding:4px 10px;cursor:pointer}
.cache{display:none!important}
ol.actions{margin:0;padding:0;list-style:none}
ol.actions li{padding:11px 0;border-top:1px solid var(--line);display:grid;grid-template-columns:96px 1fr;column-gap:8px}
ol.actions li:first-child{border-top:0}
ol.actions .body{min-width:0}
a.sec{font-size:12px;color:var(--muted);text-decoration:none;margin-right:6px}
a.sec:hover{text-decoration:underline}
.none{color:var(--ok);font-weight:600;margin:0}
ul.manual{margin:0;padding-left:20px}ul.manual li{margin:6px 0}
footer{color:var(--muted);font-size:12.5px;text-align:center;margin-top:28px}
@media (max-width:720px){.kpis{grid-template-columns:repeat(2,1fr)}ol.actions li{grid-template-columns:1fr}table.findings td:first-child{width:auto}}
@media print{body{background:#fff}.toolbar{display:none}.card{break-inside:avoid-page}}
EOF
)

score_card() { local g; g=$(grade "$2"); printf '<button type="button" class="score" data-cat="%s" aria-pressed="false" title="Afficher uniquement les contrôles « %s »"><span class="grade g-%s">%s</span><div><div class="sl">%s</div><div class="sv">%s<small> / 100</small></div></div></button>' "$3" "$1" "$g" "$g" "$1" "$2"; }

render_table() {
  local f=$1 line first=1 ncol=0 k c
  local -a cells=()
  printf '<div class="tw"><table class="data">'
  while IFS= read -r line; do
    line=${line//$'\t'/$US}
    IFS=$US read -r -a cells <<< "$line"
    if ((first)); then
      ncol=${#cells[@]}; first=0
      printf '<thead><tr>'; for c in "${cells[@]}"; do printf '<th>%s</th>' "$c"; done; printf '</tr></thead><tbody>'
    else
      printf '<tr>'
      for ((k = 0; k < ncol; k++)); do
        c=${cells[k]:-}
        if [[ $c =~ ^@(OK|WARN|CRIT|INFO)[[:space:]]?(.*)$ ]]; then
          printf '<td class="c-%s"><span class="dot"></span>%s</td>' "${BASH_REMATCH[1]}" "${BASH_REMATCH[2]}"
        else
          if ((${#c} > 48)); then printf '<td class="w">%s</td>' "$c"; else printf '<td>%s</td>' "$c"; fi
        fi
      done
      printf '</tr>'
    fi
  done < <(html_esc < "$f")
  printf '</tbody></table></div>\n'
}

render_html() {
  local nC=$1 nW=$2 nO=$3 nI=$4 hs=$5 ss=$6 dur=$7 i lvl s
  cat <<EOF
<!DOCTYPE html>
<html lang="fr">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex">
<title>Audit $(esc "$HOST") — $(esc "$DATE_HUMAN")</title>
<style>
$CSS
</style>
</head>
<body>
<div class="wrap">
<header class="top">
  <div>
    <div class="eyebrow">Audite-moi · bilan de santé et audit de sécurité$( ((QUICK)) && echo ' · mode rapide')</div>
    <h1>$(esc "$HOST")</h1>
    <div class="meta">$(esc "$DATE_HUMAN") · $(esc "$OS_PRETTY") · noyau $(esc "$KERNEL") · $(esc "${CPU_MODEL:-CPU}") · $(hbytes "$MEM_TOTAL") de RAM</div>
  </div>
  <div class="scores">$(score_card "Santé" "$hs" sante)$(score_card "Sécurité" "$ss" secu)</div>
</header>
<div class="kpis">
  <button type="button" class="kpi k-CRIT" data-lvl="CRIT" aria-pressed="false"><span class="n">$nC</span><span class="l">critique(s)</span></button>
  <button type="button" class="kpi k-WARN" data-lvl="WARN" aria-pressed="false"><span class="n">$nW</span><span class="l">avertissement(s)</span></button>
  <button type="button" class="kpi k-OK" data-lvl="OK" aria-pressed="false"><span class="n">$nO</span><span class="l">contrôle(s) OK</span></button>
  <button type="button" class="kpi k-INFO" data-lvl="INFO" aria-pressed="false"><span class="n">$nI</span><span class="l">information(s)</span></button>
</div>
<div class="filtre cache" id="filtre">Filtre : <b id="ftxt"></b><button type="button" id="fclear">Tout afficher</button></div>
EOF
  # Plan d'action
  local out="" n=0 t m fx
  for lvl in CRIT WARN; do
    for i in "${!R_LVL[@]}"; do
      [[ ${R_LVL[i]} == "$lvl" ]] || continue
      n=$((n + 1))
      fmt_to "${R_TTL[i]}"; t=$REPLY; fmt_to "${R_MSG[i]}"; m=$REPLY; fmt_to "${R_FIX[i]}"; fx=$REPLY
      out+="<li data-lvl=\"$lvl\" data-cat=\"${SEC_CAT[${R_SEC[i]}]}\"><div><span class=\"badge b-$lvl\">${LVL_FR[$lvl]}</span></div><div class=\"body\"><a class=\"sec\" href=\"#${R_SEC[i]}\">${SEC_SHORT[${R_SEC[i]}]}</a><span class=\"ttl\">$t</span>"
      [[ -n $m ]] && out+="<div class=\"msg\">$m</div>"
      [[ -n $fx ]] && out+="<div class=\"fix\">$fx</div>"
      out+="</div></li>"
    done
  done
  printf '<section class="card" id="plan"><h2>Plan d’action <span class="mini">%s point(s) à traiter, du plus urgent au moins urgent</span></h2>' "$n"
  if ((n)); then printf '<ol class="actions">%s</ol>' "$out"; else printf '<p class="none">Aucune action requise : tout est au vert.</p>'; fi
  printf '</section>\n'
  # Sommaire
  printf '<div class="toolbar"><nav class="toc">'
  for s in "${SEC_ORDER[@]}"; do
    has_content "$s" || continue
    printf '<a href="#%s"><span class="dot c-%s"></span>%s</a>' "$s" "$(sec_worst "$s")" "${SEC_SHORT[$s]}"
  done
  printf '</nav><label class="toggle"><input type="checkbox" id="only"> Problèmes uniquement</label></div>\n'
  # Sections
  for s in "${SEC_ORDER[@]}"; do
    has_content "$s" || continue
    local c1=0 c2=0 c3=0 c4=0 rowsC="" rowsW="" rowsR="" r
    for i in "${!R_SEC[@]}"; do
      [[ ${R_SEC[i]} == "$s" ]] || continue
      lvl=${R_LVL[i]}
      case $lvl in CRIT) c1=$((c1 + 1)) ;; WARN) c2=$((c2 + 1)) ;; OK) c3=$((c3 + 1)) ;; *) c4=$((c4 + 1)) ;; esac
      fmt_to "${R_TTL[i]}"
      r="<tr class=\"lvl-$lvl\"><td><span class=\"badge b-$lvl\">${LVL_FR[$lvl]}</span></td><td><div class=\"ttl\">$REPLY</div>"
      if [[ -n ${R_MSG[i]} ]]; then fmt_to "${R_MSG[i]}"; r+="<div class=\"msg\">$REPLY</div>"; fi
      if [[ -n ${R_FIX[i]} ]]; then fmt_to "${R_FIX[i]}"; r+="<div class=\"fix\">$REPLY</div>"; fi
      r+="</td></tr>"
      case $lvl in CRIT) rowsC+=$r ;; WARN) rowsW+=$r ;; *) rowsR+=$r ;; esac
    done
    local counts; counts=$(join_list ' · ' "$( ((c1)) && echo "$c1 critique(s)")" "$( ((c2)) && echo "$c2 avertissement(s)")" "$( ((c3)) && echo "$c3 OK")" "$( ((c4)) && echo "$c4 info(s)")")
    printf '<section class="card" id="%s" data-cat="%s"><h2>%s <span class="cat">%s</span><span class="mini">%s</span></h2>\n' \
      "$s" "${SEC_CAT[$s]}" "$(esc "${SEC_TITLE[$s]}")" "$( [[ ${SEC_CAT[$s]} == secu ]] && echo Sécurité || echo Santé)" "$counts"
    [[ -n $rowsC$rowsW$rowsR ]] && printf '<table class="findings">%s%s%s</table>\n' "$rowsC" "$rowsW" "$rowsR"
    for i in "${!T_SEC[@]}"; do
      [[ ${T_SEC[i]} == "$s" ]] || continue
      printf '<h3>%s</h3>' "$(esc "${T_TTL[i]}")"; render_table "${T_FILE[i]}"
    done
    for i in "${!X_SEC[@]}"; do
      [[ ${X_SEC[i]} == "$s" ]] || continue
      printf '<details><summary>Données brutes : %s</summary><pre>' "$(esc "${X_TTL[i]}")"; html_esc < "${X_FILE[i]}"; printf '</pre></details>\n'
    done
    printf '</section>\n'
  done
  # Vérifications manuelles
  local hlist="" h
  for r in "${INGRESS[@]}"; do h=${r%%"$US"*}; [[ $h != "*" ]] && hlist+="<code>$(esc "$h")</code> "; done
  cat <<EOF
<section class="card" id="manuel"><h2>Vérifications manuelles <span class="cat">Hors de portée du script</span></h2>
<ul class="manual">
<li><b>Cloudflare Access</b> : chaque nom d’hôte publié ${hlist:+(${hlist% }) }est protégé par une application Zero Trust Access (connexion + MFA). N’ajoutez une exception (« Bypass ») que si une application cliente l’exige, et restreignez-la alors (pays, règles WAF).</li>
<li><b>Box / routeur</b> : aucune redirection de port vers le NAS (les tunnels n’en ont pas besoin), UPnP désactivé, pare-feu IPv6 bloquant les connexions entrantes.</li>
<li><b>Comptes en ligne</b> : double authentification sur le compte Cloudflare et sur les applications exposées ; comptes par défaut supprimés.</li>
<li><b>Sauvegardes</b> : une restauration réelle a été testée récemment, et une copie est conservée hors site.</li>
<li><b>Mises à jour applicatives</b> : les images Docker des services exposés sont mises à jour au moins une fois par mois.</li>
<li><b>Micrologiciels</b> : BIOS/UEFI, SSD et carte graphique à jour ; interface d’administration matérielle (IPMI/BMC) éventuelle non exposée.</li>
</ul></section>
<footer>Généré par Audite-moi $VERSION en $dur s · note = 100 × 0,75<sup>critiques</sup> × 0,96<sup>avertissements</sup> pour chaque catégorie · rapport confidentiel : il décrit les faiblesses de votre serveur.</footer>
</div>
<script>
(function(){
var st={cat:'',lvl:''},Q=function(s){return Array.prototype.slice.call(document.querySelectorAll(s));};
var NOMS={sante:'Santé',secu:'Sécurité',CRIT:'critiques',WARN:'avertissements',OK:'contrôles OK',INFO:'informations',PB:'problèmes (critiques et avertissements)'};
function okLvl(l){return !st.lvl||(st.lvl==='PB'?(l==='CRIT'||l==='WARN'):l===st.lvl);}
function apply(){
  Q('section.card[data-cat]').forEach(function(s){
    var n=0;Q('#'+s.id+' tr[class^="lvl-"]').forEach(function(r){var v=okLvl(r.className.slice(4));r.classList.toggle('cache',!v);if(v)n++;});
    Q('#'+s.id+' h3, #'+s.id+' .tw, #'+s.id+' details').forEach(function(e){e.classList.toggle('cache',!!st.lvl);});
    var vis=(!st.cat||s.dataset.cat===st.cat)&&(!st.lvl||n>0);
    s.classList.toggle('cache',!vis);
    Q('nav.toc a[href="#'+s.id+'"]').forEach(function(a){a.classList.toggle('cache',!vis);});
  });
  Q('#plan li[data-lvl]').forEach(function(li){li.classList.toggle('cache',!((!st.cat||li.dataset.cat===st.cat)&&okLvl(li.dataset.lvl)));});
  Q('button.score').forEach(function(b){b.setAttribute('aria-pressed',b.dataset.cat===st.cat?'true':'false');});
  Q('button.kpi').forEach(function(b){b.setAttribute('aria-pressed',b.dataset.lvl===st.lvl?'true':'false');});
  var t=[];if(st.cat)t.push(NOMS[st.cat]);if(st.lvl)t.push(NOMS[st.lvl]);
  document.getElementById('ftxt').textContent=t.join(' · ');
  document.getElementById('filtre').classList.toggle('cache',!t.length);
  var o=document.getElementById('only');if(o)o.checked=st.lvl==='PB';
}
Q('button.score').forEach(function(b){b.addEventListener('click',function(){st.cat=st.cat===b.dataset.cat?'':b.dataset.cat;apply();});});
Q('button.kpi').forEach(function(b){b.addEventListener('click',function(){st.lvl=st.lvl===b.dataset.lvl?'':b.dataset.lvl;apply();});});
document.getElementById('fclear').addEventListener('click',function(){st.cat='';st.lvl='';apply();});
var o=document.getElementById('only');if(o)o.addEventListener('change',function(){st.lvl=o.checked?'PB':'';apply();});
})();
</script>
</body>
</html>
EOF
}

txt_table() {
  awk -F'\t' '{ for (i = 1; i <= NF; i++) { v = $i; gsub(/@(OK|WARN|CRIT|INFO) ?/, "", v); c[NR, i] = v; l = length(v); if (l > w[i]) w[i] = l }
                if (NF > nf) nf = NF; n = NR }
    END { for (r = 1; r <= n; r++) { line = "    "; for (i = 1; i <= nf; i++) line = line sprintf("%-" w[i] "s  ", c[r, i]); sub(/ +$/, "", line); print line } }' "$1"
}

render_txt() {
  local nC=$1 nW=$2 nO=$3 nI=$4 hs=$5 ss=$6 i lvl s
  printf '%s\n' "======================================================================"
  printf ' AUDITE-MOI — %s — %s%s\n' "$HOST" "$DATE_HUMAN" "$( ((QUICK)) && echo ' (mode rapide)')"
  printf ' %s · noyau %s\n' "$OS_PRETTY" "$KERNEL"
  printf '%s\n' "======================================================================"
  printf ' Santé : %s (%s/100)    Sécurité : %s (%s/100)\n' "$(grade "$hs")" "$hs" "$(grade "$ss")" "$ss"
  printf ' %d critique(s), %d avertissement(s), %d OK, %d info(s)\n' "$nC" "$nW" "$nO" "$nI"
  printf '\nPLAN D’ACTION\n-------------\n'
  for lvl in CRIT WARN; do
    for i in "${!R_LVL[@]}"; do
      [[ ${R_LVL[i]} == "$lvl" ]] || continue
      printf ' [%s] %s — %s\n' "${LVL_FR[$lvl]}" "${SEC_SHORT[${R_SEC[i]}]}" "${R_TTL[i]}"
      [[ -n ${R_FIX[i]} ]] && printf '     → %s\n' "${R_FIX[i]//$NL/$NL       }"
    done
  done
  for s in "${SEC_ORDER[@]}"; do
    has_content "$s" || continue
    printf '\n== %s ==\n' "${SEC_TITLE[$s]}"
    for i in "${!R_SEC[@]}"; do
      [[ ${R_SEC[i]} == "$s" ]] || continue
      printf ' [%-9s] %s\n' "${LVL_FR[${R_LVL[i]}]}" "${R_TTL[i]}"
      [[ -n ${R_MSG[i]} ]] && printf '      %s\n' "${R_MSG[i]//$NL/$NL      }"
      [[ -n ${R_FIX[i]} ]] && printf '      → %s\n' "${R_FIX[i]//$NL/$NL        }"
    done
    for i in "${!T_SEC[@]}"; do
      [[ ${T_SEC[i]} == "$s" ]] || continue
      printf '\n  -- %s --\n' "${T_TTL[i]}"; txt_table "${T_FILE[i]}"
    done
  done
  printf '\n\n####################### DONNÉES BRUTES #######################\n'
  for i in "${!X_SEC[@]}"; do
    printf '\n--- [%s] %s ---\n' "${SEC_SHORT[${X_SEC[i]}]}" "${X_TTL[i]}"; cat "${X_FILE[i]}"
  done
}

render_json() {
  local nC=$1 nW=$2 nO=$3 nI=$4 hs=$5 ss=$6 dur=$7 base=$8 s i
  local secs; secs=$(for s in "${SEC_ORDER[@]}"; do printf '%s%s%s%s%s%s%s\n' "$s" "$US" "${SEC_TITLE[$s]}" "$US" "${SEC_SHORT[$s]}" "$US" "${SEC_CAT[$s]}"; done \
    | jq -Rn '[inputs | split("\u001f") | {key: .[0], value: {titre: .[1], court: .[2], categorie: .[3]}}] | from_entries')
  for i in "${!R_LVL[@]}"; do
    printf '%s%s%s%s%s%s%s%s%s%s' "${R_SEC[i]}" "$US" "${R_LVL[i]}" "$US" "${R_TTL[i]}" "$US" "${R_MSG[i]}" "$US" "${R_FIX[i]}" "$RS"
  done | jq -Rs --arg hote "$HOST" --arg date "$DATE_HUMAN" --argjson horodatage "$START" --arg version "$VERSION" \
      --arg os "$OS_PRETTY" --arg noyau "$KERNEL" --argjson duree "$dur" --arg mode "$( ((QUICK)) && echo rapide || echo complet)" \
      --argjson hs "$hs" --argjson ss "$ss" --arg hg "$(grade "$hs")" --arg sg "$(grade "$ss")" \
      --argjson c "$nC" --argjson w "$nW" --argjson o "$nO" --argjson n "$nI" --arg base "$base" --argjson secs "$secs" '
    {version: $version, hote: $hote, date: $date, horodatage: $horodatage, os: $os, noyau: $noyau, duree_s: $duree, mode: $mode,
     notes: {sante: {score: $hs, lettre: $hg}, securite: {score: $ss, lettre: $sg}},
     compteurs: {CRIT: $c, WARN: $w, OK: $o, INFO: $n},
     fichiers: {html: ($base + ".html"), txt: ($base + ".txt"), json: ($base + ".json")},
     sections: $secs,
     constats: (split("\u001e") | map(select(length > 0) | split("\u001f")
       | {section: .[0], niveau: .[1], titre: .[2], detail: .[3], correctif: .[4]}))}'
}

prune_reports() {
  ((KEEP > 0)) || return 0
  local -a all=()
  mapfile -t all < <(find "$OUTDIR" -maxdepth 1 -type f -name 'rapport-*-[0-9]*-[0-9]*.html' -printf '%f\n' | sed 's/\.html$//' \
    | awk '{n = split($0, a, "-"); print a[n - 1] a[n] "\t" $0}' | sort -k1,1 | cut -f2)
  local n=$(( ${#all[@]} - KEEP )) i
  for ((i = 0; i < n; i++)); do rm -f "$OUTDIR/${all[i]}".{html,txt,json}; done
}

# ================================================================== MAIN ===
main() {
  check_deps
  charger_conf
  setup_output
  printf '%sAudite-moi %s%s — audit de %s (%s)\n' "$C_BOLD" "$VERSION" "$C_0" "$HOST" "$OS_PRETTY"
  ((QUICK)) && note "Mode rapide : analyses longues désactivées."
  read_arc
  zfs_prep
  check_systeme
  check_materiel
  check_disques
  check_zfs
  check_docker
  check_gpu
  check_reseau
  check_sauvegardes
  check_cloudflare
  check_exposition
  check_applis
  check_opnsense
  check_lan
  check_maj
  check_comptes
  check_ssh
  check_parefeu
  check_dockersec
  check_fichiers
  check_noyau
  check_journaux
  check_outils

  local nC nW nO nI hs ss dur
  nC=$(count_lvl CRIT); nW=$(count_lvl WARN); nO=$(count_lvl OK); nI=$(count_lvl INFO)
  hs=$(score sante); ss=$(score secu); dur=$(( $(date +%s) - START ))
  local base="rapport-${HOST}-${DATE_FILE}"
  local html="$OUTDIR/$base.html" txt="$OUTDIR/$base.txt" json="$OUTDIR/$base.json"
  render_html "$nC" "$nW" "$nO" "$nI" "$hs" "$ss" "$dur" > "$html"
  render_txt "$nC" "$nW" "$nO" "$nI" "$hs" "$ss" > "$txt"
  render_json "$nC" "$nW" "$nO" "$nI" "$hs" "$ss" "$dur" "$base" > "$json"
  ln -sfn "$base.html" "$OUTDIR/rapport-dernier.html"
  ln -sfn "$base.txt" "$OUTDIR/rapport-dernier.txt"
  if [[ -n $OUTGROUP ]]; then
    chgrp "$OUTGROUP" "$html" "$txt" "$json" && chmod 640 "$html" "$txt" "$json"
  elif [[ -n $REPORT_OWNER ]]; then
    chown "$REPORT_OWNER": "$html" "$txt" "$json"
    chown -h "$REPORT_OWNER": "$OUTDIR/rapport-dernier.html" "$OUTDIR/rapport-dernier.txt"
  fi
  prune_reports

  printf '\n%s══ Résultat ══%s\n' "$C_BOLD" "$C_0"
  printf '  Santé : %s (%s/100)    Sécurité : %s (%s/100)\n' "$(grade "$hs")" "$hs" "$(grade "$ss")" "$ss"
  printf '  %s%d critique(s)%s, %s%d avertissement(s)%s, %d OK, %d info(s) — %d s\n' "$C_R" "$nC" "$C_0" "$C_Y" "$nW" "$C_0" "$nO" "$nI" "$dur"
  local i shown=0 lvl
  for lvl in CRIT WARN; do
    for i in "${!R_LVL[@]}"; do
      [[ ${R_LVL[i]} == "$lvl" ]] || continue
      ((shown++ < 12)) && printf '   %s• %s%s\n' "$( [[ $lvl == CRIT ]] && echo "$C_R" || echo "$C_Y")" "${R_TTL[i]}" "$C_0"
    done
  done
  ((shown > 12)) && printf '   … et %d autre(s) : voir le rapport\n' $((shown - 12))
  printf '\n  Rapport HTML  : %s\n  Rapport texte : %s\n' "$html" "$txt"
  if [[ -n $REPORT_OWNER ]]; then
    printf '  Depuis votre PC : scp %s@%s:%s .\n' "$REPORT_OWNER" "$HOST" "$html"
  fi
  if ((nC)); then return 2; elif ((nW)); then return 1; fi
  return 0
}

main "$@"
exit $?
