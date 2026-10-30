#!/usr/bin/env bash
# =============================================================================
#  Installation d'Audite-moi : script d'audit + interface web + audit hebdomadaire
#
#    sudo ./install.sh                  # installation complète (recommandé)
#    sudo ./install.sh --help           # options
#
#  Relancer le script met à jour une installation existante (configuration et
#  rapports conservés).
# =============================================================================
set -euo pipefail

PORT=8765 ECOUTE=0.0.0.0 TLS=1 WEB=1 MINUTEUR=1 NOUVEAU_MDP=0 MINIMAL=0 OUVRIR=0 OPN=0 TG=0
usage() {
  cat <<'EOF'
Installation d'Audite-moi

  sudo ./install.sh [options]

  --port N               port de l'interface web (défaut : 8765)
  --ecoute ADRESSE       adresse d'écoute (défaut : 0.0.0.0 = toutes ; ex. 192.168.1.10)
  --sans-tls             interface en HTTP simple (déconseillé)
  --sans-web             n'installe pas l'interface web (script + audit hebdomadaire)
  --sans-minuteur        pas d'audit automatique hebdomadaire
  --nouveau-mot-de-passe redéfinit le mot de passe de l'interface web
  --minimal              n'installe que les dépendances indispensables
  --ouvrir-pare-feu      autorise l'interface dans UFW depuis tous les réseaux privés, sans poser la question
  --configurer-opnsense  enregistre l'adresse et la clé API du routeur OPNsense (voir le README)
  --configurer-telegram  active les alertes sur Telegram (création du bot guidée)
  -h, --help             cette aide
EOF
}
while (($#)); do
  case $1 in
    --port) PORT=${2:?}; shift 2 ;;
    --ecoute) ECOUTE=${2:?}; shift 2 ;;
    --sans-tls) TLS=0; shift ;;
    --sans-web) WEB=0; shift ;;
    --sans-minuteur) MINUTEUR=0; shift ;;
    --nouveau-mot-de-passe) NOUVEAU_MDP=1; shift ;;
    --minimal) MINIMAL=1; shift ;;
    --ouvrir-pare-feu) OUVRIR=1; shift ;;
    --configurer-opnsense) OPN=1; shift ;;
    --configurer-telegram) TG=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Option inconnue : $1" >&2; usage >&2; exit 1 ;;
  esac
done
if ! [[ $PORT =~ ^[0-9]+$ ]] || ((PORT < 1 || PORT > 65535)); then echo "Port invalide : $PORT" >&2; exit 1; fi
((EUID == 0)) || { echo "Lancez l'installation en root : sudo $0 $*" >&2; exit 1; }
command -v apt-get >/dev/null || { echo "Ce programme vise Ubuntu/Debian (apt-get introuvable)." >&2; exit 1; }

SRC=$(cd "$(dirname "$0")" && pwd)
LIB=/usr/local/lib/audite-moi
ETC=/etc/audite-moi
VAR=/var/lib/audite-moi
SYSTEMD=0; [[ -d /run/systemd/system ]] && SYSTEMD=1
etape() { printf '\n\e[1m▶ %s\e[0m\n' "$*"; }

etape "Dépendances"
paquets=(jq python3 smartmontools curl)
((TLS && WEB)) && paquets+=(openssl)
((MINIMAL)) || paquets+=(lynis vainfo pciutils nmap conntrack)
manque=()
for p in "${paquets[@]}"; do dpkg -s "$p" >/dev/null 2>&1 || manque+=("$p"); done
if ((${#manque[@]})); then
  echo "Installation de : ${manque[*]}"
  DEBIAN_FRONTEND=noninteractive apt-get update -qq
  # --no-install-recommends : évite par exemple qu'smartmontools n'installe un serveur de messagerie
  DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --no-install-recommends "${manque[@]}"
else
  echo "Déjà présentes : ${paquets[*]}"
fi

etape "Fichiers du programme"
install -m 755 "$SRC/audite-moi.sh" /usr/local/sbin/audite-moi
install -d -m 755 "$LIB"
install -m 755 "$SRC/systemd/audite-moi-run" "$LIB/audite-moi-run"
install -m 755 "$SRC/systemd/audite-moi-mesures" "$LIB/audite-moi-mesures"
install -m 755 "$SRC/systemd/audite-moi-corriger" "$LIB/audite-moi-corriger"
install -m 644 "$SRC/seuils.json" "$SRC/references.json" "$LIB/"
install -m 755 "$SRC/web/audite-moi-web.py" "$LIB/audite-moi-web.py"
echo "/usr/local/sbin/audite-moi, $LIB/"

etape "Utilisateur et dossiers"
if ! getent passwd audite-moi >/dev/null; then
  useradd --system --user-group --no-create-home --home-dir "$VAR" --shell /usr/sbin/nologin audite-moi
  echo "Utilisateur système « audite-moi » créé (sans shell, sans droits root)"
fi
install -d -o root -g audite-moi -m 750 "$VAR" "$ETC"
install -d -o root -g audite-moi -m 2750 "$VAR/rapports" "$VAR/etat"
install -d -o root -g audite-moi -m 2770 "$VAR/demande" "$VAR/reglages"
echo "$VAR/{rapports,etat,demande,reglages}"

etape "Réglages des contrôles réseau"
CONF=$ETC/audit.conf
if [[ ! -f $CONF ]]; then
  cat > "$CONF" <<'EOC'
# Audite-moi — réglages des contrôles réseau (lu par root uniquement : gardez ce fichier en 600)
# Format : CLÉ=valeur (une par ligne). Ce fichier n'est jamais exécuté.

# Test depuis Internet des services publiés (tunnels Cloudflare) : oui / non
EXTERNE=oui
# Noms d'hôte supplémentaires à tester depuis Internet (séparés par des espaces)
DOMAINES_EXTRA=""

# Routeur OPNsense (lecture seule via l'API) — voir le README pour créer la clé
#   sudo ./install.sh --configurer-opnsense
OPNSENSE_URL=""
OPNSENSE_KEY=""
OPNSENSE_SECRET=""
# Vérifier le certificat HTTPS du routeur (non : certificat auto-signé d'origine)
OPNSENSE_VERIFIER_TLS=non

# Scan nmap du réseau local pendant l'audit complet : oui / non
SCAN_RESEAU=oui
# Réseaux à scanner (vide = ceux d'OPNsense, sinon ceux du NAS), ex. "10.10.1.0/24 192.168.10.0/24"
SCAN_RESEAUX=""
EOC
  echo "Modèle créé : $CONF"
fi
chown root:root "$CONF"; chmod 600 "$CONF"
# réglages ajoutés par les versions récentes (sans toucher à ceux déjà présents)
grep -q '^SAUVEGARDES=' "$CONF" || cat >> "$CONF" <<'EOC'

# Preuves de sauvegarde à vérifier, « nom:type:cible:heures » séparés par des espaces (voir le README) :
#   type zfs = dernier snapshot du dataset, fichier = fichier le plus récent du dossier, unite = service systemd réussi
#   ex. SAUVEGARDES="photos-usb:zfs:usb/photos:26 cloud:unite:restic-cloud.service:26"
SAUVEGARDES=""
EOC
grep -q '^TELEGRAM_TOKEN=' "$CONF" || cat >> "$CONF" <<'EOC'

# Alertes Telegram — sudo ./install.sh --configurer-telegram
TELEGRAM_TOKEN=""
TELEGRAM_CHAT_ID=""
# oui / non : pools, disques, sauvegardes, nouveaux ports, résumé de chaque audit
ALERTES=oui
# Adresse de l'interface ajoutée aux messages (lien cliquable depuis le réseau local)
INTERFACE_URL=""
EOC

conf_set() {   # conf_set CLÉ valeur : remplace (ou ajoute) la ligne dans audit.conf
  CLE=$1 VAL=$2 python3 - "$CONF" <<'PY'
import os, re, sys
p, k, v = sys.argv[1], os.environ["CLE"], os.environ["VAL"]
lignes = open(p, encoding="utf-8").read().splitlines()
nouv = f'{k}="{v}"'
for i, l in enumerate(lignes):
    if re.match(rf"\s*{k}\s*=", l): lignes[i] = nouv; break
else: lignes.append(nouv)
tmp = p + ".tmp"
fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
with os.fdopen(fd, "w", encoding="utf-8") as f: f.write("\n".join(lignes) + "\n")
os.replace(tmp, p)
PY
}

if ((TG)); then
  [[ -t 0 ]] || { echo "--configurer-telegram demande un terminal interactif." >&2; exit 1; }
  cat <<'EOT'

Alertes Telegram : 3 étapes.
  1. Dans Telegram, ouvrez une conversation avec @BotFather, envoyez /newbot,
     choisissez un nom (ex. « NAS maison ») puis un identifiant finissant par « bot ».
  2. BotFather répond avec un jeton du type 123456789:AA…  : copiez-le ci-dessous.
  3. Ouvrez la conversation avec votre nouveau bot et envoyez-lui un message (ex. « bonjour »).
EOT
  read -r -s -p "Jeton du bot (non affiché) : " jeton; echo
  if ! [[ $jeton =~ ^[0-9]{5,}:[A-Za-z0-9_-]{30,}$ ]]; then echo "Ce jeton n'a pas le bon format : rien n'a été enregistré." >&2; exit 1; fi
  chat=""
  for essai in 1 2 3; do
    read -r -p "Envoyez maintenant un message à votre bot dans Telegram, puis appuyez sur Entrée… " _
    if r=$(printf '%s\n' "$jeton" | python3 "$LIB/audite-moi-mesures" --trouver-chat 2>/dev/null); then
      chat=${r%%$'\t'*}; echo "✔ Conversation trouvée : ${r#*$'\t'} ($chat)"; break
    fi
    echo "Aucun message reçu par le bot pour l'instant (essai $essai/3)."
  done
  [[ $chat =~ ^-?[0-9]+$ ]] || { echo "Impossible de trouver la conversation : vérifiez le jeton et réessayez." >&2; exit 1; }
  ip_nas=$(hostname -I 2>/dev/null | tr ' ' '\n' | grep -E '^(10|192\.168|172\.(1[6-9]|2[0-9]|3[01]))\.' | grep -vE '^172\.(1[7-9]|2[0-9]|3[01])\.0\.1$' | head -n 1 || true)
  schema_tg=https; ((TLS)) || schema_tg=http
  conf_set TELEGRAM_TOKEN "$jeton"; conf_set TELEGRAM_CHAT_ID "$chat"; conf_set ALERTES oui
  [[ -n $ip_nas ]] && conf_set INTERFACE_URL "$schema_tg://$ip_nas:$PORT/"
  unset jeton
  python3 "$LIB/audite-moi-mesures" --test-telegram --conf "$CONF" || exit 1
  echo "Alertes activées : vous recevrez un premier message récapitulatif au prochain relevé (10 minutes au plus)."
fi

if ((OPN)); then
  [[ -t 0 ]] || { echo "--configurer-opnsense demande un terminal interactif." >&2; exit 1; }
  defaut=$(ip route show default 2>/dev/null | awk '{print $3; exit}')
  read -r -p "Adresse de l'interface d'OPNsense [https://${defaut:-192.168.1.1}] : " url
  url=${url:-https://${defaut:-192.168.1.1}}
  [[ $url == http*://* ]] || url="https://$url"
  read -r -p "Clé API (key) : " cle_api
  read -r -s -p "Secret API (secret, non affiché) : " secret_api; echo
  if [[ -z $cle_api || -z $secret_api || $cle_api$secret_api$url == *[\"\\[:space:]]* ]]; then
    echo "Clé ou secret vide ou invalide : rien n'a été enregistré." >&2; exit 1
  fi
  code=$(printf 'user = "%s:%s"\n' "$cle_api" "$secret_api" | curl -sS -k -m 15 -K - -o /dev/null -w '%{http_code}' "${url%/}/api/core/firmware/status" 2>/dev/null || true)
  case $code in
    200) echo "✔ Connexion à l'API d'OPNsense réussie" ;;
    401) echo "✘ OPNsense refuse cette clé (HTTP 401) : vérifiez la clé et le secret." >&2; exit 1 ;;
    403) echo "⚠ Clé acceptée mais privilège « System: Firmware » manquant (voir le README) ; enregistrement quand même." ;;
    *)   echo "⚠ OPNsense ne répond pas (code ${code:-aucun}) à ${url%/} ; enregistrement quand même." ;;
  esac
  conf_set OPNSENSE_URL "${url%/}"; conf_set OPNSENSE_KEY "$cle_api"; conf_set OPNSENSE_SECRET "$secret_api"
  unset secret_api cle_api
  echo "Clé enregistrée dans $CONF (lisible par root uniquement)"
fi

MDP_AFFICHE=""
if ((WEB)); then
  etape "Configuration de l'interface web"
  if [[ ! -f $ETC/web.json ]] || ((NOUVEAU_MDP)); then
    mdp=""
    if [[ -t 0 ]]; then
      while :; do
        read -r -s -p "Choisissez le mot de passe de l'interface web (8 caractères minimum) : " mdp; echo
        read -r -s -p "Confirmez : " mdp2; echo
        [[ $mdp == "$mdp2" && ${#mdp} -ge 8 ]] && break
        echo "Mots de passe différents ou trop courts, recommencez."
      done
    else
      mdp=$(python3 -c 'import secrets; print(secrets.token_urlsafe(15))')
      MDP_AFFICHE=$mdp
    fi
    hash=$(printf '%s\n' "$mdp" | python3 "$LIB/audite-moi-web.py" --hachage)
    unset mdp mdp2
    cert="" cle=""
    ((TLS)) && cert=$ETC/tls/cert.pem cle=$ETC/tls/cle.pem
    HASH=$hash ECOUTE=$ECOUTE PORT=$PORT CERT=$cert CLE=$cle python3 - "$ETC/web.json" <<'PY'
import json, os, sys
conf = {"ecoute": os.environ["ECOUTE"], "port": int(os.environ["PORT"]), "mot_de_passe": os.environ["HASH"],
        "rapports": "/var/lib/audite-moi/rapports", "demandes": "/var/lib/audite-moi/demande", "etat": "/var/lib/audite-moi/etat",
        "tls_cert": os.environ["CERT"], "tls_cle": os.environ["CLE"], "duree_session_h": 12}
with open(sys.argv[1] + ".tmp", "w", encoding="utf-8") as f:
    json.dump(conf, f, indent=2, ensure_ascii=False)
os.replace(sys.argv[1] + ".tmp", sys.argv[1])
PY
    echo "Configuration écrite dans $ETC/web.json"
  else
    # mise à jour : on applique seulement le port et l'adresse demandés
    PORT=$PORT ECOUTE=$ECOUTE python3 - "$ETC/web.json" <<'PY'
import json, os, sys
p = sys.argv[1]
conf = json.load(open(p, encoding="utf-8"))
conf["port"] = int(os.environ["PORT"]); conf["ecoute"] = os.environ["ECOUTE"]
json.dump(conf, open(p, "w", encoding="utf-8"), indent=2, ensure_ascii=False)
PY
    echo "Configuration existante conservée ($ETC/web.json)"
  fi
  chown root:audite-moi "$ETC/web.json"; chmod 640 "$ETC/web.json"
  cert=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["tls_cert"])' "$ETC/web.json")
  cle=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["tls_cle"])' "$ETC/web.json")
  if [[ -n $cert && ! -f $cert ]]; then
    install -d -o root -g audite-moi -m 750 "$(dirname "$cert")"
    hote=$(hostname -s)
    san="DNS:$hote,DNS:$hote.local,DNS:localhost,IP:127.0.0.1"
    for ip in $(hostname -I 2>/dev/null); do san+=",IP:$ip"; done
    openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 3650 \
      -subj "/CN=$hote" -addext "subjectAltName=$san" -keyout "$cle" -out "$cert" 2>/dev/null
    chown root:audite-moi "$cert" "$cle"; chmod 644 "$cert"; chmod 640 "$cle"
    echo "Certificat HTTPS auto-signé créé (valable 10 ans) : $cert"
  fi
fi

etape "Services systemd"
install -m 644 "$SRC/systemd/audite-moi.service" "$SRC/systemd/audite-moi.path" "$SRC/systemd/audite-moi.timer" /etc/systemd/system/
((WEB)) && install -m 644 "$SRC/systemd/audite-moi-web.service" "$SRC/systemd/audite-moi-mesures.service" \
  "$SRC/systemd/audite-moi-mesures.timer" "$SRC/systemd/audite-moi-mesures.path" \
  "$SRC/systemd/audite-moi-corriger.service" "$SRC/systemd/audite-moi-corriger.path" /etc/systemd/system/
if ((SYSTEMD)); then
  systemctl daemon-reload
  systemctl enable --now audite-moi.path >/dev/null
  if ((MINUTEUR)); then systemctl enable --now audite-moi.timer >/dev/null; echo "Audit complet automatique : chaque lundi vers 7 h 30"
  else systemctl disable --now audite-moi.timer >/dev/null 2>&1 || true; fi
  if ((WEB)); then
    # relevé des disques pour la page « Matériel » : toutes les 10 min et à la demande
    systemctl enable --now audite-moi-mesures.timer audite-moi-mesures.path audite-moi-corriger.path >/dev/null
    systemctl start --no-block audite-moi-mesures.service
    echo "Relevé des disques, des connexions et alertes : toutes les 10 minutes ; corrections en un clic actives"
    systemctl enable audite-moi-web.service >/dev/null
    systemctl restart audite-moi-web.service
    sleep 1
    systemctl is-active --quiet audite-moi-web.service || { echo "L'interface web n'a pas démarré : journalctl -u audite-moi-web -n 30" >&2; }
  fi
  if ! compgen -G "$VAR/rapports/rapport-*.json" >/dev/null; then
    echo complet > "$VAR/demande/lancer"
    echo "Premier audit complet lancé en arrière-plan (quelques minutes)"
  fi
else
  echo "systemd n'est pas actif ici : services copiés mais non démarrés."
fi

if ((WEB)); then
  etape "Accès à l'interface"
  schema=https; ((TLS)) || schema=http
  ipv4=$(hostname -I 2>/dev/null | tr ' ' '\n' | grep -E '^(10|192\.168|172\.(1[6-9]|2[0-9]|3[01]))\.' | grep -vE '^172\.(1[7-9]|2[0-9]|3[01])\.0\.1$' | head -n 1 || true)
  echo "  ${schema}://${ipv4:-<ip-du-nas>}:$PORT/"
  ((TLS)) && echo "  (certificat auto-signé : votre navigateur affichera un avertissement la première fois, acceptez-le)"
  [[ -n $MDP_AFFICHE ]] && echo "  Mot de passe généré : $MDP_AFFICHE   (changez-le avec : sudo ./install.sh --nouveau-mot-de-passe)"
  # 1) Le service répond-il sur le serveur lui-même ?
  if ((SYSTEMD)); then
    local_ip=127.0.0.1; [[ $ECOUTE != 0.0.0.0 && $ECOUTE != "::" ]] && local_ip=$ECOUTE
    reponse=""
    for _ in 1 2 3 4 5 6; do
      reponse=$(python3 - "$schema://$local_ip:$PORT/connexion" <<'PY' 2>/dev/null || true
import ssl, sys, urllib.request, urllib.error
ctx = ssl.create_default_context(); ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
try:
    print(urllib.request.urlopen(sys.argv[1], context=ctx, timeout=5).status)
except urllib.error.HTTPError as e:
    print(e.code)
except Exception as e:
    print("erreur : %s" % e)
PY
)
      [[ $reponse == 200 ]] && break
      sleep 1
    done
    if [[ $reponse == 200 ]]; then
      echo "  ✔ L'interface répond sur le serveur (test local réussi)."
    else
      echo "  ✘ L'interface ne répond pas sur le serveur (${reponse:-pas de réponse}) : sudo journalctl -u audite-moi-web -n 30" >&2
    fi
  fi
  # 2) Un pare-feu bloque-t-il l'accès depuis le réseau local ?
  #    On autorise les plages d'adresses privées (10/8, 172.16/12, 192.168/16) : tous les
  #    sous-réseaux de la maison, jamais Internet.
  PRIVES=(10.0.0.0/8 172.16.0.0/12 192.168.0.0/16)
  if command -v ufw >/dev/null && ufw status 2>/dev/null | grep -q '^Status: active'; then
    manquants=()
    for r in "${PRIVES[@]}"; do
      ufw status 2>/dev/null | grep -qE "^$PORT(/tcp)?[[:space:]]+ALLOW( IN)?[[:space:]]+${r//./\\.}([[:space:]]|$)" || manquants+=("$r")
    done
    if ((${#manquants[@]} == 0)); then
      echo "  ✔ UFW autorise le port $PORT depuis les réseaux privés."
    else
      rep=n
      if ((OUVRIR)); then rep=o
      elif [[ -t 0 ]]; then read -r -p "  UFW : autoriser le port $PORT depuis tous vos réseaux locaux (${manquants[*]}) ? [O/n] " rep; [[ -z $rep ]] && rep=o
      fi
      if [[ $rep =~ ^[oOyY] ]]; then
        for r in "${manquants[@]}"; do ufw allow from "$r" to any port "$PORT" proto tcp comment "Audite-moi" >/dev/null; done
        echo "  ✔ Règles UFW ajoutées : port $PORT autorisé depuis les réseaux privés (${manquants[*]}), pas depuis Internet."
      else
        echo "  ⚠ UFW peut bloquer le port $PORT (le navigateur affichera « délai d'attente dépassé »). Pour l'ouvrir à vos réseaux locaux :"
        for r in "${manquants[@]}"; do echo "    sudo ufw allow from $r to any port $PORT proto tcp comment Audite-moi"; done
      fi
    fi
  elif [[ $(iptables -S INPUT 2>/dev/null | head -n 1) == "-P INPUT DROP" ]] || nft list ruleset 2>/dev/null | grep -qE 'hook input.*policy drop'; then
    echo "  ⚠ Un pare-feu (iptables/nftables) filtre les connexions entrantes : autorisez le port TCP $PORT depuis vos réseaux locaux."
  fi
  echo "  N'exposez pas cette interface sur Internet (ou seulement derrière Cloudflare Access) : elle décrit les faiblesses du serveur."
fi
echo
echo "Audit manuel à tout moment :  sudo audite-moi        (rapports visibles dans l'interface)"
