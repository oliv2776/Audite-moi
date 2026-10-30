#!/usr/bin/env bash
# Désinstallation d'Audite-moi.
#   sudo ./uninstall.sh           # retire le programme et les services (garde rapports et configuration)
#   sudo ./uninstall.sh --purge   # supprime aussi rapports, configuration et utilisateur système
set -u
((EUID == 0)) || { echo "Lancez en root : sudo $0 $*" >&2; exit 1; }
if [[ -d /run/systemd/system ]]; then
  systemctl disable --now audite-moi-web.service audite-moi.path audite-moi.timer audite-moi-mesures.timer audite-moi-mesures.path >/dev/null 2>&1
  systemctl stop audite-moi.service >/dev/null 2>&1
fi
rm -f /etc/systemd/system/audite-moi.service /etc/systemd/system/audite-moi.path \
      /etc/systemd/system/audite-moi.timer /etc/systemd/system/audite-moi-web.service \
      /etc/systemd/system/audite-moi-mesures.service /etc/systemd/system/audite-moi-mesures.timer /etc/systemd/system/audite-moi-mesures.path
[[ -d /run/systemd/system ]] && systemctl daemon-reload
rm -f /usr/local/sbin/audite-moi
rm -rf /usr/local/lib/audite-moi
echo "Programme et services retirés."
if [[ ${1:-} == --purge ]]; then
  rm -rf /etc/audite-moi /var/lib/audite-moi
  getent passwd audite-moi >/dev/null && userdel audite-moi 2>/dev/null
  getent group audite-moi >/dev/null && groupdel audite-moi 2>/dev/null
  echo "Rapports, configuration et utilisateur « audite-moi » supprimés."
else
  echo "Rapports (/var/lib/audite-moi) et configuration (/etc/audite-moi) conservés : --purge pour les supprimer."
fi
