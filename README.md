# Audite-moi

**Bilan de santé et audit de sécurité pour un NAS sous Ubuntu**, avec une interface web : pools ZFS, disques, conteneurs Docker, transcodage GPU (iGPU Intel/AMD + carte graphique AMD/NVIDIA), tunnels Cloudflare, SSH, pare-feu, mises à jour, sauvegardes…

Chaque audit produit un rapport classé par priorité (**critique**, **attention**, **OK**, **info**), avec pour chaque problème la commande ou le réglage à appliquer, et deux notes sur 100 : **Santé** et **Sécurité**.

![Tableau de bord](docs/tableau-de-bord.png)

> Les captures proviennent d'un NAS simulé (le jeu d'essai des tests).

## Ce qui est vérifié

**Santé**
- **Système** : redémarrage en attente, services en échec, horloge, espace disque et inodes, erreurs du noyau (E/S, ATA, NVMe…).
- **Matériel** : charge, attente disque, mémoire (en tenant compte du cache ARC de ZFS), OOM killer, températures, ECC, onduleur (NUT / apcupsd).
- **Disques (SMART)** : état global, secteurs réalloués / en attente / irrécupérables, erreurs CRC (câble), température, usure des SSD et NVMe, auto-tests, démon smartd.
- **ZFS** : état des pools, remplissage, erreurs, dernier scrub et sa planification, TRIM des pools SSD, ZED et ses notifications, ARC, chiffrement, modules prêts pour le prochain noyau.
- **Docker** : conteneurs arrêtés en erreur, en boucle de redémarrage, *unhealthy*, tués par manque de mémoire, consommation, espace récupérable, rotation des journaux.
- **GPU et transcodage** : correspondance `/dev/dri/renderD*` ↔ GPU, pilotes (i915/xe, amdgpu, nvidia), encodage VA-API, firmware GuC/HuC, température / charge / mémoire vidéo de la carte AMD, accès réel de chaque conteneur à chaque GPU.
- **Réseau** et **sauvegardes** : vitesse des liens, DNS, IPv6 publique, snapshots par pool, outils de sauvegarde (règle 3-2-1).

**Sécurité**
- **Tunnels Cloudflare** : connexion du tunnel (point de contrôle `/ready`), version de cloudflared, services d'origine injoignables, noms d'hôte publiés et conteneurs ciblés, Cloudflare Access, services aussi joignables sans passer par le tunnel.
- **Mises à jour** : correctifs de sécurité en attente, mises à jour automatiques, fin de support d'Ubuntu.
- **Comptes et SSH** : UID 0, mots de passe vides, sudo sans mot de passe, groupe docker, clés SSH, configuration de sshd, tentatives de connexion depuis Internet, fail2ban / CrowdSec.
- **Pare-feu** : UFW, ports Docker qui **contournent UFW**, bases de données exposées, Samba (SMB1, partages invités), NFS, redirections UPnP de la box.
- **Sécurité Docker** : conteneurs privilégiés, socket Docker monté, réseau *host*, capacités dangereuses, montages sensibles, secrets en clair, âge des images (plus strict pour les services exposés sur Internet).
- **Fichiers, noyau, journaux** : droits des fichiers sensibles, binaires SUID hors paquets, intégrité des binaires critiques (`dpkg --verify`), paramètres sysctl, AppArmor, vulnérabilités du processeur, processus suspects (mineurs, exécution depuis `/tmp`).
- **Analyses complémentaires** si installées : [Lynis](https://cisofy.com/lynis/), [Trivy](https://trivy.dev) (vulnérabilités des images), rkhunter.

Le script est en **lecture seule** : il ne modifie rien sur le serveur. Les secrets (jetons, mots de passe) sont masqués dans les rapports.

## Installation

```bash
git clone https://github.com/oliv2776/Audite-moi.git
cd Audite-moi
sudo ./install.sh
```

L'installateur :
1. installe les dépendances (`jq`, `python3`, `smartmontools`, `openssl`, ainsi que `lynis`, `vainfo` et `pciutils` sauf avec `--minimal`) ;
2. copie le script dans `/usr/local/sbin/audite-moi` ;
3. crée l'utilisateur système `audite-moi` (sans shell ni droits root) qui fait tourner l'interface web ;
4. vous demande un mot de passe et crée un certificat HTTPS auto-signé ;
5. active l'interface web, un audit complet automatique **chaque lundi vers 7 h 30**, et lance un premier audit.

Ouvrez ensuite **`https://<ip-du-nas>:8765/`**. Le navigateur affichera un avertissement la première fois (certificat auto-signé) : acceptez-le.

Options utiles : `--port 9000`, `--ecoute 192.168.1.10`, `--sans-web` (script + audit hebdomadaire seulement), `--sans-minuteur`, `--nouveau-mot-de-passe`. Relancer `sudo ./install.sh` après un `git pull` met à jour le programme en conservant configuration et rapports.

## Utilisation

### Interface web

- une barre de navigation toujours visible : **Tableau de bord**, **Constats**, **Historique**, **Rapport complet**, et les boutons **▶ Lancer un audit** (complet, quelques minutes) / **Audit rapide** (sans Lynis, Trivy ni recherche des fichiers SUID), avec le déroulement affiché en direct ;
- les notes **Santé** / **Sécurité** et les compteurs (critiques, avertissements, OK, infos) sont **cliquables** : un clic n'affiche que les constats correspondants (ex. Sécurité + Critiques), un second clic annule ;
- la liste des **constats** se filtre aussi par catégorie, niveau, section ou mot-clé (ex. « ssh », « jellyfin ») ; par défaut elle montre ce qu'il faut corriger, du plus urgent au moins urgent, avec la correction à appliquer ;
- **évolution des notes** et **historique** : un clic sur une date affiche cet ancien audit dans le tableau de bord ;
- le **rapport complet** (avec un bouton « ← Tableau de bord » et les mêmes filtres cliquables), sa version texte et le JSON.

![Évolution des notes](docs/evolution.png)

### En ligne de commande

```bash
sudo audite-moi              # audit complet ; le rapport apparaît aussi dans l'interface
sudo audite-moi --quick      # audit rapide
sudo audite-moi --help       # toutes les options
```

Sans installation, le script fonctionne aussi seul : `sudo ./audite-moi.sh` (les rapports vont alors dans `~/audite-moi/`).

Codes de sortie : `0` rien à signaler, `1` avertissements, `2` problèmes critiques, `3` erreur.

![Rapport](docs/rapport.png)

## Sécurité de l'interface web

Le rapport décrit précisément les faiblesses de votre serveur : l'interface est conçue pour rester privée.

- Le serveur web (Python, bibliothèque standard uniquement) tourne sous l'utilisateur `audite-moi`, sans droits root et dans un service systemd durci. Il ne peut **pas** exécuter de commande : il dépose seulement une demande que `audite-moi.path` transmet à `audite-moi.service`.
- Mot de passe haché (PBKDF2-SHA256, 600 000 itérations), session en cookie `HttpOnly` / `SameSite=Strict`, protection CSRF, blocage après 5 échecs en 15 minutes, HTTPS par défaut, en-têtes de sécurité stricts (CSP…).
- **Ne l'exposez pas sur Internet.** Si UFW est actif, l'installateur propose de l'ouvrir uniquement aux réseaux privés (tous vos sous-réseaux, pas Internet). Pour un accès à distance, passez par un VPN, ou par votre tunnel Cloudflare **derrière Cloudflare Access** (avec `noTLSVerify: true` vers l'origine, le certificat étant auto-signé).

## GPU : Intel + AMD dans un même conteneur

Avec un iGPU et une carte AMD, chaque puce a son nœud (`renderD128`, `renderD129`…) : la section « GPU et transcodage » indique lequel correspond à quel GPU, et lesquels chaque conteneur voit vraiment. Pour donner les deux à un conteneur :

```yaml
services:
  transcodage:
    devices:
      - /dev/dri:/dev/dri
    group_add:
      - "993"   # GID du groupe « render » : stat -c %g /dev/dri/renderD128
```

## Outils optionnels

| Outil | Apport | Installation |
|---|---|---|
| Lynis | ~300 tests de durcissement | `sudo apt install lynis` |
| Trivy | vulnérabilités des images Docker | [trivy.dev](https://trivy.dev) |
| rkhunter | recherche de rootkits | `sudo apt install rkhunter` |
| vainfo | profils d'encodage VA-API | `sudo apt install vainfo` |
| radeontop / intel-gpu-tools | charge instantanée du GPU | `sudo apt install radeontop intel-gpu-tools` |
| miniupnpc | redirections UPnP de la box | `sudo apt install miniupnpc` |

## Dépannage

**« Le délai d'attente est dépassé » dans le navigateur** : un pare-feu bloque le port 8765 (le plus souvent UFW sur le NAS).

```bash
sudo systemctl status audite-moi-web --no-pager       # le service doit être « active (running) »
curl -kI https://127.0.0.1:8765/connexion              # depuis le NAS : doit répondre « HTTP/1.1 200 »
sudo ufw status                                        # UFW actif sans règle pour 8765 ?
sudo ufw allow from 192.168.0.0/16 to any port 8765 proto tcp comment Audite-moi  # idem pour 10.0.0.0/8 et 172.16.0.0/12
```

`sudo ./install.sh --ouvrir-pare-feu` ouvre automatiquement le port à tous les réseaux privés (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16) : tous les PC de la maison, quel que soit leur sous-réseau, mais pas Internet. Pensez aussi à bien taper **https://** (et non http://).

**« La connexion a échoué »** (refus immédiat) : le service ne tourne pas, voir `sudo journalctl -u audite-moi-web -n 30`.

## Désinstallation

```bash
sudo ./uninstall.sh          # garde rapports et configuration
sudo ./uninstall.sh --purge  # supprime tout
```

## Tests

Les tests rejouent l'audit sur un NAS simulé (faux `zpool`, `docker`, `smartctl`, `journalctl`… dans `tests/mock/bin`) et testent l'interface web :

```bash
sudo tests/run-tests.sh          # scénario simulé + interface web + shellcheck
sudo tests/run-tests.sh --reel   # + une exécution réelle (lecture seule) sur la machine
```

## Structure

```
audite-moi.sh            le script d'audit (bash)
web/audite-moi-web.py    l'interface web (Python 3, sans dépendance)
systemd/                 services : audit (.service/.path/.timer) et interface web
install.sh, uninstall.sh
tests/                   simulations, données d'exemple et tests
```
