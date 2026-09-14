# Linux Toolbox

Boîte à outils en ligne de commande pour l'administration système Linux, regroupant trois modules indépendants : **diagnostic**, **audit de sécurité** et **gestion de sauvegardes**.

Projet réalisé dans le cadre du BTS SIO, option SISR (Solutions d'Infrastructure, Systèmes et Réseaux).

---

## Sommaire

- [Fonctionnalités](#fonctionnalités)
- [Prérequis](#prérequis)
- [Installation](#installation)
- [Utilisation](#utilisation)
- [Structure du projet](#structure-du-projet)
- [Détail des modules](#détail-des-modules)
- [Rapports générés](#rapports-générés)

---

## Fonctionnalités

### 🔍 Diagnostic système
Inventaire complet d'une machine Linux :
- système, distribution, noyau
- processeur (modèle, cœurs, fréquence, utilisation)
- mémoire RAM et swap
- disques et partitions
- interfaces réseau, adresses IP, trafic, passerelle, DNS
- uptime et températures
- processus consommant le plus de CPU/RAM
- ports en écoute
- services systemd
- utilisateurs et groupes sensibles (`sudo`, `adm`, ...)
- état du pare-feu (UFW / nftables / iptables)
- résumé automatique avec alertes (`[OK]` / `[INFO]` / `[ALERTE]`)

### 🛡️ Audit de sécurité
Analyse passive (aucune modification du système) :
- comptes et groupes sensibles
- fichiers SUID / SGID
- permissions sensibles (`/etc/shadow`, `/etc/passwd`, ...)
- configuration du pare-feu
- ports et sockets réseau ouverts
- services systemd en échec
- configuration SSH (`sshd -T`)
- mises à jour de sécurité disponibles
- politique de mots de passe (PAM)
- tâches planifiées (cron / timers systemd)
- journaux système (erreurs récentes)
- répertoires world-writable

Chaque point contrôlé produit un résultat classé par sévérité (`CRITIQUE`, `ÉLEVÉ`, `MOYEN`, `FAIBLE`, `INFO`), accompagné d'un conseil de remédiation, et aboutit à un score de sécurité global sur 100.

### 💾 Gestionnaire de sauvegardes
- création d'archives `.tar.gz` avec empreinte SHA-256 et manifeste embarqué
- listing des sauvegardes disponibles
- vérification d'intégrité (hash + structure de l'archive)
- restauration vers un dossier dédié (avec protections contre l'écrasement du projet)
- suppression sécurisée (confirmation requise)
- autocomplétion des chemins (TAB) via `readline`

---

## Prérequis

- **Linux** (le projet utilise des modules Python spécifiques à Unix : `pwd`, `grp`, `readline`)
- **Python 3.10+**
- Le module externe [`psutil`](https://pypi.org/project/psutil/) (utilisé par le diagnostic)

Certaines vérifications (pare-feu, permissions, SSH, mises à jour...) nécessitent d'être exécutées avec les droits administrateur pour donner des résultats complets.

## Installation

```bash
git clone https://github.com/<votre-utilisateur>/linux-toolbox.git
cd linux-toolbox
pip install -r requirements.txt
```

## Utilisation

```bash
python3 main.py
```

Un menu interactif permet ensuite de choisir l'outil à lancer :

```
======================================================================
                        LINUX TOOLBOX
======================================================================

1. Diagnostic complet de la machine
2. Audit de sécurité
3. Gestionnaire de sauvegardes
0. Quitter
```

Pour un audit ou un diagnostic complet (accès à toutes les informations système) :

```bash
sudo python3 main.py
```

## Structure du projet

```
linux-toolbox/
├── main.py                  # Point d'entrée : menu principal
├── requirements.txt         # Dépendances Python
├── modules/
│   ├── __init__.py
│   ├── utils.py              # Fonctions utilitaires partagées
│   ├── diagnostic.py          # Module diagnostic système
│   ├── security_audit.py      # Module audit de sécurité
│   └── backup.py              # Module gestion des sauvegardes
├── reports/                  # Rapports générés (TXT / JSON)
├── logs/                     # Journaux d'exécution
└── backups/                  # Archives de sauvegarde par défaut
```

Les dossiers `reports/`, `logs/` et `backups/` sont créés automatiquement au premier lancement s'ils n'existent pas.

## Détail des modules

| Module | Rôle | Modifie le système ? |
|---|---|---|
| `diagnostic.py` | Inventaire et état de la machine | Non |
| `security_audit.py` | Analyse de sécurité passive | Non |
| `backup.py` | Création / restauration d'archives | Oui (écriture dans le dossier de destination choisi) |

## Rapports générés

Chaque module génère automatiquement, à la fin de son exécution :

- un **rapport texte** (`.txt`), lisible directement, résumant les résultats,
- un **rapport JSON** (`.json`), exploitable par un autre programme ou pour de l'archivage,
- une **entrée de journal** (`.log`) dans le dossier `logs/`.

Les sauvegardes créées par le module `backup.py` embarquent en plus un manifeste JSON (`LINUX_TOOLBOX_MANIFEST.json`) directement dans l'archive, contenant les métadonnées de la sauvegarde (date, machine, taille, nombre de fichiers...), ainsi qu'un fichier `.sha256` associé permettant de vérifier l'intégrité de l'archive à tout moment.
