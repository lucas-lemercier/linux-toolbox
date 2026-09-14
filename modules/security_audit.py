"""
Linux Toolbox - Audit de sécurité Linux

Version : 1.3

Objectif :
    Réaliser un audit de sécurité passif d'une machine Linux.

Principe :
    - Aucune modification du système.
    - Analyse des comptes et groupes.
    - Analyse SUID / SGID.
    - Vérification de permissions sensibles.
    - Vérification du pare-feu.
    - Analyse des ports et sockets.
    - Analyse des services systemd.
    - Vérification de SSH.
    - Vérification des mises à jour.
    - Vérification de la politique de mots de passe.
    - Analyse des tâches planifiées.
    - Analyse des journaux.
    - Analyse des répertoires world-writable.
    - Génération de rapports TXT et JSON.
    - Journalisation des audits.
"""

from pathlib import Path
from datetime import datetime
import json
import logging
import os
import pwd
import grp
import stat

from .utils import executer_commande as executer_commande_utils


# ============================================================================
# CONFIGURATION
# ============================================================================

VERSION = "1.3"

BASE_DIR = Path(__file__).resolve().parent.parent

REPORTS_DIR = BASE_DIR / "reports"
LOGS_DIR = BASE_DIR / "logs"

LOG_FILE = LOGS_DIR / "security_audit.log"


# ============================================================================
# INITIALISATION
# ============================================================================

REPORTS_DIR.mkdir(exist_ok=True)
LOGS_DIR.mkdir(exist_ok=True)

logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(message)s",
)


# ============================================================================
# OUTILS GENERAUX
# ============================================================================

def executer_commande(commande, timeout=15):
    """
    Exécute une commande système.

    Timeout par défaut plus élevé que le module
    diagnostic, car certaines commandes d'audit
    (ex: recherche de fichiers, mises à jour) peuvent
    être plus longues.

    Retourne :
        (code_retour, stdout, stderr)
    """

    return executer_commande_utils(
        commande,
        timeout=timeout,
    )


def commande_existe(commande):
    """
    Vérifie si une commande existe sur le système.
    """

    code, _, _ = executer_commande(
        ["which", commande]
    )

    return code == 0


def est_root():
    """
    Retourne True si le programme est exécuté avec les privilèges root.
    """

    return os.geteuid() == 0


def ajouter_resultat(
    resultats,
    severite,
    titre,
    details,
    conseil,
    affichage=None,
):
    """
    Ajoute un résultat à la liste des résultats.

    'details' :
        Informations complètes utilisées dans les rapports.

    'affichage' :
        Texte éventuellement plus court pour le terminal.
        Si None, 'details' est utilisé.
    """

    resultats.append(
        {
            "severite": severite,
            "titre": titre,
            "details": details,
            "affichage": (
                affichage
                if affichage is not None
                else details
            ),
            "conseil": conseil,
        }
    )


# ============================================================================
# 1. COMPTES ET GROUPES
# ============================================================================

def auditer_comptes_groupes(resultats):
    """
    Analyse les comptes utilisateurs et les groupes sensibles.
    """

    print("[...] Comptes et groupes")

    # ------------------------------------------------------------------------
    # Comptes avec UID 0
    # ------------------------------------------------------------------------

    utilisateurs_uid_zero = []

    try:

        for utilisateur in pwd.getpwall():

            if utilisateur.pw_uid == 0:

                utilisateurs_uid_zero.append(
                    utilisateur.pw_name
                )

    except Exception as erreur:

        logging.error(
            "Erreur UID 0 : %s",
            erreur,
        )

    if len(utilisateurs_uid_zero) > 1:

        ajouter_resultat(
            resultats,
            "ELEVE",
            "Plusieurs comptes possèdent un UID 0",
            ", ".join(utilisateurs_uid_zero),
            "Vérifier que tous les comptes UID 0 sont légitimes.",
        )

    # ------------------------------------------------------------------------
    # Groupes sensibles
    # ------------------------------------------------------------------------

    groupes_sensibles = [
        "adm",
        "sudo",
        "docker",
        "lxd",
        "disk",
        "shadow",
    ]

    try:

        for nom_groupe in groupes_sensibles:

            try:

                groupe = grp.getgrnam(
                    nom_groupe
                )

            except KeyError:

                continue

            membres = list(groupe.gr_mem)

            if membres:

                ajouter_resultat(
                    resultats,
                    "INFO",
                    f'Groupe sensible « {nom_groupe} » utilisé',
                    f"Membres : {', '.join(membres)}",
                    "Vérifier périodiquement que les membres sont toujours légitimes.",
                )

    except Exception as erreur:

        logging.error(
            "Erreur groupes : %s",
            erreur,
        )


# ============================================================================
# 2. SUID / SGID
# ============================================================================

def auditer_suid_sgid(resultats):
    """
    Recherche les fichiers SUID et SGID.

    Leur présence n'est pas automatiquement une vulnérabilité.
    """

    print("[...] SUID / SGID")

    fichiers_suid = []
    fichiers_sgid = []

    chemins = [
        "/bin",
        "/sbin",
        "/usr/bin",
        "/usr/sbin",
        "/usr/local/bin",
        "/usr/local/sbin",
    ]

    for chemin in chemins:

        if not os.path.exists(chemin):
            continue

        code, stdout, _ = executer_commande(
            [
                "find",
                chemin,
                "-xdev",
                "-type",
                "f",
                "(",
                "-perm",
                "-4000",
                "-o",
                "-perm",
                "-2000",
                ")",
                "-print",
            ],
            timeout=30,
        )

        if code != 0:
            continue

        for ligne in stdout.splitlines():

            fichier = ligne.strip()

            if not fichier:
                continue

            try:

                informations = os.stat(
                    fichier
                )

                permissions = informations.st_mode

                if permissions & stat.S_ISUID:

                    fichiers_suid.append(
                        fichier
                    )

                if permissions & stat.S_ISGID:

                    fichiers_sgid.append(
                        fichier
                    )

            except Exception:

                continue

    if fichiers_suid or fichiers_sgid:

        ajouter_resultat(
            resultats,
            "INFO",
            "Fichiers SUID/SGID détectés",
            (
                f"{len(fichiers_suid)} SUID et "
                f"{len(fichiers_sgid)} SGID détectés."
            ),
            (
                "Vérifier les fichiers inhabituels "
                "ou provenant de logiciels non nécessaires."
            ),
        )


# ============================================================================
# 3. PERMISSIONS SENSIBLES
# ============================================================================

def auditer_permissions_sensibles(resultats):
    """
    Vérifie quelques fichiers sensibles.
    """

    print("[...] Permissions sensibles")

    fichiers = [
        "/etc/passwd",
        "/etc/group",
        "/etc/shadow",
        "/etc/sudoers",
        "/etc/ssh/sshd_config",
    ]

    for chemin in fichiers:

        fichier = Path(chemin)

        if not fichier.exists():
            continue

        try:

            mode = fichier.stat().st_mode

            permissions = stat.S_IMODE(
                mode
            )

            # /etc/shadow ne doit normalement pas être
            # lisible par les utilisateurs ordinaires.

            if chemin == "/etc/shadow":

                if permissions & stat.S_IROTH:

                    ajouter_resultat(
                        resultats,
                        "ELEVE",
                        "Permissions dangereuses sur /etc/shadow",
                        f"Permissions actuelles : {oct(permissions)}",
                        "Retirer les permissions de lecture pour les utilisateurs non privilégiés.",
                    )

            # Vérification de l'écriture globale.

            if chemin != "/etc/shadow":

                if permissions & stat.S_IWOTH:

                    ajouter_resultat(
                        resultats,
                        "ELEVE",
                        f"Fichier sensible modifiable par tous : {chemin}",
                        f"Permissions actuelles : {oct(permissions)}",
                        "Retirer les droits d'écriture pour les utilisateurs non privilégiés.",
                    )

        except Exception as erreur:

            logging.error(
                "Erreur permissions %s : %s",
                chemin,
                erreur,
            )


# ============================================================================
# 4. PARE-FEU
# ============================================================================

def auditer_pare_feu(resultats):
    """
    Vérifie UFW, nftables et iptables.

    Classification :

        Pare-feu actif :
            aucune alerte.

        Aucun filtrage :
            MOYEN.

        Vérification impossible sans root :
            INFO.
    """

    print("[...] Pare-feu")

    ufw_present = commande_existe("ufw")
    nft_present = commande_existe("nft")
    iptables_present = commande_existe("iptables")

    filtrage_ufw = False
    filtrage_nft = False
    filtrage_iptables = False

    verification_complete = est_root()

    # ------------------------------------------------------------------------
    # UFW
    # ------------------------------------------------------------------------

    if ufw_present:

        code, stdout, _ = executer_commande(
            [
                "ufw",
                "status",
            ]
        )

        if code == 0:

            texte = stdout.lower()

            if "status: active" in texte:

                filtrage_ufw = True

    # ------------------------------------------------------------------------
    # nftables
    # ------------------------------------------------------------------------

    if nft_present and verification_complete:

        code, stdout, _ = executer_commande(
            [
                "nft",
                "list",
                "ruleset",
            ]
        )

        if code == 0:

            if stdout.strip():

                filtrage_nft = True

    # ------------------------------------------------------------------------
    # iptables
    # ------------------------------------------------------------------------

    if iptables_present and verification_complete:

        code, stdout, _ = executer_commande(
            [
                "iptables",
                "-L",
                "-n",
            ]
        )

        if code == 0:

            lignes = stdout.splitlines()

            politiques = []

            for ligne in lignes:

                if (
                    ligne.startswith("Chain INPUT")
                    or ligne.startswith("Chain FORWARD")
                    or ligne.startswith("Chain OUTPUT")
                ):

                    if "policy" in ligne.lower():

                        politiques.append(
                            ligne.upper()
                        )

            nombre_regles = 0

            for ligne in lignes:

                ligne = ligne.strip()

                if not ligne:
                    continue

                if ligne.startswith("target"):
                    continue

                if ligne.startswith("Chain"):
                    continue

                nombre_regles += 1

            politique_drop = any(
                "POLICY DROP" in politique
                for politique in politiques
            )

            if nombre_regles > 0 or politique_drop:

                filtrage_iptables = True

    # ------------------------------------------------------------------------
    # Résultat
    # ------------------------------------------------------------------------

    filtrage_actif = (
        filtrage_ufw
        or filtrage_nft
        or filtrage_iptables
    )

    if filtrage_actif:

        logging.info(
            "Filtrage réseau actif détecté."
        )

        return

    # ------------------------------------------------------------------------
    # Vérification incomplète
    # ------------------------------------------------------------------------

    if not verification_complete:

        ajouter_resultat(
            resultats,
            "INFO",
            "Vérification du pare-feu incomplète",
            (
                "Les règles nftables/iptables nécessitent "
                "des privilèges administrateur."
            ),
            "Relancer Linux Toolbox avec sudo.",
        )

        return

    # ------------------------------------------------------------------------
    # Aucun filtrage
    # ------------------------------------------------------------------------

    ajouter_resultat(
        resultats,
        "MOYEN",
        "Aucun filtrage réseau actif détecté",
        (
            "Aucun filtrage actif n'a été détecté avec "
            "UFW, nftables ou iptables."
        ),
        (
            "Activer et configurer un pare-feu adapté "
            "au rôle de la machine."
        ),
    )


# ============================================================================
# 5. PORTS ET SOCKETS
# ============================================================================

def auditer_ports(resultats):
    """
    Analyse les sockets réseau.

    TCP :
        Seuls les sockets LISTEN sont considérés comme des ports
        en écoute.

    UDP :
        UDP n'utilise pas l'état LISTEN.
        Les sockets UDP sont donc indiqués comme liés.
    """

    print("[...] Ports et sockets réseau")

    if not commande_existe("ss"):

        return

    code, stdout, stderr = executer_commande(
        [
            "ss",
            "-lntup",
        ]
    )

    if code != 0:

        logging.warning(
            "Impossible d'obtenir les sockets : %s",
            stderr,
        )

        return

    sockets_tcp = []
    sockets_udp = []

    for ligne in stdout.splitlines():

        ligne = ligne.strip()

        if not ligne:
            continue

        if ligne.startswith("Netid"):
            continue

        morceaux = ligne.split()

        if len(morceaux) < 5:
            continue

        protocole = morceaux[0]

        if protocole == "tcp":

            etat = morceaux[1]

            if etat != "LISTEN":
                continue

            adresse = morceaux[4]

            sockets_tcp.append(
                adresse
            )

        elif protocole == "udp":

            adresse = morceaux[4]

            sockets_udp.append(
                adresse
            )

    # ------------------------------------------------------------------------
    # TCP
    # ------------------------------------------------------------------------

    if sockets_tcp:

        ajouter_resultat(
            resultats,
            "INFO",
            f"{len(sockets_tcp)} port(s) TCP en écoute détecté(s)",
            "\n".join(
                f"TCP {adresse}"
                for adresse in sockets_tcp
            ),
            (
                "Vérifier que chaque service TCP en écoute "
                "est nécessaire et correctement configuré."
            ),
        )

    # ------------------------------------------------------------------------
    # UDP
    # ------------------------------------------------------------------------

    sockets_udp_interessants = []

    for adresse in sockets_udp:

        if ":68" in adresse:

            sockets_udp_interessants.append(
                f"UDP {adresse} (DHCP client)"
            )

        elif ":67" in adresse:

            sockets_udp_interessants.append(
                f"UDP {adresse} (DHCP server)"
            )

        else:

            sockets_udp_interessants.append(
                f"UDP {adresse} (socket lié)"
            )

    if sockets_udp_interessants:

        ajouter_resultat(
            resultats,
            "INFO",
            f"{len(sockets_udp_interessants)} socket(s) UDP détecté(s)",
            "\n".join(
                sockets_udp_interessants
            ),
            (
                "Vérifier que les sockets UDP détectés "
                "correspondent à des services légitimes."
            ),
        )


# ============================================================================
# 6. SERVICES SYSTEMD
# ============================================================================

def auditer_services(resultats):
    """
    Vérifie les services systemd actuellement en échec.
    """

    print("[...] Services systemd")

    if not commande_existe("systemctl"):

        return

    code, stdout, stderr = executer_commande(
        [
            "systemctl",
            "--failed",
            "--type=service",
            "--no-legend",
            "--no-pager",
        ]
    )

    if code != 0:

        logging.warning(
            "Impossible de vérifier les services : %s",
            stderr,
        )

        return

    services_echoues = []

    for ligne in stdout.splitlines():

        ligne = ligne.strip()

        if not ligne:
            continue

        morceaux = ligne.split()

        if not morceaux:
            continue

        nom_service = morceaux[0]

        # Protection supplémentaire contre le symbole
        # utilisé parfois par systemctl.

        if nom_service.startswith("●"):

            nom_service = nom_service.lstrip("●")

        if nom_service:

            services_echoues.append(
                nom_service
            )

    if services_echoues:

        ajouter_resultat(
            resultats,
            "MOYEN",
            f"{len(services_echoues)} service(s) systemd en échec",
            "\n".join(
                services_echoues
            ),
            (
                "Examiner les journaux des services concernés "
                "et corriger les erreurs."
            ),
        )


# ============================================================================
# 7. SSH
# ============================================================================

def auditer_ssh(resultats):
    """
    Vérifie quelques paramètres de sécurité SSH.

    sshd -T est utilisé pour obtenir la configuration effective.
    """

    print("[...] Configuration SSH")

    fichier_config = Path(
        "/etc/ssh/sshd_config"
    )

    if not fichier_config.exists():

        return

    if not commande_existe("sshd"):

        return

    code, stdout, _ = executer_commande(
        [
            "sshd",
            "-T",
        ]
    )

    if code != 0:

        return

    configuration = {}

    for ligne in stdout.splitlines():

        morceaux = ligne.split(
            None,
            1,
        )

        if len(morceaux) == 2:

            configuration[
                morceaux[0].lower()
            ] = morceaux[1].strip().lower()

    # ------------------------------------------------------------------------
    # Root login
    # ------------------------------------------------------------------------

    if configuration.get(
        "permitrootlogin"
    ) == "yes":

        ajouter_resultat(
            resultats,
            "MOYEN",
            "Connexion SSH directe de root autorisée",
            "PermitRootLogin yes",
            (
                "Désactiver la connexion SSH directe de root "
                "si elle n'est pas nécessaire."
            ),
        )

    # ------------------------------------------------------------------------
    # Empty passwords
    # ------------------------------------------------------------------------

    if configuration.get(
        "permitemptypasswords"
    ) == "yes":

        ajouter_resultat(
            resultats,
            "ELEVE",
            "SSH autorise les mots de passe vides",
            "PermitEmptyPasswords yes",
            "Désactiver PermitEmptyPasswords.",
        )

    # ------------------------------------------------------------------------
    # Password authentication
    # ------------------------------------------------------------------------

    if configuration.get(
        "passwordauthentication"
    ) == "yes":

        ajouter_resultat(
            resultats,
            "INFO",
            "Authentification SSH par mot de passe activée",
            "PasswordAuthentication yes",
            (
                "Pour un environnement renforcé, envisager "
                "l'utilisation de clés SSH."
            ),
        )


# ============================================================================
# 8. MISES A JOUR
# ============================================================================

def auditer_mises_a_jour(resultats):
    """
    Recherche les mises à jour disponibles.

    Les mises à jour génériques sont classées INFO.
    Leur présence n'est pas automatiquement une vulnérabilité.
    """

    print("[...] Mises à jour")

    # ------------------------------------------------------------------------
    # Debian / Kali
    # ------------------------------------------------------------------------

    if commande_existe("apt-get"):

        code, stdout, stderr = executer_commande(
            [
                "apt-get",
                "-s",
                "upgrade",
            ],
            timeout=60,
        )

        if code != 0:

            logging.warning(
                "apt-get upgrade impossible : %s",
                stderr,
            )

            return

        paquets = []

        for ligne in stdout.splitlines():

            ligne = ligne.strip()

            if ligne.startswith("Inst "):

                morceaux = ligne.split()

                if len(morceaux) >= 2:

                    paquets.append(
                        morceaux[1]
                    )

        if paquets:

            ajouter_resultat(
                resultats,
                "INFO",
                f"{len(paquets)} mise(s) à jour disponible(s)",
                ", ".join(
                    paquets[:30]
                ),
                (
                    "Vérifier régulièrement les mises à jour "
                    "et appliquer les correctifs selon la "
                    "politique de maintenance."
                ),
            )

        return

    # ------------------------------------------------------------------------
    # Fedora / RHEL
    # ------------------------------------------------------------------------

    if commande_existe("dnf"):

        code, stdout, stderr = executer_commande(
            [
                "dnf",
                "check-update",
                "-q",
            ],
            timeout=60,
        )

        if code not in (0, 100):

            return

        lignes = [
            ligne
            for ligne in stdout.splitlines()
            if ligne.strip()
        ]

        if lignes:

            ajouter_resultat(
                resultats,
                "INFO",
                f"{len(lignes)} mise(s) à jour potentielle(s)",
                "\n".join(
                    lignes[:30]
                ),
                (
                    "Vérifier régulièrement les mises à jour "
                    "et appliquer les correctifs nécessaires."
                ),
            )


# ============================================================================
# 9. POLITIQUE MOTS DE PASSE
# ============================================================================

def auditer_mots_de_passe(resultats):
    """
    Analyse quelques paramètres de /etc/login.defs.
    """

    print("[...] Politique mots de passe")

    fichier = Path(
        "/etc/login.defs"
    )

    if not fichier.exists():

        return

    configuration = {}

    try:

        contenu = fichier.read_text(
            errors="ignore"
        )

        for ligne in contenu.splitlines():

            ligne = ligne.strip()

            if not ligne or ligne.startswith("#"):
                continue

            morceaux = ligne.split()

            if len(morceaux) >= 2:

                configuration[
                    morceaux[0]
                ] = morceaux[1]

    except Exception as erreur:

        logging.error(
            "Erreur login.defs : %s",
            erreur,
        )

        return

    try:

        longueur_minimum = int(
            configuration.get(
                "PASS_MIN_LEN",
                "0",
            )
        )

        if (
            longueur_minimum > 0
            and longueur_minimum < 8
        ):

            ajouter_resultat(
                resultats,
                "MOYEN",
                "Politique de longueur de mot de passe faible",
                f"PASS_MIN_LEN = {longueur_minimum}",
                (
                    "Augmenter la longueur minimale des mots de passe "
                    "selon la politique de sécurité."
                ),
            )

    except ValueError:

        pass


# ============================================================================
# 10. CRON / TIMERS
# ============================================================================

def auditer_taches_planifiees(resultats):
    """
    Recherche les timers systemd et fichiers cron.
    """

    print("[...] Cron / timers")

    nombre_timers = 0
    nombre_cron = 0

    # ------------------------------------------------------------------------
    # Systemd timers
    # ------------------------------------------------------------------------

    if commande_existe("systemctl"):

        code, stdout, _ = executer_commande(
            [
                "systemctl",
                "list-timers",
                "--all",
                "--no-legend",
                "--no-pager",
            ]
        )

        if code == 0:

            for ligne in stdout.splitlines():

                if ligne.strip():

                    nombre_timers += 1

    # ------------------------------------------------------------------------
    # Fichiers cron
    # ------------------------------------------------------------------------

    chemins_cron = [
        "/etc/crontab",
        "/etc/cron.d",
        "/etc/cron.daily",
        "/etc/cron.hourly",
        "/etc/cron.weekly",
        "/etc/cron.monthly",
    ]

    for chemin in chemins_cron:

        fichier = Path(chemin)

        if not fichier.exists():

            continue

        if fichier.is_file():

            nombre_cron += 1

        elif fichier.is_dir():

            try:

                nombre_cron += len(
                    list(
                        fichier.iterdir()
                    )
                )

            except Exception:

                pass

    if nombre_timers or nombre_cron:

        ajouter_resultat(
            resultats,
            "INFO",
            "Tâches planifiées détectées",
            (
                f"{nombre_timers} timer(s) systemd et "
                f"{nombre_cron} fichier(s) cron."
            ),
            (
                "Vérifier les tâches inhabituelles "
                "et leur propriétaire."
            ),
        )


# ============================================================================
# 11. JOURNAUX
# ============================================================================

def auditer_journaux(resultats):
    """
    Recherche les erreurs récentes dans journalctl.

    IMPORTANT :
        Une erreur journalctl n'est pas automatiquement une vulnérabilité.

    Les détails complets sont conservés dans le rapport.
    Le terminal n'affiche qu'un résumé afin de rester lisible.
    """

    print("[...] Journaux")

    if not commande_existe("journalctl"):

        return

    code, stdout, stderr = executer_commande(
        [
            "journalctl",
            "-p",
            "err",
            "-b",
            "--no-pager",
            "-n",
            "20",
        ]
    )

    if code != 0:

        logging.warning(
            "Impossible de lire journalctl : %s",
            stderr,
        )

        return

    lignes = [
        ligne
        for ligne in stdout.splitlines()
        if ligne.strip()
    ]

    if not lignes:

        return

    # ------------------------------------------------------------------------
    # Détails complets pour les rapports
    # ------------------------------------------------------------------------

    details_complets = "\n".join(
        lignes[:20]
    )

    nombre_erreurs = len(
        lignes
    )

    # ------------------------------------------------------------------------
    # Résumé affiché dans le terminal
    # ------------------------------------------------------------------------

    resume = (
        f"{nombre_erreurs} erreur(s) système détectée(s) "
        f"dans les journaux depuis le dernier démarrage."
    )

    ajouter_resultat(
        resultats,
        "INFO",
        "Erreurs système détectées dans les journaux",
        details_complets,
        (
            "Examiner les événements journalctl concernés "
            "pour déterminer s'ils sont importants."
        ),
        affichage=resume,
    )


# ============================================================================
# 12. REPERTOIRES WORLD-WRITABLE
# ============================================================================

def auditer_world_writable(resultats):
    """
    Recherche les répertoires accessibles en écriture par tout le monde.

    Exception :
        Les répertoires possédant le sticky bit, comme /tmp et /var/tmp,
        sont considérés comme normaux.
    """

    print("[...] Répertoires world-writable")

    chemins = [
        "/tmp",
        "/var/tmp",
        "/home",
        "/opt",
        "/var/www",
    ]

    dangereux = []

    for chemin in chemins:

        racine = Path(chemin)

        if not racine.exists():

            continue

        try:

            mode = racine.stat().st_mode

            world_writable = bool(
                mode & stat.S_IWOTH
            )

            sticky_bit = bool(
                mode & stat.S_ISVTX
            )

            if world_writable and not sticky_bit:

                dangereux.append(
                    chemin
                )

        except Exception:

            continue

    if dangereux:

        ajouter_resultat(
            resultats,
            "MOYEN",
            (
                f"{len(dangereux)} répertoire(s) "
                "world-writable sans sticky bit"
            ),
            "\n".join(
                dangereux
            ),
            (
                "Vérifier les permissions et retirer "
                "l'écriture globale si elle n'est pas nécessaire."
            ),
        )


# ============================================================================
# SCORE
# ============================================================================

def calculer_score(resultats):
    """
    Calcule le score de sécurité.

    Critique : -30
    Élevé    : -10
    Moyen    : -5
    Faible   : -2
    Info     :  0
    """

    penalites = {
        "CRITIQUE": 30,
        "ELEVE": 10,
        "MOYEN": 5,
        "FAIBLE": 2,
        "INFO": 0,
    }

    score = 100

    for resultat in resultats:

        severite = resultat[
            "severite"
        ]

        score -= penalites.get(
            severite,
            0,
        )

    return max(
        0,
        min(
            100,
            score,
        ),
    )


def determiner_niveau(score):
    """
    Détermine le niveau global.
    """

    if score >= 90:

        return "BON"

    if score >= 75:

        return "MOYEN"

    if score >= 50:

        return "FAIBLE"

    return "CRITIQUE"


# ============================================================================
# RAPPORT TXT
# ============================================================================

def generer_rapport_txt(
    resultats,
    score,
    niveau,
    date_audit,
):
    """
    Génère le rapport texte.

    Les détails complets des journaux sont conservés ici,
    contrairement à l'affichage du terminal.
    """

    fichier = (
        REPORTS_DIR
        / f"security_audit_{date_audit}.txt"
    )

    lignes = []

    lignes.append(
        "=" * 80
    )

    lignes.append(
        "AUDIT DE SECURITE - LINUX TOOLBOX"
    )

    lignes.append(
        "=" * 80
    )

    lignes.append(
        f"Version          : {VERSION}"
    )

    lignes.append(
        f"Machine          : {os.uname().nodename}"
    )

    lignes.append(
        "Date             : "
        + datetime.now().strftime(
            "%d/%m/%Y %H:%M:%S"
        )
    )

    lignes.append(
        f"Exécution root   : {est_root()}"
    )

    lignes.append(
        f"Score sécurité   : {score}/100"
    )

    lignes.append(
        f"Niveau global    : {niveau}"
    )

    lignes.append("")

    lignes.append(
        "RESULTATS"
    )

    lignes.append(
        "-" * 80
    )

    for resultat in resultats:

        lignes.append(
            f"[{resultat['severite']}] "
            f"{resultat['titre']}"
        )

        lignes.append(
            f"  -> {resultat['details']}"
        )

        lignes.append(
            f"  -> Conseil : "
            f"{resultat['conseil']}"
        )

        lignes.append("")

    fichier.write_text(
        "\n".join(lignes),
        encoding="utf-8",
    )

    return fichier


# ============================================================================
# RAPPORT JSON
# ============================================================================

def generer_rapport_json(
    resultats,
    score,
    niveau,
    date_audit,
):
    """
    Génère le rapport JSON.
    """

    fichier = (
        REPORTS_DIR
        / f"security_audit_{date_audit}.json"
    )

    donnees = {
        "outil": "Linux Toolbox",
        "version": VERSION,
        "type": "security_audit",
        "machine": os.uname().nodename,
        "date": datetime.now().isoformat(),
        "root": est_root(),
        "score": score,
        "niveau": niveau,
        "resultats": resultats,
    }

    fichier.write_text(
        json.dumps(
            donnees,
            indent=4,
            ensure_ascii=False,
        ),
        encoding="utf-8",
    )

    return fichier


# ============================================================================
# AFFICHAGE
# ============================================================================

def afficher_resultats(
    resultats,
    score,
    niveau,
):
    """
    Affiche les résultats dans le terminal.
    """

    print()
    print("=" * 80)

    print(
        "                 AUDIT DE SECURITE"
    )

    print("=" * 80)

    print()

    print(
        f"Machine          : {os.uname().nodename}"
    )

    print(
        f"Exécution root   : {est_root()}"
    )

    print(
        f"Score sécurité   : {score}/100"
    )

    print(
        f"Niveau global    : {niveau}"
    )

    print()

    print(
        "RESULTATS"
    )

    print(
        "-" * 80
    )

    compteurs = {
        "CRITIQUE": 0,
        "ELEVE": 0,
        "MOYEN": 0,
        "FAIBLE": 0,
        "INFO": 0,
    }

    for resultat in resultats:

        severite = resultat[
            "severite"
        ]

        compteurs[
            severite
        ] = compteurs.get(
            severite,
            0,
        ) + 1

    print(
        f"Critique : {compteurs['CRITIQUE']}"
    )

    print(
        f"Élevé    : {compteurs['ELEVE']}"
    )

    print(
        f"Moyen    : {compteurs['MOYEN']}"
    )

    print(
        f"Faible   : {compteurs['FAIBLE']}"
    )

    print(
        f"Info     : {compteurs['INFO']}"
    )

    print()

    for resultat in resultats:

        print(
            f"[{resultat['severite']}] "
            f"{resultat['titre']}"
        )

        # Le terminal utilise le résumé court lorsqu'il existe.
        print(
            f"  -> {resultat['affichage']}"
        )

        print(
            f"  -> Conseil : "
            f"{resultat['conseil']}"
        )

        print()


# ============================================================================
# FONCTION PRINCIPALE
# ============================================================================

def lancer_audit_securite():
    """
    Lance l'audit complet.
    """

    print()
    print("=" * 80)

    print(
        "Lancement de l'audit de sécurité..."
    )

    print(
        "Aucune modification du système ne sera effectuée."
    )

    print("=" * 80)
    print()

    debut = datetime.now()

    date_audit = debut.strftime(
        "%Y%m%d_%H%M%S"
    )

    resultats = []

    # ------------------------------------------------------------------------
    # AUDITS
    # ------------------------------------------------------------------------

    auditer_comptes_groupes(
        resultats
    )

    auditer_suid_sgid(
        resultats
    )

    auditer_permissions_sensibles(
        resultats
    )

    auditer_pare_feu(
        resultats
    )

    auditer_ports(
        resultats
    )

    auditer_services(
        resultats
    )

    auditer_ssh(
        resultats
    )

    auditer_mises_a_jour(
        resultats
    )

    auditer_mots_de_passe(
        resultats
    )

    auditer_taches_planifiees(
        resultats
    )

    auditer_journaux(
        resultats
    )

    auditer_world_writable(
        resultats
    )

    # ------------------------------------------------------------------------
    # SCORE
    # ------------------------------------------------------------------------

    score = calculer_score(
        resultats
    )

    niveau = determiner_niveau(
        score
    )

    # ------------------------------------------------------------------------
    # AFFICHAGE
    # ------------------------------------------------------------------------

    afficher_resultats(
        resultats,
        score,
        niveau,
    )

    # ------------------------------------------------------------------------
    # RAPPORTS
    # ------------------------------------------------------------------------

    fichier_txt = generer_rapport_txt(
        resultats,
        score,
        niveau,
        date_audit,
    )

    fichier_json = generer_rapport_json(
        resultats,
        score,
        niveau,
        date_audit,
    )

    # ------------------------------------------------------------------------
    # LOG
    # ------------------------------------------------------------------------

    duree = (
        datetime.now() - debut
    ).total_seconds()

    logging.info(
        (
            "Audit terminé | machine=%s | "
            "root=%s | score=%s | niveau=%s | "
            "duree=%.2fs"
        ),
        os.uname().nodename,
        est_root(),
        score,
        niveau,
        duree,
    )

    print()
    print(
        "RAPPORTS"
    )

    print(
        "-" * 80
    )

    print(
        f"TXT  : {fichier_txt}"
    )

    print(
        f"JSON : {fichier_json}"
    )

    print(
        f"LOG  : {LOG_FILE}"
    )

    print()

    print(
        f"Durée de l'audit : {duree:.2f} seconde(s)"
    )
