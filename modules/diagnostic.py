"""
LINUX TOOLBOX
Module : Diagnostic système
Version : 2.3

Objectif :
    Réaliser un inventaire complet d'une machine Linux :

    - système / distribution / noyau
    - processeur / utilisation / fréquence
    - RAM / swap
    - disques / partitions
    - interfaces réseau / adresses / trafic
    - passerelle / DNS
    - uptime
    - températures
    - processus CPU / RAM
    - ports en écoute
    - services systemd
    - utilisateurs / groupes sensibles
    - état du firewall
    - résumé automatique
    - rapports TXT / JSON
    - logs

IMPORTANT :
    Ce module réalise principalement un diagnostic et un inventaire.

    Il ne considère PAS automatiquement :
        - un port ouvert
        - un service actif
        - une RAM élevée
        - une utilisation CPU élevée
    comme une vulnérabilité.

    L'analyse de sécurité détaillée sera réalisée dans :
        modules/security_audit.py
"""

import json
import os
import platform
import re
import shutil
import socket
import time
from datetime import datetime
from pathlib import Path

import psutil

from .utils import executer_commande


# ============================================================
# CONFIGURATION
# ============================================================

BASE_DIR = Path(__file__).resolve().parent.parent

REPORTS_DIR = BASE_DIR / "reports"
LOGS_DIR = BASE_DIR / "logs"

REPORTS_DIR.mkdir(
    parents=True,
    exist_ok=True
)

LOGS_DIR.mkdir(
    parents=True,
    exist_ok=True
)


# ============================================================
# OUTILS GENERIQUES
# ============================================================

def verifier_commande_disponible(nom):
    """
    Vérifie si une commande existe.
    """

    return shutil.which(nom) is not None


def octets_vers_go(valeur):
    """
    Convertit des octets en Go.
    """

    return valeur / (1024 ** 3)


def octets_vers_ko(valeur):
    """
    Convertit des octets en Ko.
    """

    return valeur / 1024


def formater_duree(secondes):
    """
    Transforme des secondes en durée lisible.
    """

    secondes = int(secondes)

    jours, secondes = divmod(
        secondes,
        86400
    )

    heures, secondes = divmod(
        secondes,
        3600
    )

    minutes, secondes = divmod(
        secondes,
        60
    )

    morceaux = []

    if jours:
        morceaux.append(
            f"{jours}j"
        )

    if heures:
        morceaux.append(
            f"{heures}h"
        )

    if minutes:
        morceaux.append(
            f"{minutes}m"
        )

    morceaux.append(
        f"{secondes}s"
    )

    return " ".join(morceaux)


def valeur_inconnue(valeur):
    """
    Remplace les valeurs absentes par 'Inconnue'.
    """

    if valeur is None or valeur == "":
        return "Inconnue"

    return valeur


# ============================================================
# SYSTEME
# ============================================================

def collecter_systeme():

    systeme = platform.system()

    nom_os = "Inconnu"
    version_os = "Inconnue"
    identifiant_os = "Inconnu"

    # --------------------------------------------------------
    # Distribution Linux
    # --------------------------------------------------------

    try:

        if hasattr(
            platform,
            "freedesktop_os_release"
        ):

            distribution = (
                platform.freedesktop_os_release()
            )

            nom_os = distribution.get(
                "PRETTY_NAME",
                distribution.get(
                    "NAME",
                    "Inconnu"
                )
            )

            version_os = distribution.get(
                "VERSION_ID",
                "Inconnue"
            )

            identifiant_os = distribution.get(
                "ID",
                "Inconnu"
            )

    except Exception:
        pass

    # --------------------------------------------------------
    # Nom du processeur
    # --------------------------------------------------------

    processeur = platform.processor()

    # Fallback /proc/cpuinfo
    if not processeur:

        try:

            with open(
                "/proc/cpuinfo",
                "r",
                encoding="utf-8"
            ) as fichier:

                for ligne in fichier:

                    if ligne.lower().startswith(
                        "model name"
                    ):

                        processeur = (
                            ligne
                            .split(":", 1)[1]
                            .strip()
                        )

                        break

        except Exception:
            pass

    # Fallback lscpu
    if (
        not processeur
        and verifier_commande_disponible(
            "lscpu"
        )
    ):

        code, sortie, _ = executer_commande(
            ["lscpu"]
        )

        if code == 0:

            for ligne in sortie.splitlines():

                if "Model name:" in ligne:

                    processeur = (
                        ligne
                        .split(":", 1)[1]
                        .strip()
                    )

                    break

    if not processeur:
        processeur = "Inconnu"

    return {

        "nom_machine":
            socket.gethostname(),

        "systeme":
            systeme,

        "os":
            nom_os,

        "version_os":
            version_os,

        "identifiant_os":
            identifiant_os,

        "kernel":
            platform.release(),

        "version_kernel":
            platform.version(),

        "architecture":
            platform.machine(),

        "processeur":
            processeur,

        "python":
            platform.python_version()

    }


# ============================================================
# CPU
# ============================================================

def collecter_cpu():

    utilisation_globale = (
        psutil.cpu_percent(
            interval=1
        )
    )

    coeurs_physiques = (
        psutil.cpu_count(
            logical=False
        )
    )

    coeurs_logiques = (
        psutil.cpu_count(
            logical=True
        )
    )

    frequence = psutil.cpu_freq()

    frequence_actuelle = None
    frequence_min = None
    frequence_max = None

    if frequence:

        frequence_actuelle = (
            frequence.current
        )

        frequence_min = (
            frequence.min
        )

        frequence_max = (
            frequence.max
        )

    # --------------------------------------------------------
    # Utilisation de chaque cœur
    # --------------------------------------------------------

    utilisations = psutil.cpu_percent(
        interval=0.5,
        percpu=True
    )

    par_coeur = []

    for numero, valeur in enumerate(
        utilisations
    ):

        par_coeur.append({

            "coeur":
                numero,

            "utilisation":
                valeur

        })

    return {

        "coeurs_physiques":
            coeurs_physiques,

        "coeurs_logiques":
            coeurs_logiques,

        "utilisation_globale":
            utilisation_globale,

        "frequence_actuelle_mhz":
            frequence_actuelle,

        "frequence_min_mhz":
            frequence_min,

        "frequence_max_mhz":
            frequence_max,

        "par_coeur":
            par_coeur

    }


# ============================================================
# RAM / SWAP
# ============================================================

def collecter_memoire():

    ram = psutil.virtual_memory()
    swap = psutil.swap_memory()

    return {

        "ram": {

            "total_go":
                octets_vers_go(
                    ram.total
                ),

            "utilisee_go":
                octets_vers_go(
                    ram.used
                ),

            "disponible_go":
                octets_vers_go(
                    ram.available
                ),

            "libre_go":
                octets_vers_go(
                    ram.free
                ),

            "pourcentage":
                ram.percent

        },

        "swap": {

            "total_go":
                octets_vers_go(
                    swap.total
                ),

            "utilisee_go":
                octets_vers_go(
                    swap.used
                ),

            "libre_go":
                octets_vers_go(
                    swap.free
                ),

            "pourcentage":
                swap.percent

        }

    }


# ============================================================
# DISQUES PHYSIQUES
# ============================================================

def collecter_disques():

    disques = []

    if not verifier_commande_disponible(
        "lsblk"
    ):

        return disques

    code, sortie, _ = executer_commande(
        [
            "lsblk",
            "-J",
            "-b",
            "-o",
            "NAME,SIZE,TYPE,MODEL,TRAN"
        ]
    )

    if code != 0:
        return disques

    try:

        donnees = json.loads(
            sortie
        )

        for disque in donnees.get(
            "blockdevices",
            []
        ):

            if disque.get("type") != "disk":
                continue

            nom = disque.get(
                "name",
                ""
            )

            # Évite boot0 / boot1 des eMMC
            if nom in (
                "boot0",
                "boot1"
            ):
                continue

            taille = disque.get(
                "size"
            )

            disques.append({

                "nom":
                    f"/dev/{nom}",

                "taille_go":
                    (
                        octets_vers_go(
                            int(taille)
                        )
                        if taille
                        else 0
                    ),

                "type":
                    disque.get(
                        "type",
                        "Inconnu"
                    ),

                "modele":
                    disque.get(
                        "model"
                    )
                    or "Inconnu",

                "transport":
                    disque.get(
                        "tran"
                    )
                    or "Inconnu"

            })

    except Exception:
        pass

    return disques


# ============================================================
# PARTITIONS
# ============================================================

def collecter_partitions():

    partitions = []

    try:

        for partition in psutil.disk_partitions(
            all=False
        ):

            try:

                utilisation = (
                    psutil.disk_usage(
                        partition.mountpoint
                    )
                )

                partitions.append({

                    "device":
                        partition.device,

                    "point_montage":
                        partition.mountpoint,

                    "systeme_fichiers":
                        partition.fstype,

                    "total_go":
                        octets_vers_go(
                            utilisation.total
                        ),

                    "utilise_go":
                        octets_vers_go(
                            utilisation.used
                        ),

                    "libre_go":
                        octets_vers_go(
                            utilisation.free
                        ),

                    "pourcentage":
                        utilisation.percent

                })

            except Exception:
                continue

    except Exception:
        pass

    return partitions


# ============================================================
# RESEAU
# ============================================================

def collecter_reseau():

    interfaces = psutil.net_if_addrs()

    statistiques = (
        psutil.net_if_stats()
    )

    trafic = (
        psutil.net_io_counters(
            pernic=True
        )
    )

    resultat = []

    for nom, adresses in interfaces.items():

        stats_interface = (
            statistiques.get(nom)
        )

        infos_interface = {

            "nom":
                nom,

            "etat":
                (
                    "UP"
                    if (
                        stats_interface
                        and stats_interface.isup
                    )
                    else "DOWN"
                ),

            "vitesse_mbps":
                None,

            "mtu":
                (
                    stats_interface.mtu
                    if stats_interface
                    else None
                ),

            "vitesse_wifi":
                None,

            "adresses":
                [],

            "trafic":
                {}

        }

        # ----------------------------------------------------
        # Vitesse de l'interface
        # ----------------------------------------------------

        if stats_interface:

            vitesse = (
                stats_interface.speed
            )

            if vitesse and vitesse > 0:

                infos_interface[
                    "vitesse_mbps"
                ] = vitesse

        # ----------------------------------------------------
        # Vitesse Wi-Fi
        # ----------------------------------------------------

        if (
            infos_interface["etat"] == "UP"
            and nom != "lo"
            and verifier_commande_disponible(
                "iw"
            )
        ):

            code, sortie, _ = (
                executer_commande(
                    [
                        "iw",
                        "dev",
                        nom,
                        "link"
                    ]
                )
            )

            if code == 0 and sortie:

                match = re.search(
                    r"tx bitrate:\s*(.+)",
                    sortie
                )

                if match:

                    infos_interface[
                        "vitesse_wifi"
                    ] = (
                        match.group(1)
                        .strip()
                    )

        # ----------------------------------------------------
        # Adresses IP / MAC
        # ----------------------------------------------------

        for adresse in adresses:

            famille = adresse.family

            if famille == socket.AF_INET:

                type_adresse = "IPv4"

            elif famille == socket.AF_INET6:

                type_adresse = "IPv6"

            elif str(famille).endswith(
                "AF_LINK"
            ):

                type_adresse = "MAC"

            else:

                type_adresse = str(
                    famille
                )

            infos_interface[
                "adresses"
            ].append({

                "type":
                    type_adresse,

                "adresse":
                    adresse.address,

                "masque":
                    valeur_inconnue(
                        adresse.netmask
                    )

            })

        # ----------------------------------------------------
        # Trafic réseau
        # ----------------------------------------------------

        if nom in trafic:

            stats = trafic[nom]

            infos_interface[
                "trafic"
            ] = {

                "envoye_ko":
                    octets_vers_ko(
                        stats.bytes_sent
                    ),

                "recu_ko":
                    octets_vers_ko(
                        stats.bytes_recv
                    ),

                "paquets_tx":
                    stats.packets_sent,

                "paquets_rx":
                    stats.packets_recv,

                "erreurs_tx":
                    stats.errout,

                "erreurs_rx":
                    stats.errin,

                "drops_tx":
                    stats.dropout,

                "drops_rx":
                    stats.dropin

            }

        resultat.append(
            infos_interface
        )

    return resultat


# ============================================================
# PASSERELLE
# ============================================================

def collecter_passerelle():

    if not verifier_commande_disponible(
        "ip"
    ):

        return {

            "passerelle":
                "Inconnue",

            "interface":
                "Inconnue"

        }

    code, sortie, _ = executer_commande(
        [
            "ip",
            "route",
            "show",
            "default"
        ]
    )

    if code != 0 or not sortie:

        return {

            "passerelle":
                "Aucune",

            "interface":
                "Inconnue"

        }

    morceaux = (
        sortie.splitlines()[0]
        .split()
    )

    passerelle = "Inconnue"
    interface = "Inconnue"

    if "via" in morceaux:

        index = morceaux.index(
            "via"
        )

        if index + 1 < len(
            morceaux
        ):

            passerelle = (
                morceaux[index + 1]
            )

    if "dev" in morceaux:

        index = morceaux.index(
            "dev"
        )

        if index + 1 < len(
            morceaux
        ):

            interface = (
                morceaux[index + 1]
            )

    return {

        "passerelle":
            passerelle,

        "interface":
            interface

    }


# ============================================================
# DNS
# ============================================================

def collecter_dns():

    serveurs = []

    # --------------------------------------------------------
    # resolvectl
    # --------------------------------------------------------

    if verifier_commande_disponible(
        "resolvectl"
    ):

        code, sortie, _ = (
            executer_commande(
                [
                    "resolvectl",
                    "dns"
                ]
            )
        )

        if code == 0:

            for ligne in sortie.splitlines():

                morceaux = ligne.split()

                if len(morceaux) < 2:
                    continue

                for morceau in morceaux[1:]:

                    if re.match(
                        r"^[0-9a-fA-F:.]+$",
                        morceau
                    ):

                        if (
                            morceau
                            not in serveurs
                        ):

                            serveurs.append(
                                morceau
                            )

    # --------------------------------------------------------
    # Fallback /etc/resolv.conf
    # --------------------------------------------------------

    if not serveurs:

        try:

            with open(
                "/etc/resolv.conf",
                "r",
                encoding="utf-8"
            ) as fichier:

                for ligne in fichier:

                    if ligne.startswith(
                        "nameserver"
                    ):

                        morceaux = (
                            ligne.split()
                        )

                        if len(morceaux) >= 2:

                            serveur = (
                                morceaux[1]
                            )

                            if (
                                serveur
                                not in serveurs
                            ):

                                serveurs.append(
                                    serveur
                                )

        except Exception:
            pass

    return serveurs


# ============================================================
# UPTIME
# ============================================================

def collecter_uptime():

    uptime_secondes = (
        time.time()
        - psutil.boot_time()
    )

    date_demarrage = (
        datetime.fromtimestamp(
            psutil.boot_time()
        )
    )

    return {

        "demarrage":
            date_demarrage.strftime(
                "%d/%m/%Y %H:%M:%S"
            ),

        "duree":
            formater_duree(
                uptime_secondes
            )

    }


# ============================================================
# TEMPERATURES
# ============================================================

def collecter_temperatures():

    temperatures = []

    try:

        donnees = (
            psutil.sensors_temperatures(
                fahrenheit=False
            )
        )

        for capteur, valeurs in (
            donnees.items()
        ):

            for valeur in valeurs:

                temperatures.append({

                    "capteur":
                        capteur,

                    "nom":
                        (
                            valeur.label
                            if valeur.label
                            else "Inconnu"
                        ),

                    "temperature":
                        valeur.current,

                    "critique":
                        valeur.critical

                })

    except Exception:
        pass

    return temperatures


# ============================================================
# PROCESSUS CPU
# ============================================================

def collecter_processus_cpu():

    processus = []

    # Premier échantillon
    for proc in psutil.process_iter(
        ["pid", "name"]
    ):

        try:

            proc.cpu_percent(
                None
            )

            processus.append(
                proc
            )

        except (
            psutil.NoSuchProcess,
            psutil.AccessDenied
        ):

            continue

    # Petit délai pour calculer réellement
    # l'utilisation CPU.
    time.sleep(0.5)

    resultats = []

    for proc in processus:

        try:

            cpu = proc.cpu_percent(
                None
            )

            info = proc.info

            resultats.append({

                "pid":
                    info["pid"],

                "nom":
                    (
                        info["name"]
                        or "Inconnu"
                    ),

                "cpu":
                    cpu

            })

        except (
            psutil.NoSuchProcess,
            psutil.AccessDenied
        ):

            continue

    resultats.sort(
        key=lambda x: x["cpu"],
        reverse=True
    )

    return resultats[:10]


# ============================================================
# PROCESSUS RAM
# ============================================================

def collecter_processus_ram():

    resultats = []

    for proc in psutil.process_iter(
        [
            "pid",
            "name",
            "memory_percent"
        ]
    ):

        try:

            resultats.append({

                "pid":
                    proc.info["pid"],

                "nom":
                    (
                        proc.info["name"]
                        or "Inconnu"
                    ),

                "ram":
                    (
                        proc.info[
                            "memory_percent"
                        ]
                        or 0
                    )

            })

        except (
            psutil.NoSuchProcess,
            psutil.AccessDenied
        ):

            continue

    resultats.sort(
        key=lambda x: x["ram"],
        reverse=True
    )

    return resultats[:10]


# ============================================================
# PORTS
# ============================================================

def identifier_service_port(
    port,
    protocole
):
    """
    Identifie quelques ports courants.

    Attention :
        Cela indique simplement le rôle
        généralement associé au port.

        Ce n'est PAS une analyse de vulnérabilité.
    """

    services = {

        ("TCP", 22):
            "SSH",

        ("TCP", 80):
            "HTTP",

        ("TCP", 443):
            "HTTPS",

        ("TCP", 631):
            "IPP / CUPS",

        ("TCP", 3306):
            "MySQL / MariaDB",

        ("TCP", 5432):
            "PostgreSQL",

        ("TCP", 6379):
            "Redis",

        ("TCP", 8000):
            "HTTP alternatif",

        ("TCP", 8080):
            "HTTP alternatif",

        ("UDP", 53):
            "DNS",

        ("TCP", 53):
            "DNS",

        ("UDP", 67):
            "DHCP serveur",

        ("UDP", 68):
            "DHCP client"

    }

    return services.get(
        (
            protocole,
            port
        ),
        "Inconnu"
    )


def collecter_ports():

    ports = []

    try:

        connexions = (
            psutil.net_connections(
                kind="inet"
            )
        )

        for connexion in connexions:

            if not connexion.laddr:
                continue

            # ------------------------------------------------
            # TCP
            # ------------------------------------------------

            if (
                connexion.type
                == socket.SOCK_STREAM
            ):

                if (
                    connexion.status
                    != psutil.CONN_LISTEN
                ):

                    continue

                protocole = "TCP"

            # ------------------------------------------------
            # UDP
            # ------------------------------------------------

            else:

                protocole = "UDP"

            adresse = (
                connexion.laddr.ip
            )

            port = (
                connexion.laddr.port
            )

            pid = connexion.pid

            nom_processus = "Inconnu"

            if pid:

                try:

                    nom_processus = (
                        psutil.Process(
                            pid
                        ).name()
                    )

                except (
                    psutil.NoSuchProcess,
                    psutil.AccessDenied
                ):

                    pass

            service = (
                identifier_service_port(
                    port,
                    protocole
                )
            )

            ports.append({

                "protocole":
                    protocole,

                "adresse":
                    adresse,

                "port":
                    port,

                "pid":
                    (
                        pid
                        if pid
                        else "-"
                    ),

                "processus":
                    nom_processus,

                "service_connu":
                    service

            })

    except Exception:
        pass

    # --------------------------------------------------------
    # Suppression des doublons
    # --------------------------------------------------------

    uniques = []

    deja_vus = set()

    for port in ports:

        cle = (

            port["protocole"],

            port["adresse"],

            port["port"],

            port["pid"]

        )

        if cle not in deja_vus:

            deja_vus.add(
                cle
            )

            uniques.append(
                port
            )

    return uniques


# ============================================================
# SERVICES SYSTEMD
# ============================================================

def collecter_services():

    resultat = {

        "actifs":
            [],

        "inactifs":
            [],

        "en_echec":
            [],

        "nombre_actifs":
            0,

        "nombre_inactifs":
            0,

        "nombre_echec":
            0

    }

    if not verifier_commande_disponible(
        "systemctl"
    ):

        return resultat

    # --------------------------------------------------------
    # Services actifs
    # --------------------------------------------------------

    code, sortie, _ = (
        executer_commande(
            [
                "systemctl",
                "list-units",
                "--type=service",
                "--state=active",
                "--no-legend",
                "--no-pager"
            ]
        )
    )

    if code == 0:

        for ligne in sortie.splitlines():

            morceaux = ligne.split()

            if morceaux:

                resultat[
                    "actifs"
                ].append(
                    morceaux[0]
                )

    # --------------------------------------------------------
    # Services inactifs
    # --------------------------------------------------------

    code, sortie, _ = (
        executer_commande(
            [
                "systemctl",
                "list-units",
                "--type=service",
                "--state=inactive",
                "--no-legend",
                "--no-pager"
            ]
        )
    )

    if code == 0:

        for ligne in sortie.splitlines():

            morceaux = ligne.split()

            if morceaux:

                resultat[
                    "inactifs"
                ].append(
                    morceaux[0]
                )

    # --------------------------------------------------------
    # Services en échec
    # --------------------------------------------------------

    code, sortie, _ = (
        executer_commande(
            [
                "systemctl",
                "list-units",
                "--type=service",
                "--state=failed",
                "--no-legend",
                "--no-pager"
            ]
        )
    )

    if code == 0:

        for ligne in sortie.splitlines():

            morceaux = ligne.split()

            if morceaux:

                resultat[
                    "en_echec"
                ].append(
                    morceaux[0]
                )

    resultat[
        "nombre_actifs"
    ] = len(
        resultat["actifs"]
    )

    resultat[
        "nombre_inactifs"
    ] = len(
        resultat["inactifs"]
    )

    resultat[
        "nombre_echec"
    ] = len(
        resultat["en_echec"]
    )

    return resultat


# ============================================================
# UTILISATEURS
# ============================================================

def collecter_utilisateurs():

    utilisateurs = []

    try:

        import pwd

        for compte in pwd.getpwall():

            uid = compte.pw_uid
            nom = compte.pw_name
            shell = compte.pw_shell

            if uid == 0:

                categorie = "ROOT"

            elif uid == 65534:

                categorie = "SYSTEME"

            elif uid < 1000:

                categorie = "SYSTEME"

            else:

                categorie = "STANDARD"

            utilisateurs.append({

                "nom":
                    nom,

                "uid":
                    uid,

                "categorie":
                    categorie,

                "shell":
                    shell

            })

    except Exception:
        pass

    return utilisateurs


# ============================================================
# GROUPES SENSIBLES
# ============================================================

def collecter_groupes_sensibles():

    groupes_a_verifier = [

        "root",
        "adm",
        "sudo",
        "wheel",
        "docker",
        "lxd"

    ]

    resultat = {}

    try:

        import grp

        for nom_groupe in (
            groupes_a_verifier
        ):

            try:

                groupe = grp.getgrnam(
                    nom_groupe
                )

                resultat[
                    nom_groupe
                ] = list(
                    groupe.gr_mem
                )

            except KeyError:

                # Groupe inexistant
                continue

    except Exception:
        pass

    return resultat


# ============================================================
# FIREWALL - UFW
# ============================================================

def analyser_ufw():

    if not verifier_commande_disponible(
        "ufw"
    ):

        return {

            "installe":
                False,

            "etat":
                "NON INSTALLE",

            "details":
                ""

        }

    code, sortie, erreur = (
        executer_commande(
            ["ufw", "status"]
        )
    )

    texte = (
        sortie
        + "\n"
        + erreur
    )

    if code == 0:

        if "Status: active" in texte:

            return {

                "installe":
                    True,

                "etat":
                    "ACTIF",

                "details":
                    sortie

            }

        if "Status: inactive" in texte:

            return {

                "installe":
                    True,

                "etat":
                    "INACTIF",

                "details":
                    sortie

            }

    return {

        "installe":
            True,

        "etat":
            "PERMISSIONS INSUFFISANTES / INCONNU",

        "details":
            texte.strip()

    }


# ============================================================
# FIREWALL - NFTABLES
# ============================================================

def analyser_nftables():

    if not verifier_commande_disponible(
        "nft"
    ):

        return {

            "installe":
                False,

            "etat":
                "NON INSTALLE",

            "regles":
                None,

            "details":
                ""

        }

    code, sortie, erreur = (
        executer_commande(
            [
                "nft",
                "list",
                "ruleset"
            ]
        )
    )

    # --------------------------------------------------------
    # La commande est accessible
    # --------------------------------------------------------

    if code == 0:

        if sortie.strip():

            return {

                "installe":
                    True,

                "etat":
                    "REGLES DETECTEES",

                "regles":
                    sortie,

                "details":
                    ""

            }

        return {

            "installe":
                True,

            "etat":
                "AUCUNE REGLE",

            "regles":
                "",

            "details":
                ""

        }

    # --------------------------------------------------------
    # Accès refusé
    # --------------------------------------------------------

    return {

        "installe":
            True,

        "etat":
            "PERMISSIONS INSUFFISANTES",

        "regles":
            None,

        "details":
            erreur

    }


# ============================================================
# FIREWALL - IPTABLES
# ============================================================

def analyser_iptables():

    if not verifier_commande_disponible(
        "iptables"
    ):

        return {

            "installe":
                False,

            "etat":
                "NON INSTALLE",

            "regles":
                None,

            "details":
                ""

        }

    code, sortie, erreur = (
        executer_commande(
            [
                "iptables",
                "-L",
                "-n"
            ]
        )
    )

    if code != 0:

        return {

            "installe":
                True,

            "etat":
                "PERMISSIONS INSUFFISANTES",

            "regles":
                None,

            "details":
                erreur

        }

    # --------------------------------------------------------
    # Extraction des règles réelles
    # --------------------------------------------------------

    lignes = sortie.splitlines()

    regles_reelles = []

    for ligne in lignes:

        ligne = ligne.strip()

        if not ligne:
            continue

        if ligne.startswith(
            "Chain"
        ):
            continue

        if ligne.startswith(
            "target"
        ):
            continue

        regles_reelles.append(
            ligne
        )

    if not regles_reelles:

        return {

            "installe":
                True,

            "etat":
                "AUCUNE REGLE",

            "regles":
                sortie,

            "details":
                ""

        }

    return {

        "installe":
            True,

        "etat":
            "REGLES DETECTEES",

        "regles":
            sortie,

        "details":
            ""

    }


# ============================================================
# SERVICE NFTABLES
# ============================================================

def analyser_service_nftables():

    if not verifier_commande_disponible(
        "systemctl"
    ):

        return "INCONNU"

    code, sortie, _ = (
        executer_commande(
            [
                "systemctl",
                "is-active",
                "nftables"
            ]
        )
    )

    if code == 0:

        return (
            sortie.strip().upper()
        )

    return "INACTIF"


# ============================================================
# COLLECTE COMPLETE DU FIREWALL
# ============================================================

def collecter_firewall():

    execution_root = (
        os.geteuid() == 0
    )

    ufw = analyser_ufw()
    nftables = analyser_nftables()
    iptables = analyser_iptables()

    resultat = {

        "execution_root":
            execution_root,

        "ufw":
            ufw,

        "nftables":
            nftables,

        "service_nftables":
            analyser_service_nftables(),

        "iptables":
            iptables,

        "etat_global":
            "INCONNU"

    }

    # --------------------------------------------------------
    # UFW actif
    # --------------------------------------------------------

    if ufw["etat"] == "ACTIF":

        resultat[
            "etat_global"
        ] = "ACTIF"

        return resultat

    # --------------------------------------------------------
    # nftables avec règles
    # --------------------------------------------------------

    if nftables["etat"] == (
        "REGLES DETECTEES"
    ):

        resultat[
            "etat_global"
        ] = "ACTIF"

        return resultat

    # --------------------------------------------------------
    # iptables avec règles
    # --------------------------------------------------------

    if iptables["etat"] == (
        "REGLES DETECTEES"
    ):

        resultat[
            "etat_global"
        ] = "ACTIF"

        return resultat

    # --------------------------------------------------------
    # Pas root + accès impossible
    # --------------------------------------------------------

    if (
        not execution_root
        and (
            nftables["etat"]
            == "PERMISSIONS INSUFFISANTES"
            or
            iptables["etat"]
            == "PERMISSIONS INSUFFISANTES"
        )
    ):

        resultat[
            "etat_global"
        ] = "PERMISSIONS INSUFFISANTES"

        return resultat

    # --------------------------------------------------------
    # Aucun filtrage
    # --------------------------------------------------------

    nft_aucune = (
        nftables["etat"]
        in (
            "AUCUNE REGLE",
            "NON INSTALLE"
        )
    )

    iptables_aucune = (
        iptables["etat"]
        in (
            "AUCUNE REGLE",
            "NON INSTALLE"
        )
    )

    ufw_inactif = (
        ufw["etat"]
        in (
            "NON INSTALLE",
            "INACTIF"
        )
    )

    if (
        nft_aucune
        and iptables_aucune
        and ufw_inactif
    ):

        resultat[
            "etat_global"
        ] = "AUCUN FILTRAGE DETECTE"

        return resultat

    # --------------------------------------------------------
    # Cas restant
    # --------------------------------------------------------

    resultat[
        "etat_global"
    ] = "INACTIF / A VERIFIER"

    return resultat


# ============================================================
# ANALYSE AUTOMATIQUE
# ============================================================

def analyser_resultats(donnees):

    alertes = []
    informations = []
    points_ok = []

    # --------------------------------------------------------
    # CPU
    # --------------------------------------------------------

    cpu = donnees[
        "cpu"
    ][
        "utilisation_globale"
    ]

    if cpu >= 90:

        alertes.append(
            "Utilisation CPU très élevée."
        )

    else:

        points_ok.append(
            "Utilisation CPU normale."
        )

    # --------------------------------------------------------
    # RAM
    # --------------------------------------------------------

    ram = donnees[
        "memoire"
    ][
        "ram"
    ][
        "pourcentage"
    ]

    if ram >= 90:

        alertes.append(
            "Utilisation RAM très élevée."
        )

    else:

        points_ok.append(
            "Utilisation RAM normale."
        )

    # --------------------------------------------------------
    # SWAP
    # --------------------------------------------------------

    swap = donnees[
        "memoire"
    ][
        "swap"
    ][
        "pourcentage"
    ]

    if swap >= 80:

        informations.append(
            "Utilisation importante de la swap."
        )

    else:

        points_ok.append(
            "Utilisation de la swap normale."
        )

    # --------------------------------------------------------
    # TEMPERATURES
    # --------------------------------------------------------

    temperatures_problematiques = []

    for temperature in (
        donnees["temperatures"]
    ):

        valeur = temperature.get(
            "temperature"
        )

        critique = temperature.get(
            "critique"
        )

        if valeur is None:
            continue

        if (
            critique
            and valeur >= critique
        ):

            temperatures_problematiques.append(
                temperature
            )

        elif valeur >= 90:

            temperatures_problematiques.append(
                temperature
            )

    if temperatures_problematiques:

        alertes.append(
            "Une ou plusieurs températures "
            "sont très élevées."
        )

    else:

        points_ok.append(
            "Températures normales."
        )

    # --------------------------------------------------------
    # SERVICES
    # --------------------------------------------------------

    nombre_echec = donnees[
        "services"
    ][
        "nombre_echec"
    ]

    if nombre_echec:

        informations.append(
            f"{nombre_echec} service(s) "
            "systemd en échec."
        )

    else:

        points_ok.append(
            "Aucun service systemd en échec."
        )

    # --------------------------------------------------------
    # PORTS
    # --------------------------------------------------------

    nombre_ports = len(
        donnees["ports"]
    )

    if nombre_ports:

        informations.append(
            f"{nombre_ports} port(s) "
            "en écoute détecté(s)."
        )

    else:

        informations.append(
            "Aucun port en écoute détecté."
        )

    # --------------------------------------------------------
    # FIREWALL
    # --------------------------------------------------------

    etat_firewall = (
        donnees[
            "firewall"
        ][
            "etat_global"
        ]
    )

    if etat_firewall == "ACTIF":

        points_ok.append(
            "Un mécanisme de filtrage "
            "réseau est actif."
        )

    elif etat_firewall == (
        "AUCUN FILTRAGE DETECTE"
    ):

        informations.append(
            "Aucun filtrage réseau "
            "n'a été détecté."
        )

    elif etat_firewall == (
        "PERMISSIONS INSUFFISANTES"
    ):

        informations.append(
            "La vérification complète du "
            "firewall nécessite les privilèges "
            "administrateur."
        )

    else:

        informations.append(
            "Etat du firewall à vérifier."
        )

    return {

        "ok":
            points_ok,

        "alertes":
            alertes,

        "informations":
            informations

    }


# ============================================================
# RAPPORT TXT
# ============================================================

def generer_rapport_txt(
    donnees,
    chemin
):

    with open(
        chemin,
        "w",
        encoding="utf-8"
    ) as fichier:

        fichier.write(
            "=" * 70 + "\n"
        )

        fichier.write(
            "                   LINUX TOOLBOX\n"
        )

        fichier.write(
            "                 RAPPORT DIAGNOSTIC\n"
        )

        fichier.write(
            "=" * 70 + "\n\n"
        )

        fichier.write(
            f"Date : {donnees['date']}\n\n"
        )

        # ----------------------------------------------------
        # SYSTEME
        # ----------------------------------------------------

        fichier.write(
            "==================== SYSTEME ====================\n"
        )

        for cle, valeur in (
            donnees["systeme"].items()
        ):

            fichier.write(
                f"{cle} : {valeur}\n"
            )

        # ----------------------------------------------------
        # CPU
        # ----------------------------------------------------

        fichier.write(
            "\n==================== CPU ====================\n"
        )

        cpu = donnees["cpu"]

        fichier.write(
            f"Cœurs physiques : "
            f"{cpu['coeurs_physiques']}\n"
        )

        fichier.write(
            f"Cœurs logiques : "
            f"{cpu['coeurs_logiques']}\n"
        )

        fichier.write(
            f"Utilisation : "
            f"{cpu['utilisation_globale']:.1f}%\n"
        )

        fichier.write(
            f"Fréquence actuelle : "
            f"{valeur_inconnue(cpu['frequence_actuelle_mhz'])} MHz\n"
        )

        fichier.write(
            f"Fréquence minimale : "
            f"{valeur_inconnue(cpu['frequence_min_mhz'])} MHz\n"
        )

        fichier.write(
            f"Fréquence maximale : "
            f"{valeur_inconnue(cpu['frequence_max_mhz'])} MHz\n"
        )

        for coeur in cpu[
            "par_coeur"
        ]:

            fichier.write(
                f"CPU {coeur['coeur']} : "
                f"{coeur['utilisation']:.1f}%\n"
            )

        # ----------------------------------------------------
        # MEMOIRE
        # ----------------------------------------------------

        fichier.write(
            "\n==================== MEMOIRE ====================\n"
        )

        ram = donnees[
            "memoire"
        ][
            "ram"
        ]

        swap = donnees[
            "memoire"
        ][
            "swap"
        ]

        fichier.write(
            f"RAM totale : "
            f"{ram['total_go']:.2f} Go\n"
        )

        fichier.write(
            f"RAM utilisée : "
            f"{ram['utilisee_go']:.2f} Go\n"
        )

        fichier.write(
            f"RAM disponible : "
            f"{ram['disponible_go']:.2f} Go\n"
        )

        fichier.write(
            f"RAM libre : "
            f"{ram['libre_go']:.2f} Go\n"
        )

        fichier.write(
            f"RAM utilisée : "
            f"{ram['pourcentage']:.1f}%\n"
        )

        fichier.write(
            f"Swap totale : "
            f"{swap['total_go']:.2f} Go\n"
        )

        fichier.write(
            f"Swap utilisée : "
            f"{swap['utilisee_go']:.2f} Go\n"
        )

        fichier.write(
            f"Swap libre : "
            f"{swap['libre_go']:.2f} Go\n"
        )

        fichier.write(
            f"Swap utilisée : "
            f"{swap['pourcentage']:.1f}%\n"
        )

        # ----------------------------------------------------
        # DISQUES
        # ----------------------------------------------------

        fichier.write(
            "\n==================== DISQUES ====================\n"
        )

        for disque in donnees[
            "disques"
        ]:

            fichier.write(
                f"{disque['nom']}\n"
            )

            fichier.write(
                f"  Taille : "
                f"{disque['taille_go']:.2f} Go\n"
            )

            fichier.write(
                f"  Type : "
                f"{disque['type']}\n"
            )

            fichier.write(
                f"  Modèle : "
                f"{disque['modele']}\n"
            )

            fichier.write(
                f"  Transport : "
                f"{disque['transport']}\n"
            )

        # ----------------------------------------------------
        # PARTITIONS
        # ----------------------------------------------------

        fichier.write(
            "\n==================== PARTITIONS ====================\n"
        )

        for partition in (
            donnees["partitions"]
        ):

            fichier.write(
                f"{partition['device']} "
                f"-> {partition['point_montage']}\n"
            )

            fichier.write(
                f"  {partition['systeme_fichiers']} | "
                f"Total : "
                f"{partition['total_go']:.2f} Go | "
                f"Utilisé : "
                f"{partition['utilise_go']:.2f} Go | "
                f"Libre : "
                f"{partition['libre_go']:.2f} Go | "
                f"{partition['pourcentage']:.1f}%\n"
            )

        # ----------------------------------------------------
        # RESEAU
        # ----------------------------------------------------

        fichier.write(
            "\n==================== RESEAU ====================\n"
        )

        for interface in (
            donnees["reseau"]
        ):

            vitesse = interface.get(
                "vitesse_wifi"
            )

            if not vitesse:

                vitesse_mbps = (
                    interface.get(
                        "vitesse_mbps"
                    )
                )

                if vitesse_mbps is not None:

                    vitesse = (
                        f"{vitesse_mbps} Mbit/s"
                    )

                else:

                    vitesse = "Inconnue"

            fichier.write(
                f"{interface['nom']} | "
                f"{interface['etat']} | "
                f"Vitesse : {vitesse} | "
                f"MTU : "
                f"{valeur_inconnue(interface['mtu'])}\n"
            )

            for adresse in (
                interface["adresses"]
            ):

                fichier.write(
                    f"  {adresse['type']} : "
                    f"{adresse['adresse']} | "
                    f"Masque : "
                    f"{adresse['masque']}\n"
                )

            trafic = interface[
                "trafic"
            ]

            fichier.write(
                f"  Envoyé : "
                f"{trafic.get('envoye_ko', 0):.2f} Ko | "
                f"Reçu : "
                f"{trafic.get('recu_ko', 0):.2f} Ko\n"
            )

            fichier.write(
                f"  TX : "
                f"{trafic.get('paquets_tx', 0)} | "
                f"RX : "
                f"{trafic.get('paquets_rx', 0)}\n"
            )

            fichier.write(
                f"  Erreurs TX/RX : "
                f"{trafic.get('erreurs_tx', 0)}/"
                f"{trafic.get('erreurs_rx', 0)} | "
                f"Drops TX/RX : "
                f"{trafic.get('drops_tx', 0)}/"
                f"{trafic.get('drops_rx', 0)}\n"
            )

        # ----------------------------------------------------
        # PASSERELLE / DNS
        # ----------------------------------------------------

        fichier.write(
            "\n==================== RESEAU SYSTEME ====================\n"
        )

        fichier.write(
            f"Passerelle : "
            f"{donnees['passerelle']['passerelle']}\n"
        )

        fichier.write(
            f"Interface : "
            f"{donnees['passerelle']['interface']}\n"
        )

        fichier.write(
            "DNS : "
            + (
                ", ".join(
                    donnees["dns"]
                )
                if donnees["dns"]
                else "Inconnu"
            )
            + "\n"
        )

        # ----------------------------------------------------
        # UPTIME
        # ----------------------------------------------------

        fichier.write(
            "\n==================== UPTIME ====================\n"
        )

        fichier.write(
            f"Démarrage : "
            f"{donnees['uptime']['demarrage']}\n"
        )

        fichier.write(
            f"Durée : "
            f"{donnees['uptime']['duree']}\n"
        )

        # ----------------------------------------------------
        # TEMPERATURES
        # ----------------------------------------------------

        fichier.write(
            "\n==================== TEMPERATURES ====================\n"
        )

        if donnees[
            "temperatures"
        ]:

            for temperature in (
                donnees["temperatures"]
            ):

                fichier.write(
                    f"{temperature['capteur']} "
                    f"{temperature['nom']} : "
                    f"{temperature['temperature']:.1f}°C\n"
                )

        else:

            fichier.write(
                "Aucune température disponible.\n"
            )

        # ----------------------------------------------------
        # TOP CPU
        # ----------------------------------------------------

        fichier.write(
            "\n==================== TOP CPU ====================\n"
        )

        for processus in (
            donnees["processus_cpu"]
        ):

            fichier.write(
                f"{processus['nom']} | "
                f"{processus['cpu']:.1f}% | "
                f"PID {processus['pid']}\n"
            )

        # ----------------------------------------------------
        # TOP RAM
        # ----------------------------------------------------

        fichier.write(
            "\n==================== TOP RAM ====================\n"
        )

        for processus in (
            donnees["processus_ram"]
        ):

            fichier.write(
                f"{processus['nom']} | "
                f"{processus['ram']:.1f}% | "
                f"PID {processus['pid']}\n"
            )

        # ----------------------------------------------------
        # PORTS
        # ----------------------------------------------------

        fichier.write(
            "\n==================== PORTS ====================\n"
        )

        if donnees["ports"]:

            for port in (
                donnees["ports"]
            ):

                fichier.write(
                    f"{port['protocole']} "
                    f"{port['adresse']}:"
                    f"{port['port']} | "
                    f"PID={port['pid']} | "
                    f"Processus={port['processus']} | "
                    f"Service={port['service_connu']}\n"
                )

        else:

            fichier.write(
                "Aucun port en écoute détecté.\n"
            )

        # ----------------------------------------------------
        # SERVICES
        # ----------------------------------------------------

        fichier.write(
            "\n==================== SERVICES ====================\n"
        )

        services = donnees[
            "services"
        ]

        fichier.write(
            f"Actifs : "
            f"{services['nombre_actifs']}\n"
        )

        fichier.write(
            f"Inactifs : "
            f"{services['nombre_inactifs']}\n"
        )

        fichier.write(
            f"En échec : "
            f"{services['nombre_echec']}\n"
        )

        # ----------------------------------------------------
        # UTILISATEURS
        # ----------------------------------------------------

        fichier.write(
            "\n==================== UTILISATEURS ====================\n"
        )

        for utilisateur in (
            donnees["utilisateurs"]
        ):

            fichier.write(
                f"{utilisateur['nom']} | "
                f"UID={utilisateur['uid']} | "
                f"{utilisateur['categorie']} | "
                f"shell={utilisateur['shell']}\n"
            )

        # ----------------------------------------------------
        # GROUPES SENSIBLES
        # ----------------------------------------------------

        fichier.write(
            "\n==================== GROUPES SENSIBLES ====================\n"
        )

        for groupe, membres in (
            donnees[
                "groupes_sensibles"
            ].items()
        ):

            if membres:

                fichier.write(
                    f"{groupe} : "
                    + ", ".join(membres)
                    + "\n"
                )

            else:

                fichier.write(
                    f"{groupe} : aucun\n"
                )

        # ----------------------------------------------------
        # FIREWALL
        # ----------------------------------------------------

        fichier.write(
            "\n==================== FIREWALL ====================\n"
        )

        firewall = donnees[
            "firewall"
        ]

        fichier.write(
            f"Etat global : "
            f"{firewall['etat_global']}\n"
        )

        fichier.write(
            f"Exécution root : "
            f"{firewall['execution_root']}\n"
        )

        fichier.write(
            f"UFW : "
            f"{firewall['ufw']['etat']}\n"
        )

        fichier.write(
            f"nftables : "
            f"{firewall['nftables']['etat']}\n"
        )

        fichier.write(
            f"Service nftables : "
            f"{firewall['service_nftables']}\n"
        )

        fichier.write(
            f"iptables : "
            f"{firewall['iptables']['etat']}\n"
        )

        # ----------------------------------------------------
        # RESUME
        # ----------------------------------------------------

        fichier.write(
            "\n==================== RESUME ====================\n"
        )

        analyse = donnees[
            "analyse"
        ]

        for element in analyse[
            "ok"
        ]:

            fichier.write(
                f"[OK] {element}\n"
            )

        for element in analyse[
            "alertes"
        ]:

            fichier.write(
                f"[ALERTE] {element}\n"
            )

        for element in analyse[
            "informations"
        ]:

            fichier.write(
                f"[INFO] {element}\n"
            )


# ============================================================
# RAPPORT JSON
# ============================================================

def generer_rapport_json(
    donnees,
    chemin
):

    with open(
        chemin,
        "w",
        encoding="utf-8"
    ) as fichier:

        json.dump(
            donnees,
            fichier,
            indent=4,
            ensure_ascii=False
        )


# ============================================================
# LOG
# ============================================================

def enregistrer_log(message):

    chemin = LOGS_DIR / "diagnostic.log"

    date = datetime.now().strftime(
        "%Y-%m-%d %H:%M:%S"
    )

    try:

        with open(
            chemin,
            "a",
            encoding="utf-8"
        ) as fichier:

            fichier.write(
                f"[{date}] {message}\n"
            )

    except Exception:
        pass


# ============================================================
# AFFICHAGE
# ============================================================

def afficher_section(titre):

    print()
    print("=" * 70)
    print(titre)
    print("=" * 70)


def afficher_diagnostic(donnees):

    # ========================================================
    # SYSTEME
    # ========================================================

    afficher_section(
        "SYSTEME"
    )

    systeme = donnees[
        "systeme"
    ]

    print(
        f"Nom de la machine              : "
        f"{systeme['nom_machine']}"
    )

    print(
        f"Système                        : "
        f"{systeme['os']}"
    )

    print(
        f"Version OS                     : "
        f"{systeme['version_os']}"
    )

    print(
        f"Identifiant OS                 : "
        f"{systeme['identifiant_os']}"
    )

    print(
        f"Kernel                         : "
        f"{systeme['kernel']}"
    )

    print(
        f"Version Kernel                 : "
        f"{systeme['version_kernel']}"
    )

    print(
        f"Architecture                   : "
        f"{systeme['architecture']}"
    )

    print(
        f"Processeur                     : "
        f"{systeme['processeur']}"
    )

    print(
        f"Python                         : "
        f"{systeme['python']}"
    )

    # ========================================================
    # CPU
    # ========================================================

    afficher_section(
        "CPU"
    )

    cpu = donnees[
        "cpu"
    ]

    print(
        f"Cœurs physiques                : "
        f"{cpu['coeurs_physiques']}"
    )

    print(
        f"Cœurs logiques                 : "
        f"{cpu['coeurs_logiques']}"
    )

    print(
        f"Utilisation CPU                : "
        f"{cpu['utilisation_globale']:.1f} %"
    )

    print(
        f"Fréquence actuelle             : "
        f"{valeur_inconnue(cpu['frequence_actuelle_mhz'])} MHz"
    )

    print(
        f"Fréquence minimale             : "
        f"{valeur_inconnue(cpu['frequence_min_mhz'])} MHz"
    )

    print(
        f"Fréquence maximale             : "
        f"{valeur_inconnue(cpu['frequence_max_mhz'])} MHz"
    )

    for coeur in cpu[
        "par_coeur"
    ]:

        print(
            f"CPU {coeur['coeur']}                          : "
            f"{coeur['utilisation']:.1f} %"
        )

    # ========================================================
    # MEMOIRE
    # ========================================================

    afficher_section(
        "MEMOIRE"
    )

    ram = donnees[
        "memoire"
    ][
        "ram"
    ]

    swap = donnees[
        "memoire"
    ][
        "swap"
    ]

    print(
        f"RAM totale                     : "
        f"{ram['total_go']:.2f} Go"
    )

    print(
        f"RAM utilisée                   : "
        f"{ram['utilisee_go']:.2f} Go"
    )

    print(
        f"RAM disponible                 : "
        f"{ram['disponible_go']:.2f} Go"
    )

    print(
        f"RAM libre                      : "
        f"{ram['libre_go']:.2f} Go"
    )

    print(
        f"RAM utilisée                   : "
        f"{ram['pourcentage']:.1f} %"
    )

    print(
        f"Swap totale                    : "
        f"{swap['total_go']:.2f} Go"
    )

    print(
        f"Swap utilisée                  : "
        f"{swap['utilisee_go']:.2f} Go"
    )

    print(
        f"Swap libre                     : "
        f"{swap['libre_go']:.2f} Go"
    )

    print(
        f"Swap utilisée                  : "
        f"{swap['pourcentage']:.1f} %"
    )

    # ========================================================
    # DISQUES
    # ========================================================

    afficher_section(
        "DISQUES PHYSIQUES"
    )

    for disque in donnees[
        "disques"
    ]:

        print(
            disque["nom"]
        )

        print(
            f"  Taille       : "
            f"{disque['taille_go']:.2f} Go"
        )

        print(
            f"  Type         : "
            f"{disque['type']}"
        )

        print(
            f"  Modèle       : "
            f"{disque['modele']}"
        )

        print(
            f"  Transport    : "
            f"{disque['transport']}"
        )

    # ========================================================
    # PARTITIONS
    # ========================================================

    afficher_section(
        "PARTITIONS MONTEES"
    )

    for partition in donnees[
        "partitions"
    ]:

        print(
            f"{partition['device']} "
            f"monté sur "
            f"{partition['point_montage']}"
        )

        print(
            f"  {partition['systeme_fichiers']} | "
            f"Total : "
            f"{partition['total_go']:.2f} Go | "
            f"Utilisé : "
            f"{partition['utilise_go']:.2f} Go | "
            f"Libre : "
            f"{partition['libre_go']:.2f} Go | "
            f"{partition['pourcentage']:.1f} %"
        )

    # ========================================================
    # RESEAU
    # ========================================================

    afficher_section(
        "RESEAU"
    )

    for interface in donnees[
        "reseau"
    ]:

        vitesse = interface.get(
            "vitesse_wifi"
        )

        if not vitesse:

            vitesse_mbps = interface.get(
                "vitesse_mbps"
            )

            if vitesse_mbps is not None:

                vitesse = (
                    f"{vitesse_mbps} Mbit/s"
                )

            else:

                vitesse = "Inconnue"

        print(
            f"{interface['nom']} | "
            f"{interface['etat']} | "
            f"vitesse : {vitesse} | "
            f"MTU : "
            f"{valeur_inconnue(interface['mtu'])}"
        )

        for adresse in interface[
            "adresses"
        ]:

            print(
                f"  {adresse['type']} : "
                f"{adresse['adresse']} | "
                f"Masque : "
                f"{adresse['masque']}"
            )

        trafic = interface[
            "trafic"
        ]

        print(
            f"  Envoyé "
            f"{trafic.get('envoye_ko', 0):.2f} Ko | "
            f"Reçu "
            f"{trafic.get('recu_ko', 0):.2f} Ko"
        )

        print(
            f"  TX "
            f"{trafic.get('paquets_tx', 0)} | "
            f"RX "
            f"{trafic.get('paquets_rx', 0)}"
        )

        print(
            f"  Erreurs "
            f"{trafic.get('erreurs_tx', 0)}/"
            f"{trafic.get('erreurs_rx', 0)} | "
            f"Drops "
            f"{trafic.get('drops_tx', 0)}/"
            f"{trafic.get('drops_rx', 0)}"
        )

    # ========================================================
    # PASSERELLE / DNS
    # ========================================================

    afficher_section(
        "RESEAU SYSTEME"
    )

    print(
        f"Passerelle                     : "
        f"{donnees['passerelle']['passerelle']} "
        f"via "
        f"{donnees['passerelle']['interface']}"
    )

    print(
        f"DNS                            : "
        f"{', '.join(donnees['dns']) if donnees['dns'] else 'Inconnu'}"
    )

    # ========================================================
    # UPTIME
    # ========================================================

    afficher_section(
        "UPTIME"
    )

    print(
        f"Démarrage                      : "
        f"{donnees['uptime']['demarrage']}"
    )

    print(
        f"Durée                          : "
        f"{donnees['uptime']['duree']}"
    )

    # ========================================================
    # TEMPERATURES
    # ========================================================

    afficher_section(
        "TEMPERATURES"
    )

    if donnees[
        "temperatures"
    ]:

        for temperature in (
            donnees["temperatures"]
        ):

            print(
                f"{temperature['capteur']} "
                f"{temperature['nom']} : "
                f"{temperature['temperature']:.1f}°C"
            )

    else:

        print(
            "Aucune température disponible."
        )

    # ========================================================
    # PROCESSUS CPU
    # ========================================================

    afficher_section(
        "TOP PROCESSUS CPU"
    )

    for processus in (
        donnees["processus_cpu"]
    ):

        print(
            f"{processus['nom']} "
            f"{processus['cpu']:.1f}% "
            f"PID {processus['pid']}"
        )

    # ========================================================
    # PROCESSUS RAM
    # ========================================================

    afficher_section(
        "TOP PROCESSUS RAM"
    )

    for processus in (
        donnees["processus_ram"]
    ):

        print(
            f"{processus['nom']} "
            f"{processus['ram']:.1f}% "
            f"PID {processus['pid']}"
        )

    # ========================================================
    # PORTS
    # ========================================================

    afficher_section(
        "PORTS EN ECOUTE"
    )

    if donnees[
        "ports"
    ]:

        for port in donnees[
            "ports"
        ]:

            print(
                f"{port['protocole']} "
                f"{port['adresse']}:"
                f"{port['port']} "
                f"PID={port['pid']} "
                f"Processus={port['processus']} "
                f"Service={port['service_connu']}"
            )

    else:

        print(
            "Aucun port en écoute détecté."
        )

    # ========================================================
    # SERVICES
    # ========================================================

    afficher_section(
        "SERVICES SYSTEMD"
    )

    services = donnees[
        "services"
    ]

    print(
        f"Services actifs                : "
        f"{services['nombre_actifs']}"
    )

    print(
        f"Services inactifs              : "
        f"{services['nombre_inactifs']}"
    )

    print(
        f"Services en échec              : "
        f"{services['nombre_echec']}"
    )

    # ========================================================
    # UTILISATEURS
    # ========================================================

    afficher_section(
        "UTILISATEURS"
    )

    for utilisateur in (
        donnees["utilisateurs"]
    ):

        print(
            f"{utilisateur['nom']} "
            f"UID={utilisateur['uid']} "
            f"{utilisateur['categorie']} "
            f"shell={utilisateur['shell']}"
        )

    # ========================================================
    # GROUPES
    # ========================================================

    afficher_section(
        "GROUPES SENSIBLES"
    )

    for groupe, membres in (
        donnees[
            "groupes_sensibles"
        ].items()
    ):

        if membres:

            print(
                f"{groupe} : "
                + ", ".join(membres)
            )

        else:

            print(
                f"{groupe} : aucun"
            )

    # ========================================================
    # FIREWALL
    # ========================================================

    afficher_section(
        "FIREWALL"
    )

    firewall = donnees[
        "firewall"
    ]

    print(
        f"Etat global                  : "
        f"{firewall['etat_global']}"
    )

    print(
        f"Exécution root               : "
        f"{firewall['execution_root']}"
    )

    print(
        f"UFW                          : "
        f"{firewall['ufw']['etat']}"
    )

    print(
        f"nftables                     : "
        f"{firewall['nftables']['etat']}"
    )

    print(
        f"Service nftables             : "
        f"{firewall['service_nftables']}"
    )

    print(
        f"iptables                     : "
        f"{firewall['iptables']['etat']}"
    )

    # ========================================================
    # RESUME
    # ========================================================

    afficher_section(
        "RESUME AUTOMATIQUE"
    )

    analyse = donnees[
        "analyse"
    ]

    for element in analyse[
        "ok"
    ]:

        print(
            f"[OK] {element}"
        )

    for element in analyse[
        "alertes"
    ]:

        print(
            f"[ALERTE] {element}"
        )

    for element in analyse[
        "informations"
    ]:

        print(
            f"[INFO] {element}"
        )


# ============================================================
# LANCEMENT DU DIAGNOSTIC
# ============================================================

def lancer_diagnostic():

    debut = time.time()

    afficher_section(
        "DIAGNOSTIC COMPLET DE LA MACHINE"
    )

    print(
        "Collecte des informations..."
    )

    try:

        donnees = {

            "date":
                datetime.now().strftime(
                    "%d/%m/%Y %H:%M:%S"
                ),

            "systeme":
                collecter_systeme(),

            "cpu":
                collecter_cpu(),

            "memoire":
                collecter_memoire(),

            "disques":
                collecter_disques(),

            "partitions":
                collecter_partitions(),

            "reseau":
                collecter_reseau(),

            "passerelle":
                collecter_passerelle(),

            "dns":
                collecter_dns(),

            "uptime":
                collecter_uptime(),

            "temperatures":
                collecter_temperatures(),

            "processus_cpu":
                collecter_processus_cpu(),

            "processus_ram":
                collecter_processus_ram(),

            "ports":
                collecter_ports(),

            "services":
                collecter_services(),

            "utilisateurs":
                collecter_utilisateurs(),

            "groupes_sensibles":
                collecter_groupes_sensibles(),

            "firewall":
                collecter_firewall()

        }

        # ----------------------------------------------------
        # Analyse automatique
        # ----------------------------------------------------

        donnees[
            "analyse"
        ] = analyser_resultats(
            donnees
        )

        # ----------------------------------------------------
        # Affichage
        # ----------------------------------------------------

        afficher_diagnostic(
            donnees
        )

        # ----------------------------------------------------
        # Nom des rapports
        # ----------------------------------------------------

        horodatage = (
            datetime.now().strftime(
                "%Y%m%d_%H%M%S"
            )
        )

        chemin_txt = (
            REPORTS_DIR
            / f"diagnostic_{horodatage}.txt"
        )

        chemin_json = (
            REPORTS_DIR
            / f"diagnostic_{horodatage}.json"
        )

        # ----------------------------------------------------
        # Génération des rapports
        # ----------------------------------------------------

        generer_rapport_txt(
            donnees,
            chemin_txt
        )

        generer_rapport_json(
            donnees,
            chemin_json
        )

        # ----------------------------------------------------
        # Temps total
        # ----------------------------------------------------

        duree = (
            time.time()
            - debut
        )

        enregistrer_log(
            "Diagnostic terminé avec succès "
            f"en {duree:.2f} secondes."
        )

        # ----------------------------------------------------
        # Résultat
        # ----------------------------------------------------

        afficher_section(
            "RAPPORTS"
        )

        print(
            f"Rapport TXT : "
            f"{chemin_txt}"
        )

        print(
            f"Rapport JSON : "
            f"{chemin_json}"
        )

        print(
            f"Durée du diagnostic : "
            f"{duree:.2f} secondes"
        )

    except KeyboardInterrupt:

        print()

        print(
            "[INFO] Diagnostic interrompu "
            "par l'utilisateur."
        )

        enregistrer_log(
            "Diagnostic interrompu par "
            "l'utilisateur."
        )

    except Exception as erreur:

        print()

        print(
            "[ERREUR] Le diagnostic a rencontré "
            "une erreur."
        )

        print(
            f"Détails : {erreur}"
        )

        enregistrer_log(
            "Erreur pendant le diagnostic : "
            f"{erreur}"
        )
