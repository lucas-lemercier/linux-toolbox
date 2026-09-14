from __future__ import annotations

import hashlib
import io
import json
import logging
import platform
import readline
import socket
import tarfile
import time

from datetime import datetime
from pathlib import Path


# ============================================================
# CONFIGURATION
# ============================================================

# Racine du projet :
#
# linux-toolbox/
# ├── main.py
# ├── modules/
# │   └── backup.py
# ├── reports/
# ├── logs/
# └── backups/
#
# __file__ = modules/backup.py
# parent   = modules/
# parent.parent = linux-toolbox/
BASE_DIR = Path(__file__).resolve().parent.parent

REPORTS_DIR = BASE_DIR / "reports"
LOGS_DIR = BASE_DIR / "logs"
BACKUP_DEFAULT_DIR = BASE_DIR / "backups"

# Nom du fichier manifeste embarqué dans chaque archive.
# Centralisé ici pour éviter de répéter la chaîne en dur
# à plusieurs endroits du fichier.
MANIFEST_FILENAME = "LINUX_TOOLBOX_MANIFEST.json"


# Création des dossiers nécessaires
REPORTS_DIR.mkdir(
    parents=True,
    exist_ok=True
)

LOGS_DIR.mkdir(
    parents=True,
    exist_ok=True
)

BACKUP_DEFAULT_DIR.mkdir(
    parents=True,
    exist_ok=True
)


LOG_FILE = LOGS_DIR / "backup.log"


# ============================================================
# JOURNALISATION
# ============================================================

logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(message)s",
    encoding="utf-8",
)


# ============================================================
# EXCEPTION PERSONNALISÉE
# ============================================================

class BackupError(Exception):
    """
    Erreur contrôlée du gestionnaire de sauvegardes.

    Cela permet d'afficher une erreur compréhensible
    à l'utilisateur sans faire planter tout Linux Toolbox.
    """

    pass


# ============================================================
# OUTILS GÉNÉRAUX
# ============================================================

def horodatage() -> str:
    """
    Retourne la date actuelle sous la forme :

    YYYYMMDD_HHMMSS

    Exemple :
    20260914_235501
    """

    return datetime.now().strftime(
        "%Y%m%d_%H%M%S"
    )


def format_bytes(value: int | float) -> str:
    """
    Convertit une taille en octets
    vers une unité lisible.

    Exemple :
    1536 -> 1.50 Ko
    """

    value = float(value)

    units = [
        "o",
        "Ko",
        "Mo",
        "Go",
        "To",
    ]

    for unit in units:

        if value < 1024:
            return f"{value:.2f} {unit}"

        value /= 1024

    return f"{value:.2f} Po"


def format_duration(seconds: float) -> str:
    """
    Transforme une durée en secondes
    en format lisible.

    Exemple :
    73.5 -> 1 min 13 s
    """

    seconds = int(round(seconds))

    if seconds < 60:
        return f"{seconds} s"

    minutes, seconds = divmod(
        seconds,
        60
    )

    if minutes < 60:
        return (
            f"{minutes} min "
            f"{seconds} s"
        )

    hours, minutes = divmod(
        minutes,
        60
    )

    return (
        f"{hours} h "
        f"{minutes} min "
        f"{seconds} s"
    )


def normaliser_chemin(
    valeur: str
) -> Path:
    """
    Transforme une saisie utilisateur
    en chemin absolu propre.

    Gère notamment :

    ~/Documents
    ./test
    ../backup
    /home/kaliuser/test
    """

    valeur = valeur.strip()

    # Expansion de "~"
    chemin = Path(
        valeur
    ).expanduser()

    # Conversion en chemin absolu.
    #
    # strict=False permet de résoudre également
    # un chemin qui n'existe pas encore.
    return chemin.resolve(
        strict=False
    )


def est_dans(
    chemin: Path,
    parent: Path
) -> bool:
    """
    Vérifie si 'chemin' se trouve dans 'parent'.

    Exemple :

    parent :
        /home/kali/projet

    chemin :
        /home/kali/projet/backups

    résultat :
        True
    """

    try:

        chemin.relative_to(
            parent
        )

        return True

    except ValueError:

        return False


# ============================================================
# AUTOCOMPLÉTION TAB
# ============================================================

def completer_chemin(
    text: str,
    state: int
):
    """
    Fonction utilisée par GNU Readline
    pour l'autocomplétion avec TAB.

    Exemple :

        ~/Doc + TAB

    peut devenir :

        ~/Documents/

    La fonction est appelée plusieurs fois
    avec state = 0, 1, 2...
    jusqu'à ce qu'elle retourne None.
    """

    try:

        # ----------------------------------------------------
        # Texte actuellement saisi
        # ----------------------------------------------------

        if not text:

            text = ""

        # ----------------------------------------------------
        # Détermination du dossier à parcourir
        # ----------------------------------------------------

        # Si le texte finit par '/',
        # on cherche directement dans ce dossier.
        if text.endswith("/"):

            directory = normaliser_chemin(
                text
            )

            prefix = ""

        else:

            raw_path = Path(
                text
            ).expanduser()

            directory = (
                raw_path.parent
                .resolve(
                    strict=False
                )
            )

            prefix = raw_path.name

        # ----------------------------------------------------
        # Le dossier parent doit exister
        # ----------------------------------------------------

        if not directory.is_dir():

            return None

        # ----------------------------------------------------
        # Recherche des correspondances
        # ----------------------------------------------------

        matches = []

        for item in sorted(
            directory.iterdir(),
            key=lambda p: p.name.lower()
        ):

            if not item.name.startswith(
                prefix
            ):

                continue

            # ------------------------------------------------
            # Reconstruction du chemin affiché
            # ------------------------------------------------

            if text.endswith("/"):

                candidate = (
                    text
                    + item.name
                )

            else:

                # Partie correspondant au dossier parent
                parent_text = str(
                    Path(text).parent
                )

                if parent_text == ".":

                    candidate = item.name

                elif parent_text == "~":

                    candidate = (
                        "~/"
                        + item.name
                    )

                else:

                    candidate = (
                        parent_text
                        + "/"
                        + item.name
                    )

            # ------------------------------------------------
            # Les dossiers reçoivent automatiquement "/"
            # ------------------------------------------------

            if item.is_dir():

                candidate += "/"

            matches.append(
                candidate
            )

        # ----------------------------------------------------
        # Retour de la correspondance demandée
        # ----------------------------------------------------

        if state < len(matches):

            return matches[state]

        return None

    except (
        OSError,
        ValueError,
        IndexError
    ):

        return None


def activer_autocompletion() -> None:
    """
    Active l'autocomplétion des chemins avec TAB.

    Sous Linux/Kali, Python utilise GNU Readline.
    """

    try:

        # Important :
        # on retire les séparateurs habituels
        # afin que Readline considère tout le chemin
        # comme la zone à compléter.
        readline.set_completer_delims(
            "\t\n"
        )

        readline.set_completer(
            completer_chemin
        )

        readline.parse_and_bind(
            "tab: complete"
        )

    except Exception:

        # Si Readline n'est pas disponible
        # correctement, le programme reste utilisable
        # sans autocomplétion.
        logging.warning(
            "Autocomplétion Readline indisponible."
        )


def demander_chemin(
    message: str,
    must_exist: bool = False,
    must_be_directory: bool = False,
    create_if_missing: bool = False
) -> Path:
    """
    Demande un chemin avec autocomplétion TAB.

    Paramètres :

    must_exist=True
        Le chemin doit exister.

    must_be_directory=True
        Le chemin doit être un dossier.

    create_if_missing=True
        Si le chemin n'existe pas,
        il est créé automatiquement.

    Exemple :

        source :
            must_exist=True

        destination :
            create_if_missing=True
            must_be_directory=True
    """

    activer_autocompletion()

    while True:

        try:

            valeur = input(
                message
            ).strip()

        except EOFError:

            raise BackupError(
                "Saisie interrompue."
            )

        if not valeur:

            print(
                "[ERREUR] Aucun chemin "
                "n'a été saisi."
            )

            continue

        chemin = normaliser_chemin(
            valeur
        )

        # ----------------------------------------------------
        # Chemin obligatoire
        # ----------------------------------------------------

        if must_exist:

            if not chemin.exists():

                print(
                    "[ERREUR] Le chemin "
                    "n'existe pas :"
                )

                print(
                    f"         {chemin}"
                )

                print(
                    "[INFO] Utilisez TAB "
                    "pour parcourir les chemins."
                )

                continue

        # ----------------------------------------------------
        # Création automatique
        # ----------------------------------------------------

        if (
            not chemin.exists()
            and create_if_missing
        ):

            try:

                chemin.mkdir(
                    parents=True,
                    exist_ok=True
                )

                print(
                    f"[INFO] Dossier créé : "
                    f"{chemin}"
                )

            except OSError as exc:

                print(
                    "[ERREUR] Impossible de "
                    f"créer le dossier : {exc}"
                )

                continue

        # ----------------------------------------------------
        # Vérification dossier
        # ----------------------------------------------------

        if (
            must_be_directory
            and not chemin.is_dir()
        ):

            print(
                "[ERREUR] Le chemin doit "
                "être un dossier."
            )

            continue

        return chemin


# ============================================================
# STATISTIQUES
# ============================================================

def collecter_statistiques(
    source: Path
) -> tuple[int, int]:
    """
    Compte :

    - le nombre de fichiers
    - leur taille totale

    Les liens symboliques ne sont pas suivis.
    """

    if source.is_file():

        try:

            return (
                1,
                source.stat().st_size
            )

        except OSError as exc:

            raise BackupError(
                "Impossible de lire "
                f"la source : {exc}"
            ) from exc

    fichiers = 0
    taille = 0

    try:

        for element in source.rglob("*"):

            try:

                # On ne suit pas les liens symboliques.
                if element.is_symlink():

                    continue

                if element.is_file():

                    fichiers += 1

                    taille += (
                        element.stat().st_size
                    )

            except OSError:

                logging.warning(
                    "Impossible de lire "
                    f"les métadonnées : {element}"
                )

    except OSError as exc:

        raise BackupError(
            "Impossible de parcourir "
            f"la source : {exc}"
        ) from exc

    return (
        fichiers,
        taille
    )


# ============================================================
# SHA-256
# ============================================================

def sha256_fichier(
    path: Path,
    chunk_size: int = 1024 * 1024
) -> str:
    """
    Calcule le SHA-256 d'un fichier.

    Lecture par blocs de 1 Mo afin d'éviter
    de charger toute l'archive en mémoire.
    """

    digest = hashlib.sha256()

    try:

        with path.open(
            "rb"
        ) as fichier:

            while True:

                bloc = fichier.read(
                    chunk_size
                )

                if not bloc:
                    break

                digest.update(
                    bloc
                )

    except OSError as exc:

        raise BackupError(
            "Impossible de calculer "
            f"le SHA-256 : {exc}"
        ) from exc

    return digest.hexdigest()


def chemin_checksum(
    archive: Path
) -> Path:
    """
    Retourne le fichier SHA-256 associé.

    Exemple :

    backup_test.tar.gz

    devient :

    backup_test.tar.gz.sha256
    """

    return archive.with_name(
        archive.name + ".sha256"
    )


# ============================================================
# RAPPORTS
# ============================================================

def chemin_rapport(
    prefix: str,
    timestamp: str,
    extension: str
) -> Path:

    return REPORTS_DIR / (
        f"{prefix}_{timestamp}.{extension}"
    )


# ============================================================
# LISTE DES SAUVEGARDES
# ============================================================

def sauvegardes_existantes(
    destination: Path | None = None
) -> list[Path]:
    """
    Retourne les archives .tar.gz
    présentes dans le dossier indiqué.
    """

    dossier = (
        destination
        if destination
        else BACKUP_DEFAULT_DIR
    )

    if not dossier.exists():

        return []

    try:

        return sorted(
            [
                path
                for path in dossier.iterdir()
                if (
                    path.is_file()
                    and path.name.endswith(
                        ".tar.gz"
                    )
                )
            ],
            key=lambda path: (
                path.stat().st_mtime
            ),
            reverse=True
        )

    except OSError as exc:

        raise BackupError(
            "Impossible de lire le "
            f"dossier de sauvegarde : {exc}"
        ) from exc


def afficher_sauvegardes(
    destination: Path | None = None
) -> list[Path]:
    """
    Affiche les sauvegardes disponibles.
    """

    dossier = (
        destination
        if destination
        else BACKUP_DEFAULT_DIR
    )

    archives = sauvegardes_existantes(
        dossier
    )

    print()
    print(
        "SAUVEGARDES DISPONIBLES"
    )
    print("-" * 70)

    print(
        f"Dossier : {dossier}"
    )

    print()

    if not archives:

        print(
            "Aucune sauvegarde trouvée."
        )

        return []

    for index, archive in enumerate(
        archives,
        start=1
    ):

        try:

            taille = format_bytes(
                archive.stat().st_size
            )

            date = datetime.fromtimestamp(
                archive.stat().st_mtime
            ).strftime(
                "%d/%m/%Y %H:%M:%S"
            )

        except OSError:

            taille = "inconnue"
            date = "inconnue"

        checksum = (
            chemin_checksum(
                archive
            )
        )

        if checksum.exists():

            etat_hash = (
                "SHA-256 présent"
            )

        else:

            etat_hash = (
                "SHA-256 absent"
            )

        print(
            f"{index}. {archive.name}"
        )

        print(
            f"   Taille       : {taille}"
        )

        print(
            f"   Date         : {date}"
        )

        print(
            f"   Intégrité    : {etat_hash}"
        )

        print()

    return archives


# ============================================================
# MANIFESTE
# ============================================================

def creer_manifest(
    source: Path,
    timestamp: str,
    fichiers: int,
    taille_source: int
) -> dict:
    """
    Crée les informations enregistrées
    dans l'archive.
    """

    return {

        "application": "Linux Toolbox",

        "module": "backup",

        "version": "1.0",

        "operation": "backup",

        "date": datetime.now().isoformat(
            timespec="seconds"
        ),

        "timestamp": timestamp,

        "hostname": socket.gethostname(),

        "systeme": platform.system(),

        "architecture": platform.machine(),

        "source": str(source),

        "nom_source": (
            source.name
            or "root"
        ),

        "nombre_fichiers": fichiers,

        "taille_source_octets":
            taille_source,

        "compression": "gzip",

        "format": "tar.gz",
    }


def ajouter_manifest(
    archive: tarfile.TarFile,
    manifest: dict
) -> None:
    """
    Ajoute le manifeste JSON
    directement dans l'archive TAR.
    """

    data = json.dumps(
        manifest,
        ensure_ascii=False,
        indent=2
    ).encode(
        "utf-8"
    )

    info = tarfile.TarInfo(
        MANIFEST_FILENAME
    )

    info.size = len(
        data
    )

    info.mode = 0o600

    archive.addfile(
        info,
        fileobj=io.BytesIO(
            data
        )
    )


# ============================================================
# CRÉATION D'UNE SAUVEGARDE
# ============================================================

def creer_sauvegarde(
    source: Path,
    destination: Path
) -> dict:
    """
    Crée une sauvegarde compressée.

    Étapes :

    1. vérification de la source
    2. vérification de la destination
    3. protection contre destination dans source
    4. calcul des statistiques
    5. création TAR.GZ
    6. ajout du manifeste
    7. calcul SHA-256
    8. création du fichier checksum
    9. journalisation
    """

    debut = time.perf_counter()

    source = source.resolve(
        strict=True
    )

    destination = destination.resolve(
        strict=False
    )

    # --------------------------------------------------------
    # Source
    # --------------------------------------------------------

    if not source.exists():

        raise BackupError(
            "Le chemin source "
            "n'existe pas."
        )

    if source.is_symlink():

        raise BackupError(
            "La source ne doit pas "
            "être un lien symbolique."
        )

    # --------------------------------------------------------
    # Destination
    # --------------------------------------------------------

    destination.mkdir(
        parents=True,
        exist_ok=True
    )

    if not destination.is_dir():

        raise BackupError(
            "La destination n'est "
            "pas un dossier."
        )

    # --------------------------------------------------------
    # Protection :
    #
    # destination à l'intérieur
    # de la source = interdit.
    # --------------------------------------------------------

    if source.is_dir():

        if est_dans(
            destination,
            source
        ):

            raise BackupError(
                "La destination de sauvegarde "
                "se trouve dans le dossier source. "
                "Choisissez une destination externe."
            )

    # --------------------------------------------------------
    # Nom
    # --------------------------------------------------------

    timestamp = horodatage()

    nom_source = (
        source.name
        or "root"
    )

    archive = (
        destination
        / (
            f"backup_"
            f"{nom_source}_"
            f"{timestamp}.tar.gz"
        )
    )

    if archive.exists():

        raise BackupError(
            "Une sauvegarde portant "
            "le même nom existe déjà."
        )

    checksum_path = (
        chemin_checksum(
            archive
        )
    )

    # --------------------------------------------------------
    # Statistiques
    # --------------------------------------------------------

    fichiers, taille_source = (
        collecter_statistiques(
            source
        )
    )

    manifest = creer_manifest(
        source,
        timestamp,
        fichiers,
        taille_source
    )

    # --------------------------------------------------------
    # Affichage
    # --------------------------------------------------------

    print()
    print(
        "CRÉATION DE LA SAUVEGARDE"
    )
    print("-" * 70)

    print(
        f"Source      : {source}"
    )

    print(
        f"Destination : {archive}"
    )

    print(
        f"Fichiers    : {fichiers}"
    )

    print(
        f"Taille      : "
        f"{format_bytes(taille_source)}"
    )

    print()

    # --------------------------------------------------------
    # Création archive
    # --------------------------------------------------------

    try:

        with tarfile.open(
            archive,
            mode="w:gz",
            dereference=False
        ) as tar:

            tar.add(
                source,
                arcname=nom_source,
                recursive=True
            )

            ajouter_manifest(
                tar,
                manifest
            )

        print(
            "Calcul du SHA-256..."
        )

        checksum = sha256_fichier(
            archive
        )

        checksum_path.write_text(
            (
                f"{checksum}  "
                f"{archive.name}\n"
            ),
            encoding="utf-8"
        )

    except Exception as exc:

        # Une archive incomplète ne doit
        # pas rester comme une sauvegarde valide.

        try:

            archive.unlink(
                missing_ok=True
            )

            checksum_path.unlink(
                missing_ok=True
            )

        except OSError:

            pass

        raise BackupError(
            "Échec de la création : "
            f"{exc}"
        ) from exc

    # --------------------------------------------------------
    # Résultats
    # --------------------------------------------------------

    duree = (
        time.perf_counter()
        - debut
    )

    taille_archive = (
        archive.stat().st_size
    )

    if taille_source > 0:

        taux_compression = (
            1
            - (
                taille_archive
                / taille_source
            )
        ) * 100

    else:

        taux_compression = 0.0

    resultat = {

        "operation": "creation",

        "date": datetime.now().isoformat(
            timespec="seconds"
        ),

        "source": str(source),

        "destination": str(destination),

        "archive": str(archive),

        "checksum": checksum,

        "fichiers": fichiers,

        "taille_source_octets":
            taille_source,

        "taille_archive_octets":
            taille_archive,

        "taux_compression":
            round(
                taux_compression,
                2
            ),

        "duree_secondes":
            round(
                duree,
                2
            ),

        "statut": "SUCCES",
    }

    logging.info(
        "Sauvegarde créée | "
        "source=%s | "
        "archive=%s | "
        "fichiers=%s | "
        "taille_source=%s | "
        "taille_archive=%s | "
        "sha256=%s | "
        "duree=%.2fs",
        source,
        archive,
        fichiers,
        taille_source,
        taille_archive,
        checksum,
        duree,
    )

    return resultat


# ============================================================
# VÉRIFICATION D'INTÉGRITÉ
# ============================================================

def verifier_integrite(
    archive: Path
) -> dict:
    """
    Vérifie :

    1. le fichier SHA-256
    2. le SHA-256 réel
    3. la validité de l'archive TAR
    4. la présence du manifeste
    """

    debut = time.perf_counter()

    archive = archive.resolve(
        strict=False
    )

    if not archive.is_file():

        raise BackupError(
            "L'archive sélectionnée "
            "n'existe pas."
        )

    checksum_path = (
        chemin_checksum(
            archive
        )
    )

    # --------------------------------------------------------
    # SHA-256 absent
    # --------------------------------------------------------

    if not checksum_path.is_file():

        return {

            "operation":
                "verification",

            "date":
                datetime.now().isoformat(
                    timespec="seconds"
                ),

            "archive":
                str(archive),

            "checksum":
                "ABSENT",

            "archive_valide":
                False,

            "statut":
                "INCOMPLET",

            "message":
                "Fichier SHA-256 absent.",
        }

    # --------------------------------------------------------
    # Lecture checksum attendu
    # --------------------------------------------------------

    try:

        ligne = checksum_path.read_text(
            encoding="utf-8"
        ).strip()

    except OSError as exc:

        raise BackupError(
            "Impossible de lire le "
            f"fichier SHA-256 : {exc}"
        ) from exc

    morceaux = ligne.split()

    if not morceaux:

        raise BackupError(
            "Le fichier SHA-256 est vide."
        )

    attendu = morceaux[0]

    if (
        len(attendu) != 64
        or any(
            caractere
            not in "0123456789abcdefABCDEF"
            for caractere in attendu
        )
    ):

        raise BackupError(
            "Le fichier SHA-256 est invalide."
        )

    # --------------------------------------------------------
    # Calcul réel
    # --------------------------------------------------------

    print(
        "Calcul du SHA-256..."
    )

    obtenu = sha256_fichier(
        archive
    )

    hash_ok = (
        obtenu.lower()
        == attendu.lower()
    )

    # --------------------------------------------------------
    # Test TAR + manifeste
    # --------------------------------------------------------

    print(
        "Vérification de l'archive..."
    )

    archive_ok = False
    manifeste_ok = False
    nombre_elements = 0
    archive_message = ""

    try:

        with tarfile.open(
            archive,
            mode="r:gz"
        ) as tar:

            membres = tar.getmembers()

            nombre_elements = len(
                membres
            )

            archive_ok = True

            manifeste_ok = any(
                membre.name
                == MANIFEST_FILENAME
                for membre in membres
            )

            if manifeste_ok:

                archive_message = (
                    f"{nombre_elements} "
                    "élément(s), "
                    "manifeste présent."
                )

            else:

                archive_message = (
                    f"{nombre_elements} "
                    "élément(s), "
                    "manifeste absent."
                )

    except (
        tarfile.TarError,
        OSError
    ) as exc:

        archive_message = str(
            exc
        )

    duree = (
        time.perf_counter()
        - debut
    )

    # --------------------------------------------------------
    # Résultat
    # --------------------------------------------------------

    if (
        hash_ok
        and archive_ok
        and manifeste_ok
    ):

        statut = "VALIDE"

    elif not hash_ok:

        statut = "CORROMPU / MODIFIE"

    elif not archive_ok:

        statut = "ARCHIVE INVALIDE"

    else:

        statut = "MANIFESTE ABSENT"

    resultat = {

        "operation":
            "verification",

        "date":
            datetime.now().isoformat(
                timespec="seconds"
            ),

        "archive":
            str(archive),

        "sha256_attendu":
            attendu,

        "sha256_obtenu":
            obtenu,

        "sha256_ok":
            hash_ok,

        "archive_valide":
            archive_ok,

        "manifeste_present":
            manifeste_ok,

        "nombre_elements":
            nombre_elements,

        "archive_message":
            archive_message,

        "duree_secondes":
            round(
                duree,
                2
            ),

        "statut":
            statut,
    }

    logging.info(
        "Vérification | "
        "archive=%s | "
        "sha256_ok=%s | "
        "archive_ok=%s | "
        "manifeste=%s | "
        "statut=%s",
        archive,
        hash_ok,
        archive_ok,
        manifeste_ok,
        statut,
    )

    return resultat


# ============================================================
# CHOIX D'UNE ARCHIVE
# ============================================================

def choisir_archive() -> Path | None:
    """
    Affiche les sauvegardes et permet
    d'en sélectionner une.
    """

    archives = afficher_sauvegardes()

    if not archives:

        return None

    while True:

        choix = input(
            "Numéro de la sauvegarde "
            "(0 pour annuler) : "
        ).strip()

        if choix == "0":

            return None

        try:

            index = int(
                choix
            ) - 1

            if (
                0 <= index
                < len(archives)
            ):

                return archives[
                    index
                ]

        except ValueError:

            pass

        print(
            "[ERREUR] Numéro invalide."
        )


# ============================================================
# VALIDATION RESTAURATION
# ============================================================

def valider_destination_restauration(
    archive: Path,
    destination: Path
) -> None:
    """
    Vérifications avant restauration.
    """

    destination = destination.resolve(
        strict=False
    )

    # --------------------------------------------------------
    # Destination
    # --------------------------------------------------------

    if (
        destination.exists()
        and not destination.is_dir()
    ):

        raise BackupError(
            "La destination de restauration "
            "n'est pas un dossier."
        )

    # --------------------------------------------------------
    # Protection du projet
    # --------------------------------------------------------

    if destination == BASE_DIR:

        raise BackupError(
            "Pour éviter d'écraser le projet, "
            "choisissez un dossier dédié "
            "à la restauration."
        )

    # --------------------------------------------------------
    # Protection du dossier backups
    # --------------------------------------------------------

    if destination == BACKUP_DEFAULT_DIR:

        raise BackupError(
            "Le dossier interne 'backups' "
            "ne peut pas être utilisé comme "
            "destination de restauration."
        )

    # --------------------------------------------------------
    # Vérification du manifeste
    # --------------------------------------------------------

    try:

        with tarfile.open(
            archive,
            mode="r:gz"
        ) as tar:

            noms = {
                membre.name
                for membre in tar.getmembers()
            }

            if (
                MANIFEST_FILENAME
                not in noms
            ):

                raise BackupError(
                    "Cette archive ne contient "
                    "pas le manifeste Linux Toolbox. "
                    "Restauration refusée."
                )

    except tarfile.TarError as exc:

        raise BackupError(
            f"Archive illisible : {exc}"
        ) from exc


# ============================================================
# RESTAURATION
# ============================================================

def restaurer_sauvegarde(
    archive: Path,
    destination: Path
) -> dict:
    """
    Restaure une sauvegarde.

    Avant extraction :

    - SHA-256
    - validité TAR
    - manifeste
    - destination

    L'extraction utilise le filtre sécurisé
    'data' disponible avec Python 3.12+.
    """

    debut = time.perf_counter()

    archive = archive.resolve(
        strict=True
    )

    destination = destination.resolve(
        strict=False
    )

    if not archive.is_file():

        raise BackupError(
            "L'archive n'existe pas."
        )

    # --------------------------------------------------------
    # Intégrité AVANT toute écriture
    # --------------------------------------------------------

    integrite = verifier_integrite(
        archive
    )

    if integrite.get(
        "statut"
    ) != "VALIDE":

        raise BackupError(
            "Restauration refusée : "
            "sauvegarde non valide "
            f"({integrite.get('statut')})."
        )

    # --------------------------------------------------------
    # Validation destination
    # --------------------------------------------------------

    valider_destination_restauration(
        archive,
        destination
    )

    # --------------------------------------------------------
    # Création destination
    # --------------------------------------------------------

    if not destination.exists():

        try:

            destination.mkdir(
                parents=True,
                exist_ok=True
            )

            print(
                f"[INFO] Dossier de restauration "
                f"créé : {destination}"
            )

        except OSError as exc:

            raise BackupError(
                "Impossible de créer le "
                f"dossier de restauration : {exc}"
            ) from exc

    # --------------------------------------------------------
    # Destination non vide
    # --------------------------------------------------------

    if any(
        destination.iterdir()
    ):

        print()
        print(
            "[ATTENTION] Le dossier de "
            "destination n'est pas vide."
        )

        print(
            "La restauration peut créer "
            "ou remplacer certains fichiers."
        )

        confirmation = input(
            "Continuer ? (oui/non) : "
        ).strip().lower()

        if confirmation not in {
            "oui",
            "o"
        }:

            raise BackupError(
                "Restauration annulée."
            )

    # --------------------------------------------------------
    # Extraction sécurisée
    # --------------------------------------------------------

    print()
    print(
        "Restauration en cours..."
    )

    try:

        with tarfile.open(
            archive,
            mode="r:gz"
        ) as tar:

            # Python 3.12+.
            #
            # Le filtre data bloque notamment
            # les chemins dangereux et certains
            # liens pouvant sortir du dossier cible.
            tar.extractall(
                path=destination,
                filter="data"
            )

    except (
        tarfile.TarError,
        OSError,
        ValueError
    ) as exc:

        raise BackupError(
            "Échec de la restauration : "
            f"{exc}"
        ) from exc

    duree = (
        time.perf_counter()
        - debut
    )

    resultat = {

        "operation":
            "restauration",

        "date":
            datetime.now().isoformat(
                timespec="seconds"
            ),

        "archive":
            str(archive),

        "destination":
            str(destination),

        "duree_secondes":
            round(
                duree,
                2
            ),

        "statut":
            "SUCCES",
    }

    logging.info(
        "Restauration effectuée | "
        "archive=%s | "
        "destination=%s | "
        "duree=%.2fs",
        archive,
        destination,
        duree,
    )

    return resultat


# ============================================================
# SUPPRESSION
# ============================================================

def supprimer_sauvegarde(
    archive: Path
) -> dict:
    """
    Supprime :

    - l'archive .tar.gz
    - le fichier .sha256 associé

    uniquement après confirmation.
    """

    archive = archive.resolve(
        strict=False
    )

    if not archive.is_file():

        raise BackupError(
            "L'archive n'existe pas."
        )

    print()

    print(
        f"Sauvegarde sélectionnée : "
        f"{archive.name}"
    )

    print(
        f"Taille : "
        f"{format_bytes(archive.stat().st_size)}"
    )

    print()

    confirmation = input(
        "Confirmer la suppression ? "
        "(oui/non) : "
    ).strip().lower()

    if confirmation not in {
        "oui",
        "o"
    }:

        raise BackupError(
            "Suppression annulée."
        )

    checksum = (
        chemin_checksum(
            archive
        )
    )

    try:

        archive.unlink()

        checksum.unlink(
            missing_ok=True
        )

    except OSError as exc:

        raise BackupError(
            "Impossible de supprimer "
            f"la sauvegarde : {exc}"
        ) from exc

    logging.info(
        "Sauvegarde supprimée | "
        "archive=%s",
        archive
    )

    return {

        "operation":
            "suppression",

        "date":
            datetime.now().isoformat(
                timespec="seconds"
            ),

        "archive":
            str(archive),

        "statut":
            "SUCCES",
    }


# ============================================================
# RAPPORTS TXT / JSON
# ============================================================

def generer_rapports(
    resultat: dict
) -> tuple[Path, Path]:
    """
    Génère :

    reports/backup_DATE.txt
    reports/backup_DATE.json
    """

    timestamp = horodatage()

    txt_path = chemin_rapport(
        "backup",
        timestamp,
        "txt"
    )

    json_path = chemin_rapport(
        "backup",
        timestamp,
        "json"
    )

    lignes = [

        "LINUX TOOLBOX - "
        "RAPPORT DE SAUVEGARDE",

        "=" * 70,

        (
            f"Date       : "
            f"{resultat.get('date', 'N/A')}"
        ),

        (
            f"Opération  : "
            f"{resultat.get('operation', 'N/A')}"
        ),

        (
            f"Statut     : "
            f"{resultat.get('statut', 'N/A')}"
        ),

        "",
    ]

    for cle, valeur in resultat.items():

        if cle in {
            "date",
            "operation",
            "statut"
        }:

            continue

        if (
            isinstance(valeur, int)
            and cle.endswith(
                "_octets"
            )
        ):

            valeur_affichee = (
                f"{valeur} "
                f"({format_bytes(valeur)})"
            )

        elif cle == "taux_compression":

            valeur_affichee = (
                f"{valeur} %"
            )

        elif cle == "duree_secondes":

            valeur_affichee = (
                f"{valeur} s"
            )

        else:

            valeur_affichee = str(
                valeur
            )

        lignes.append(
            f"{cle:28} : "
            f"{valeur_affichee}"
        )

    try:

        txt_path.write_text(
            "\n".join(
                lignes
            ) + "\n",
            encoding="utf-8"
        )

        json_path.write_text(
            json.dumps(
                resultat,
                ensure_ascii=False,
                indent=2
            ),
            encoding="utf-8"
        )

    except OSError as exc:

        raise BackupError(
            "Impossible de générer "
            f"les rapports : {exc}"
        ) from exc

    return (
        txt_path,
        json_path
    )


# ============================================================
# AFFICHAGE RÉSULTAT
# ============================================================

def afficher_resultat(
    resultat: dict
) -> None:
    """
    Affiche le résultat d'une opération
    et génère les rapports.
    """

    print()
    print(
        "RESULTAT"
    )
    print("-" * 70)

    for cle, valeur in resultat.items():

        if cle in {
            "date",
            "operation"
        }:

            continue

        if (
            isinstance(valeur, int)
            and cle.endswith(
                "_octets"
            )
        ):

            valeur = (
                f"{valeur} "
                f"({format_bytes(valeur)})"
            )

        elif cle == "taux_compression":

            valeur = f"{valeur} %"

        elif cle == "duree_secondes":

            valeur = (
                f"{valeur} s "
                f"({format_duration(valeur)})"
            )

        print(
            f"{cle:28} : {valeur}"
        )

    try:

        txt, js = generer_rapports(
            resultat
        )

        print()
        print(
            "RAPPORTS"
        )
        print("-" * 70)

        print(
            f"TXT  : {txt}"
        )

        print(
            f"JSON : {js}"
        )

        print(
            f"LOG  : {LOG_FILE}"
        )

    except BackupError as exc:

        print(
            f"[AVERTISSEMENT] {exc}"
        )

        logging.exception(
            "Erreur lors de la génération "
            "des rapports"
        )


# ============================================================
# ACTION : CRÉATION
# ============================================================

def action_creation() -> None:

    print()
    print(
        "CRÉER UNE SAUVEGARDE"
    )
    print("-" * 70)

    print(
        "Vous pouvez utiliser TAB "
        "pour compléter les chemins."
    )

    print()

    # --------------------------------------------------------
    # Source
    # --------------------------------------------------------

    source = demander_chemin(
        "Fichier/dossier source : ",
        must_exist=True
    )

    # --------------------------------------------------------
    # Destination
    # --------------------------------------------------------

    print()

    print(
        "Destination par défaut :"
    )

    print(
        f"{BACKUP_DEFAULT_DIR}"
    )

    print()

    activer_autocompletion()

    destination_texte = input(
        "Dossier de destination "
        "[Entrée = défaut] : "
    ).strip()

    if not destination_texte:

        destination = (
            BACKUP_DEFAULT_DIR
        )

    else:

        destination = normaliser_chemin(
            destination_texte
        )

        # ----------------------------------------------------
        # Création automatique
        # ----------------------------------------------------

        if not destination.exists():

            try:

                destination.mkdir(
                    parents=True,
                    exist_ok=True
                )

                print(
                    f"[INFO] Dossier créé : "
                    f"{destination}"
                )

            except OSError as exc:

                raise BackupError(
                    "Impossible de créer "
                    f"la destination : {exc}"
                ) from exc

        if not destination.is_dir():

            raise BackupError(
                "La destination doit "
                "être un dossier."
            )

    # --------------------------------------------------------
    # Création
    # --------------------------------------------------------

    resultat = creer_sauvegarde(
        source,
        destination
    )

    afficher_resultat(
        resultat
    )


# ============================================================
# ACTION : LISTE
# ============================================================

def action_liste() -> None:

    afficher_sauvegardes()


# ============================================================
# ACTION : VÉRIFICATION
# ============================================================

def action_verification() -> None:

    archive = choisir_archive()

    if archive is None:

        return

    try:

        resultat = verifier_integrite(
            archive
        )

        afficher_resultat(
            resultat
        )

    except BackupError as exc:

        print(
            f"[ERREUR] {exc}"
        )

        logging.error(
            "Vérification échouée | %s",
            exc
        )


# ============================================================
# ACTION : RESTAURATION
# ============================================================

def action_restauration() -> None:

    archive = choisir_archive()

    if archive is None:

        return

    print()
    print(
        "RESTAURATION"
    )
    print("-" * 70)

    print(
        "Conseil : utilisez un dossier dédié "
        "pour éviter d'écraser des fichiers."
    )

    print(
        "TAB permet de compléter le chemin."
    )

    print()

    destination = demander_chemin(
        "Dossier de restauration : ",
        must_exist=False,
        must_be_directory=True,
        create_if_missing=True
    )

    try:

        resultat = restaurer_sauvegarde(
            archive,
            destination
        )

        afficher_resultat(
            resultat
        )

    except BackupError as exc:

        print(
            f"[ERREUR] {exc}"
        )

        logging.error(
            "Restauration échouée | %s",
            exc
        )


# ============================================================
# ACTION : SUPPRESSION
# ============================================================

def action_suppression() -> None:

    archive = choisir_archive()

    if archive is None:

        return

    try:

        resultat = supprimer_sauvegarde(
            archive
        )

        afficher_resultat(
            resultat
        )

    except BackupError as exc:

        print(
            f"[ERREUR] {exc}"
        )

        logging.error(
            "Suppression échouée | %s",
            exc
        )


# ============================================================
# MENU DU MODULE
# ============================================================

def lancer_gestionnaire_sauvegardes() -> None:
    """
    Point d'entrée principal du module Backup.
    """

    # Active TAB dès l'arrivée dans le module.
    activer_autocompletion()

    while True:

        print()
        print(
            "=" * 70
        )

        print(
            "              "
            "GESTIONNAIRE DE SAUVEGARDES"
        )

        print(
            "=" * 70
        )

        print()

        print(
            "Dossier de sauvegarde par défaut :"
        )

        print(
            f"{BACKUP_DEFAULT_DIR}"
        )

        print()

        print(
            "1. Créer une sauvegarde"
        )

        print(
            "2. Lister les sauvegardes"
        )

        print(
            "3. Vérifier l'intégrité "
            "d'une sauvegarde"
        )

        print(
            "4. Restaurer une sauvegarde"
        )

        print(
            "5. Supprimer une sauvegarde"
        )

        print(
            "0. Retour"
        )

        print()

        try:

            choix = input(
                "Votre choix : "
            ).strip()

        except EOFError:

            print()

            print(
                "[INFO] Saisie interrompue."
            )

            return

        try:

            # ------------------------------------------------
            # Création
            # ------------------------------------------------

            if choix == "1":

                action_creation()

            # ------------------------------------------------
            # Liste
            # ------------------------------------------------

            elif choix == "2":

                action_liste()

            # ------------------------------------------------
            # Vérification
            # ------------------------------------------------

            elif choix == "3":

                action_verification()

            # ------------------------------------------------
            # Restauration
            # ------------------------------------------------

            elif choix == "4":

                action_restauration()

            # ------------------------------------------------
            # Suppression
            # ------------------------------------------------

            elif choix == "5":

                action_suppression()

            # ------------------------------------------------
            # Retour
            # ------------------------------------------------

            elif choix == "0":

                print()
                print(
                    "Retour au menu principal."
                )

                return

            else:

                print()
                print(
                    "[ERREUR] Choix invalide."
                )

        except BackupError as exc:

            print()
            print(
                f"[ERREUR] {exc}"
            )

            logging.error(
                "Opération échouée | %s",
                exc
            )

        except PermissionError as exc:

            print()
            print(
                "[ERREUR] Permission refusée."
            )

            print(
                f"Détail : {exc}"
            )

            logging.error(
                "Permission refusée | %s",
                exc
            )

        except OSError as exc:

            print()
            print(
                "[ERREUR] Erreur système : "
                f"{exc}"
            )

            logging.error(
                "Erreur système | %s",
                exc
            )

        except KeyboardInterrupt:

            print()
            print(
                "[INFO] Opération interrompue "
                "par l'utilisateur."
            )

            logging.warning(
                "Opération interrompue "
                "par l'utilisateur"
            )


# ============================================================
# ALIAS
# ============================================================

# Permet également d'appeler le module
# avec un nom plus court depuis main.py.

lancer_backup = (
    lancer_gestionnaire_sauvegardes
)


# ============================================================
# EXÉCUTION DIRECTE
# ============================================================

if __name__ == "__main__":

    lancer_gestionnaire_sauvegardes()
