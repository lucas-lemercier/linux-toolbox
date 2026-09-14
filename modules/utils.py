"""
Linux Toolbox
Module : Fonctions utilitaires partagées

Objectif :
    Centraliser les fonctions communes utilisées par
    plusieurs modules (diagnostic, audit de sécurité),
    afin d'éviter la duplication de code.
"""

import subprocess


def executer_commande(commande, timeout=10):
    """
    Exécute une commande système.

    Retourne :
        (code_retour, stdout, stderr)

    En cas d'échec (timeout, commande introuvable,
    ou toute autre erreur), retourne un code -1
    accompagné d'un message d'erreur explicite.
    """

    try:

        resultat = subprocess.run(
            commande,
            capture_output=True,
            text=True,
            timeout=timeout,
        )

        return (
            resultat.returncode,
            resultat.stdout.strip(),
            resultat.stderr.strip(),
        )

    except subprocess.TimeoutExpired:

        return (
            -1,
            "",
            "Commande interrompue : délai dépassé.",
        )

    except FileNotFoundError:

        return (
            -1,
            "",
            "Commande introuvable.",
        )

    except Exception as erreur:

        return (
            -1,
            "",
            str(erreur),
        )
