from modules.diagnostic import lancer_diagnostic
from modules.security_audit import lancer_audit_securite
from modules.backup import lancer_gestionnaire_sauvegardes


def main():
    """
    Point d'entrée principal de Linux Toolbox.

    Le programme propose :
    1. Diagnostic complet de la machine
    2. Audit de sécurité
    3. Gestionnaire de sauvegardes
    0. Quitter
    """

    while True:

        print()
        print("=" * 70)
        print("                        LINUX TOOLBOX")
        print("=" * 70)
        print()

        print("1. Diagnostic complet de la machine")
        print("2. Audit de sécurité")
        print("3. Gestionnaire de sauvegardes")
        print("0. Quitter")
        print()

        choix = input("Votre choix : ").strip()

        # ====================================================
        # OUTIL 1 : DIAGNOSTIC
        # ====================================================

        if choix == "1":

            try:

                lancer_diagnostic()

            except KeyboardInterrupt:

                print()
                print(
                    "[INFO] Diagnostic interrompu "
                    "par l'utilisateur."
                )

            except Exception as exc:

                print()
                print(
                    "[ERREUR] Une erreur est survenue "
                    f"pendant le diagnostic : {exc}"
                )

            print()

            input(
                "Appuyez sur Entrée pour revenir au menu..."
            )

        # ====================================================
        # OUTIL 2 : AUDIT DE SÉCURITÉ
        # ====================================================

        elif choix == "2":

            try:

                lancer_audit_securite()

            except KeyboardInterrupt:

                print()
                print(
                    "[INFO] Audit interrompu "
                    "par l'utilisateur."
                )

            except Exception as exc:

                print()
                print(
                    "[ERREUR] Une erreur est survenue "
                    f"pendant l'audit : {exc}"
                )

            print()

            input(
                "Appuyez sur Entrée pour revenir au menu..."
            )

        # ====================================================
        # OUTIL 3 : SAUVEGARDES
        # ====================================================

        elif choix == "3":

            try:

                lancer_gestionnaire_sauvegardes()

            except KeyboardInterrupt:

                print()
                print(
                    "[INFO] Gestionnaire de sauvegardes "
                    "interrompu par l'utilisateur."
                )

            except Exception as exc:

                print()
                print(
                    "[ERREUR] Une erreur est survenue "
                    f"dans le gestionnaire de sauvegardes : {exc}"
                )

            print()

            input(
                "Appuyez sur Entrée pour revenir au menu..."
            )

        # ====================================================
        # QUITTER
        # ====================================================

        elif choix == "0":

            print()
            print(
                "Fermeture de Linux Toolbox."
            )
            print()

            break

        # ====================================================
        # CHOIX INVALIDE
        # ====================================================

        else:

            print()
            print(
                "[ERREUR] Choix invalide."
            )
            print()


if __name__ == "__main__":
    main()
