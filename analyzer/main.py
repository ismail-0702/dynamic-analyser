import asyncio
import argparse
import uuid
import sys
import logging
from pathlib import Path

# Ajout du chemin pour l'importation des modules locaux
sys.path.insert(0, str(Path(__file__).parent))

# Import de la classe principale qui contient maintenant le code d'envoi
from analyzer import DynamicAnalyzer

# Configuration du logging pour voir les envois en temps réel dans la console
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)
log = logging.getLogger("main")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="APK Dynamic Analyzer")
    parser.add_argument("apk", help="Chemin vers l'APK")
    parser.add_argument("--session", default=str(uuid.uuid4()), help="ID de session unique")
    parser.add_argument("--ws", default="ws://localhost:8000", help="URL du backend FastAPI")
    parser.add_argument("--serial", default=None, help="Numéro de série ADB (optionnel)")
    parser.add_argument("--frida-server", default=None, help="Chemin local vers frida-server")
    parser.add_argument("--skip-install", action="store_true", help="Sauter l'installation si l'APK est déjà présent")
    args = parser.parse_args()

    log.info(f"Démarrage de l'analyse pour la session: {args.session}")

    # Initialisation de l'analyseur
    # C'est ici que le code d'envoi (websocket.send_json) doit être implémenté
    analyzer = DynamicAnalyzer(
        apk_path=args.apk,
        session_id=args.session,
        ws_uri=args.ws,
        adb_serial=args.serial,
        frida_server_local=args.frida_server,
        skip_install=args.skip_install,
    )

    try:
        # Exécution de la boucle asynchrone
        asyncio.run(analyzer.run())
    except KeyboardInterrupt:
        log.info("Analyse interrompue par l'utilisateur.")
    except Exception as e:
        log.error(f"Erreur fatale lors de l'exécution: {e}")