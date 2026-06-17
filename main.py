"""
main.py — Flusso sequenziale delle 5 fasi del protocollo di e-voto.

Esegue una piccola elezione end-to-end a terminale, riusando l'orchestratore
`Elezione`. Ad ogni avvio lo stato riparte pulito (bacheca.json e log troncati).

    python main.py
"""

import argparse
import random
from datetime import datetime
from pathlib import Path
from tqdm  import tqdm
from config import MODALITA_CIFRATURA
from elezione import Elezione


def main():
    parser = argparse.ArgumentParser(description="Simula un'elezione e genera report temporali.")
    parser.add_argument("-n", "--n_elettori", type=int, default=5,
                        help="Numero di elettori da simulare")
    parser.add_argument("--no-echo", action="store_true",
                        help="Non stampare le righe di log su terminale")
    args = parser.parse_args()

    report_dir = Path("report")
    report_dir.mkdir(parents=True, exist_ok=True)

    timestamp = datetime.now().strftime("%H%M")
    log_path = report_dir / f"protocol_log_{timestamp}_{MODALITA_CIFRATURA.lower()}.txt"

    elezione = Elezione()

    # ------------------------------------------------------------------
    # FASE 1 — Setup
    # ------------------------------------------------------------------
    print("\n########## FASE 1: SETUP ##########")
    elezione.avvia(
        n_utenti=args.n_elettori,
        echo_log=not args.no_echo,
        log_path=str(log_path),
    )
    opzioni = elezione.opzioni
    print(f"Opzioni dell'elezione: {opzioni}")

    # ------------------------------------------------------------------
    # FASE 2+3 — Autenticazione e Voto di ogni elettore
    # ------------------------------------------------------------------
    print("\n########## FASE 2+3: AUTENTICAZIONE E VOTO ##########")
    elettori = []
    preferenze_attese = {}
    #iterator = tqdm(range(args.n_elettori), desc="Simulazione voti", unit="elettore") if tqdm is not None else range(args.n_elettori)
    #for _ in iterator:
    for _ in tqdm(range(args.n_elettori), desc="Simulazione voti", unit="elettore"):
        utente, password = elezione.preleva_account()
        preferenza = random.randrange(len(opzioni))      # voto casuale fra le opzioni
        elettore = elezione.crea_elettore(utente)
        esito = elezione.vota_elettore(elettore, password, preferenza)
        preferenze_attese[utente] = preferenza
        elettori.append(elettore)
        #print(f"  {utente} ha votato '{opzioni[preferenza]}' "
        #      f"-> identificativo i={esito['identificativo']}")

    # ------------------------------------------------------------------
    # FASE 4 — Scrutinio
    # ------------------------------------------------------------------
    print("\n########## FASE 4: SCRUTINIO ##########")
    risultato = elezione.chiudi_e_scrutina()
    print(f"  Totali: {risultato['totali']}")
    print(f"  Radice di Merkle: {risultato['merkle_root']}")

    # ------------------------------------------------------------------
    # FASE 5 — Verifica individuale di ogni elettore
    # ------------------------------------------------------------------
    print("\n########## FASE 5: VERIFICA ##########")
    tutti_ok = True
    #for elettore in elettori:
    for elettore in tqdm(elettori):        
        esito = elettore.verifica_individuale(elezione.bp)
        tutti_ok = tutti_ok and esito["tutto_ok"]
        #print(f"  {elettore.matricola}: verifica {'OK' if esito['tutto_ok'] else 'FALLITA'} "
        #      f"(voto pubblicato='{esito['voto_pubblicato']}')")

    # integrità della Bacheca Pubblica (append-only)
    print(f"\n  Integrità BP (blockchain): "
          f"{'OK' if elezione.bp.verifica_integrita() else 'COMPROMESSA'}")
    print(f"  Verifica individuale di tutti gli elettori: "
          f"{'OK' if tutti_ok else 'FALLITA'}")

    # ------------------------------------------------------------------
    # Report cronometrico finale (anche su protocol_log.txt)
    # ------------------------------------------------------------------
    elezione.logger.stampa_report()
    elezione.logger.chiudi()


if __name__ == "__main__":
    main()
