"""
elezione.py — Orchestratore dell'elezione.

Tiene insieme tutte le entità (CA, IdP, SA, AE, BP) e offre i metodi che eseguono
le cinque fasi del protocollo. È riusato sia da main.py (flusso sequenziale a
terminale) sia da app.py (web app Flask), così la logica di setup/wiring sta in
un solo posto.

Ogni chiamata ad avvia() riparte da uno stato pulito (requisito di reset):
  - cancella la blockchain bacheca.json,
  - apre un nuovo file di log (troncandolo),
  - rigenera tutte le chiavi e svuota le tabelle.
"""

import os

from config import BACHECA_PATH, LOG_PATH, OPZIONI_DEFAULT
from elements.ProtocolLogger import ProtocolLogger
from elements.cripto import genera_coppia_rsa
from elements.bp_objects.bp import BachecaPubblicaObjects
from entities import (CertificationAuthority, IdentityProvider,
                      SistemaAutenticazione, AutoritaElettorale, Elettore,
                      Osservatore)


class Elezione:
    """Stato globale e fasi del protocollo di e-voto."""

    def __init__(self):
        self._logger = None
        self._log_path = LOG_PATH
        self._ca = None
        self._idp = None
        self._sa = None
        self._ae = None
        self._bp = None

        self._opzioni = list(OPZIONI_DEFAULT)
        self._n_utenti = 0
        self._account_disponibili = []   # (utente, password) non ancora usati
        self._urna_chiusa = False
        self._risultato = None
        self._avviata = False

    # ==================================================================
    # FASE 1 — Setup (reset completo + generazione chiavi + certificati)
    # ==================================================================

    def avvia(self, n_utenti: int, opzioni: list = None, echo_log: bool = True,
              log_path: str = None) -> None:
        """
        FASE 1: prepara una nuova elezione da zero.
        Crea le entità, fa certificare le chiavi alla CA, popola l'IdP con N utenti
        e pubblica i parametri di voto sulla BP.
        """
        # 1) reset dello stato persistente: blockchain pulita e log nuovo
        if os.path.exists(BACHECA_PATH):
            os.remove(BACHECA_PATH)
        if self._logger is not None:
            self._logger.chiudi()
        log_path = log_path or LOG_PATH
        self._log_path = log_path
        self._logger = ProtocolLogger(log_path=log_path, echo_terminale=echo_log)
        self._logger.evento("=== FASE 1: SETUP ===")

        self._opzioni = list(opzioni) if opzioni else list(OPZIONI_DEFAULT)
        self._n_utenti = n_utenti

        # 2) creazione delle entità
        self._ca = CertificationAuthority(logger=self._logger)
        self._idp = IdentityProvider(logger=self._logger)
        self._bp = BachecaPubblicaObjects(bp_id="BP", json_path=BACHECA_PATH, logger=self._logger)
        self._sa = SistemaAutenticazione(self._idp, self._ca, logger=self._logger)
        self._ae = AutoritaElettorale(self._ca, self._bp, opzioni=self._opzioni, logger=self._logger)

        # 3) la CA certifica la chiave pubblica della BP (che la BP usa per firmare
        #    la radice di Merkle che costruisce alla chiusura dell'urna)
        self._cert_BP = self._ca.emetti_certificato("BP", self._bp.pk_BP)

        # 4) l'AE acquisisce e verifica la chiave pubblica dell'SA tramite la CA
        self._ae.collega_sistema_autenticazione(self._sa.get_certificato(), self._ca)

        # 5) l'AE pubblica i parametri firmati sulla BP
        self._ae.pubblica_parametri()

        # 6) l'IdP viene popolato con N coppie (utente, password)
        self._account_disponibili = self._idp.popola(n_utenti)

        self._urna_chiusa = False
        self._risultato = None
        self._avviata = True
        self._logger.evento(f"Setup completato: {n_utenti} utenti, opzioni={self._opzioni}")

    # ==================================================================
    # Gestione degli account (pool condiviso fra demo e batch)
    # ==================================================================

    def preleva_account(self) -> tuple[str, str]:
        """Restituisce e consuma una coppia (utente, password) libera. Errore se esaurite."""
        if not self._account_disponibili:
            raise ValueError("Nessun account disponibile: aumenta N o avvia una nuova elezione")
        return self._account_disponibili.pop(0)

    def crea_elettore(self, matricola: str) -> Elettore:
        """Crea un'istanza Elettore agganciata al logger dell'elezione."""
        return Elettore(matricola, logger=self._logger)

    # ==================================================================
    # FASE 2 + 3 — Flusso completo di un singolo elettore (usato dal batch)
    # ==================================================================

    def vota_elettore(self, elettore: Elettore, password: str, preferenza: int) -> dict:
        """Esegue Fase 2 e Fase 3 per un elettore già creato. Restituisce (identificativo, ricevuta)."""
        # Fase 2 — Autenticazione
        elettore.verifica_certificato_sa(self._sa.get_certificato(), self._ca)
        elettore.login(self._sa, password)
        elettore.genera_chiavi_effimere()
        elettore.richiedi_credenziale(self._sa)

        # Fase 3 — Voto
        elettore.richiedi_parametri(self._bp)
        elettore.scegli_preferenza(preferenza)
        elettore.prepara_pacchetto()
        ricevuta = elettore.invia_voto(self._ae)
        return {"identificativo": elettore.identificativo, "ricevuta": ricevuta.hex()}

    # ==================================================================
    # FASE 4 — Scrutinio
    # ==================================================================

    def chiudi_e_scrutina(self, stampa_report: bool = False, chiudi_logger: bool = False,
                           esporta_report: str = None) -> dict:
        """FASE 4: chiude l'urna, esegue lo scrutinio e pubblica l'esito sulla BP.

        Se richiesto, stampa anche il report finale su file e chiude il logger.
        Questo permette alla web app di generare il report automatico alla fine
        dell'elezione senza duplicare la logica in app.py.
        """
        self._logger.evento("=== FASE 4: SCRUTINIO ===")
        self._risultato = self._ae.chiudi_urna_e_scrutina()
        self._urna_chiusa = True
        if stampa_report and self._logger is not None:
            self._logger.stampa_report()
        if esporta_report and self._logger is not None:
            self._logger.esporta_json(esporta_report)
        if chiudi_logger and self._logger is not None:
            self._logger.chiudi()
        return self._risultato

    # ==================================================================
    # FASE 5 — Verifica universale (chiunque, dai soli dati pubblici)
    # ==================================================================

    def verifica_universale(self) -> dict:
        """FASE 5: un osservatore esterno ricalcola l'esito dai dati pubblici della BP."""
        self._logger.evento("=== FASE 5: VERIFICA UNIVERSALE ===")
        osservatore = Osservatore(logger=self._logger)
        # l'osservatore legge tutto dalla BP (chiavi pubbliche incluse): l'AE non è coinvolto
        return osservatore.verifica_universale(self._bp, self.opzioni)

    # ==================================================================
    # Accessori
    # ==================================================================

    @property
    def logger(self):
        return self._logger

    @property
    def ca(self):
        return self._ca

    @property
    def idp(self):
        return self._idp

    @property
    def sa(self):
        return self._sa

    @property
    def ae(self):
        return self._ae

    @property
    def bp(self):
        return self._bp

    @property
    def opzioni(self):
        return list(self._opzioni)

    @property
    def avviata(self):
        return self._avviata

    @property
    def urna_chiusa(self):
        return self._urna_chiusa

    @property
    def risultato(self):
        return self._risultato

    @property
    def account_rimanenti(self) -> int:
        return len(self._account_disponibili)
