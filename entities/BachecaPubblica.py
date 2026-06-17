from abc import ABC, abstractmethod


class BachecaPubblica(ABC):
    """
    Registro pubblico append-only della Bacheca Pubblica (BP).

    Ruolo nel protocollo:
      - Solo l'AE scrive (le voci sono prodotte e firmate dall'AE).
      - Chiunque legge, in sola lettura.
      - Le voci non possono essere modificate o cancellate una volta pubblicate.

    L'interfaccia è divisa in tre livelli:

    1. Primitive del registro — il contratto minimo di un registro append-only:
         pubblica(), get_voci(), verifica_integrita().

    2. Voci del protocollo di voto — scorciatoie che serializzano i dati del
       protocollo e li accodano tramite pubblica():
         riceve_parametri_da_ae() (Fase 1),
         riceve_voto_da_ae()      (Fase 3),
         riceve_scrutinio_da_ae() (Fase 4).

    3. Letture del protocollo — recuperano dati pubblici dal registro:
         get_opzioni(), get_pk_ae_enc(), get_ultimo_blocco().
    """

    # --- 1. Primitive del registro -----------------------------------------

    @abstractmethod
    def pubblica(self, entry: str) -> None:
        """Aggiunge una nuova voce in coda al registro. Non modifica le voci precedenti."""
        ...

    @abstractmethod
    def get_voci(self) -> list[str]:
        """Restituisce tutte le voci pubblicate, nell'ordine di inserimento."""
        ...

    @abstractmethod
    def verifica_integrita(self) -> bool:
        """True se il registro append-only è integro, False se manomesso."""
        ...

    # --- 2. Voci del protocollo di voto ------------------------------------

    @abstractmethod
    def riceve_parametri_da_ae(self, opzioni: list, pk_ae_enc_pem: str,
                               pk_ae_sig_pem: str = None) -> None:
        """Fase 1: pubblica la lista chiusa delle opzioni, la pk_AE_enc e la pk_AE_sig."""
        ...

    @abstractmethod
    def riceve_voto_da_ae(self, voce: tuple) -> None:
        """Fase 3: pubblica una voce di voto (identificativo i, scheda B, ricevuta R)."""
        ...

    @abstractmethod
    def riceve_scrutinio_da_ae(self, voce_scrutinio: str) -> None:
        """Fase 4: pubblica la voce finale di scrutinio (JSON già firmato dall'AE)."""
        ...

    # --- 3. Letture del protocollo -----------------------------------------

    @abstractmethod
    def get_opzioni(self) -> list:
        """Restituisce la lista chiusa delle opzioni, letta dal registro."""
        ...

    @abstractmethod
    def get_pk_ae_enc(self):
        """Restituisce la chiave pubblica di cifratura dell'AE, letta dal registro."""
        ...

    @abstractmethod
    def get_ultimo_blocco(self):
        """Restituisce l'ultima voce/blocco pubblicato (la voce di scrutinio in Fase 5)."""
        ...
