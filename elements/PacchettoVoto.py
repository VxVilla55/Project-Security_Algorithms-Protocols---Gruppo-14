from elements.Scheda import Scheda
from elements.Credenziale import Credenziale


class PacchettoVoto:
    """
    Il pacchetto M = (B, (pk_v, sigma_SA), sigma_v) inviato dall'Elettore all'AE.
    """
    scheda: Scheda
    credenziale: Credenziale
    sigma_v: bytes

    def __init__(self, scheda: Scheda, credenziale: Credenziale, sigma_v: bytes):
        self.scheda = scheda
        self.credenziale = credenziale
        self.sigma_v = sigma_v
