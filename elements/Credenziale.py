class Credenziale:
    """
    La credenziale dell'elettore (pk_v, sigma_SA).
    Dimostra all'AE che chi si presenta è stato autorizzato dall'SA a votare,
    senza rivelare la sua identità reale.
    """
    pk_v: object    # RSAPublicKey — chiave pubblica effimera dell'elettore
    sigma_SA: bytes # Sign(sk_SA, pk_v) — firma dell'SA che attesta il diritto di voto

    def __init__(self, pk_v, sigma_SA: bytes):
        self.pk_v = pk_v
        self.sigma_SA = sigma_SA
