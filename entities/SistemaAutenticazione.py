"""
SistemaAutenticazione (SA) — Fase 2: Autenticazione.

L'SA è la Relying Party OIDC: autentica l'elettore tramite l'IdP e gli rilascia
una credenziale di voto pseudonima firmando la sua chiave pubblica effimera pk_v.

Tabella interna (privata) di dimensione N:
    entry = (token, pk_v_firmata_la_prima_volta)
Per gestire l'IDEMPOTENZA (diagramma: "stessa identità ripresentata con stessa pk_v")
indicizziamo per identità (utente), salvando token, pk_v e la firma σ_SA prodotta
la PRIMA volta. Se l'elettore si ripresenta:
    - con la STESSA pk_v  -> restituiamo la STESSA σ_SA (recovery da crash);
    - con una pk_v DIVERSA -> rifiutiamo (niente seconda credenziale valida).
"""

from cryptography import x509

from config import PSS_PADDING_LENGTH_SA
from elements.cripto import genera_coppia_rsa, firma_pss, pk_to_der, pk_to_pem
from elements.ProtocolLogger import _NullLogger
from entities.IdentityProvider import IdentityProvider
from entities.CertificationAuthority import CertificationAuthority


class SistemaAutenticazione:
    """Rilascia credenziali di voto pseudonime, in modo idempotente."""

    # Fase 1 — Setup
    # _sk_SA : RSAPrivateKey — firma le credenziali (segreta)
    # pk_SA  : RSAPublicKey  — verifica le credenziali (pubblica)
    # _cert_SA : x509.Certificate — certificato rilasciato dalla CA

    # Fase 2 — Autenticazione
    # _registro : utente -> {"token", "pk_v_pem", "sigma_SA"}  (idempotenza)

    def __init__(self, idp: IdentityProvider, ca: CertificationAuthority, logger=None):
        self._logger = logger or _NullLogger()
        self._idp = idp

        with self._logger.misura("fase1.sa.genera_chiavi"):
            self._sk_SA, self.pk_SA = genera_coppia_rsa()

        # la CA certifica la chiave pubblica dell'SA
        self._cert_SA = ca.emetti_certificato("SA", self.pk_SA)

        self._registro: dict[str, dict] = {}

    # ------------------------------------------------------------------
    # 2.1 Login (OIDC mockato): l'SA verifica il diritto al voto tramite l'IdP
    # ------------------------------------------------------------------

    def login(self, utente: str, password: str) -> str:
        """
        Avvia l'autenticazione: l'SA chiede all'IdP di verificare le credenziali e
        riceve il token (ID Token). Restituisce il token all'elettore.
        """
        with self._logger.misura("fase2.sa.login_oidc"):
            token = self._idp.login(utente, password)   # redirect + verifica identità (mock)
            self._idp.verifica_token(token)              # l'SA valida il token ricevuto
        return token

    # ------------------------------------------------------------------
    # 2.2 Rilascio della credenziale: firma pk_v con sk_SA (idempotente)
    # ------------------------------------------------------------------

    def rilascia_credenziale(self, token: str, pk_v) -> bytes:
        """
        Riceve (token, pk_v), verifica l'identità tramite il token e firma pk_v.
        Restituisce σ_SA = Sign_sk_SA(pk_v).

        Idempotenza:
          - identità nuova           -> firma e registra;
          - identità + stessa pk_v   -> restituisce la firma salvata;
          - identità + pk_v diversa  -> ValueError (credenziale già ritirata).
        """
        utente = self._idp.verifica_token(token)         # risale all'identità servita
        pk_v_pem = pk_to_pem(pk_v)

        # caso: l'identità si è già presentata in passato
        if utente in self._registro:
            registrato = self._registro[utente]
            if registrato["pk_v_pem"] == pk_v_pem:
                self._logger.evento(f"SA: recovery idempotente per {utente} (stessa pk_v)")
                return registrato["sigma_SA"]            # stessa firma di prima
            raise ValueError("Credenziale già ritirata con una pk_v diversa: rifiutato")

        # caso: prima volta -> firma RSA-PSS sulla rappresentazione DER di pk_v
        with self._logger.misura("fase2.sa.firma_credenziale"):
            sigma_SA = firma_pss(self._sk_SA, pk_to_der(pk_v), PSS_PADDING_LENGTH_SA)

        self._registro[utente] = {
            "token": token,
            "pk_v_pem": pk_v_pem,
            "sigma_SA": sigma_SA,
        }
        self._logger.registra_byte("byte.sigma_SA", len(sigma_SA))
        self._logger.evento(f"SA: credenziale rilasciata a {utente}")
        return sigma_SA

    # ------------------------------------------------------------------
    # Setup helper e letture
    # ------------------------------------------------------------------

    def get_certificato(self) -> x509.Certificate:
        """Certificato X.509 dell'SA (per chi deve verificare pk_SA tramite la CA)."""
        return self._cert_SA

    def reset(self) -> None:
        """Svuota il registro delle credenziali (nuova elezione)."""
        self._registro.clear()

    def snapshot_tabella(self) -> list[dict]:
        """Copia leggibile della tabella (token, pk_v firmata) per la web app."""
        return [
            {
                "utente": u,
                "token": d["token"][:12] + "...",
                #"token": d["token"],
                "pk_v": d["pk_v_pem"],
                "sigma_SA": d["sigma_SA"].hex()[:24] + "...",
                #"sigma_SA": d["sigma_SA"].hex(),
            }
            for u, d in self._registro.items()
        ]
