"""
CertificationAuthority — Radice di fiducia del sistema (Fase 1: Setup).

In questa spike usiamo veri certificati X.509 (libreria `cryptography`):
  - la CA genera la propria coppia di chiavi e un certificato self-signed;
  - emette un certificato X.509 per ogni chiave pubblica delle autorità (SA, AE, BP);
  - chiunque può verificare un certificato con la chiave pubblica della CA (pk_CA).

La CA NON partecipa alle fasi di voto e scrutinio: serve solo a garantire
l'autenticità delle chiavi pubbliche prima dell'elezione.
"""

import datetime

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding

from elements.cripto import genera_coppia_rsa
from elements.ProtocolLogger import _NullLogger


class CertificationAuthority:
    """Emette e verifica certificati X.509 per le autorità del protocollo."""

    # Fase 1 — Setup
    # _sk_CA : RSAPrivateKey — firma i certificati (resta segreta)
    # pk_CA  : RSAPublicKey  — permette a chiunque di verificarli (pubblica)
    # _cert_CA : x509.Certificate — certificato self-signed della CA

    def __init__(self, ca_id: str = "CA", logger=None):
        self._logger = logger or _NullLogger()
        self._ca_id = ca_id

        with self._logger.misura("fase1.ca.genera_chiavi"):
            self._sk_CA, self.pk_CA = genera_coppia_rsa()

        self._cert_CA = self._costruisci_certificato(
            common_name=ca_id,
            chiave_pubblica=self.pk_CA,
            is_ca=True,
        )

    # ------------------------------------------------------------------
    # Emissione certificati
    # ------------------------------------------------------------------

    def emetti_certificato(self, common_name: str, chiave_pubblica) -> x509.Certificate:
        """
        Emette un certificato X.509 per `chiave_pubblica`, firmato con sk_CA.
        È l'operazione richiamata da SA/AE/BP durante il Setup.
        """
        with self._logger.misura("fase1.ca.emetti_certificato"):
            cert = self._costruisci_certificato(common_name, chiave_pubblica, is_ca=False)
        self._logger.registra_byte("byte.certificato", len(cert.public_bytes(_DER)))
        return cert

    def verifica_certificato(self, cert: x509.Certificate) -> bool:
        """
        Verifica che `cert` sia stato emesso dalla CA (firma valida con pk_CA)
        e che sia nel periodo di validità. Restituisce True/False.
        """
        with self._logger.misura("fase1.ca.verifica_certificato"):
            try:
                # 1) la firma del certificato deve verificare con la chiave pubblica della CA
                self.pk_CA.verify(
                    cert.signature,
                    cert.tbs_certificate_bytes,
                    asym_padding.PKCS1v15(),
                    cert.signature_hash_algorithm,
                )
                # 2) il certificato non deve essere scaduto
                adesso = datetime.datetime.now(datetime.timezone.utc)
                valido = cert.not_valid_before_utc <= adesso <= cert.not_valid_after_utc
                return valido
            except Exception:
                return False

    def get_certificato_ca(self) -> x509.Certificate:
        """Restituisce il certificato self-signed della CA."""
        return self._cert_CA

    # ------------------------------------------------------------------
    # Utilità interne
    # ------------------------------------------------------------------

    def _costruisci_certificato(self, common_name, chiave_pubblica, is_ca: bool) -> x509.Certificate:
        soggetto = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
        # l'emittente è sempre la CA (per il self-signed soggetto == emittente)
        emittente = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, self._ca_id)])

        adesso = datetime.datetime.now(datetime.timezone.utc)
        builder = (
            x509.CertificateBuilder()
            .subject_name(soggetto)
            .issuer_name(emittente)
            .public_key(chiave_pubblica)
            .serial_number(x509.random_serial_number())
            .not_valid_before(adesso - datetime.timedelta(minutes=1))
            .not_valid_after(adesso + datetime.timedelta(days=1))
            .add_extension(x509.BasicConstraints(ca=is_ca, path_length=None), critical=True)
        )
        # la firma del certificato è sempre prodotta con la chiave privata della CA
        return builder.sign(private_key=self._sk_CA, algorithm=hashes.SHA256())


# Encoding DER importato qui per non appesantire l'header del file
from cryptography.hazmat.primitives.serialization import Encoding as _Encoding
_DER = _Encoding.DER
