"""
Elettore (E) — Client dell'elettore. Esegue tutte le operazioni lato studente.

Flusso (segue i diagrammi di sequenza):
  Fase 2 (Autenticazione)
    login()                  -> ottiene il token dall'SA (via IdP)
    genera_chiavi_effimere() -> (pk_v, sk_v)
    richiedi_credenziale()   -> invia pk_v all'SA, riceve σ_SA -> Credenziale
  Fase 3 (Voto)
    richiedi_parametri()     -> dalla BP: pk_AE_enc + lista opzioni
    scegli_preferenza()      -> indice dell'opzione
    prepara_pacchetto()      -> cifratura ibrida + firma σ_v -> M
    invia_voto()             -> invia M all'AE, riceve la ricevuta R
  Fase 5 (Verifica)
    verifica_individuale()   -> controlla ricevuta, inclusione Merkle e voto
"""

import secrets

import config   # letto a runtime per la modalità di cifratura (ibrida / rsa)
from config import (AES_KEY_SIZE, AES_IV_SIZE, VOTER_CHOICE_BYTE_LENGTH,
                    PSS_PADDING_LENGTH_ELETTORE, PSS_PADDING_LENGTH_AE, PSS_PADDING_LENGTH_BP)
from elements.cripto import (genera_coppia_rsa, cifra_aes_cbc, decifra_aes_cbc,
                             cifra_rsa_oaep, firma_pss, verifica_pss,
                             serializza_B, foglia_merkle, hash_blocco_hex,
                             sha256_hex, pk_to_pem, pem_to_pk)
from elements.ProtocolLogger import _NullLogger
from elements.Credenziale import Credenziale
from elements.Scheda import Scheda
from elements.PacchettoVoto import PacchettoVoto
from entities import CertificationAuthority, AutoritaElettorale, BachecaPubblica, SistemaAutenticazione

class Elettore:
    """Modellazione dell'Elettore e di tutte le sue operazioni crittografiche."""

    def __init__(self, matricola: str, logger=None):
        self._logger = logger or _NullLogger()

        # Fase 1 & 2 — identità e autenticazione
        self._matricola = matricola
        self._token = None             # ID Token ottenuto dall'SA (via IdP)
        self._pk_v = None              # RSAPublicKey effimera (None finché non generata)
        self._sk_v = None              # RSAPrivateKey effimera (resta segreta)
        self._credenziale = None       # Credenziale(pk_v, σ_SA) rilasciata dall'SA

        # Fase 3 — voto
        self._opzioni = []             # lista chiusa letta dalla BP
        self._pk_ae_enc = None         # chiave pubblica di cifratura dell'AE
        self._preferenza = None        # indice dell'opzione scelta
        self._k_AES = None             # chiave simmetrica di sessione
        self._iv = None                # IV per AES-CBC
        self._c_voto = None            # voto cifrato (AES-CBC)
        self._c_k = None               # k_AES cifrata (RSA-OAEP)
        self._scheda = None            # Scheda B = (c_voto, c_k, iv)
        self._sigma_v = None           # firma dell'elettore su B
        self._pacchetto = None         # PacchettoVoto M = (B, credenziale, σ_v)

        # Fase 3/5 — ricevuta e verifica
        self._i = None           # identificativo i assegnato dall'AE
        self._ricevuta = None          # R = Sign_sk_AE_sig(H(B||i))
        # "Fotografia" del voto effettivamente inviato: serve per la verifica.
        # Se l'elettore riprepara/ritenta il voto, i campi _c_voto/_iv qui sopra
        # cambierebbero; questa copia congelata resta fedele alla scheda registrata.
        self._voto_inviato = None      # {c_voto, c_k, iv, preferenza, identificativo}

    # ==================================================================
    # FASE 2 — Autenticazione
    # ==================================================================

    def verifica_certificato_sa(self, cert_SA, ca: CertificationAuthority) -> bool:
        """Controlla il certificato dell'SA con pk_CA prima di fidarsi (diagramma: E verifica Cert_SA)."""
        return ca.verifica_certificato(cert_SA)

    def login(self, sa, password: str) -> None:
        """Login OIDC presso l'SA: ottiene e memorizza il token (ID Token)."""
        self._token = sa.login(self._matricola, password)
        self._logger.evento(f"Elettore {self._matricola}: login effettuato")

    def genera_chiavi_effimere(self) -> None:
        """Genera la coppia di chiavi effimere (pk_v, sk_v) per questa elezione."""
        with self._logger.misura("fase2.elettore.genera_chiavi_effimere"):
            self._sk_v, self._pk_v = genera_coppia_rsa()

    def richiedi_credenziale(self, sa: SistemaAutenticazione) -> Credenziale:
        """
        Invia SOLO pk_v all'SA e riceve σ_SA. Costruisce e memorizza la
        credenziale (pk_v, σ_SA). sk_v resta segreta.
        """
        if self._pk_v is None:
            raise ValueError("Genera prima la coppia di chiavi effimere")
        sigma_SA = sa.rilascia_credenziale(self._token, self._pk_v)
        self._credenziale = Credenziale(self._pk_v, sigma_SA)
        self._logger.evento(f"Elettore {self._matricola}: credenziale ricevuta")
        return self._credenziale

    # ==================================================================
    # FASE 3 — Voto
    # ==================================================================

    def richiedi_parametri(self, bp : BachecaPubblica) -> None:
        """Dalla BP recupera la lista chiusa delle opzioni e pk_AE_enc."""
        self._opzioni = bp.get_opzioni()
        self._pk_ae_enc = bp.get_pk_ae_enc()
        self._logger.evento(f"Elettore {self._matricola}: parametri di voto acquisiti")

    def scegli_preferenza(self, indice: int) -> None:
        """Sceglie l'opzione di voto (indice nella lista chiusa)."""
        if not (0 <= indice < len(self._opzioni)):
            raise ValueError("Preferenza fuori dalla lista delle opzioni")
        self._preferenza = indice

    def prepara_pacchetto(self) -> PacchettoVoto:
        """
        Prepara e cifra il voto, poi firma la scheda. La cifratura dipende da
        config.MODALITA_CIFRATURA:
          - "ibrida": C_voto = AES-CBC(voto) ; C_k = RSA-OAEP(pk_AE_enc, k_AES)
          - "rsa"   : C_voto = RSA-OAEP(pk_AE_enc, voto) ; niente AES (C_k e IV vuoti)
        In entrambi i casi: B = (C_voto, C_k, IV), σ_v = Sign_sk_v(B), M = (B, cred, σ_v).
        """
        if self._preferenza is None:
            raise ValueError("Scegli prima una preferenza")
        if self._credenziale is None:
            raise ValueError("Serve la credenziale rilasciata dall'SA")

        voto_bytes = self._preferenza.to_bytes(VOTER_CHOICE_BYTE_LENGTH, "big")

        if config.MODALITA_CIFRATURA == "rsa":
            # cifratura del voto DIRETTAMENTE con RSA-OAEP: niente chiave AES né IV
            self._k_AES = b""
            self._iv = b""
            with self._logger.misura("fase3.elettore.cifra_voto"):
                self._c_voto = cifra_rsa_oaep(self._pk_ae_enc, voto_bytes)
            self._c_k = b""
        else:
            # cifratura ibrida (default): AES-CBC sul voto, RSA-OAEP sulla chiave AES
            self._k_AES = secrets.token_bytes(AES_KEY_SIZE)
            self._iv = secrets.token_bytes(AES_IV_SIZE)
            with self._logger.misura("fase3.elettore.cifra_voto"):
                self._c_voto = cifra_aes_cbc(self._k_AES, self._iv, voto_bytes)
            with self._logger.misura("fase3.elettore.cifra_chiave"):
                self._c_k = cifra_rsa_oaep(self._pk_ae_enc, self._k_AES)

        # compone la scheda B e la firma con sk_v (RSA-PSS)
        self._scheda = Scheda(self._c_voto, self._c_k, self._iv)
        B_bytes = serializza_B(self._c_voto, self._c_k, self._iv)
        with self._logger.misura("fase3.elettore.firma_scheda"):
            self._sigma_v = firma_pss(self._sk_v, B_bytes, PSS_PADDING_LENGTH_ELETTORE)

        self._pacchetto = PacchettoVoto(self._scheda, self._credenziale, self._sigma_v)

        # dimensioni che viaggiano sulla rete
        self._logger.registra_byte("byte.scheda.c_voto", len(self._c_voto))
        self._logger.registra_byte("byte.scheda.c_k", len(self._c_k))
        self._logger.registra_byte("byte.scheda.iv", len(self._iv))
        self._logger.registra_byte("byte.scheda", len(B_bytes))
        self._logger.registra_byte(
            "byte.pacchetto",
            len(B_bytes) + len(self._credenziale.sigma_SA) + len(self._sigma_v),
        )
        self._logger.evento(f"Elettore {self._matricola}: pacchetto M pronto")
        return self._pacchetto

    def invia_voto(self, ae : AutoritaElettorale) -> bytes:
        """Invia M all'AE e riceve la ricevuta R (memorizza l'identivicativo i e R)."""
        if self._pacchetto is None:
            raise ValueError("Prepara prima il pacchetto di voto")
        if self._voto_inviato is not None:
            raise ValueError("Hai già votato: la credenziale è monouso")

        self._i, self._ricevuta = ae.riceve_voto(self._pacchetto)

        # congeliamo la scheda inviata: da qui in poi la verifica usa questi valori,
        # così eventuali nuove preparazioni non corrompono i dati di verifica
        self._voto_inviato = {
            "c_voto": self._c_voto,
            "c_k": self._c_k,
            "iv": self._iv,
            "preferenza": self._preferenza,
            "identificativo": self._i,
        }
        self._logger.evento(
            f"Elettore {self._matricola}: voto inviato, ricevuta per i={self._i}"
        )
        return self._ricevuta

    # ==================================================================
    # FASE 5 — Verifica individuale
    # ==================================================================

    def verifica_individuale(self, bp) -> dict:
        """
        Verifica individuale a PASSI, contattando SOLO la Bacheca Pubblica (l'AE
        non viene coinvolto). Le chiavi pubbliche servono solo a verificare firme e
        sono lette dalla BP (pk_AE_sig) o appartengono alla BP (pk_BP).

        I dati usati sono quelli "congelati" all'invio (self._voto_inviato), non
        quelli correnti: così riprepare il voto non corrompe la verifica.

        Passi (durante l'elezione):
          1) il mio voto è incluso nel blocco i della BP?
          2) il contenuto pubblicato (C_voto, C_k, IV) è ciò che ho inviato?
          3) la ricevuta pubblicata è quella che l'AE mi ha restituito?
          4) la ricevuta R è una firma valida dell'AE su H(B||i)?
        Passi aggiuntivi (dopo lo scrutinio, quando la BP ha costruito l'albero):
          5) la BP mi dà una prova di inclusione: ricalcolo la radice dalla mia foglia;
          6) la radice ricalcolata è firmata dalla BP (merkleRootFirmata)?
          7) il voto pubblicato nell'esito coincide con la preferenza espressa?
          8) ridecifrando C_voto si riottiene la preferenza (solo cifratura ibrida).
        """
        if self._voto_inviato is None:
            raise ValueError("L'elettore non ha ancora votato")

        # dati congelati all'invio (immuni a nuove preparazioni del voto)
        v = self._voto_inviato
        c_voto, c_k, iv = v["c_voto"], v["c_k"], v["iv"]
        i, preferenza = v["identificativo"], v["preferenza"]

        passi = []
        def aggiungi(titolo, dettaglio, esito):
            # numera i passi automaticamente in base a quanti ne abbiamo già
            passi.append({"titolo": f"{len(passi) + 1} · {titolo}", "dettaglio": dettaglio, "esito": esito})

        pk_ae_sig = bp.get_pk_ae_sig()   # chiave di firma dell'AE, letta dalla BP

        # ============ A) Verifiche disponibili DURANTE l'elezione ============
        # leggo dalla blockchain la voce di voto con il mio identificativo i
        voce = bp.leggi_voto(i)
        incluso = voce is not None
        aggiungi("Il mio voto è sulla BP (blocco i)",
                 f"Cerco nella blockchain la voce di voto con il mio identificativo i={i}.",
                 incluso)

        if incluso:
            # il contenuto pubblicato coincide con la scheda che ho spedito?
            contenuto_ok = (voce["c_voto"] == c_voto.hex()
                            and voce["c_k"] == c_k.hex()
                            and voce["iv"] == iv.hex())
            aggiungi("Il contenuto del blocco è ciò che ho inviato",
                     "Confronto C_voto, C_k e IV pubblicati con quelli della scheda spedita.",
                     contenuto_ok)

            # la ricevuta pubblicata è quella che l'AE mi ha restituito all'invio?
            ricevuta_pubblicata_ok = (voce["ricevuta"] == self._ricevuta.hex())
            aggiungi("La ricevuta pubblicata è quella che mi è stata restituita",
                     "Confronto la ricevuta R nel blocco con quella ricevuta dall'AE.",
                     ricevuta_pubblicata_ok)

            # R è davvero una firma valida dell'AE su H(B||i)? (pk_AE_sig dalla BP)
            h_bi = hash_blocco_hex(c_voto, c_k, iv, i)
            with self._logger.misura("fase5.elettore.verifica_ricevuta"):
                firma_ok = verifica_pss(
                    pk_ae_sig, self._ricevuta, bytes.fromhex(h_bi), PSS_PADDING_LENGTH_AE)
            aggiungi("La ricevuta R è una firma valida dell'AE su H(B||i)",
                     "Verifico la firma RSA-PSS dell'AE sull'hash del blocco.",
                     firma_ok)

        # ============ B) Verifiche aggiuntive DOPO lo scrutinio (via BP) ============
        voto_pubblicato = None
        try:
            # la BP mi fornisce la prova di inclusione + la radice firmata da lei
            prova = bp.genera_prova_inclusione(i)
        except ValueError:
            prova = None   # albero non ancora costruito: urna ancora aperta

        if prova is not None:
            # 5) ricalcolo io stesso la radice partendo dalla mia foglia
            foglia = foglia_merkle(c_voto, c_k, iv, i)
            with self._logger.misura("fase5.elettore.verifica_merkle"):
                corrente = sha256_hex(foglia)
                for posizione, fratello in prova["proof"]:
                    corrente = (sha256_hex(corrente + fratello) if posizione == "right"
                                else sha256_hex(fratello + corrente))
                merkle_ok = (corrente == prova["root"])
            aggiungi("Prova di inclusione di Merkle (dalla BP)",
                     f"Ricalcolo la radice dalla mia foglia: {corrente[:24]}...",
                     merkle_ok)

            # 6) la radice è firmata dalla BP? (merkleRootFirmata, verificata con pk_BP)
            firma_radice = bytes.fromhex(prova["firma_radice"])
            with self._logger.misura("fase5.elettore.verifica_firma_radice"):
                firma_radice_ok = verifica_pss(
                    bp.get_pk_bp(), firma_radice, prova["root"].encode("utf-8"), PSS_PADDING_LENGTH_BP)
            aggiungi("La radice è firmata dalla BP (merkleRootFirmata)",
                     "Verifico la firma RSA-PSS della BP sulla radice di Merkle.",
                     firma_radice_ok)

            # 7) il voto pubblicato nell'esito coincide con la mia preferenza?
            esito = bp.leggi_esito()
            triple = esito["corpo"]["triple"] if esito else []
            mia = next((t for t in triple if t["i"] == i), None)
            if mia is not None:
                voto_pubblicato = mia["voto"]
                voto_ok = (mia["voto"] == self._opzioni[preferenza])
                aggiungi("Voto pubblicato == preferenza",
                         f"Pubblicato '{mia['voto']}', io avevo scelto '{self._opzioni[preferenza]}'.",
                         voto_ok)

                # 8) ridecifratura (solo cifratura ibrida: la k_AES è pubblicata)
                if mia["k_AES"]:
                    k = bytes.fromhex(mia["k_AES"])
                    iv_pub = bytes.fromhex(mia["iv"])
                    try:
                        voto_ridecifrato = int.from_bytes(decifra_aes_cbc(k, iv_pub, c_voto), "big")
                        ridecifra_ok = (voto_ridecifrato == preferenza)
                        dettaglio = f"Con la k_AES pubblicata ridecifro C_voto e riottengo l'indice {voto_ridecifrato}."
                    except Exception:
                        # C_voto corrotto o non coerente: la decifratura fallisce
                        ridecifra_ok = False
                        dettaglio = "La ridecifratura di C_voto è fallita (scheda non coerente)."
                    aggiungi("Ridecifratura di C_voto", dettaglio, ridecifra_ok)

        tutto_ok = all(p["esito"] for p in passi)
        self._logger.evento(
            f"Elettore {self._matricola}: verifica individuale -> {'OK' if tutto_ok else 'FALLITA'}"
        )
        return {
            "identificativo": i,
            "fase": "scrutinio" if prova is not None else "in_corso",
            "voto_pubblicato": voto_pubblicato,
            "passi": passi,
            "tutto_ok": tutto_ok,
        }

    # ==================================================================
    # Letture per la web app
    # ==================================================================

    def stato(self) -> dict:
        """Riepilogo leggibile dello stato dell'elettore (per la sezione step-by-step)."""
        return {
            "matricola": self._matricola,
            #"token": (self._token[:12] + "...") if self._token else None,
            "token": self._token if self._token else None,
            "ha_votato": self._voto_inviato is not None,
            "ha_chiavi": self._pk_v is not None,
            "ha_credenziale": self._credenziale is not None,
            "ha_pacchetto": self._pacchetto is not None,
            "credenziale": {
                "pk_v": pk_to_pem(self._pk_v) if self._pk_v is not None else None,
                "sigma_SA": self._credenziale.sigma_SA.hex(),
            } if self._credenziale is not None else None,
            "preferenza": self._preferenza,
            "pacchetto": {
                "c_voto": self._pacchetto.scheda.c_voto.hex(),
                "c_k": self._pacchetto.scheda.c_k.hex(),
                "iv": self._pacchetto.scheda.iv.hex(),
                "sigma_v": self._pacchetto.sigma_v.hex(),
            } if self._pacchetto is not None else None,
            "voto_inviato": {
                "c_voto": self._voto_inviato["c_voto"].hex(),
                "c_k": self._voto_inviato["c_k"].hex(),
                "iv": self._voto_inviato["iv"].hex(),
                "preferenza": self._voto_inviato["preferenza"],
                "identificativo": self._voto_inviato["identificativo"],
            } if self._voto_inviato is not None else None,
            "identificativo": self._i,
            "ricevuta": self._ricevuta.hex() if self._ricevuta else None,
        }

    @property
    def matricola(self) -> str:
        return self._matricola

    @property
    def identificativo(self):
        return self._i

    @property
    def seriale(self):
        return self._i
