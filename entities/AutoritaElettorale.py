"""
AutoritaElettorale (AE) — Fasi 1, 3, 4, 5.

L'AE raccoglie le schede cifrate, rilascia le ricevute, e a urne chiuse esegue lo
scrutinio pubblicando l'esito sulla Bacheca Pubblica.

Chiavi (Fase 1: due coppie distinte per separare le funzioni):
    (pk_AE_enc, sk_AE_enc) -> cifratura/decifratura dei voti (RSA-OAEP)
    (pk_AE_sig, sk_AE_sig) -> firma delle pubblicazioni e delle ricevute (RSA-PSS)

Tabelle interne (private):
    _tabella_voti      : Fase 3 — entry (i, C_voto, C_k, IV) costruita man mano
                         che arrivano voti validi (più pk_v e ricevuta R).
    _tabella_scrutinio : Fase 4 — entry (i, voto, k_AES) costruita decifrando.
    _pk_v_usate        : insieme delle pk_v già spese (anti doppio voto).
    _merkle            : albero di Merkle sulle foglie H(B||i), costruito a urne chiuse.
"""

import json

import config   # letto a runtime per la modalità di cifratura (ibrida / rsa)
from config import (PSS_PADDING_LENGTH_AE, PSS_PADDING_LENGTH_ELETTORE, OPZIONI_DEFAULT,
                    VOTER_CHOICE_BYTE_LENGTH)
from elements.cripto import (genera_coppia_rsa, firma_pss, verifica_pss,
                             decifra_rsa_oaep, decifra_aes_cbc,
                             serializza_B, hash_blocco_hex,
                             pk_to_der, pk_to_pem)
from elements.ProtocolLogger import _NullLogger
from elements.Scheda import Scheda
from elements.PacchettoVoto import PacchettoVoto


class AutoritaElettorale:
    """Raccoglie i voti, esegue lo scrutinio e pubblica i risultati firmati."""

    def __init__(self, ca, bp, opzioni: list = None, logger=None):
        self._logger = logger or _NullLogger()
        self._bp = bp
        self._opzioni = list(opzioni) if opzioni else list(OPZIONI_DEFAULT)

        # Fase 1 — due coppie di chiavi
        with self._logger.misura("fase1.ae.genera_chiavi_enc"):
            self._sk_AE_enc, self.pk_AE_enc = genera_coppia_rsa()
        with self._logger.misura("fase1.ae.genera_chiavi_sig"):
            self._sk_AE_sig, self.pk_AE_sig = genera_coppia_rsa()

        # la CA certifica entrambe le chiavi pubbliche dell'AE
        self._cert_AE_enc = ca.emetti_certificato("AE-enc", self.pk_AE_enc)
        self._cert_AE_sig = ca.emetti_certificato("AE-sig", self.pk_AE_sig)

        # chiave pubblica dell'SA (impostata in setup, dopo aver verificato il cert)
        self._pk_SA = None

        # Fase 3 — registro dei voti ricevuti
        self._tabella_voti: list[dict] = []   # {i, c_voto, c_k, iv, pk_v_pem, ricevuta}
        self._pk_v_usate: set = set()

        # Fase 4 — scrutinio (l'albero di Merkle è ora responsabilità della BP)
        self._tabella_scrutinio: list[dict] = []  # {i, voto_idx, voto_label, k_AES, iv}
        self._totali: dict = {}
        self._urna_chiusa = False

    # ==================================================================
    # FASE 1 — Setup
    # ==================================================================

    def collega_sistema_autenticazione(self, cert_SA, ca) -> None:
        """
        Verifica il certificato dell'SA con la CA ed estrae pk_SA.
        Da qui in poi l'AE può validare le credenziali firmate dall'SA.
        """
        if not ca.verifica_certificato(cert_SA):
            raise ValueError("Certificato SA non valido: setup interrotto")
        self._pk_SA = cert_SA.public_key()
        self._logger.evento("AE: pk_SA acquisita e certificato verificato")

    def pubblica_parametri(self) -> None:
        """
        Fase 1: firma i parametri (pk_AE_enc + lista chiusa delle opzioni) con
        sk_AE_sig e li pubblica sulla BP.
        """
        pk_enc_pem = pk_to_pem(self.pk_AE_enc)
        pk_sig_pem = pk_to_pem(self.pk_AE_sig)
        # firmiamo la coppia (opzioni, pk_enc) così che chiunque possa verificarne l'autenticità
        contenuto = json.dumps({"opzioni": self._opzioni, "pk_ae_enc": pk_enc_pem},
                               sort_keys=True).encode("utf-8")
        with self._logger.misura("fase1.ae.firma_parametri"):
            firma = firma_pss(self._sk_AE_sig, contenuto, PSS_PADDING_LENGTH_AE)

        # pubblichiamo anche pk_AE_sig: così elettori e osservatori verificano le
        # firme dell'AE leggendola dalla BP, senza dover contattare l'AE.
        self._bp.riceve_parametri_da_ae(self._opzioni, pk_enc_pem, pk_sig_pem)
        self._logger.registra_byte("byte.firma_parametri", len(firma))
        self._logger.evento("AE: parametri di voto pubblicati sulla BP")

    # ==================================================================
    # FASE 3 — Ricezione e registrazione del voto
    # ==================================================================

    def riceve_voto(self, pacchetto: PacchettoVoto) -> tuple[int, bytes]:
        """
        Riceve M = (B, (pk_v, σ_SA), σ_v). Verifica credenziale, firma ed unicità.
        Se tutto è valido assegna l'indice i, calcola H(B||i), firma la ricevuta R,
        registra la entry e la pubblica sulla BP. Restituisce (i, R).
        Solleva ValueError se la scheda è rifiutata.
        """
        if self._urna_chiusa:
            raise ValueError("Urna chiusa: voto non accettato")

        scheda = pacchetto.scheda
        pk_v = pacchetto.credenziale.pk_v
        sigma_SA = pacchetto.credenziale.sigma_SA
        sigma_v = pacchetto.sigma_v

        B_bytes = serializza_B(scheda.c_voto, scheda.c_k, scheda.iv)
        pk_v_pem = pk_to_pem(pk_v)

        # 1) la credenziale è valida? σ_SA deve verificare su pk_v con pk_SA
        with self._logger.misura("fase3.ae.verifica_credenziale"):
            cred_valida = verifica_pss(self._pk_SA, sigma_SA, pk_to_der(pk_v), PSS_PADDING_LENGTH_AE)
        if not cred_valida:
            raise ValueError("Scheda rifiutata: credenziale (σ_SA) non valida")

        # 2) la firma dell'elettore sulla scheda è valida? σ_v deve verificare su B con pk_v
        with self._logger.misura("fase3.ae.verifica_firma_scheda"):
            ballot_valido = verifica_pss(pk_v, sigma_v, B_bytes, PSS_PADDING_LENGTH_ELETTORE)
        if not ballot_valido:
            raise ValueError("Scheda rifiutata: firma dell'elettore (σ_v) non valida")

        # 3) la pk_v non deve essere già stata usata (anti doppio voto)
        if pk_v_pem in self._pk_v_usate:
            raise ValueError("Scheda rifiutata: credenziale già spesa")

        # assegna l'indice i e calcola la ricevuta R = Sign_sk_AE_sig(H(B||i))
        i = len(self._tabella_voti)+2
        h_bi = hash_blocco_hex(scheda.c_voto, scheda.c_k, scheda.iv, i)
        with self._logger.misura("fase3.ae.firma_ricevuta"):
            ricevuta = firma_pss(self._sk_AE_sig, bytes.fromhex(h_bi), PSS_PADDING_LENGTH_AE)

        # registra la entry e marca la credenziale come spesa
        self._tabella_voti.append({
            "i": i,
            "c_voto": scheda.c_voto,
            "c_k": scheda.c_k,
            "iv": scheda.iv,
            "pk_v_pem": pk_v_pem,
            "ricevuta": ricevuta,
        })
        self._pk_v_usate.add(pk_v_pem)

        # pubblica (i, C_voto, C_k, IV, R) sulla BP
        self._bp.riceve_voto_da_ae((i, scheda, ricevuta))

        self._logger.registra_byte("byte.ricevuta", len(ricevuta))
        self._logger.evento(f"AE: voto registrato con identificativo i={i}")
        return i, ricevuta

    # ==================================================================
    # FASE 4 — Scrutinio (a urne chiuse)
    # ==================================================================

    def chiudi_urna_e_scrutina(self) -> dict:
        """
        Chiude l'urna, decifra ogni scheda, conta i voti, costruisce l'albero di
        Merkle sulle foglie H(B||i) e pubblica il risultato firmato sulla BP.
        Restituisce un riepilogo (totali, radice di Merkle, n_voti).
        """
        self._urna_chiusa = True
        self._tabella_scrutinio.clear()
        conteggio = {opzione: 0 for opzione in self._opzioni}

        for entry in self._tabella_voti:
            if config.MODALITA_CIFRATURA == "rsa":
                # il voto è cifrato direttamente con RSA-OAEP: una sola decifratura
                with self._logger.misura("fase4.ae.decifra_voto"):
                    voto_bytes = decifra_rsa_oaep(self._sk_AE_enc, entry["c_voto"])
                k_AES = b""   # nessuna chiave di sessione in questa modalità
            else:
                # cifratura ibrida: prima la chiave AES (RSA-OAEP), poi il voto (AES-CBC)
                with self._logger.misura("fase4.ae.decifra_chiave"):
                    k_AES = decifra_rsa_oaep(self._sk_AE_enc, entry["c_k"])
                with self._logger.misura("fase4.ae.decifra_voto"):
                    voto_bytes = decifra_aes_cbc(k_AES, entry["iv"], entry["c_voto"])

            voto_idx = int.from_bytes(voto_bytes, "big")
            voto_label = self._opzioni[voto_idx]
            conteggio[voto_label] += 1

            self._tabella_scrutinio.append({
                "i": entry["i"],
                "voto_idx": voto_idx,
                "voto_label": voto_label,
                "k_AES": k_AES,
                "iv": entry["iv"],
            })

        self._totali = conteggio

        # 3) pubblica l'esito (triple i/voto/k_AES + totali) firmato con sk_AE_sig
        self._pubblica_risultato()

        # 4) chiede alla BP di costruirsi il proprio albero di Merkle e di
        #    pubblicarne la radice firmata. Da qui in poi è la BP a servire le
        #    prove di inclusione: l'AE esce di scena.
        radice = self._bp.costruisci_merkle()

        self._logger.evento(f"AE: scrutinio completato — {len(self._tabella_voti)} voti")
        return {
            "totali": self._totali,
            "merkle_root": radice,
            "n_voti": len(self._tabella_voti),
        }

    def _pubblica_risultato(self) -> None:
        """Compone la voce di esito (triple i/voto/k_AES + totali), la firma e la pubblica."""
        triple = [
            {
                "i": s["i"],
                "voto": s["voto_label"],
                "k_AES": s["k_AES"].hex(),
                "iv": s["iv"].hex(),
            }
            for s in self._tabella_scrutinio
        ]
        corpo = {
            "tipo": "scrutinio",
            "triple": triple,
            "totali": self._totali,
        }
        contenuto = json.dumps(corpo, sort_keys=True).encode("utf-8")
        with self._logger.misura("fase4.ae.firma_risultato"):
            firma = firma_pss(self._sk_AE_sig, contenuto, PSS_PADDING_LENGTH_AE)

        voce = json.dumps({"corpo": corpo, "firma": firma.hex()})
        self._bp.riceve_scrutinio_da_ae(voce)
        self._logger.registra_byte("byte.voce_scrutinio", len(voce.encode("utf-8")))

    # ==================================================================
    # Letture e reset
    # ==================================================================

    def get_pk_sig(self):
        """Chiave pubblica di firma dell'AE (per verificare ricevute e pubblicazioni)."""
        return self.pk_AE_sig

    def get_opzioni(self) -> list:
        return list(self._opzioni)

    def get_totali(self) -> dict:
        return dict(self._totali)

    def snapshot_voti(self) -> list[dict]:
        """Tabella dei voti ricevuti (in forma leggibile) per la web app."""
        return [
            {
                "i": e["i"],
                "c_voto": e["c_voto"].hex()[:16] + "...",
                #"c_voto": e["c_voto"].hex(),
                "c_k": e["c_k"].hex()[:16] + "...",
                #"c_k": e["c_k"].hex(),
                "iv": e["iv"].hex(),
            }
            for e in self._tabella_voti
        ]

    def snapshot_scrutinio(self) -> list[dict]:
        """Tabella di scrutinio (i, voto, k_AES) per la web app."""
        return [
            {
                "i": entry["i"],
                "voto": entry["voto_label"],
                #"k_AES": entry["k_AES"].hex()[:16] + "...",
                "k_AES": entry["k_AES"].hex(),
            }
            for entry in self._tabella_scrutinio
        ]

    def reset(self) -> None:
        """Svuota tutte le tabelle e lo stato dell'urna (nuova elezione)."""
        self._tabella_voti.clear()
        self._pk_v_usate.clear()
        self._tabella_scrutinio.clear()
        self._totali = {}
        self._merkle = None
        self._urna_chiusa = False
