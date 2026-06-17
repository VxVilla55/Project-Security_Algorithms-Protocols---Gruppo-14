"""
Osservatore (O) — Fase 5: Verifica universale.

Chiunque, usando SOLO i dati pubblici della Bacheca Pubblica e la chiave pubblica
di firma dell'AE (pk_AE_sig, certificata dalla CA), può ricalcolare l'esito da zero
e accorgersi di eventuali imbrogli. L'osservatore NON conosce alcun segreto.

Controlli (come da diagramma 'verifica'):
  1) Autenticità : ogni ricevuta R e la voce di scrutinio sono firmate dall'AE.
  2) Integrità   : ricostruisce l'albero di Merkle dalle foglie H(B||i) e confronta la radice.
  3) Decifratura : ridecifra ogni C_voto con la k_AES pubblicata e verifica il voto.
  4) Conteggio   : risomma i voti e confronta con i totali dichiarati.
"""

import json

from config import PSS_PADDING_LENGTH_AE, PSS_PADDING_LENGTH_BP
from elements.cripto import (verifica_pss, decifra_aes_cbc, foglia_merkle, hash_blocco_hex)
from elements.MerkleTree import MerkleTree
from elements.ProtocolLogger import _NullLogger


class Osservatore:
    """Verificatore esterno e indipendente dell'esito dell'elezione."""

    def __init__(self, logger=None):
        self._logger = logger or _NullLogger()

    def verifica_universale(self, bp, opzioni: list) -> dict:
        """
        Esegue i 4 controlli pubblici leggendo TUTTO dalla BP (l'AE non viene
        contattato): le chiavi pubbliche (pk_AE_sig, pk_BP), i voti, l'esito e la
        radice di Merkle firmata dalla BP. Restituisce la lista ordinata dei passi.
        """
        voci = bp.get_voci()
        voti = self._leggi_voti(voci)            # entry di voto pubblicate in Fase 3
        scrutinio = self._leggi_scrutinio(voci)  # esito (triple + totali) firmato dall'AE
        merkle = bp.leggi_radice_firmata()       # radice + firma della BP

        if scrutinio is None or merkle is None or not voti:
            raise ValueError("La verifica universale richiede voti, esito e radice già pubblicati")

        pk_ae_sig = bp.get_pk_ae_sig()           # chiavi pubbliche lette dalla BP
        pk_bp = bp.get_pk_bp()

        corpo = scrutinio["corpo"]
        firma_scrutinio = bytes.fromhex(scrutinio["firma"])
        radice_pubblicata = merkle["merkle_root"]
        firma_radice = bytes.fromhex(merkle["firma_bp"])

        # --- Passo 1: Autenticità (firme dell'AE sull'esito/ricevute, firma BP sulla radice) ---
        with self._logger.misura("fase5.osservatore.autenticita"):
            # 1a) ogni ricevuta R firma H(B||i) (firma dell'AE)
            ricevute_ok = True
            for v in voti:
                h_bi = hash_blocco_hex(v["c_voto"], v["c_k"], v["iv"], v["i"])
                if not verifica_pss(pk_ae_sig, v["ricevuta"], bytes.fromhex(h_bi), PSS_PADDING_LENGTH_AE):
                    ricevute_ok = False
                    break
            # 1b) la voce di esito è firmata dall'AE
            contenuto = json.dumps(corpo, sort_keys=True).encode("utf-8")
            esito_ok = verifica_pss(pk_ae_sig, firma_scrutinio, contenuto, PSS_PADDING_LENGTH_AE)
            # 1c) la radice di Merkle è firmata dalla BP
            radice_ok = verifica_pss(pk_bp, firma_radice, radice_pubblicata.encode("utf-8"),
                                     PSS_PADDING_LENGTH_BP)
        autenticita_ok = ricevute_ok and esito_ok and radice_ok

        # --- Passo 2: Integrità (ricalcolo dell'albero di Merkle) ---
        with self._logger.misura("fase5.osservatore.integrita"):
            foglie = [foglia_merkle(v["c_voto"], v["c_k"], v["iv"], v["i"]) for v in voti]
            radice_ricalcolata = MerkleTree(foglie).root
            integrita_ok = (radice_ricalcolata == radice_pubblicata)

        # --- Passo 3: Decifratura di ogni scheda con la chiave pubblicata ---
        # Possibile solo in cifratura ibrida: l'AE pubblica le k_AES. In modalità
        # RSA-pura il voto è cifrato con la chiave dell'AE e nessuno, all'infuori
        # dell'AE, può decifrarlo: questo passo viene quindi saltato.
        decifrabile = bool(corpo["triple"]) and all(t["k_AES"] for t in corpo["triple"])
        with self._logger.misura("fase5.osservatore.decifratura"):
            decifratura_ok = True
            if decifrabile:
                voti_per_i = {v["i"]: v for v in voti}
                for t in corpo["triple"]:
                    v = voti_per_i.get(t["i"])
                    k_AES = bytes.fromhex(t["k_AES"])
                    iv = bytes.fromhex(t["iv"])
                    indice = int.from_bytes(decifra_aes_cbc(k_AES, iv, v["c_voto"]), "big")
                    if opzioni[indice] != t["voto"]:
                        decifratura_ok = False
                        break

        # --- Passo 4: Conteggio indipendente ---
        with self._logger.misura("fase5.osservatore.conteggio"):
            conteggio = {opzione: 0 for opzione in opzioni}
            for t in corpo["triple"]:
                conteggio[t["voto"]] += 1
            conteggio_ok = (conteggio == corpo["totali"])

        passi = [
            {"titolo": "1 · Autenticità delle firme",
             "dettaglio": f"Verifico le {len(voti)} ricevute R e l'esito (firma AE) e la radice di Merkle (firma BP).",
             "esito": autenticita_ok},
            {"titolo": "2 · Integrità (radice di Merkle)",
             #"dettaglio": f"Ricalcolo la radice dalle foglie H(B||i): {radice_ricalcolata[:24]}...",
             "dettaglio": f"Ricalcolo la radice dalle foglie H(B||i): {radice_ricalcolata}",
             "esito": integrita_ok},
            {"titolo": "3 · Decifratura di ogni scheda",
             "dettaglio": ("Ridecifro ogni C_voto con la k_AES pubblicata e confronto col voto dichiarato."
                           if decifrabile else
                           "Saltata: in modalità RSA-pura la k_AES non è pubblicata, solo l'AE può decifrare."),
             "esito": decifratura_ok},
            {"titolo": "4 · Conteggio indipendente",
             "dettaglio": f"Risommo i voti: {conteggio}",
             "esito": conteggio_ok},
        ]
        tutto_ok = all(p["esito"] for p in passi)
        self._logger.evento(f"Osservatore: verifica universale -> {'OK' if tutto_ok else 'FALLITA'}")
        return {
            "passi": passi,
            "totali_ricalcolati": conteggio,
            "totali_pubblicati": corpo["totali"],
            "merkle_root": radice_pubblicata,
            "tutto_ok": tutto_ok,
        }

    # ------------------------------------------------------------------
    # Lettura dei dati pubblici dalla BP
    # ------------------------------------------------------------------

    @staticmethod
    def _leggi_voti(voci: list) -> list:
        """Estrae le entry di voto (tipo 'voto') convertendo i campi hex in byte."""
        voti = []
        for entry in voci:
            try:
                d = json.loads(entry)
            except (ValueError, TypeError):
                continue
            if isinstance(d, dict) and d.get("tipo") == "voto":
                voti.append({
                    "i": d["i"],
                    "c_voto": bytes.fromhex(d["c_voto"]),
                    "c_k": bytes.fromhex(d["c_k"]),
                    "iv": bytes.fromhex(d["iv"]),
                    "ricevuta": bytes.fromhex(d["ricevuta"]),
                })
        voti.sort(key=lambda v: v["i"])   # ordine per identificativo i
        return voti

    @staticmethod
    def _leggi_scrutinio(voci: list) -> dict:
        """Estrae la voce di scrutinio ({corpo, firma}) dalla BP, se presente."""
        for entry in reversed(voci):
            try:
                d = json.loads(entry)
            except (ValueError, TypeError):
                continue
            if isinstance(d, dict) and d.get("corpo", {}).get("tipo") == "scrutinio":
                return d
        return None
