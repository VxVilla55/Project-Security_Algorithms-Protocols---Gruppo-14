import hashlib
import json
import time
from pathlib import Path
from typing import List

from cryptography.hazmat.primitives.serialization import load_pem_public_key

from entities.BachecaPubblica import BachecaPubblica
from elements.ProtocolLogger import _NullLogger
from elements.MerkleTree import MerkleTree
from elements.cripto import genera_coppia_rsa, firma_pss, pk_to_pem
from config import PSS_PADDING_LENGTH_BP


# --- Strutture interne della blockchain ---

class Transaction:
    entry: str

    def __init__(self, entry: str):
        self.entry = entry

    def to_dict(self) -> dict:
        return {"entry": self.entry}

    @staticmethod
    def from_dict(data: dict) -> "Transaction":
        return Transaction(entry=data["entry"])


class BlockHeader:
    index: int
    timestamp: float
    nonce: int
    hash_previous_block: str

    def __init__(self, index: int, timestamp: float, nonce: int,
                 hash_previous_block: str):
        self.index = index
        self.timestamp = timestamp
        self.nonce = nonce
        self.hash_previous_block = hash_previous_block

    def to_string(self) -> str:
        return f"{self.index}{self.timestamp}{self.nonce}{self.hash_previous_block}"

    def to_dict(self) -> dict:
        return {
            "index": self.index,
            "timestamp": self.timestamp,
            "nonce": self.nonce,
            "hash_previous_block": self.hash_previous_block,
        }

    @staticmethod
    def from_dict(data: dict) -> "BlockHeader":
        return BlockHeader(
            index=data["index"],
            timestamp=data["timestamp"],
            nonce=data["nonce"],
            hash_previous_block=data["hash_previous_block"],
        )


class Block:
    header: BlockHeader
    transactions: List[Transaction]
    hash: str

    def __init__(self, index: int, hash_previous_block: str, data: List[Transaction]):
        self.transactions = data
        self.header = BlockHeader(
            index=index,
            timestamp=time.time(),
            nonce=0,
            hash_previous_block=hash_previous_block,
        )
        self.hash = self.calculate_hash()

    def calculate_hash(self) -> str:
        # l'hash del blocco lega header + transazioni: così l'integrità della catena
        # copre anche il contenuto pubblicato, non solo i metadati dell'header.
        contenuto = self.header.to_string() + "".join(tx.entry for tx in self.transactions)
        return hashlib.sha256(contenuto.encode("utf-8")).hexdigest()

    def to_dict(self) -> dict:
        return {
            "header": self.header.to_dict(),
            "transactions": [tx.to_dict() for tx in self.transactions],
            "hash": self.hash,
        }

    @staticmethod
    def from_dict(data: dict) -> "Block":
        transactions = [Transaction.from_dict(tx) for tx in data["transactions"]]
        header = BlockHeader.from_dict(data["header"])
        # ricostruiamo il blocco senza ricalcolare (i valori vengono dal file)
        block = object.__new__(Block)
        block.transactions = transactions
        block.header = header
        block.hash = data["hash"]
        return block


class BlockChain:
    json_path: Path
    chain: List[Block]

    def __init__(self, json_path: Path):
        self.json_path = json_path
        self.chain: List[Block] = []

        if json_path.exists():
            self._load_from_file()
        else:
            self._create_first_block()
            self._save_to_file()

    def _create_first_block(self): #dovrà contenere i parametri della votazione: opzioni della lista chiusa ad esempio.
        first_block = Block(
            index=0,
            hash_previous_block="0" * 64,
            data=[Transaction(entry="First Block")],
        )
        self.chain.append(first_block)

    def add_block(self, transactions: List[Transaction]):
        last_block = self.chain[-1]
        new_block = Block(
            index=last_block.header.index + 1,
            hash_previous_block=last_block.hash,
            data=transactions,
        )
        self.chain.append(new_block)
        self._save_to_file()

    def is_valid(self) -> bool:
        for i in range(1, len(self.chain)):
            current = self.chain[i]
            previous = self.chain[i - 1]
            if current.hash != current.calculate_hash():
                return False
            if current.header.hash_previous_block != previous.hash:
                return False
        return True

    def _save_to_file(self):
        data = [block.to_dict() for block in self.chain]
        self.json_path.write_text(json.dumps(data, indent=2), encoding="utf-8")

    def _load_from_file(self):
        data = json.loads(self.json_path.read_text(encoding="utf-8"))
        self.chain = [Block.from_dict(block) for block in data]


# --- Implementazione concreta di BachecaPubblica ---

class BachecaPubblicaObjects(BachecaPubblica):
    """
    Implementazione della BP basata su blockchain a oggetti con persistenza su JSON.
    Ogni voce pubblicata diventa una Transaction in un nuovo Block,
    e la catena viene salvata su file ad ogni scrittura.
    """

    def __init__(self, bp_id: str, json_path: str = "bacheca.json", logger=None):
        self.bp_id = bp_id
        self._blockchain = BlockChain(json_path=Path(json_path))
        self._logger = logger or _NullLogger()

        # Coppia di chiavi propria della BP (certificata dalla CA nel Setup):
        # serve a firmare la radice di Merkle che la BP costruisce alla chiusura.
        with self._logger.misura("fase1.bp.genera_chiavi"):
            self._sk_BP, self.pk_BP = genera_coppia_rsa()

        # Albero di Merkle costruito dalla BP alla chiusura dell'urna (Fase 4/5).
        self._merkle: MerkleTree = None
        self._radice: str = None
        self._firma_radice: bytes = None
        self._ordine_i: dict = {}   # identificativo i -> posizione della foglia

    # ------------------------------------------------------------------
    # Primitive del registro (interfaccia BachecaPubblica)
    # ------------------------------------------------------------------

    def pubblica(self, entry: str) -> None:
        """Scrittura (solo AE): accoda una voce e ne cronometra/misura la scrittura."""
        with self._logger.misura("fase_bp.scrittura_blocco"):
            self._blockchain.add_block([Transaction(entry=entry)])
        # dimensione della voce in byte: una stringa va prima codificata in UTF-8,
        # len() su str conta i caratteri, non i byte effettivamente scritti.
        self._logger.registra_byte("byte.bp_entry", len(entry.encode("utf-8")))

    def get_voci(self) -> list[str]:
        """Lettura (chiunque): tutte le voci pubblicate, saltando il blocco genesis (index 0)."""
        voci = []
        for block in self._blockchain.chain[1:]:
            for tx in block.transactions:
                voci.append(tx.entry)
        return voci

    def verifica_integrita(self) -> bool:
        """Lettura (chiunque): True se la catena append-only non è stata manomessa."""
        return self._blockchain.is_valid()

    # ------------------------------------------------------------------
    # Voci del protocollo di voto (serializzate dall'AE, accodate dalla BP)
    # ------------------------------------------------------------------

    def riceve_parametri_da_ae(self, opzioni: list, pk_ae_enc_pem: str,
                               pk_ae_sig_pem: str = None) -> None:
        """
        Fase 1: pubblica i parametri dell'elezione: lista chiusa delle opzioni,
        chiave pubblica di cifratura dell'AE (pk_AE_enc) e chiave pubblica di firma
        dell'AE (pk_AE_sig). Quest'ultima permette a elettori e osservatori di
        verificare le firme dell'AE leggendola dalla BP, senza contattare l'AE.
        """
        entry = json.dumps({
            "tipo": "opzioni",
            "opzioni": opzioni,
            "pk_ae_enc": pk_ae_enc_pem,
            "pk_ae_sig": pk_ae_sig_pem,
        })
        self.pubblica(entry)

    def _leggi_parametri(self) -> dict:
        """Recupera dal registro la voce dei parametri (tipo 'opzioni')."""
        for entry in self.get_voci():
            dato = json.loads(entry)
            if dato.get("tipo") == "opzioni":
                return dato
        raise RuntimeError("Parametri dell'elezione non trovati sulla BP.")

    def get_opzioni(self) -> list:
        """Lettura: la lista chiusa delle opzioni, letta direttamente dal registro pubblico."""
        return self._leggi_parametri()["opzioni"]

    def get_pk_ae_enc(self):
        """Lettura: la chiave pubblica di cifratura dell'AE, ricostruita dal PEM pubblicato."""
        pem = self._leggi_parametri()["pk_ae_enc"]
        return load_pem_public_key(pem.encode("utf-8"))

    def get_pk_ae_sig(self):
        """Lettura: la chiave pubblica di FIRMA dell'AE, per verificare ricevute ed esito."""
        pem = self._leggi_parametri()["pk_ae_sig"]
        return load_pem_public_key(pem.encode("utf-8"))

    def get_pk_bp(self):
        """Chiave pubblica della BP, per verificare la radice di Merkle firmata dalla BP."""
        return self.pk_BP

    def riceve_voto_da_ae(self, voce: tuple) -> None:
        """Fase 3: riceve (i, scheda B, ricevuta) da AE e la pubblica sulla blockchain."""
        i, B, ricevuta = voce
        entry = json.dumps({
            "tipo": "voto",
            "i": i,
            "c_voto": B.c_voto.hex(),
            "c_k": B.c_k.hex(),
            "iv": B.iv.hex(),
            "ricevuta": ricevuta.hex(),
        })
        self.pubblica(entry)

    def leggi_voto(self, i: int) -> dict:
        """
        Lettura pubblica: recupera la voce di voto con identificativo i (così come
        pubblicata sulla BP). Serve all'elettore per la verifica individuale durante
        l'elezione: confronta ciò che è scritto sulla Bacheca con ciò che ha inviato.
        Restituisce un dizionario con i campi (in esadecimale) oppure None se assente.
        """
        for entry in self.get_voci():
            try:
                dato = json.loads(entry)
            except (ValueError, TypeError):
                continue
            if isinstance(dato, dict) and dato.get("tipo") == "voto" and dato.get("i") == i:
                return dato
        return None

    def riceve_scrutinio_da_ae(self, voce_scrutinio: str) -> None:
        """
        Fase 4: riceve da AE la voce finale di scrutinio (JSON già firmato) e la pubblica
        in un UNICO blocco. Contiene gli esiti per identificativo i (voto, k_AES, iv) e i totali.
        """
        self.pubblica(voce_scrutinio)

    def leggi_esito(self) -> dict:
        """Restituisce la voce di esito {corpo, firma} pubblicata dall'AE, o None."""
        for entry in reversed(self.get_voci()):
            try:
                d = json.loads(entry)
            except (ValueError, TypeError):
                continue
            if isinstance(d, dict) and d.get("corpo", {}).get("tipo") == "scrutinio":
                return d
        return None

    # ------------------------------------------------------------------
    # Albero di Merkle (responsabilità della BP, non più dell'AE)
    # ------------------------------------------------------------------

    def costruisci_merkle(self) -> str:
        """
        Su richiesta dell'AE (alla chiusura dell'urna): la BP costruisce il proprio
        albero di Merkle sulle foglie H(B||i) ricavate dai voti già pubblicati,
        firma la radice con la propria chiave (sk_BP) e la pubblica in un blocco.
        Da questo momento la BP può servire le prove di inclusione agli elettori.
        Restituisce la radice (o None se non ci sono voti).
        """
        voti = []
        for entry in self.get_voci():
            try:
                d = json.loads(entry)
            except (ValueError, TypeError):
                continue
            if isinstance(d, dict) and d.get("tipo") == "voto":
                voti.append(d)
        voti.sort(key=lambda d: d["i"])   # le foglie seguono l'ordine di identificativo i

        if not voti:
            self._merkle = None
            self._radice = None
            self._firma_radice = None
            self._ordine_i = {}
            return None

        # la foglia ha lo stesso formato di elements.cripto.foglia_merkle
        foglie = [f"{d['c_voto']}|{d['c_k']}|{d['iv']}|{d['i']}" for d in voti]
        with self._logger.misura("fase4.bp.costruisce_merkle"):
            self._merkle = MerkleTree(foglie)
        self._ordine_i = {d["i"]: k for k, d in enumerate(voti)}
        self._radice = self._merkle.root

        # la BP firma la propria radice con sk_BP -> "merkleRootFirmata"
        with self._logger.misura("fase4.bp.firma_radice"):
            self._firma_radice = firma_pss(self._sk_BP, self._radice.encode("utf-8"),
                                           PSS_PADDING_LENGTH_BP)

        voce = json.dumps({
            "tipo": "merkle",
            "merkle_root": self._radice,
            "firma_bp": self._firma_radice.hex(),
            "pk_bp": pk_to_pem(self.pk_BP),
        })
        self.pubblica(voce)
        self._logger.registra_byte("byte.firma_radice", len(self._firma_radice))
        self._logger.evento("BP: MerkleTree costruito e radice firmata pubblicata")
        return self._radice

    def genera_prova_inclusione(self, i: int) -> dict:
        """
        Verifica individuale (Fase 5): dato l'identificativo i, la BP restituisce la
        prova di inclusione di Merkle e la radice firmata. L'elettore ricalcola da sé
        la radice dalla propria foglia e la confronta con quella firmata dalla BP.
        """
        if self._merkle is None:
            raise ValueError("Albero di Merkle non ancora costruito (urna non chiusa)")
        if i not in self._ordine_i:
            raise ValueError(f"Nessun voto con identificativo i={i}")
        with self._logger.misura("fase5.bp.genera_merkle_proof"):
            proof = self._merkle.generate_proof(self._ordine_i[i])
        return {
            "i": i,
            "proof": proof,
            "root": self._radice,
            "firma_radice": self._firma_radice.hex(),
        }

    def leggi_radice_firmata(self) -> dict:
        """Restituisce il blocco Merkle {merkle_root, firma_bp, pk_bp} pubblicato dalla BP, o None."""
        for entry in reversed(self.get_voci()):
            try:
                d = json.loads(entry)
            except (ValueError, TypeError):
                continue
            if isinstance(d, dict) and d.get("tipo") == "merkle":
                return d
        return None

    def get_ultimo_blocco(self) -> Block:
        """Restituisce l'ultimo blocco della blockchain."""
        return self._blockchain.chain[-1]

    def riassunto_blocchi(self) -> list[dict]:
        """
        Riassunto leggibile della catena per la dashboard: per ogni blocco
        index, hash, hash precedente, numero di transazioni e tipo di contenuto.
        """
        riassunto = []
        for block in self._blockchain.chain:
            tipo = self._tipo_blocco(block)
            riassunto.append({
                "index": block.header.index,
                "hash": block.hash[:16] + "...",
                #"hash": block.hash,
                "prev": block.header.hash_previous_block[:16] + "...",
                #"prev": block.header.hash_previous_block,
                "n_tx": len(block.transactions),
                "tipo": tipo,
            })
        return riassunto

    def dettaglio_blocco(self, index: int) -> dict:
        """
        Contenuto completo di un blocco (per ispezionarlo dalla dashboard):
        header e l'elenco delle transazioni (le voci pubblicate, come stringhe JSON).
        """
        if index < 0 or index >= len(self._blockchain.chain):
            raise IndexError("Indice di blocco fuori intervallo")
        block = self._blockchain.chain[index]
        return {
            "index": block.header.index,
            "tipo": self._tipo_blocco(block),
            "timestamp": block.header.timestamp,
            "hash": block.hash,
            "prev": block.header.hash_previous_block,
            "transazioni": [tx.entry for tx in block.transactions],
        }

    @staticmethod
    def _tipo_blocco(block: Block) -> str:
        """Deduce il tipo di contenuto di un blocco dalla sua prima transazione."""
        if block.header.index == 0:
            return "genesis"
        entry = block.transactions[0].entry
        try:
            dato = json.loads(entry)
        except (ValueError, TypeError):
            return "?"
        if dato.get("tipo"):
            return dato["tipo"]               # "opzioni" o "voto"
        if dato.get("corpo", {}).get("tipo"):
            return dato["corpo"]["tipo"]       # "scrutinio"
        return "?"
