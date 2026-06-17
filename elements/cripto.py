"""
cripto.py — Funzioni crittografiche riutilizzabili.

Raccoglie in un solo posto le primitive usate dalle entità (RSA-OAEP, AES-CBC,
RSA-PSS, SHA-256, serializzazione delle chiavi), seguendo lo stesso schema del
laboratorio del professore (lab_professore/LAB_4/hybrid.py).

Sono funzioni "pure": NON cronometrano nulla. Il cronometraggio è responsabilità
delle entità, che racchiudono le chiamate dentro `with logger.misura(...)`.
Così le primitive restano semplici e la misurazione resta separata.
"""

import hashlib

from cryptography.hazmat.primitives.asymmetric import rsa, padding as asym_padding
from cryptography.hazmat.primitives import hashes, padding as sym_padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.serialization import (
    Encoding, PublicFormat, load_pem_public_key,
)

from config import (RSA_KEY_SIZE, RSA_PUBLIC_EXPONENT, OAEP_HASH, OAEP_MGF_HASH,
                    AES_PADDING_BLOCK_SIZE)


# ---------------------------------------------------------------------------
# Chiavi RSA
# ---------------------------------------------------------------------------

def genera_coppia_rsa():
    """Genera e restituisce una coppia di chiavi RSA (chiave_privata, chiave_pubblica)."""
    sk = rsa.generate_private_key(
        public_exponent=RSA_PUBLIC_EXPONENT,
        key_size=RSA_KEY_SIZE,
    )
    return sk, sk.public_key()


def pk_to_pem(pk) -> str:
    """Serializza una chiave pubblica RSA in stringa PEM (per pubblicarla/trasmetterla)."""
    return pk.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo).decode("utf-8")


def pem_to_pk(pem: str):
    """Ricostruisce una chiave pubblica RSA da una stringa PEM."""
    return load_pem_public_key(pem.encode("utf-8"))


def pk_to_der(pk) -> bytes:
    """
    Rappresentazione binaria canonica (DER) di una chiave pubblica.
    È ciò che viene effettivamente firmato quando l'SA firma pk_v: serve un
    formato deterministico e senza ambiguità.
    """
    return pk.public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)


# ---------------------------------------------------------------------------
# Hash SHA-256
# ---------------------------------------------------------------------------

def sha256_hex(dati: str) -> str:
    """SHA-256 di una stringa, restituito come stringa esadecimale."""
    return hashlib.sha256(dati.encode("utf-8")).hexdigest()


def sha256_bytes(dati: bytes) -> bytes:
    """SHA-256 di una sequenza di byte, restituito come byte."""
    return hashlib.sha256(dati).digest()


# ---------------------------------------------------------------------------
# AES-CBC (cifratura simmetrica del voto)
# ---------------------------------------------------------------------------

def cifra_aes_cbc(chiave: bytes, iv: bytes, messaggio: bytes) -> bytes:
    """Cifra `messaggio` con AES-CBC, applicando prima il padding PKCS7."""
    padder = sym_padding.PKCS7(AES_PADDING_BLOCK_SIZE).padder()
    imbottito = padder.update(messaggio) + padder.finalize()

    cifratore = Cipher(algorithms.AES(chiave), modes.CBC(iv)).encryptor()
    return cifratore.update(imbottito) + cifratore.finalize()


def decifra_aes_cbc(chiave: bytes, iv: bytes, ciphertext: bytes) -> bytes:
    """Decifra un ciphertext AES-CBC e rimuove il padding PKCS7."""
    decifratore = Cipher(algorithms.AES(chiave), modes.CBC(iv)).decryptor()
    imbottito = decifratore.update(ciphertext) + decifratore.finalize()

    unpadder = sym_padding.PKCS7(AES_PADDING_BLOCK_SIZE).unpadder()
    return unpadder.update(imbottito) + unpadder.finalize()


# ---------------------------------------------------------------------------
# RSA-OAEP (cifratura della chiave AES con la chiave pubblica dell'AE)
# ---------------------------------------------------------------------------

def _oaep():
    return asym_padding.OAEP(
        mgf=asym_padding.MGF1(algorithm=OAEP_MGF_HASH),
        algorithm=OAEP_HASH,
        label=None,
    )


def cifra_rsa_oaep(pk, messaggio: bytes) -> bytes:
    """Cifra `messaggio` (tipicamente k_AES) con RSA-OAEP usando la chiave pubblica `pk`."""
    return pk.encrypt(messaggio, _oaep())


def decifra_rsa_oaep(sk, ciphertext: bytes) -> bytes:
    """Decifra un ciphertext RSA-OAEP usando la chiave privata `sk`."""
    return sk.decrypt(ciphertext, _oaep())


# ---------------------------------------------------------------------------
# RSA-PSS (firme digitali)
# ---------------------------------------------------------------------------

def _pss(salt_length):
    return asym_padding.PSS(
        mgf=asym_padding.MGF1(hashes.SHA256()),
        salt_length=salt_length,
    )


def firma_pss(sk, messaggio: bytes, salt_length) -> bytes:
    """Firma `messaggio` con RSA-PSS usando la chiave privata `sk`."""
    return sk.sign(messaggio, _pss(salt_length), hashes.SHA256())


def verifica_pss(pk, firma: bytes, messaggio: bytes, salt_length) -> bool:
    """
    Verifica una firma RSA-PSS. Restituisce True/False invece di lanciare
    eccezioni, per rendere il codice chiamante più leggibile (stile Java boolean).
    """
    try:
        pk.verify(firma, messaggio, _pss(salt_length), hashes.SHA256())
        return True
    except Exception:
        return False


# ---------------------------------------------------------------------------
# Scheda B e blocco H(B||i) — devono essere calcolati IDENTICI da AE ed Elettore
# ---------------------------------------------------------------------------

def serializza_B(c_voto: bytes, c_k: bytes, iv: bytes) -> bytes:
    """
    Rappresentazione binaria canonica della scheda B = (C_voto, C_k, IV).
    È ciò che l'elettore firma con σ_v e ciò su cui si calcola H(B||i).
    """
    return c_voto + c_k + iv


def foglia_merkle(c_voto: bytes, c_k: bytes, iv: bytes, i: int) -> str:
    """
    Stringa-foglia dell'albero di Merkle per il blocco i: codifica B e l'indice i.
    Sia l'AE (costruzione albero) sia l'elettore/osservatore (verifica inclusione)
    devono comporla allo stesso modo, altrimenti gli hash non coincidono.
    """
    return f"{c_voto.hex()}|{c_k.hex()}|{iv.hex()}|{i}"


def hash_blocco_hex(c_voto: bytes, c_k: bytes, iv: bytes, i: int) -> str:
    """H(B||i) in esadecimale: coincide con l'hash della foglia di Merkle del blocco i."""
    return sha256_hex(foglia_merkle(c_voto, c_k, iv, i))
