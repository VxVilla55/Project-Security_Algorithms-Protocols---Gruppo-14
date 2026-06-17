"""
config.py — Parametri globali del protocollo di e-voto.

Tutte le entità importano da qui le costanti crittografiche, in modo da poter
confrontare facilmente configurazioni diverse (es. RSA-2048 vs RSA-4096) cambiando
un solo file. Pensa a questo file come a una classe `Constants` statica in Java.
"""

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding

# ---------------------------------------------------------------------------
# RSA — usato per: firme (PSS) e cifratura della chiave AES (OAEP)
# ---------------------------------------------------------------------------
RSA_KEY_SIZE = 2048             # dimensione del modulo RSA in bit
RSA_PUBLIC_EXPONENT = 65537     # esponente pubblico standard (0x10001)

# ---------------------------------------------------------------------------
# AES — cifratura simmetrica del voto (modalità CBC)
# ---------------------------------------------------------------------------
AES_KEY_SIZE = 32               # 32 byte = chiave AES-256
AES_IV_SIZE = 16                # 16 byte = un blocco AES (IV per CBC)
AES_PADDING_BLOCK_SIZE = 128    # dimensione del blocco in bit per il padding PKCS7

# ---------------------------------------------------------------------------
# OAEP — schema di padding per cifrare k_AES con RSA (RSA-OAEP)
# ---------------------------------------------------------------------------
OAEP_HASH = hashes.SHA256()       # hash interno di OAEP
OAEP_MGF_HASH = hashes.SHA256()   # hash della mask generation function

# ---------------------------------------------------------------------------
# PSS — schema di padding per le firme RSA (RSA-PSS)
# Ogni autorità ha la sua costante: così se in futuro si vuole differenziare
# la lunghezza del padding PSS per entità, basta cambiare qui.
# ---------------------------------------------------------------------------
PSS_PADDING_LENGTH_ELETTORE = asym_padding.PSS.MAX_LENGTH
PSS_PADDING_LENGTH_SA = asym_padding.PSS.MAX_LENGTH
PSS_PADDING_LENGTH_AE = asym_padding.PSS.MAX_LENGTH
PSS_PADDING_LENGTH_BP = asym_padding.PSS.MAX_LENGTH

# ---------------------------------------------------------------------------
# Codifiche del protocollo
# ---------------------------------------------------------------------------
# Il "voto" è l'indice dell'opzione scelta: lo serializziamo come intero a N byte.
VOTER_CHOICE_BYTE_LENGTH = 1 # sufficiente per indici che vanno da 0 a 255
# Il valore i (identificativo del blocco) usato in H(B||i): intero a N byte.
SERIAL_BYTE_LENGTH = 4

# ---------------------------------------------------------------------------
# Modalità di cifratura del voto (per confrontare efficienza e dimensioni)
#   "ibrida" -> cifratura ibrida AES-CBC (voto) + RSA-OAEP (chiave AES). È quella
#               del protocollo: permette la verifica pubblica (l'AE pubblica k_AES).
#   "rsa"    -> il voto è cifrato DIRETTAMENTE con RSA-OAEP, senza AES. Più semplice
#               ma il pacchetto è diverso e la ridecifratura pubblica non è possibile
#               (solo l'AE, con la sua chiave privata, può decifrare).
#
# Cambia questo valore e riavvia per generare un nuovo protocol_log.txt da confrontare.
# ---------------------------------------------------------------------------
#MODALITA_CIFRATURA = "ibrida"   # "ibrida" oppure "rsa"
MODALITA_CIFRATURA = "ibrida"   # "ibrida" oppure "rsa"

# ---------------------------------------------------------------------------
# Parametri dell'elezione (lista chiusa delle opzioni)
# Il voto valido è un indice di questa lista.
# ---------------------------------------------------------------------------
OPZIONI_DEFAULT = ["Lista A", "Lista B", "Lista C", "Scheda Bianca"]

# ---------------------------------------------------------------------------
# File di stato (spike): vengono ricreati ad ogni nuova elezione (reset)
# ---------------------------------------------------------------------------
BACHECA_PATH = "bacheca.json"     # blockchain della Bacheca Pubblica
LOG_PATH = "protocol_log.txt"     # log cronometrico del protocollo
