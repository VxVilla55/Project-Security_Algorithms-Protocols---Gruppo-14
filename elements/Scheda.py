class Scheda:
    """
        La scheda cifrata B = (c_voto, c_k, iv) pronta per essere inviata all'AE.
            c_voto : preferenza cifrata con AES-CBC
            c_k    : chiave AES cifrata con RSA-OAEP (pk_AE)
            iv     : vettore di inizializzazione usato per AES-CBC
    """
    c_voto: bytes
    c_k: bytes
    iv: bytes

    def __init__(self, c_voto: bytes, c_k: bytes, iv: bytes):
        self.c_voto = c_voto
        self.c_k = c_k
        self.iv = iv