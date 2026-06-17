"""
IdentityProvider — IdP di ateneo (esterno al protocollo, ruolo OIDC mockato).

In una spike NON realizziamo il vero flusso OpenID Connect con redirect: l'IdP
si limita a verificare (utente, password in chiaro) e a rilasciare un token opaco
che fa le veci dell'ID Token OIDC.

Tabella interna (privata) di dimensione N impostata dall'admin:
    entry = (utente, password_in_chiaro, token)
    -> implementata come dizionario  utente -> {"password", "token"}

Il token, una volta emesso al login, permette all'SA di validare l'accesso e di
risalire all'identità (utente) di chi si è autenticato.
"""

import secrets, random

from elements.ProtocolLogger import _NullLogger


class IdentityProvider:
    """Verifica le credenziali di ateneo e rilascia token di accesso."""

    # Fase 2 — Autenticazione (login)
    # _tabella : utente -> {"password": str, "token": str | None}
    #            struttura dati privata di dimensione N (l'admin sceglie N)
    # _token_index : token -> utente   (indice inverso per la validazione rapida)

    def __init__(self, logger=None):
        self._logger = logger or _NullLogger()
        self._tabella: dict[str, dict] = {}
        self._token_index: dict[str, str] = {}

    # ------------------------------------------------------------------
    # Setup della popolazione di utenti (chiamato dall'admin)
    # ------------------------------------------------------------------

    def popola(self, n: int) -> list[tuple[str, str]]:
        """
        Riempie la tabella con N utenti fittizi: utente1/password1 ... utenteN/passwordN.
        Restituisce la lista (utente, password) per comodità della web app.
        """
        self.reset()
        credenziali = []
        for i in range(1, n + 1):
            utente = f"utente{i}"
            password = f"password{i}"
            self._tabella[utente] = {"password": password, "token": None}
            credenziali.append((utente, password))
        self._logger.evento(f"IDP popolato con {n} utenti")
        return credenziali

    def reset(self) -> None:
        """Svuota completamente la tabella (nuova elezione)."""
        self._tabella.clear()
        self._token_index.clear()

    # ------------------------------------------------------------------
    # Login (Fase 2): mocking di OIDC
    # ------------------------------------------------------------------

    def login(self, utente: str, password: str) -> str:
        """
        Verifica (utente, password). Se corrette, genera e registra un token opaco
        (l'ID Token mockato) e lo restituisce. Solleva ValueError se errate.
        """
        with self._logger.misura("fase2.idp.login"):
            entry = self._tabella.get(utente)
            if entry is None or entry["password"] != password:
                raise ValueError("Credenziali di ateneo non valide")

            # se l'utente aveva già un token (re-login), lo rigeneriamo
            token = secrets.token_hex(16)
            entry["token"] = token
            self._token_index[token] = utente

        self._logger.registra_byte("byte.id_token", len(token.encode("utf-8")))
        return token

    def verifica_token(self, token: str) -> str:
        """
        Valida un token e restituisce l'utente associato (per l'SA).
        Solleva ValueError se il token non è valido.
        """
        utente = self._token_index.get(token)
        if utente is None:
            raise ValueError("Token IDP non valido")
        return utente

    # ------------------------------------------------------------------
    # Letture di supporto (per la web app / debug)
    # ------------------------------------------------------------------

    def get_utenti(self) -> list[str]:
        """Elenco degli utenti registrati (solo i nomi, non le password)."""
        return list(self._tabella.keys())

    def snapshot_tabella(self) -> list[dict]:
        """Copia leggibile della tabella per mostrarla nella web app."""
        return [
            {"utente": u, "password": d["password"], "token": d["token"]}
            for u, d in self._tabella.items()
        ]
