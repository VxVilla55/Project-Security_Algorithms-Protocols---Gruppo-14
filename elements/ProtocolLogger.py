import json
import statistics
import time
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path


class ProtocolLogger:
    """
    Logger del protocollo di e-voto.

    Ha due responsabilità:
      1. LIVE — scrive su terminale e su file .txt una riga per OGNI operazione
         crittografica/hash/firma, con timestamp e durata in ms, e una riga per
         ogni dimensione di pacchetto/struttura che viaggerebbe sulla rete.
      2. AGGREGATO — accumula le misure per produrre alla fine un report con
         statistiche (min/max/media/std), utile per confrontare configurazioni
         diverse (es. RSA-2048 vs RSA-4096, SHA-256 vs SHA-512).

    Utilizzo in main.py:
        logger = ProtocolLogger()
        IDP = IdentityProvider(logger=logger)
        SA  = SistemaAutenticazione(IDP, logger=logger)
        AE  = AutoritaElettorale(logger=logger)
        ...
        logger.stampa_report()
        logger.esporta_json("log_rsa2048.json")

    Naming convention delle chiavi:
        "fase2.elettore.genera_chiavi_effimere"
        "fase3.ae.verifica_credenziale"
        "byte.scheda"
        "byte.pacchetto"
    """

    def __init__(self, log_path: str = "protocol_log.txt", echo_terminale: bool = True):
        self._durate: dict[str, list[float]] = {}  # chiave → [ms, ms, ...]
        self._byte:   dict[str, list[int]]   = {}  # chiave → [n_byte, n_byte, ...]

        # Scrittura live su file .txt: apriamo in modalità 'w' così ogni nuova
        # elezione/esecuzione riparte da un log pulito (requisito di reset).
        self._echo_terminale = echo_terminale
        self._log_path = Path(log_path)
        self._file = self._log_path.open("w", encoding="utf-8")
        self._scrivi_riga(f"# LOG PROTOCOLLO E-VOTO — avviato {self._adesso()}")
        self._scrivi_riga(f"# {'timestamp':<12} {'durata':>10}  operazione")

    # ------------------------------------------------------------------
    # Raccolta dati (con scrittura live su txt + terminale)
    # ------------------------------------------------------------------

    @contextmanager
    def misura(self, chiave: str):
        """
        Context manager: misura il tempo di esecuzione del blocco in ms,
        lo accumula per il report e lo scrive subito su file/terminale.

        Esempio:
            with self._logger.misura("fase3.elettore.cifra_chiave"):
                c_k = cifra_rsa_oaep(pk_ae_enc, k_AES)
        """
        t0 = time.perf_counter()
        yield
        elapsed_ms = (time.perf_counter() - t0) * 1000
        self._durate.setdefault(chiave, []).append(elapsed_ms)
        self._scrivi_riga(f"  {self._adesso():<12} {elapsed_ms:>8.3f}ms  {chiave}")

    def registra_byte(self, chiave: str, n_byte: int) -> None:
        """
        Registra la dimensione in byte di una struttura dati / messaggio che
        teoricamente viaggia sulla rete, la accumula e la scrive subito.

        Esempio:
            self._logger.registra_byte("byte.scheda", len(c_voto) + len(c_k) + len(iv))
        """
        self._byte.setdefault(chiave, []).append(n_byte)
        self._scrivi_riga(f"  {self._adesso():<12} {n_byte:>8} B   {chiave}")

    def evento(self, messaggio: str) -> None:
        """Scrive una riga descrittiva (non cronometrata) per scandire le fasi del protocollo."""
        self._scrivi_riga(f"  {self._adesso():<12} {'':>10}  · {messaggio}")

    # ------------------------------------------------------------------
    # Scrittura su file + terminale
    # ------------------------------------------------------------------

    @staticmethod
    def _adesso() -> str:
        # orario con i millisecondi: utile per leggere la sequenza temporale
        return datetime.now().strftime("%H:%M:%S.%f")[:-3]

    def _scrivi_riga(self, riga: str) -> None:
        # se il file è già stato chiuso (es. dopo il report finale), non scriviamo
        # più su disco ma non solleviamo errori: le verifiche successive (individuale,
        # universale) continuano a funzionare e a stampare a terminale.
        if not self._file.closed:
            self._file.write(riga + "\n")
            self._file.flush()        # flush immediato: il txt è leggibile anche durante l'esecuzione
        # if self._echo_terminale:
        #     try:
        #         print(riga)
        #     except UnicodeEncodeError:
        #         # alcune console Windows non gestiscono i caratteri unicode (·, —):
        #         # ripieghiamo su una versione ASCII per non interrompere il protocollo
        #         print(riga.encode("ascii", "replace").decode("ascii"))

    def chiudi(self) -> None:
        """Chiude il file di log (idempotente)."""
        if not self._file.closed:
            self._file.close()

    # ------------------------------------------------------------------
    # Accesso programmatico (usato dagli harness di benchmark)
    # ------------------------------------------------------------------

    def get_stats(self, chiave: str) -> dict:
        """Restituisce le statistiche (n, min, max, media, std, tot) per una chiave di durata, o None."""
        valori = self._durate.get(chiave)
        return self._calcola_stats(valori) if valori else None

    def get_media(self, chiave: str) -> float:
        """Restituisce la durata media in ms per una chiave, o None se non misurata."""
        s = self.get_stats(chiave)
        return s["media"] if s else None

    # ------------------------------------------------------------------
    # Report
    # ------------------------------------------------------------------

    def stampa_report(self) -> None:
        """Stampa un report formattato (statistiche per operazione) su terminale E su file .txt."""
        from config import RSA_KEY_SIZE, AES_KEY_SIZE, MODALITA_CIFRATURA

        report_lines: list[str] = []

        def out(riga: str) -> None:
            self._scrivi_riga(riga)
            report_lines.append(riga)

        w = 68
        out("\n" + "=" * w)
        out(f"  REPORT PROTOCOLLO E-VOTO")
        out(f"  modalita_cifratura={MODALITA_CIFRATURA.upper()}   RSA_KEY_SIZE={RSA_KEY_SIZE} bit   "
            f"AES_KEY_SIZE={AES_KEY_SIZE * 8} bit   "
            f"n_misurazioni={max((len(v) for v in self._durate.values()), default=0)}")
        out("=" * w)

        # Raggruppa per fase
        fasi: dict[str, dict[str, list[float]]] = {}
        for chiave, valori in sorted(self._durate.items()):
            fase = chiave.split(".")[0]
            fasi.setdefault(fase, {})[chiave] = valori

        col = 38
        hdr = f"  {'operazione':<{col}} {'n':>4}  {'min ms':>8}  {'max ms':>8}  {'media ms':>9}  {'std ms':>7}"
        sep = f"  {'-'*col}  {'-'*4}  {'-'*8}  {'-'*8}  {'-'*9}  {'-'*7}"

        for fase in sorted(fasi):
            out(f"\n  [{fase.upper()}]")
            out(hdr)
            out(sep)
            for chiave, valori in sorted(fasi[fase].items()):
                s = self._calcola_stats(valori)
                nome = ".".join(chiave.split(".")[1:])   # rimuove prefisso fase
                out(f"  {nome:<{col}} {s['n']:>4}  {s['min']:>8.2f}  {s['max']:>8.2f}  "
                    f"{s['media']:>9.2f}  {s['std']:>7.2f}")

        if self._byte:
            out(f"\n  [DIMENSIONI STRUTTURE DATI — byte]")
            out(f"  {'struttura':<{col}} {'n':>4}  {'min B':>8}  {'max B':>8}  {'media B':>9}")
            out(f"  {'-'*col}  {'-'*4}  {'-'*8}  {'-'*8}  {'-'*9}")
            for chiave in sorted(self._byte.keys()):
                valori = self._byte[chiave]
                s      = self._calcola_stats([float(v) for v in valori])
                # gerarchia: 'byte.scheda' → depth 0; 'byte.scheda.c_voto' → depth 1
                parti  = chiave.split(".")          # ["byte", "scheda"] o ["byte","scheda","c_voto"]
                depth  = len(parti) - 2             # 0 per il totale, 1 per i campi
                indent = "  " * depth
                nome   = indent + parti[-1]
                out(f"  {nome:<{col}} {s['n']:>4}  {int(s['min']):>8}  {int(s['max']):>8}  {s['media']:>9.1f}")

        # Totale per fase (somma delle medie per 1 elettore)
        out(f"\n  [TOTALE PER ELETTORE — somma delle medie]")
        for fase in sorted(fasi):
            totale = sum(
                statistics.mean(v)
                for v in fasi[fase].values()
            )
            out(f"  {fase:<{col + 6}} {totale:>9.2f} ms")

        out("=" * w + "\n")

        # stampiamo sul terminale solo il report finale, non le singole misure
        if self._echo_terminale:
            for riga in report_lines:
                try:
                    print(riga)
                except UnicodeEncodeError:
                    print(riga.encode("ascii", "replace").decode("ascii"))

    def esporta_json(self, path: str) -> None:
        """Esporta dati grezzi e statistiche in JSON per analisi successive."""
        from config import RSA_KEY_SIZE, AES_KEY_SIZE

        output = {
            "config": {
                "RSA_KEY_SIZE": RSA_KEY_SIZE,
                "AES_KEY_SIZE": AES_KEY_SIZE,
            },
            "durate_ms": {
                k: {"valori": v, **self._calcola_stats(v)}
                for k, v in self._durate.items()
            },
            "byte": {
                k: {"unita": "byte", "valori": v, **self._calcola_stats([float(x) for x in v])}
                for k, v in self._byte.items()
            },
        }
        Path(path).write_text(json.dumps(output, indent=2, ensure_ascii=False), encoding="utf-8")
        print(f"  Log esportato in: {path}")

    # ------------------------------------------------------------------
    # Utilità interne
    # ------------------------------------------------------------------

    def _calcola_stats(self, valori: list[float]) -> dict:
        n = len(valori)
        return {
            "n":     n,
            "min":   min(valori),
            "max":   max(valori),
            "media": statistics.mean(valori),
            "std":   statistics.stdev(valori) if n > 1 else 0.0,
            "tot":   sum(valori),
        }


class _NullLogger:
    """
    Logger no-op usato quando le entità vengono create senza logger.
    Stessa interfaccia di ProtocolLogger, non fa nulla.
    Evita i controlli `if self._logger` ovunque nel codice delle entità.
    """

    @contextmanager
    def misura(self, chiave: str):
        yield

    def registra_byte(self, chiave: str, n_byte: int) -> None:
        pass

    def evento(self, messaggio: str) -> None:
        pass

    def chiudi(self) -> None:
        pass
