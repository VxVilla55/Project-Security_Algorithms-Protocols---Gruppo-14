"""
app.py — Web app Flask del protocollo di e-voto.

Due sezioni:
  /admin  : configurare N utenti, avviare l'elezione (Fase 1), fermarla (Fase 4),
            e simulare in automatico N elettori (batch).
  /utente : simulare un singolo elettore passo-passo, con un pulsante per ogni
            macro-operazione del protocollo e l'output mostrato a schermo.

Lo stato è in memoria, in un'unica istanza di `Elezione`. Avviando il server o
una nuova elezione, lo stato riparte pulito (tabelle vuote, BP e log azzerati).
"""

import random

from flask import Flask, jsonify, render_template, request

from elezione import Elezione

app = Flask(__name__)

# ---------------------------------------------------------------------------
# Stato globale in memoria (spike: una sola elezione alla volta)
# ---------------------------------------------------------------------------
ELEZIONE = Elezione()
DEMO = {"elettore": None, "password": None}   # elettore della sezione step-by-step


def _reset_demo():
    DEMO["elettore"] = None
    DEMO["password"] = None


# ---------------------------------------------------------------------------
# Pagine
# ---------------------------------------------------------------------------

@app.route("/")
def home():
    return render_template("index.html")


@app.route("/admin")
def pagina_admin():
    return render_template("admin.html")


@app.route("/utente")
def pagina_utente():
    return render_template("utente.html")


# ---------------------------------------------------------------------------
# API — stato generale
# ---------------------------------------------------------------------------

@app.route("/api/stato")
def api_stato():
    e = ELEZIONE
    dati = {
        "avviata": e.avviata,
        "urna_chiusa": e.urna_chiusa,
        "opzioni": e.opzioni if e.avviata else [],
        "account_rimanenti": e.account_rimanenti if e.avviata else 0,
        "risultato": e.risultato,
    }
    if e.avviata:
        dati["tabella_idp"] = e.idp.snapshot_tabella()
        dati["tabella_sa"] = e.sa.snapshot_tabella()
        dati["tabella_voti"] = e.ae.snapshot_voti()
        dati["tabella_scrutinio"] = e.ae.snapshot_scrutinio()
        dati["bp_integra"] = e.bp.verifica_integrita()
        dati["bp_voci"] = len(e.bp.get_voci())
        dati["blockchain"] = e.bp.riassunto_blocchi()
    return jsonify(dati)


@app.route("/api/blocco/<int:index>")
def api_blocco(index):
    """Contenuto completo di un singolo blocco della Bacheca Pubblica."""
    if not ELEZIONE.avviata:
        return jsonify({"errore": "Nessuna elezione avviata"}), 400
    try:
        return jsonify({"ok": True, "blocco": ELEZIONE.bp.dettaglio_blocco(index)})
    except IndexError as exc:
        return jsonify({"errore": str(exc)}), 404


# ---------------------------------------------------------------------------
# API — Admin
# ---------------------------------------------------------------------------

@app.route("/api/admin/avvia", methods=["POST"])
def api_avvia():
    """FASE 1: avvia una nuova elezione con N utenti (reset completo)."""
    body = request.get_json(force=True)
    n = int(body.get("n", 5))
    if n < 1:
        return jsonify({"errore": "N deve essere >= 1"}), 400
    # niente echo su terminale del server: il dettaglio resta nel file protocol_log.txt
    ELEZIONE.avvia(n_utenti=n, echo_log=False)
    _reset_demo()
    return jsonify({"ok": True, "n": n, "opzioni": ELEZIONE.opzioni})


@app.route("/api/admin/ferma", methods=["POST"])
def api_ferma():
    """FASE 4: chiude l'urna ed esegue lo scrutinio."""
    if not ELEZIONE.avviata:
        return jsonify({"errore": "Nessuna elezione avviata"}), 400
    if ELEZIONE.urna_chiusa:
        return jsonify({"errore": "Urna già chiusa"}), 400
    risultato = ELEZIONE.chiudi_e_scrutina(stampa_report=True, chiudi_logger=True)
    return jsonify({"ok": True, "risultato": risultato})


@app.route("/api/admin/simula", methods=["POST"])
def api_simula():
    """Simula in automatico un batch di elettori che completano l'intero flusso."""
    if not ELEZIONE.avviata:
        return jsonify({"errore": "Nessuna elezione avviata"}), 400
    if ELEZIONE.urna_chiusa:
        return jsonify({"errore": "Urna chiusa: non si accettano altri voti"}), 400

    body = request.get_json(force=True)
    richiesti = int(body.get("n", ELEZIONE.account_rimanenti))
    quanti = min(richiesti, ELEZIONE.account_rimanenti)
    opzioni = ELEZIONE.opzioni

    risultati = []
    for _ in range(quanti):
        utente, password = ELEZIONE.preleva_account()
        preferenza = random.randrange(len(opzioni))
        elettore = ELEZIONE.crea_elettore(utente)
        esito = ELEZIONE.vota_elettore(elettore, password, preferenza)
        risultati.append({
            "utente": utente,
            "voto": opzioni[preferenza],
            "identificativo": esito["identificativo"],
        })
    return jsonify({"ok": True, "votanti": risultati, "quanti": quanti})


# ---------------------------------------------------------------------------
# API — Utente (simulazione step-by-step)
# ---------------------------------------------------------------------------

def _richiedi_elettore_demo():
    if DEMO["elettore"] is None:
        raise ValueError("Crea prima un elettore con 'Nuovo elettore'")
    return DEMO["elettore"]


@app.route("/api/utente/nuovo", methods=["POST"])
def api_utente_nuovo():
    """Alloca un nuovo elettore demo (login incluso) e ne mostra lo stato iniziale."""
    if not ELEZIONE.avviata:
        return jsonify({"errore": "Avvia prima un'elezione dalla sezione Admin"}), 400
    if ELEZIONE.urna_chiusa:
        return jsonify({"errore": "Urna chiusa: non si accettano altri voti"}), 400
    try:
        utente, password = ELEZIONE.preleva_account()
    except ValueError as exc:
        return jsonify({"errore": str(exc)}), 400

    elettore = ELEZIONE.crea_elettore(utente)
    # login subito, così restano i 4 pulsanti crittografici richiesti
    elettore.verifica_certificato_sa(ELEZIONE.sa.get_certificato(), ELEZIONE.ca)
    elettore.login(ELEZIONE.sa, password)
    DEMO["elettore"] = elettore
    DEMO["password"] = password
    return jsonify({"ok": True, "opzioni": ELEZIONE.opzioni, "stato": elettore.stato()})


@app.route("/api/utente/chiavi", methods=["POST"])
def api_utente_chiavi():
    """[Genera Coppia di Chiavi (pk_v, sk_v)]"""
    try:
        elettore = _richiedi_elettore_demo()
        elettore.genera_chiavi_effimere()
    except ValueError as exc:
        return jsonify({"errore": str(exc)}), 400
    return jsonify({"ok": True, "stato": elettore.stato(),
                    "messaggio": "Coppia effimera (pk_v, sk_v) generata. sk_v resta segreta."})


@app.route("/api/utente/credenziale", methods=["POST"])
def api_utente_credenziale():
    """[Richiedi Credenziale a SA] — invia pk_v, riceve σ_SA."""
    try:
        elettore = _richiedi_elettore_demo()
        credenziale = elettore.richiedi_credenziale(ELEZIONE.sa)
    except ValueError as exc:
        return jsonify({"errore": str(exc)}), 400
    return jsonify({
        "ok": True,
        "stato": elettore.stato(),
        "sigma_SA": credenziale.sigma_SA.hex(),
        "messaggio": "Credenziale (pk_v, σ_SA) ricevuta dall'SA.",
    })


@app.route("/api/utente/prepara", methods=["POST"])
def api_utente_prepara():
    """[Prepara ed Encripta il Voto (C_voto, C_k, IV)]"""
    body = request.get_json(force=True)
    try:
        preferenza = int(body.get("preferenza", -1))
        elettore = _richiedi_elettore_demo()
        elettore.richiedi_parametri(ELEZIONE.bp)
        elettore.scegli_preferenza(preferenza)
        pacchetto = elettore.prepara_pacchetto()
    except ValueError as exc:
        return jsonify({"errore": str(exc)}), 400

    scheda = pacchetto.scheda
    return jsonify({
        "ok": True,
        "stato": elettore.stato(),
        "scheda": {
            "c_voto": scheda.c_voto.hex(),
            "c_k": scheda.c_k.hex(),
            "iv": scheda.iv.hex(),
        },
        "sigma_v": pacchetto.sigma_v.hex(),
        "messaggio": "Voto cifrato (cifratura ibrida) e scheda firmata con sk_v.",
    })


@app.route("/api/utente/invia", methods=["POST"])
def api_utente_invia():
    """[Invia Pacchetto M ad AE e Ricevi Ricevuta]"""
    try:
        elettore = _richiedi_elettore_demo()
        ricevuta = elettore.invia_voto(ELEZIONE.ae)
    except ValueError as exc:
        return jsonify({"errore": str(exc)}), 400
    return jsonify({
        "ok": True,
        "stato": elettore.stato(),
        "identificativo": elettore.identificativo,
        "ricevuta": ricevuta.hex(),
        "messaggio": f"AE ha accettato il voto. Identificativo i={elettore.identificativo}.",
    })


@app.route("/api/utente/verifica", methods=["POST"])
def api_utente_verifica():
    """
    [Verifica Individuale] — restituisce i passi da mostrare uno alla volta.
    Disponibile già DURANTE l'elezione (confronto col blocco i sulla BP);
    dopo lo scrutinio i passi includono anche Merkle e voto in chiaro.
    """
    if not ELEZIONE.avviata:
        return jsonify({"errore": "Nessuna elezione avviata"}), 400
    try:
        elettore = _richiedi_elettore_demo()
        esito = elettore.verifica_individuale(ELEZIONE.bp)   # solo la BP, non l'AE
    except ValueError as exc:
        return jsonify({"errore": str(exc)}), 400
    return jsonify({"ok": True, "esito": esito})


# ---------------------------------------------------------------------------
# API — Verifica universale (chiunque, dai soli dati pubblici)
# ---------------------------------------------------------------------------

@app.route("/api/universale", methods=["POST"])
def api_universale():
    """FASE 5: verifica universale eseguita da un osservatore esterno."""
    if not ELEZIONE.avviata:
        return jsonify({"errore": "Nessuna elezione avviata"}), 400
    if not ELEZIONE.urna_chiusa:
        return jsonify({"errore": "La verifica universale richiede lo scrutinio (Ferma elezione)"}), 400
    try:
        esito = ELEZIONE.verifica_universale()
    except ValueError as exc:
        return jsonify({"errore": str(exc)}), 400
    return jsonify({"ok": True, "esito": esito})


if __name__ == "__main__":
    import os
    import sys
    # Porta configurabile: argomento da riga di comando, oppure variabile PORT, default 5000.
    if len(sys.argv) > 1:
        porta = int(sys.argv[1])
    else:
        porta = int(os.environ.get("PORT", "5000"))
    # use_reloader=False: con un solo processo lo stato in memoria resta coerente
    app.run(host="127.0.0.1", port=porta, debug=True, use_reloader=False)
