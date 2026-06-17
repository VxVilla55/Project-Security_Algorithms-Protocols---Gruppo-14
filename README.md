Una spike di implementazione del protocollo di voto elettronico
# **Installare le dipendenze:**
```bash
pip install -r requirements.txt
```
## Come lanciare l'app Flask (modalità interattiva)
```bash
python app.py
```

L'app Flask si avvierà sul local host, porta 5000 `http://127.0.0.1:5000`

Le sezioni a disposizione sono:
- **Home**: `http://127.0.0.1:5000/` — Panoramica, da cui fare la verifica universale
- **Admin**: `http://127.0.0.1:5000/admin` — Configurazione, lancio batch, monitoraggio
- **Utente**: `http://127.0.0.1:5000/utente` — Simulazione step-by-step

**Flusso per provate da Admin:**
1. Inserire numero di utenti (es. 100)
2. Cliccare "Avvia elezione" (Fase 1)
3. Cliccare "Simula votanti" per lanciare batch automatico (Fasi 2-3)
4. Cliccare "Ferma elezione" per scrutinio (Fase 4)
5. Visualizzare risultati, come si sono popolate le tabelle interne alle entità e lo stato blockchain

---
## Come lanciare il "benchmark"
1. Modificare in `config.py` per scegliere la soluzione da testare:
```python
MODALITA_CIFRATURA = "ibrida"  # o "rsa"
```

2. Lanciare il comando da terminale
```bash
python main.py -n <numero_elettori>
```

**Esempi:**
```bash
python main.py -n 100        # Simula 100 elettori
python main.py -n 1000       # Simula 1000 elettori (default 5)
python main.py               # Usa default di 5 elettori
```

**Output:**
- Vedrai la tipica barra di progresso in tempo reale fatta con la `tqdm`
- Report statistico in file: `report/protocol_log_HHMM_MODALITA_CIFRATURA.txt`

**Esempio di output generato:**
```
# Output atteso:
# Simulazione voti: 100%|████████| 100/100 [00:XX<00:00, X.XX elettore/s]
# Report saved to: report/protocol_log_HHMM_ibrida.txt
====================================================================
  REPORT PROTOCOLLO E-VOTO
  modalita_cifratura=IBRIDA   RSA_KEY_SIZE=2048 bit   AES_KEY_SIZE=256 bit
====================================================================

  [FASE1]
  operazione                                n    min ms    max ms   media ms
  ae.genera_chiavi_enc                      1    120.12    120.12     120.12
  ae.genera_chiavi_sig                      1     93.09     93.09      93.09
  ...
  
  [TOTALE PER ELETTORE — somma delle medie]
  fase1                                           323.10 ms
  fase2                                           102.36 ms
  fase3                                             4.39 ms
  fase4                                            42.74 ms
  fase5                                             0.57 ms
  fase_bp                                         130.13 ms
```

## Flusso del protocollo

### Fase 1: Setup
- CA genera chiavi e emette certificati X.509
- AE e SA generano le proprie coppie di chiavi
- AE pubblica parametri dell'elezione sulla blockchain

### Fase 2: Autenticazione
- Elettore effettua login presso IdP (mockato)
- SA autentica l'elettore via token IdP
- SA firma la chiave pubblica effimera dell'elettore → **Credenziale**

### Fase 3: Votazione
- Elettore genera scheda cifrata (c_voto, c_k, iv)
- Firma la scheda con la propria chiave privata → **Pacchetto**
- Invia a AE, riceve ricevuta firmata → **Receipt**
- AE pubblica sulla blockchain

### Fase 4: Scrutinio
- AE decifra tutti i voti
- Conta i voti per opzione
- BP costruisce Merkle Tree su tutti i voti
- Pubblica risultato finale e radice di Merkle

### Fase 5: Verifica
- **Verifica individuale:** Elettore riceve prova di inclusione Merkle, verifica il proprio voto sulla blockchain
- **Verifica universale:** Qualsiasi osservatore esterno verifica l'integrità della blockchain e dell'esito

---

## Caratteristiche principali

**5 fasi del protocollo completamente implementate:**
- **Fase 1:** Setup con CA e certificati X.509
- **Fase 2:** Autenticazione pseudonima via IdP
- **Fase 3:** Votazione cifrata con firma digitale
- **Fase 4:** Scrutinio e costruzione dell'albero di Merkle
- **Fase 5:** Verifica universale e individuale

**Crittografia reale:**
- RSA-2048 per cifratura asimmetrica (RSA-OAEP)
- RSA-PSS per firma digitale
- AES-256 in modalità CBC per cifratura simmetrica
- SHA-256 per hash
- Merkle Tree per prove di inclusione compatte

**Blockchain append-only con persistenza JSON**

**Web app Flask** con dashboard interattiva
- Sezione Admin: configurazione, lancio batch, monitoraggio
- Sezione Utente: simulazione step-by-step del flusso di voto

**Benchmark harness** con timing microsecondo e misurazione byte
- Report statistici per ogni fase e operazione
- Log dettagliato in file con timestamp
