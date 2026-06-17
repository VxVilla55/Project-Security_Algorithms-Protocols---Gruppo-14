/* common.js — funzioni condivise da tutte le pagine.
 *
 * Contiene gli helper di rete e i controlli della barra di navigazione
 * (Avvia / Simula / Ferma), riusati sia dalla Dashboard sia dalla pagina Elettore.
 *
 * Ogni pagina può definire window.dopoAzione(stato): viene richiamata dopo ogni
 * azione e ad ogni aggiornamento periodico, così la pagina ridisegna le sue viste.
 */

async function post(url, body) {
  const r = await fetch(url, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body || {}),
  });
  return r.json();
}

async function getStato() {
  return (await fetch("/api/stato")).json();
}

function navMsg(testo, ok = true) {
  const m = document.getElementById("navmsg");
  if (!m) return;
  m.textContent = testo;
  m.style.color = ok ? "#2e8b6f" : "#b0413e";
}

// ---- Controlli della barra di navigazione ----

async function navAvvia() {
  const n = parseInt(document.getElementById("navN").value);
  const d = await post("/api/admin/avvia", { n });
  if (d.errore) return navMsg(d.errore, false);
  navMsg('Elezione avviata con N=' + d.n + '. Opzioni: ' + d.opzioni.join(", "));
  refreshNav();
}

async function navSimula() {
  const n = parseInt(document.getElementById("navBatch").value);
  const d = await post("/api/admin/simula", { n });
  if (d.errore) return navMsg(d.errore, false);
  navMsg('Simulati ' + d.quanti + ' elettori.');
  refreshNav();
}

async function navFerma() {
  const d = await post("/api/admin/ferma", {});
  if (d.errore) return navMsg(d.errore, false);
  navMsg("Urna chiusa: scrutinio eseguito.");
  refreshNav();
}

// ---- Aggiornamento dello stato + hook per la pagina ----

async function refreshNav() {
  const s = await getStato();
  const box = document.getElementById("navstato");
  if (box) {
    if (!s.avviata) box.textContent = "nessuna elezione attiva";
    else box.textContent =
      (s.urna_chiusa ? "urna CHIUSA" : "urna aperta") + ' · ' +
      'account liberi: ' + (s.account_rimanenti) + ' · voci BP: ' + (s.bp_voci ?? 0);
  }
  if (typeof window.dopoAzione === "function") window.dopoAzione(s);
}

// piccolo aiuto per costruire tabelle HTML
function tabella(righe, colonne) {
  if (!righe || righe.length === 0) return '<span class="muted">vuota</span>';
  let h = "<table><tr>" + colonne.map(c => '<th>' + c + '</th>').join("") + "</tr>";
  for (const r of righe)
    h += "<tr>" + colonne.map(c => '<td>' + (r[c] ?? "") + '</td>').join("") + "</tr>";
  return h + "</table>";
}

document.addEventListener("DOMContentLoaded", () => {
  refreshNav();
  setInterval(refreshNav, 2500);   // aggiornamento periodico delle viste
});
