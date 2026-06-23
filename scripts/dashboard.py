"""
Dark Web Intel dashboard.

Features:
  - findings split into SEPARATE TABLES by category
  - all-"unknown" columns auto-hidden per table
  - live: polls /api/findings every 10s and redraws (search text preserved)
  - EVIDENCE: each row shows its capture folder name; click it to view the
    page screenshot + captured text inline, plus the exact folder path on disk

Evidence files are served only by looking up the finding's folder from the DB
by integer id, and only the fixed filenames page.png / page.txt inside a folder
that is verified to live under captures/  (no path traversal).

Runs on 127.0.0.1:8000 (private). View it through the SSH tunnel.
"""
import os
import datetime
from pathlib import Path

import psycopg
from dotenv import load_dotenv
from flask import Flask, jsonify, send_file, Response, abort

load_dotenv()
DB = os.environ["DB_CONN"]
ROOT = Path(__file__).parent.parent
CAPTURES = (ROOT / "captures").resolve()
app = Flask(__name__)

CATEGORIES = [
    ("leak",    "Data Leaks",           ["leak", "dump", "database", "breach", "combo", "stealer", "log"]),
    ("market",  "Markets / For Sale",   ["sale", "sell", "selling", "market", "vendor", "shop", "store", "price", "carding", "card"]),
    ("fraud",   "Fraud / Scams",        ["fraud", "scam", "cashout", "paypal", "counterfeit", "money transfer"]),
    ("malware", "Malware / Ransomware", ["malware", "ransom", "rat ", "botnet", "trojan", "loader", "exploit", "stealer"]),
    ("service", "Hacking Services",     ["hack", "service", "ddos", "spoof", "hire", "crack", "phish"]),
    ("chatter", "Forums / Chatter",     ["forum", "chatter", "post", "discussion", "chat", "board", "advertisement", "ad"]),
    ("error",   "AI Failed — re-run",   ["error"]),
]
CATEGORY_ORDER = [c[0] for c in CATEGORIES] + ["other"]
CATEGORY_LABELS = {c[0]: c[1] for c in CATEGORIES}
CATEGORY_LABELS["other"] = "Other"


def categorize(type_str):
    t = (type_str or "").lower()
    for key, _label, terms in CATEGORIES:
        if any(term in t for term in terms):
            return key
    return "other"


def folder_for(fid):
    """Return the verified capture folder for a finding id, or None.
    Safe: path comes from the DB and must resolve to inside captures/."""
    with psycopg.connect(DB) as conn:
        row = conn.execute("SELECT folder FROM findings WHERE id=%s", (fid,)).fetchone()
    if not row or not row[0]:
        return None
    try:
        p = Path(row[0]).resolve()
    except Exception:
        return None
    if p != CAPTURES and CAPTURES not in p.parents:   # must be under captures/
        return None
    return p


@app.route("/api/findings")
def api_findings():
    cols = ["id", "found_at", "type", "victim", "data", "price", "threat_actor", "url", "folder"]
    with psycopg.connect(DB) as conn:
        rows = conn.execute(
            "SELECT id, found_at, type, victim, data, price, threat_actor, url, folder "
            "FROM findings ORDER BY found_at DESC"
        ).fetchall()
    findings = []
    for r in rows:
        d = dict(zip(cols, r))
        d["found_at"] = str(d["found_at"])[:16]
        d["category"] = categorize(d["type"])
        d["folder_name"] = Path(d["folder"]).name if d["folder"] else None
        findings.append(d)
    return jsonify({
        "updated": datetime.datetime.now().isoformat(timespec="seconds"),
        "order": CATEGORY_ORDER,
        "labels": CATEGORY_LABELS,
        "rows": findings,
    })


@app.route("/evidence/<int:fid>/shot")
def evidence_shot(fid):
    folder = folder_for(fid)
    if not folder:
        abort(404)
    png = folder / "page.png"
    if not png.exists():
        abort(404)
    return send_file(str(png), mimetype="image/png")


@app.route("/evidence/<int:fid>/text")
def evidence_text(fid):
    folder = folder_for(fid)
    if not folder:
        abort(404)
    out = f"folder: {folder}\n\n"
    info, txt = folder / "info.txt", folder / "page.txt"
    if info.exists():
        out += info.read_text(errors="replace") + "\n----- page text -----\n\n"
    if txt.exists():
        out += txt.read_text(errors="replace")
    return Response(out, mimetype="text/plain; charset=utf-8")


@app.route("/")
def home():
    return PAGE


PAGE = """
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Dark Web Intel</title>
<style>
  * { box-sizing: border-box; }
  body { margin: 0; padding: 24px; font-family: -apple-system, system-ui, sans-serif; background: #0b0d10; color: #e7e9ee; }
  .wrap { max-width: 1200px; margin: 0 auto; }
  header { display: flex; align-items: baseline; justify-content: space-between; flex-wrap: wrap; gap: 8px; margin-bottom: 20px; }
  h1 { margin: 0; font-size: 22px; color: #4fd1c5; }
  .meta { color: #8b909a; font-size: 13px; }
  .dot { display: inline-block; width: 8px; height: 8px; border-radius: 50%; background: #4ade80; margin-right: 6px; }
  input[type=search] { width: 100%; padding: 10px 14px; margin-bottom: 20px; background: #14171c; border: 1px solid rgba(255,255,255,0.1); border-radius: 10px; color: #e7e9ee; font-size: 14px; }
  .cat { margin-bottom: 28px; }
  .cat h2 { font-size: 15px; margin: 0 0 10px; display: flex; align-items: center; gap: 8px; }
  .count { background: #14171c; color: #8b909a; font-size: 12px; padding: 2px 8px; border-radius: 99px; font-weight: 400; }
  .tablewrap { overflow-x: auto; border: 1px solid rgba(255,255,255,0.07); border-radius: 12px; }
  table { border-collapse: collapse; width: 100%; }
  th, td { padding: 10px 13px; text-align: left; border-bottom: 1px solid rgba(255,255,255,0.06); font-size: 13px; vertical-align: top; }
  th { background: #14171c; color: #8b909a; white-space: nowrap; }
  tr:last-child td { border-bottom: none; }
  tr:hover td { background: rgba(255,255,255,0.02); }
  td.time { color: #8b909a; white-space: nowrap; }
  td.url { color: #6b8afd; font-family: ui-monospace, monospace; font-size: 12px; }
  .muted { color: #4a4f59; }
  .ev { color: #4fd1c5; cursor: pointer; font-family: ui-monospace, monospace; font-size: 12px; white-space: nowrap; }
  .ev:hover { text-decoration: underline; }
  .badge { padding: 2px 8px; border-radius: 99px; font-size: 11px; white-space: nowrap; }
  .b-leak { background: rgba(248,113,113,0.15); color: #f87171; }
  .b-market { background: rgba(96,165,250,0.15); color: #60a5fa; }
  .b-malware { background: rgba(251,191,36,0.15); color: #fbbf24; }
  .b-service { background: rgba(167,139,250,0.15); color: #a78bfa; }
  .b-chatter { background: rgba(139,144,154,0.15); color: #b8bdc7; }
  .b-other { background: rgba(79,209,197,0.15); color: #4fd1c5; }
  .b-fraud { background: rgba(244,114,182,0.15); color: #f472b6; }
  .b-error { background: rgba(248,113,113,0.20); color: #fca5a5; }
  .empty { color: #8b909a; padding: 30px; text-align: center; }

  /* evidence modal */
  .overlay { display: none; position: fixed; inset: 0; background: rgba(0,0,0,0.7); z-index: 50; padding: 24px; overflow: auto; }
  .overlay.open { display: block; }
  .modal { max-width: 900px; margin: 0 auto; background: #14171c; border: 1px solid rgba(255,255,255,0.1); border-radius: 14px; overflow: hidden; }
  .modal .bar { display: flex; justify-content: space-between; align-items: center; padding: 14px 18px; border-bottom: 1px solid rgba(255,255,255,0.08); position: sticky; top: 0; background: #14171c; }
  .modal .bar .t { font-size: 14px; color: #4fd1c5; word-break: break-all; }
  .modal .x { cursor: pointer; color: #8b909a; font-size: 22px; line-height: 1; padding: 0 6px; }
  .modal .x:hover { color: #fff; }
  .modal .pad { padding: 18px; }
  .modal img { width: 100%; border-radius: 8px; border: 1px solid rgba(255,255,255,0.08); display: block; }
  .modal .noshot { color: #8b909a; padding: 20px; text-align: center; border: 1px dashed rgba(255,255,255,0.12); border-radius: 8px; }
  .modal pre { margin: 16px 0 0; padding: 14px; background: #0b0d10; border-radius: 8px; max-height: 320px; overflow: auto; white-space: pre-wrap; word-break: break-word; font-size: 12px; color: #c7ccd6; }
</style>
</head>
<body>
<div class="wrap">
  <header>
    <h1>Dark Web Intel</h1>
    <div class="meta"><span class="dot"></span><span id="status">connecting...</span></div>
  </header>
  <input type="search" id="search" placeholder="Search victim, data, actor, type...">
  <div id="content"><div class="empty">Loading...</div></div>
</div>

<div class="overlay" id="overlay">
  <div class="modal">
    <div class="bar"><div class="t" id="ev-title"></div><div class="x" id="ev-close">&times;</div></div>
    <div class="pad">
      <img id="ev-img" alt="screenshot">
      <div class="noshot" id="ev-noshot" style="display:none">No screenshot saved for this capture.</div>
      <pre id="ev-text">loading...</pre>
    </div>
  </div>
</div>

<script>
const OPTIONAL = ["victim", "data", "price", "threat_actor"];
const HEADERS = { victim: "Victim", data: "Data", price: "Price", threat_actor: "Actor" };
let lastData = null;
let query = "";

function isEmpty(v) {
  if (v === null || v === undefined) return true;
  const s = String(v).trim().toLowerCase();
  return s === "" || s === "unknown" || s === "n/a" || s === "none" || s === "-";
}
function esc(v) { return String(v == null ? "" : v).replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;"); }
function cell(v) {
  if (isEmpty(v)) return '<td><span class="muted">—</span></td>';
  return '<td>' + esc(v) + '</td>';
}

function render() {
  if (!lastData) return;
  const { order, labels, rows } = lastData;
  const q = query.toLowerCase();
  let data = rows;
  if (q) data = rows.filter(d => (d.victim+" "+d.data+" "+d.threat_actor+" "+d.type+" "+d.price).toLowerCase().includes(q));

  const groups = {};
  for (const d of data) (groups[d.category] = groups[d.category] || []).push(d);

  let html = "";
  for (const key of order) {
    const g = groups[key];
    if (!g || g.length === 0) continue;
    const showCol = {};
    for (const c of OPTIONAL) showCol[c] = g.some(d => !isEmpty(d[c]));

    let head = "<th>Found</th><th>Type</th>";
    for (const c of OPTIONAL) if (showCol[c]) head += "<th>"+HEADERS[c]+"</th>";
    head += "<th>URL</th><th>Evidence</th>";

    let body = "";
    for (const d of g) {
      let row = '<td class="time">'+esc(d.found_at)+'</td>';
      row += '<td><span class="badge b-'+key+'">'+esc(d.type)+'</span></td>';
      for (const c of OPTIONAL) if (showCol[c]) row += cell(d[c]);
      const short = (d.url||"").replace(/^https?:\\/\\//,"").slice(0, 22) + "...";
      row += '<td class="url">'+esc(short)+'</td>';
      if (d.folder_name)
        row += '<td><span class="ev" onclick="openEv('+d.id+',\\''+esc(d.url)+'\\')">'+esc(d.folder_name)+'</span></td>';
      else
        row += '<td><span class="muted">—</span></td>';
      body += "<tr>"+row+"</tr>";
    }
    html += '<div class="cat"><h2><span class="badge b-'+key+'">'+esc(labels[key])+
            '</span><span class="count">'+g.length+'</span></h2>'+
            '<div class="tablewrap"><table><thead><tr>'+head+'</tr></thead><tbody>'+body+'</tbody></table></div></div>';
  }
  document.getElementById("content").innerHTML = html || '<div class="empty">No findings match.</div>';
}

// evidence modal
function openEv(id, url) {
  document.getElementById("ev-title").textContent = url || ("finding #" + id);
  const img = document.getElementById("ev-img");
  const noshot = document.getElementById("ev-noshot");
  img.style.display = "block"; noshot.style.display = "none";
  img.onerror = () => { img.style.display = "none"; noshot.style.display = "block"; };
  img.src = "/evidence/" + id + "/shot";
  const pre = document.getElementById("ev-text");
  pre.textContent = "loading...";
  fetch("/evidence/" + id + "/text").then(r => r.text()).then(t => pre.textContent = t)
    .catch(() => pre.textContent = "(could not load text)");
  document.getElementById("overlay").classList.add("open");
}
function closeEv() { document.getElementById("overlay").classList.remove("open"); }
document.getElementById("ev-close").addEventListener("click", closeEv);
document.getElementById("overlay").addEventListener("click", e => { if (e.target.id === "overlay") closeEv(); });
document.addEventListener("keydown", e => { if (e.key === "Escape") closeEv(); });

async function load() {
  try {
    const res = await fetch("/api/findings");
    lastData = await res.json();
    document.getElementById("status").textContent = lastData.rows.length + " findings · updated " + lastData.updated.slice(11,19);
    render();
  } catch (e) {
    document.getElementById("status").textContent = "connection lost — retrying";
  }
}
document.getElementById("search").addEventListener("input", e => { query = e.target.value; render(); });
load();
setInterval(load, 10000);
</script>
</body>
</html>
"""


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=8000)
