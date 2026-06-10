import os
import json
import psycopg
from dotenv import load_dotenv
from flask import Flask

load_dotenv()
DB = os.environ["DB_CONN"]
app = Flask(__name__)

# Plain HTML template (NOT an f-string), so no brace escaping is needed.
# The __DATA__ placeholder gets replaced with the findings as JSON.
TEMPLATE = """
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Dark Web Intel</title>
<style>
  * { box-sizing: border-box; }
  body {
    margin: 0; padding: 24px;
    font-family: -apple-system, system-ui, sans-serif;
    background: #0b0d10; color: #e7e9ee;
  }
  .wrap { max-width: 1200px; margin: 0 auto; }
  header { margin-bottom: 24px; }
  h1 { margin: 0; font-size: 24px; color: #4fd1c5; }
  .sub { color: #8b909a; margin-top: 4px; font-size: 14px; }

  .cards { display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 12px; margin-bottom: 24px; }
  .card { background: #14171c; border: 1px solid rgba(255,255,255,0.07); border-radius: 12px; padding: 16px; }
  .card .num { font-size: 28px; font-weight: 600; }
  .card .lbl { color: #8b909a; font-size: 13px; margin-top: 4px; }
  .card.leak .num { color: #f87171; }
  .card.malware .num { color: #fbbf24; }
  .card.victim .num { color: #4fd1c5; }

  .controls { display: flex; flex-wrap: wrap; gap: 10px; margin-bottom: 16px; }
  input[type=search] {
    flex: 1; min-width: 200px; padding: 10px 14px;
    background: #14171c; border: 1px solid rgba(255,255,255,0.1);
    border-radius: 10px; color: #e7e9ee; font-size: 14px;
  }
  .pill {
    padding: 8px 14px; border-radius: 10px; cursor: pointer; font-size: 13px;
    background: #14171c; border: 1px solid rgba(255,255,255,0.1); color: #b8bdc7;
  }
  .pill.active { background: #4fd1c5; color: #06231f; border-color: #4fd1c5; }

  .tablewrap { overflow-x: auto; border: 1px solid rgba(255,255,255,0.07); border-radius: 12px; }
  table { border-collapse: collapse; width: 100%; min-width: 760px; }
  th, td { padding: 12px 14px; text-align: left; border-bottom: 1px solid rgba(255,255,255,0.06); font-size: 14px; }
  th { background: #14171c; color: #8b909a; cursor: pointer; user-select: none; white-space: nowrap; }
  th:hover { color: #4fd1c5; }
  tr:hover td { background: rgba(255,255,255,0.02); }
  td.time { color: #8b909a; font-size: 13px; white-space: nowrap; }

  .badge { padding: 3px 9px; border-radius: 99px; font-size: 12px; font-weight: 500; white-space: nowrap; }
  .badge.leak { background: rgba(248,113,113,0.15); color: #f87171; }
  .badge.malware { background: rgba(251,191,36,0.15); color: #fbbf24; }
  .badge.chatter { background: rgba(139,144,154,0.15); color: #b8bdc7; }
  .badge.other { background: rgba(79,209,197,0.15); color: #4fd1c5; }

  .empty { padding: 40px; text-align: center; color: #8b909a; }
</style>
</head>
<body>
<div class="wrap">
  <header>
    <h1>Dark Web Intel</h1>
    <div class="sub">Automated threat intelligence collection</div>
  </header>

  <div class="cards" id="cards"></div>

  <div class="controls">
    <input type="search" id="search" placeholder="Search victim, data, actor...">
    <div class="pill active" data-type="all">All</div>
    <div class="pill" data-type="leak">Leaks</div>
    <div class="pill" data-type="malware">Malware</div>
    <div class="pill" data-type="chatter">Chatter</div>
  </div>

  <div class="tablewrap">
    <table>
      <thead>
        <tr>
          <th data-key="id">ID</th>
          <th data-key="found_at">Found</th>
          <th data-key="type">Type</th>
          <th data-key="victim">Victim</th>
          <th data-key="data">Data</th>
          <th data-key="price">Price</th>
          <th data-key="threat_actor">Actor</th>
        </tr>
      </thead>
      <tbody id="rows"></tbody>
    </table>
  </div>
</div>

<script>
const DATA = __DATA__;
let state = { q: "", type: "all", sortKey: "found_at", sortDir: "desc" };

// decide which color badge a type gets
function badgeClass(type) {
  const t = (type || "").toLowerCase();
  if (t.includes("leak")) return "leak";
  if (t.includes("malware") || t.includes("ransom")) return "malware";
  if (t.includes("chatter")) return "chatter";
  return "other";
}

// top stat cards (always based on full dataset)
function renderCards() {
  const leaks = DATA.filter(d => badgeClass(d.type) === "leak").length;
  const malware = DATA.filter(d => badgeClass(d.type) === "malware").length;
  const victims = new Set(DATA.map(d => d.victim).filter(v => v && v.toLowerCase() !== "unknown")).size;
  document.getElementById("cards").innerHTML = `
    <div class="card"><div class="num">${DATA.length}</div><div class="lbl">Total findings</div></div>
    <div class="card leak"><div class="num">${leaks}</div><div class="lbl">Data leaks</div></div>
    <div class="card malware"><div class="num">${malware}</div><div class="lbl">Malware</div></div>
    <div class="card victim"><div class="num">${victims}</div><div class="lbl">Known victims</div></div>
  `;
}

// the table, after filtering + sorting
function renderRows() {
  let rows = DATA.filter(d => {
    if (state.type !== "all" && badgeClass(d.type) !== state.type) return false;
    if (state.q) {
      const hay = (d.victim + " " + d.data + " " + d.threat_actor + " " + d.type).toLowerCase();
      if (!hay.includes(state.q)) return false;
    }
    return true;
  });

  rows.sort((a, b) => {
    let x = a[state.sortKey], y = b[state.sortKey];
    if (x < y) return state.sortDir === "asc" ? -1 : 1;
    if (x > y) return state.sortDir === "asc" ? 1 : -1;
    return 0;
  });

  const body = document.getElementById("rows");
  if (rows.length === 0) {
    body.innerHTML = '<tr><td colspan="7" class="empty">No findings match.</td></tr>';
    return;
  }
  body.innerHTML = rows.map(d => `
    <tr>
      <td>${d.id}</td>
      <td class="time">${d.found_at}</td>
      <td><span class="badge ${badgeClass(d.type)}">${d.type}</span></td>
      <td>${d.victim}</td>
      <td>${d.data}</td>
      <td>${d.price}</td>
      <td>${d.threat_actor}</td>
    </tr>
  `).join("");
}

// wire up the controls
document.getElementById("search").addEventListener("input", e => {
  state.q = e.target.value.toLowerCase();
  renderRows();
});
document.querySelectorAll(".pill").forEach(p => {
  p.addEventListener("click", () => {
    document.querySelectorAll(".pill").forEach(x => x.classList.remove("active"));
    p.classList.add("active");
    state.type = p.dataset.type;
    renderRows();
  });
});
document.querySelectorAll("th").forEach(th => {
  th.addEventListener("click", () => {
    const key = th.dataset.key;
    if (state.sortKey === key) state.sortDir = state.sortDir === "asc" ? "desc" : "asc";
    else { state.sortKey = key; state.sortDir = "asc"; }
    renderRows();
  });
});

renderCards();
renderRows();
</script>
</body>
</html>
"""


@app.route("/")
def home():
    cols = ["id", "found_at", "type", "victim", "data", "price", "threat_actor"]
    with psycopg.connect(DB) as conn:
        rows = conn.execute(
            "SELECT id, found_at, type, victim, data, price, threat_actor FROM findings ORDER BY found_at DESC"
        ).fetchall()
    findings = [dict(zip(cols, r)) for r in rows]
    return TEMPLATE.replace("__DATA__", json.dumps(findings, default=str))


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=8000, debug=True)
