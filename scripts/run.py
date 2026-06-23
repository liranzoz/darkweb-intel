"""
24/7 orchestrator: scrape -> analyze -> store, plus safe link discovery.

For each target:
  - skip if scraped within RESCRAPE_HOURS (dedup / rate-limit)
  - scrape via Tor, analyze with the local LLM, store the finding
  - extract onion links from the page and SCREEN each link's text BEFORE
    it is ever visited:
      passes filter + enough context -> targets.txt (scraped next run)
      matches a red-flag term         -> skips.txt (never visited)
      too little text to judge        -> review.txt (manual check)

Filtering happens before retrieval, so a bad link is never fetched later.
Meant to be run on a schedule (cron).
"""
import os
import re
import datetime
import psycopg
from pathlib import Path
from dotenv import load_dotenv
from bs4 import BeautifulSoup
from scraper import scrape
from ai_reader import analyze

load_dotenv()
DB = os.environ["DB_CONN"]
ROOT = Path("/home/liran/darkweb-intel")
TARGETS_FILE = ROOT / "targets.txt"
SKIPS_FILE = ROOT / "skips.txt"
REVIEW_FILE = ROOT / "review.txt"
FILTERS_DIR = ROOT / "filters"

RESCRAPE_HOURS = 6      # don't re-scrape the same target more often than this
MAX_NEW_PER_RUN = 20    # cap auto-added targets per run (stops runaway growth)
MIN_CONTEXT = 12        # min chars of link text to screen; below this -> review

ONION_RE = re.compile(r"\b[a-z2-7]{56}\.onion\b")


def load_filters():
    out = {}
    if FILTERS_DIR.exists():
        for f in sorted(FILTERS_DIR.glob("*.txt")):
            terms = [t.strip().lower() for t in f.read_text().splitlines()
                     if t.strip() and not t.startswith("#")]
            if terms:
                out[f.stem] = terms
    return out


def check(text, filters):
    """First red-flag match, as (reason, term), else (None, None)."""
    low = text.lower()
    for reason, terms in filters.items():
        for term in terms:
            if term in low:
                return reason, term
    return None, None


def log(path, *cols):
    stamp = datetime.datetime.now().isoformat(timespec="seconds")
    with open(path, "a") as f:
        f.write(" | ".join([stamp, *cols]) + "\n")


def bare_onions(path):
    out = set()
    if path.exists():
        for line in path.read_text().splitlines():
            m = ONION_RE.search(line.lower())
            if m:
                out.add(m.group())
    return out


def load_targets():
    if not TARGETS_FILE.exists():
        return []
    return [l.strip() for l in TARGETS_FILE.read_text().splitlines()
            if l.strip() and not l.startswith("#")]


def extract_links(html):
    """Onion links on the page, as (onion_address, context_text)."""
    soup = BeautifulSoup(html, "html.parser")
    out, seen = [], set()
    for a in soup.find_all("a", href=True):
        m = ONION_RE.search(a["href"].lower())
        if not m:
            continue
        onion = m.group()
        if onion in seen:
            continue
        seen.add(onion)
        ctx = " ".join(filter(None, [a.get_text(" ", strip=True), a.get("title", "")]))
        out.append((onion, ctx))
    return out


def scraped_recently(conn, url):
    row = conn.execute("SELECT max(found_at) FROM findings WHERE url=%s", (url,)).fetchone()
    last = row[0] if row and row[0] else None
    if not last:
        return False
    return (datetime.datetime.now() - last).total_seconds() < RESCRAPE_HOURS * 3600


def main():
    filters = load_filters()
    targets = load_targets()
    known = set().union(bare_onions(TARGETS_FILE),
                        bare_onions(SKIPS_FILE),
                        bare_onions(REVIEW_FILE))
    added = 0
    print(f"[{datetime.datetime.now():%Y-%m-%d %H:%M}] run start: {len(targets)} targets")

    with psycopg.connect(DB) as conn:
        for url in targets:
            if scraped_recently(conn, url):
                print(f"  recent, skip: {url}")
                continue
            print(f"  scrape: {url}")
            try:
                folder, title, text = scrape(url)
            except Exception as e:
                print(f"    scrape failed: {e}")
                continue

            try:
                facts = analyze(text)
                conn.execute(
                    """INSERT INTO findings (type,victim,data,price,threat_actor,url,folder)
                       VALUES (%(type)s,%(victim)s,%(data)s,%(price)s,%(threat_actor)s,%(url)s,%(folder)s)""",
                    {**facts, "url": url, "folder": str(folder)},
                )
                conn.commit()
                print(f"    stored: {facts.get('type','?')}")
            except Exception as e:
                print(f"    analyze/store failed: {e}")

            # discover onion links from the page we just fetched (no extra request)
            try:
                html = (folder / "page.html").read_text()
            except Exception:
                html = ""
            for onion, ctx in extract_links(html):
                if onion in known or added >= MAX_NEW_PER_RUN:
                    continue
                link_url = f"http://{onion}/"
                if len(ctx.strip()) < MIN_CONTEXT:
                    log(REVIEW_FILE, link_url, "thin context")   # human checks
                    known.add(onion)
                    continue
                reason, term = check(ctx, filters)
                if reason:
                    log(SKIPS_FILE, link_url, reason, f"matched: {term}")
                    known.add(onion)
                    continue
                with open(TARGETS_FILE, "a") as f:                # clean -> next run
                    f.write(link_url + "\n")
                known.add(onion)
                added += 1
                print(f"    discovered: {link_url}")

    print(f"run done: added {added} new target(s)")


if __name__ == "__main__":
    main()
