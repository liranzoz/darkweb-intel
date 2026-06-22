"""
Dark web intelligence pipeline.
Reads a list of target .onion URLs, scrapes each through Tor,
uses a local LLM to extract structured threat data, and stores
results (plus a link to the saved evidence) in Postgres.

Usage:
    python3 scripts/pipeline.py            # process all URLs in targets.txt
    python3 scripts/pipeline.py <url>      # process a single URL
"""
import os
import sys
import psycopg
from pathlib import Path
from dotenv import load_dotenv
from scraper import scrape
from ai_reader import analyze

load_dotenv()
DB = os.environ["DB_CONN"]
TARGETS_FILE = Path(__file__).parent.parent / "targets.txt"


def save(facts, url, folder):
    """Store one finding in the database, linked to its evidence folder."""
    with psycopg.connect(DB) as conn:
        conn.execute(
            """INSERT INTO findings (type, victim, data, price, threat_actor, url, folder)
               VALUES (%(type)s, %(victim)s, %(data)s, %(price)s, %(threat_actor)s, %(url)s, %(folder)s)""",
            {**facts, "url": url, "folder": str(folder)},
        )


def process(url):
    """Run the full pipeline for a single URL: scrape -> analyze -> save."""
    print(f"[*] {url}")
    try:
        folder, title, text = scrape(url)        # fetch + clean + screenshot (via Tor)
        facts = analyze(text)                     # local LLM extracts structured facts
        save(facts, url, folder)                  # persist to database
        print(f"    saved: {facts.get('type', 'unknown')} | evidence: {folder}")
    except Exception as e:
        # one bad page shouldn't stop the whole run
        print(f"    failed: {e}")


def load_targets():
    """Read target URLs from targets.txt, skipping blank lines and comments."""
    urls = []
    for line in TARGETS_FILE.read_text().splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            urls.append(line)
    return urls


if __name__ == "__main__":
    if len(sys.argv) > 1:
        process(sys.argv[1])                      # single URL from command line
    else:
        targets = load_targets()                  # whole list from targets.txt
        print(f"Processing {len(targets)} targets...")
        for url in targets:
            process(url)
        print("Done.")
