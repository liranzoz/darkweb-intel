import os
import sys
import psycopg
from dotenv import load_dotenv
from scraper import scrape
from ai_reader import analyze

load_dotenv()
DB = os.environ["DB_CONN"]


def save(facts, url, folder):
    """Save the AI's facts to the database, pointing at the evidence folder."""
    with psycopg.connect(DB) as conn:
        conn.execute(
            """INSERT INTO findings (type, victim, data, price, threat_actor, url, folder)
               VALUES (%(type)s, %(victim)s, %(data)s, %(price)s, %(threat_actor)s, %(url)s, %(folder)s)""",
            {**facts, "url": url, "folder": str(folder)},
        )


def run(url):
    """The full pipeline: scrape -> AI reads -> save."""
    print("1. Scraping:", url)
    folder, title, text = scrape(url)
    print("   saved evidence to:", folder)

    print("2. AI reading the text...")
    facts = analyze(text)
    print("   AI found:", facts)

    print("3. Saving to database...")
    save(facts, url, folder)
    print("   done.")


if __name__ == "__main__":
    if len(sys.argv) > 1:
        url = sys.argv[1]
    else:
        url = "https://duckduckgogg42xjoc72x3sjasowoarfbgcmvfimaftt6twagswzczad.onion/"
    run(url)
