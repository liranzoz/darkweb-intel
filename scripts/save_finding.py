import os
import psycopg
from dotenv import load_dotenv
from ai_reader import analyze

load_dotenv()
DB = os.environ["DB_CONN"]


def save(facts, url):
    """Insert one finding (the AI's facts) into the database."""
    with psycopg.connect(DB) as conn:
        conn.execute(
            """INSERT INTO findings (type, victim, data, price, threat_actor, url)
               VALUES (%(type)s, %(victim)s, %(data)s, %(price)s, %(threat_actor)s, %(url)s)""",
            {**facts, "url": url},
        )


if __name__ == "__main__":
    fake_post = "Selling fresh dump - Israeli insurance co, 2M users, emails+passwords, $5k. PM me."
    facts = analyze(fake_post)
    print("AI extracted:", facts)
    save(facts, "http://example.onion/post/123")
    print("Saved to database.")
