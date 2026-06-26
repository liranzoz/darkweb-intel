"""
Router: seed the scored frontier, then drain its top candidates into the scrape
queue. Runs from cron (replaces the old "queue every target" producer).

Each run:
  1. SEED the frontier:
       - manual seeds (targets.txt)        -> high score (always reconsidered)
       - known hubs (link-rich pages)      -> medium score (re-checked for fresh links)
       - stale leaves                      -> low score (occasional refresh)
       (skips dead + mirror domains; bootstraps seen_domains from page_state)
  2. DRAIN: pop the highest-scored candidates (brand-new domains discovered by
     the workers outrank everything), apply a per-domain cap, enqueue them.

Brand-new domains (scored ~15-21 by the workers) beat seeds (12) beat hubs (6)
beat stale leaves (2). So the crawler spends its time on genuinely new ground.
"""
import os
import hashlib
import datetime
from pathlib import Path

import psycopg
from dotenv import load_dotenv
from redis import Redis
from rq import Queue

from normalize import canonical, onion_of
import discovery

load_dotenv()
DB = os.environ["DB_CONN"]
ROOT = Path("/home/liran/darkweb-intel")
TARGETS_FILE = ROOT / "targets.txt"
DEAD_FILE = ROOT / "dead.txt"

BATCH = 200                # max jobs to queue per run
MAX_PER_DOMAIN = 3         # breadth cap per cycle
SEED_SCORE = 12.0
HUB_RESCRAPE_SCORE = 6.0
LEAF_RESCRAPE_SCORE = 2.0
ERROR_RETRY_SCORE = 8.0    # above hubs, below seeds — errors deserve a second shot
HUB_MIN_LINKS = 5
LEAF_RESCRAPE_HOURS = 12

r = Redis.from_url(os.environ["REDIS_URL"])
queue = Queue("scrape", connection=r)


def job_id_for(url):
    return "scrape-" + hashlib.sha1(url.encode()).hexdigest()[:16]


def dead_onions():
    out = set()
    if DEAD_FILE.exists():
        for line in DEAD_FILE.read_text().splitlines():
            o = onion_of(line)
            if o:
                out.add(o)
    return out


def seed_frontier(conn, dead):
    """Add manual seeds + error retries + due-for-rescrape known sites to the frontier."""
    seeded = set()
    # 1) manual seeds
    if TARGETS_FILE.exists():
        for line in TARGETS_FILE.read_text().splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            u = canonical(line)
            if not u:
                continue
            o = onion_of(u)
            if o in dead or discovery.is_mirror_domain(r, o):
                continue
            discovery.frontier_add(r, u, SEED_SCORE)
            seeded.add(u)
    # 2) error retries: re-queue pages where the LLM failed, then delete them
    error_rows = conn.execute(
        "SELECT url FROM findings WHERE type='error'"
    ).fetchall()
    error_count = 0
    for (url,) in error_rows:
        o = onion_of(url)
        if not o or o in dead or discovery.is_mirror_domain(r, o):
            continue
        discovery.frontier_add(r, url, ERROR_RETRY_SCORE)
        seeded.add(url)
        error_count += 1
    if error_count:
        conn.execute("DELETE FROM findings WHERE type='error'")
        conn.commit()
        print(f"Re-queued {error_count} error URLs for retry.")
    # 3) known hubs / stale leaves from page_state
    now = datetime.datetime.now()
    for url, lc, last_seen in conn.execute(
        "SELECT url, link_count, last_seen FROM page_state"
    ).fetchall():
        o = onion_of(url)
        if not o or o in dead or discovery.is_mirror_domain(r, o):
            continue
        discovery.mark_domain_seen(r, o)          # bootstrap seen-set from history
        if url in seeded:
            continue
        lc = lc or 0
        if lc >= HUB_MIN_LINKS:
            discovery.frontier_add(r, url, HUB_RESCRAPE_SCORE)
        elif last_seen is None or (now - last_seen).total_seconds() / 3600 >= LEAF_RESCRAPE_HOURS:
            discovery.frontier_add(r, url, LEAF_RESCRAPE_SCORE)
        # recent leaves: skip


def drain_and_queue(dead):
    popped = discovery.frontier_pop_top(r, BATCH)
    per_domain = {}
    queued = 0
    for url, score in popped:
        o = onion_of(url)
        if not o or o in dead or discovery.is_mirror_domain(r, o):
            continue                               # drop dead/mirror
        if per_domain.get(o, 0) >= MAX_PER_DOMAIN:
            discovery.frontier_add(r, url, score)  # put back for next cycle
            continue
        per_domain[o] = per_domain.get(o, 0) + 1
        discovery.mark_domain_seen(r, o)
        queue.enqueue("worker.process_one", url, job_id=job_id_for(url), job_timeout=600)
        queued += 1
    return queued, len(popped)


if __name__ == "__main__":
    dead = dead_onions()
    with psycopg.connect(DB) as conn:
        seed_frontier(conn, dead)
    queued, popped = drain_and_queue(dead)
    left = r.zcard(discovery.FRONTIER_KEY)
    print(f"Queued {queued} (from top {popped}). Frontier remaining: {left}. Queue depth: {len(queue)}")
