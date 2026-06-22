"""
Worker job: process ONE url (normalize -> dedup -> mirror-check -> [analyze] ->
upsert -> discover-into-frontier).

Dedup / anti-trap layers, all keyed on the CANONICAL url:
  1. URL normalization (normalize.canonical) so the same site is one string.
  2. content-hash skip: unchanged page since last visit -> no LLM, no finding
     rewrite (sector stays frozen), capture dropped.
  3. cross-domain MIRROR check: identical content under a different domain ->
     dropped, domain flagged so the router won't re-queue it.
  4. DB upsert on UNIQUE(url): one row per site.

Discovery no longer writes to targets.txt. New, safe, UNSEEN domains are SCORED
and pushed to the Redis frontier (discovery.py). targets.txt is now your manual
seed list only. The OPSEC pre-retrieval filter (skips/review) is UNCHANGED.
Graph edges (src->dst) are recorded in the `links` table to power in-degree.
"""
import os
import re
import shutil
import hashlib
import datetime
import psycopg
from pathlib import Path
from dotenv import load_dotenv
from bs4 import BeautifulSoup
from redis import Redis
from scraper import scrape
from ai_reader import analyze
from normalize import canonical, onion_of
import discovery

load_dotenv()
DB = os.environ["DB_CONN"]
ROOT = Path(__file__).parent.parent
CAPTURES = (ROOT / "captures").resolve()
TARGETS_FILE = ROOT / "targets.txt"
SKIPS_FILE = ROOT / "skips.txt"
REVIEW_FILE = ROOT / "review.txt"
DEAD_FILE = ROOT / "dead.txt"
JUNK_FILE = ROOT / "junk.txt"
MIRRORS_FILE = ROOT / "mirrors.txt"
FILTERS_DIR = ROOT / "filters"

MIN_CONTEXT = 12
ONION_RE = re.compile(r"\b[a-z2-7]{56}\.onion\b")

r = Redis.from_url(os.environ["REDIS_URL"])


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
            o = onion_of(line)
            if o:
                out.add(o)
    return out


def extract_links(html):
    soup = BeautifulSoup(html, "html.parser")
    out, seen = [], set()
    for a in soup.find_all("a", href=True):
        onion = onion_of(a["href"])
        if not onion or onion in seen:
            continue
        seen.add(onion)
        ctx = " ".join(filter(None, [a.get_text(" ", strip=True), a.get("title", "")]))
        out.append((onion, ctx))
    return out


def _record_edge(conn, src, dst):
    conn.execute(
        "INSERT INTO links (src, dst) VALUES (%s, %s) ON CONFLICT (src, dst) DO NOTHING",
        (src, dst),
    )


def _in_degree(conn, dst):
    row = conn.execute(
        "SELECT count(DISTINCT src) FROM links WHERE dst=%s", (dst,)
    ).fetchone()
    return row[0] if row else 0


def discover(conn, src_url, links, filters):
    """Record graph edges; push NEW, safe, unseen domains to the scored frontier.
    OPSEC pre-retrieval filter (skips/review) is unchanged."""
    src = onion_of(src_url)
    known_bad = bare_onions(SKIPS_FILE) | bare_onions(DEAD_FILE)
    for onion, ctx in links:
        if src and onion != src:
            _record_edge(conn, src, onion)          # graph edge (always)

        if onion in known_bad:
            continue
        if discovery.is_domain_seen(r, onion):      # already in system -> router re-scrapes it
            continue
        if discovery.is_mirror_domain(r, onion):    # known mirror -> ignore
            continue

        link_url = f"http://{onion}/"
        # --- OPSEC PRE-RETRIEVAL FILTER (unchanged) ---
        if len(ctx.strip()) < MIN_CONTEXT:
            log(REVIEW_FILE, link_url, "thin context")
            continue
        reason, term = check(ctx, filters)
        if reason:
            log(SKIPS_FILE, link_url, reason, f"matched: {term}")
            continue
        # --- safe + new -> score and push to frontier ---
        in_deg = _in_degree(conn, onion)
        score = discovery.score_candidate(link_url, ctx, in_degree=in_deg, domain_is_new=True)
        discovery.frontier_add(r, link_url, score)


def _safe_rmtree(folder):
    try:
        p = Path(folder).resolve()
        if p != CAPTURES and CAPTURES in p.parents:
            shutil.rmtree(p, ignore_errors=True)
    except Exception:
        pass


def _last_hash(conn, url):
    row = conn.execute("SELECT content_hash FROM page_state WHERE url=%s", (url,)).fetchone()
    return row[0] if row else None


def _content_seen_elsewhere(conn, page_hash, url):
    row = conn.execute(
        "SELECT 1 FROM page_state WHERE content_hash=%s AND url<>%s LIMIT 1",
        (page_hash, url),
    ).fetchone()
    return bool(row)


def _touch(conn, url, h):
    conn.execute(
        """INSERT INTO page_state (url, content_hash, last_seen)
           VALUES (%s, %s, NOW())
           ON CONFLICT (url) DO UPDATE
             SET content_hash = EXCLUDED.content_hash, last_seen = NOW()""",
        (url, h),
    )


def _save_state(conn, url, h, link_count):
    conn.execute(
        """INSERT INTO page_state (url, content_hash, link_count, last_seen)
           VALUES (%s, %s, %s, NOW())
           ON CONFLICT (url) DO UPDATE
             SET content_hash = EXCLUDED.content_hash,
                 link_count   = EXCLUDED.link_count,
                 last_seen    = NOW()""",
        (url, h, link_count),
    )


def _upsert_finding(conn, url, facts, folder, page_hash):
    conn.execute(
        """INSERT INTO findings
             (type,victim,data,price,threat_actor,url,folder,content_hash,found_at,last_seen)
           VALUES
             (%(type)s,%(victim)s,%(data)s,%(price)s,%(threat_actor)s,
              %(url)s,%(folder)s,%(content_hash)s,NOW(),NOW())
           ON CONFLICT (url) DO UPDATE SET
             type=EXCLUDED.type, victim=EXCLUDED.victim, data=EXCLUDED.data,
             price=EXCLUDED.price, threat_actor=EXCLUDED.threat_actor,
             folder=EXCLUDED.folder, content_hash=EXCLUDED.content_hash,
             last_seen=NOW()""",
        {**facts, "url": url, "folder": str(folder), "content_hash": page_hash},
    )


def process_one(raw_url):
    url = canonical(raw_url)
    if not url:
        print(f"[worker] bad url, skipped: {raw_url}")
        return "bad-url"

    print(f"[worker] processing {url}")
    folder, title, text = scrape(url)
    page_hash = hashlib.sha256(text.encode("utf-8", "replace")).hexdigest()

    with psycopg.connect(DB) as conn:
        # 1. unchanged content -> no LLM, just refresh + drop capture
        if _last_hash(conn, url) == page_hash:
            _touch(conn, url, page_hash)
            conn.execute("UPDATE findings SET last_seen=NOW() WHERE url=%s", (url,))
            conn.commit()
            _safe_rmtree(folder)
            print(f"[worker] unchanged, skipped LLM {url}")
            return "unchanged"

        # 2. cross-domain mirror -> drop, flag domain, no LLM
        if _content_seen_elsewhere(conn, page_hash, url):
            log(MIRRORS_FILE, url, "mirror")
            o = onion_of(url)
            if o:
                discovery.mark_mirror(r, o)
            _save_state(conn, url, page_hash, 0)
            conn.commit()
            _safe_rmtree(folder)
            print(f"[worker] mirror, dropped {url}")
            return "mirror"

        # 3. new/changed content -> analyze ONCE
        facts = analyze(text)

        # 4. harvest links: record graph edges + push new domains to frontier
        link_count = 0
        try:
            html = (folder / "page.html").read_text()
            links = extract_links(html)
            link_count = len(links)
            discover(conn, url, links, load_filters())
        except Exception as e:
            print(f"[worker] discovery skipped: {e}")

        # 5. upsert finding if relevant; else drop + log
        if facts.get("relevant", True):
            _upsert_finding(conn, url, facts, folder, page_hash)
            result = facts.get("type", "?")
            print(f"[worker] upserted {url}: {result} ({link_count} links)")
        else:
            log(JUNK_FILE, url, "irrelevant")
            _safe_rmtree(folder)
            result = "irrelevant"
            print(f"[worker] irrelevant, dropped {url} ({link_count} links)")

        # 6. remember content + link count
        _save_state(conn, url, page_hash, link_count)
        conn.commit()

    print(f"[worker] done {url}: {result}")
    return result
