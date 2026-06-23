"""
Smart Discovery: scoring + frontier primitives to escape spider traps.

Answers "what should we crawl NEXT?" so we favor NEW root domains and avoid
re-walking the same sites. Pure heuristics (no LLM). Uses a Redis ZSET as a
priority frontier (ZADD dedups, ZPOPMAX hands out the highest-value urls first).

The OPSEC pre-retrieval filter (skips.txt) is NOT here and is NOT changed --
scoring only ever runs on links that already passed that filter.
"""
import re
from urllib.parse import urlsplit

ONION_RE = re.compile(r"\b[a-z2-7]{56}\.onion\b")

PAGINATION_HINTS = ("page=", "/page/", "paged=", "offset=", "start=", "&p=", "?p=", "/p/", "sort=", "order=")
INTEREST = ("market", "leak", "breach", "forum", "vendor", "shop", "dump",
            "database", "ransom", "fraud", "carding", "directory", "wiki", "index")

FRONTIER_KEY = "frontier"            # ZSET: url -> score
SEEN_DOMAINS_KEY = "seen_domains"    # SET: onions ever queued
MIRROR_DOMAINS_KEY = "mirror_domains"  # SET: onions found to be content mirrors


def domain_of(url):
    m = ONION_RE.search((url or "").lower())
    return m.group(0) if m else None


def depth_of(url):
    path = urlsplit(url).path.strip("/")
    return 0 if not path else path.count("/") + 1


def looks_paginated(url):
    u = (url or "").lower()
    return any(h in u for h in PAGINATION_HINTS)


def score_candidate(url, context="", *, in_degree=0, domain_is_new=True,
                    domain_hits_this_cycle=0, is_mirror=False):
    """Priority score for crawling `url` next. Higher = sooner."""
    if is_mirror:
        return -1.0
    depth = depth_of(url)
    score = 0.0
    if domain_is_new:
        score += 10.0
    score += max(0.0, 5.0 - 2.0 * depth)
    score += min(5.0, float(in_degree))
    if any(w in (context or "").lower() for w in INTEREST):
        score += 2.0
    if looks_paginated(url):
        score -= 6.0
    score -= 1.5 * domain_hits_this_cycle
    return round(score, 2)


# ---- frontier (Redis) ----
def frontier_add(r, url, score):
    r.zadd(FRONTIER_KEY, {url: score})


def frontier_pop_top(r, n):
    out = []
    for member, score in r.zpopmax(FRONTIER_KEY, n):
        out.append((member.decode() if isinstance(member, bytes) else member, score))
    return out


# ---- seen domains ----
def mark_domain_seen(r, onion):
    r.sadd(SEEN_DOMAINS_KEY, onion)


def is_domain_seen(r, onion):
    return bool(r.sismember(SEEN_DOMAINS_KEY, onion))


# ---- mirrors ----
def mark_mirror(r, onion):
    r.sadd(MIRROR_DOMAINS_KEY, onion)


def is_mirror_domain(r, onion):
    return bool(r.sismember(MIRROR_DOMAINS_KEY, onion))


if __name__ == "__main__":
    base = "abcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefab.onion"
    other = "zzzzzzabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefab.onion"
    cases = [
        ("new root domain",   f"http://{other}/",            "leak market", dict(in_degree=4, domain_is_new=True)),
        ("known shallow",     f"http://{base}/",             "forum",       dict(in_degree=2, domain_is_new=False)),
        ("pagination trap",   f"http://{base}/forum/page/7", "next page",   dict(in_degree=2, domain_is_new=False)),
        ("mirror",            f"http://{other}/",            "",            dict(is_mirror=True)),
    ]
    for label, url, ctx, kw in cases:
        print(f"{label:<18}{score_candidate(url, ctx, **kw):>7}")
