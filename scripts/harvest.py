"""
Harvest + auto-filter.
Queries Ahmia (JavaScript-rendered, so we use a real browser via Tor),
then for each onion result decides automatically:
- listing text matches a red-flag term (filters/*.txt) -> SKIP, log to skips.txt
- otherwise -> add to targets.txt

filters/<category>.txt = one term per line; the filename is the reason logged.
Fail-safe: if results can't be read, nothing is added.

Usage:
    python3 scripts/harvest.py "data leak"
"""
import re
import sys
import datetime
from pathlib import Path
from playwright.sync_api import sync_playwright

PROXY = "socks5://127.0.0.1:9050"
ROOT = Path(__file__).parent.parent
TARGETS_FILE = ROOT / "targets.txt"
SKIPS_FILE = ROOT / "skips.txt"
FILTERS_DIR = ROOT / "filters"

ONION_RE = re.compile(r"\b[a-z2-7]{56}\.onion\b")


def load_filters():
    """Load {reason: [terms]} from filters/*.txt (filename = reason)."""
    out = {}
    if FILTERS_DIR.exists():
        for f in sorted(FILTERS_DIR.glob("*.txt")):
            terms = [t.strip().lower() for t in f.read_text().splitlines()
                     if t.strip() and not t.startswith("#")]
            if terms:
                out[f.stem] = terms
    return out


def check(text, filters):
    """First red-flag match in text, as (reason, term), else (None, None)."""
    low = text.lower()
    for reason, terms in filters.items():
        for term in terms:
            if term in low:
                return reason, term
    return None, None


def fetch_results(term):
    """
    Load Ahmia results in a real browser (through Tor) so the JavaScript runs,
    then return a list of (onion_address, surrounding_listing_text).
    """
    results = []
    with sync_playwright() as p:
        browser = p.chromium.launch(proxy={"server": PROXY})
        page = browser.new_page()
        page.goto(f"https://ahmia.fi/search/?q={term}", timeout=60000)
        page.wait_for_timeout(4000)  # give the JS a moment to render results

        # each result is a list item; grab its text + the onion inside it
        items = page.locator("li.result")
        count = items.count()
        for i in range(count):
            text = items.nth(i).inner_text()
            m = ONION_RE.search(text.lower())
            if m:
                results.append((m.group(), text))

        # fallback: if the li.result selector found nothing, scan whole page text
        if not results:
            body = page.inner_text("body")
            for onion in set(ONION_RE.findall(body.lower())):
                results.append((onion, ""))  # no listing text -> filter can't clear it

        browser.close()
    return results


def known():
    if not TARGETS_FILE.exists():
        return set()
    out = set()
    for line in TARGETS_FILE.read_text().splitlines():
        m = ONION_RE.search(line.lower())
        if m:
            out.add(m.group())
    return out


def log_skip(url, reason, term):
    stamp = datetime.datetime.now().isoformat(timespec="seconds")
    with open(SKIPS_FILE, "a") as f:
        f.write(f"{stamp} | {url} | {reason} | matched: {term}\n")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print('Usage: python3 scripts/harvest.py "search term"')
        sys.exit(1)

    term = sys.argv[1]
    print(f"Searching Ahmia for: {term}")
    filters = load_filters()

    results = fetch_results(term)
    print(f"Got {len(results)} result(s) from Ahmia.")

    seen = known()
    added = skipped = 0

    for onion, text in results:
        if onion in seen:
            continue
        seen.add(onion)
        url = f"http://{onion}/"

        # fail-safe: no listing text means we can't screen it -> skip
        if not text.strip():
            log_skip(url, "unscreened", "no listing text")
            skipped += 1
            continue

        reason, term_hit = check(text, filters)
        if reason:
            log_skip(url, reason, term_hit)
            skipped += 1
        else:
            with open(TARGETS_FILE, "a") as f:
                f.write(url + "\n")
            added += 1

    print(f"Added {added} to targets.txt, skipped {skipped} (see skips.txt).")
