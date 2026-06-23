"""
Canonicalize .onion URLs so the SAME site always produces the SAME string.

Without this, http://ABC.onion, http://abc.onion/, http://abc.onion/?ref=x and
http://abc.onion/index.html all look different -> duplicate queue jobs,
duplicate page_state rows, duplicate findings, and the content-hash dedup
never matches. Normalizing first makes every dedup downstream actually work.

Rules:
  - lowercase host (onion addresses are case-insensitive base32)
  - force scheme to http (onion is plain http through Tor; https is rare/odd)
  - drop the port, userinfo, fragment (#...) and ALL query params (?...)
  - keep the path but strip a trailing slash; treat common index files as root
  - reject anything that isn't a valid v3 .onion (returns None)

Use canonical(url) everywhere a URL enters the system (producer + worker)
before it is hashed, queued, or stored.
"""
import re
from urllib.parse import urlsplit, urlunsplit

ONION_RE = re.compile(r"\b([a-z2-7]{56}\.onion)\b")
INDEX_FILES = {"index.html", "index.htm", "index.php", "default.html", "home"}


def canonical(url):
    """Return the canonical http://<onion>/<path> form, or None if not a
    valid v3 onion URL."""
    if not url:
        return None
    raw = url.strip()

    # make sure there's a scheme so urlsplit parses the host correctly
    if "://" not in raw:
        raw = "http://" + raw

    parts = urlsplit(raw)

    # host: strip userinfo/port, lowercase, must be a real v3 onion
    host = (parts.hostname or "").lower()
    m = ONION_RE.search(host)
    if not m:
        return None
    host = m.group(1)

    # path: lowercase-safe trim. drop trailing slash; collapse index files to root
    path = parts.path or "/"
    last = path.rsplit("/", 1)[-1].lower()
    if last in INDEX_FILES:
        path = path[: -len(last)]
    path = path.rstrip("/")
    if not path:
        path = "/"

    # scheme http, no query, no fragment, no port
    return urlunsplit(("http", host, path, "", ""))


def onion_of(url):
    """Just the bare 56-char onion address from any URL/string, or None."""
    m = ONION_RE.search((url or "").lower())
    return m.group(1) if m else None


if __name__ == "__main__":
    # quick self-test
    tests = [
        "http://ABCdefABCdefABCdefABCdefABCdefABCdefABCdefABCdefABCdefAB.onion/",
        "abcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefab.onion",
        "http://abcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefab.onion:80/index.html?ref=spam#top",
        "http://abcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefab.onion/shop/",
        "https://notanonion.com/",
    ]
    for t in tests:
        print(f"{t}\n  -> {canonical(t)}\n")
