"""
Add one or more onion URLs to targets.txt.
Validates each is a real v3 .onion, skips duplicates, normalizes format.

Usage:
    python3 scripts/add_targets.py http://aaa...onion/ http://bbb...onion/
    python3 scripts/add_targets.py --file mylist.txt
"""
import re
import sys
from pathlib import Path

ROOT = Path(__file__).parent.parent
TARGETS_FILE = ROOT / "targets.txt"
ONION_RE = re.compile(r"[a-z2-7]{56}\.onion")


def existing_onions():
    """Bare onion addresses already in targets.txt."""
    out = set()
    if TARGETS_FILE.exists():
        for line in TARGETS_FILE.read_text().splitlines():
            m = ONION_RE.search(line.lower())
            if m:
                out.add(m.group())
    return out


def collect_inputs(args):
    """Gather candidate URLs from command line or a --file."""
    if args and args[0] == "--file":
        if len(args) < 2:
            print("Usage: --file <path>")
            sys.exit(1)
        return Path(args[1]).read_text().splitlines()
    return args


if __name__ == "__main__":
    args = sys.argv[1:]
    if not args:
        print("Usage: add_targets.py <url> [url ...]   OR   --file <path>")
        sys.exit(1)

    known = existing_onions()
    added, skipped_dupe, skipped_bad = 0, 0, 0

    with open(TARGETS_FILE, "a") as f:
        for raw in collect_inputs(args):
            raw = raw.strip()
            if not raw or raw.startswith("#"):
                continue
            m = ONION_RE.search(raw.lower())
            if not m:                        # not a valid onion -> reject
                print(f"  bad (not an onion): {raw}")
                skipped_bad += 1
                continue
            onion = m.group()
            if onion in known:               # already listed -> skip
                skipped_dupe += 1
                continue
            f.write(f"http://{onion}/\n")     # normalized, added
            known.add(onion)
            added += 1
            print(f"  added: http://{onion}/")

    print(f"\nDone. Added {added}, skipped {skipped_dupe} duplicate(s), "
          f"rejected {skipped_bad} invalid.")
