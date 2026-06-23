"""
AI reader: turn scraped page text into structured, CATEGORIZED threat-intel.
Uses a local LLM (no data leaves the server). Hard timeout so a stuck call
can never hang the pipeline.

Two upgrades over the old version:
  - CLOSED category menu: the model must pick ONE of a fixed set (each with a
    definition) instead of inventing a free-form 'type'. Far fewer mistags
    (e.g. a PayPal-transfer scam now lands in 'fraud', not 'malware').
  - RELEVANCE gate: pages that aren't threat-intel (search engines, blogs,
    login walls, hosting, broken pages) come back relevant=False, so the
    worker can drop them instead of storing junk.
"""
import os
from dotenv import load_dotenv
load_dotenv()
import json
import ollama

MODEL = os.environ.get("AI_MODEL", "llama3.1:8b")
AI_TIMEOUT = int(os.environ.get("AI_TIMEOUT", "120"))  # seconds
MAX_CHARS = int(os.environ.get("AI_MAX_CHARS", "6000"))  # cap page text sent to the model (~1500 tokens)
_client = ollama.Client(timeout=AI_TIMEOUT)

# the ONLY categories the model may choose from
CATEGORIES = ["data leak", "market", "fraud", "malware", "hacking service", "forum", "other"]

CATEGORY_ALIASES = {
    "data_leak": "data leak", "leak": "data leak", "leaks": "data leak",
    "data breach": "data leak", "breach": "data leak", "dump": "data leak",
    "marketplace": "market", "shop": "market", "vendor": "market",
    "scam": "fraud", "carding": "fraud", "cashout": "fraud",
    "ransomware": "malware", "exploit": "malware", "botnet": "malware",
    "hacking": "hacking service", "hacking services": "hacking service",
    "service": "hacking service", "ddos": "hacking service",
    "forums": "forum", "board": "forum", "discussion": "forum",
}

PROMPT = """You are a cyber threat intelligence analyst.
Below is the text of a page from a dark-web (.onion) site.

First decide if the page is relevant to threat intelligence at all.
NOT relevant (set "relevant": false): search engines, link directories,
wikis, personal blogs, hosting/email services, login pages, empty or broken
pages, anything not about cybercrime.

If relevant, choose EXACTLY ONE category from this list:
- "data leak": stolen/leaked data shared or sold (databases, credentials, dumps, combolists, stealer logs)
- "market": a shop or vendor selling goods/services (accounts, drugs, etc.)
- "fraud": scams, carding, cashout, bank/PayPal transfers, fake money, money laundering
- "malware": malware, ransomware, exploits, botnets, RATs offered or discussed as tools
- "hacking service": someone offering to hack, DDoS, spoof, phish, or crack on request
- "forum": a forum, board, or general discussion / chatter
- "other": cybercrime-related but none of the above

Important: a page selling money transfers or fake PayPal/bank funds is "fraud", NOT "malware".

Return ONLY a JSON object, nothing else:
{
  "relevant": true or false,
  "category": one of the categories above (use "other" if unsure),
  "victim": who is targeted/affected, or "unknown",
  "data": what data or goods are involved, or "unknown",
  "price": the asking price, or "unknown",
  "threat_actor": the seller/group/author name, or "unknown"
}

Page text:
"""


def analyze(post_text):
    """Send text to the local LLM; return categorized facts.
    On failure return type='error' (NOT 'other') so a broken call is
    never mistaken for a real, uncategorizable page."""
    error_default = {
        "relevant": True, "type": "error",
        "victim": "unknown", "data": "unknown",
        "price": "unknown", "threat_actor": "unknown",
    }
    text = (post_text or "")[:MAX_CHARS]   # truncate to top of page -> bounded, fast LLM call
    try:
        response = _client.chat(
            model=MODEL,
            messages=[{"role": "user", "content": PROMPT + text}],
            format="json",                 # force ONE valid JSON object, no prose/markdown
            options={"temperature": 0, "num_ctx": 4096, "num_predict": 256},
        )
        parsed = json.loads(response["message"]["content"])  # whole reply is the object
    except Exception as e:
        print(f"[ai_reader] analyze failed ({type(e).__name__}): {e}")  # surface it
        return error_default

    relevant = bool(parsed.get("relevant", True))

    cat = str(parsed.get("category", "other")).strip().lower()
    cat = CATEGORY_ALIASES.get(cat, cat)   # map near-misses first
    if cat not in CATEGORIES:
        print(f"[ai_reader] off-menu category {cat!r} -> other")
        cat = "other"

    return {
        "relevant": relevant,
        "type": cat,
        "victim": str(parsed.get("victim", "unknown")),
        "data": str(parsed.get("data", "unknown")),
        "price": str(parsed.get("price", "unknown")),
        "threat_actor": str(parsed.get("threat_actor", "unknown")),
    }
