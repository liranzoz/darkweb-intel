"""
Scraper: fetch a page through Tor, save evidence, return clean text.
Routes a headless browser through the Tor SOCKS proxy to reach .onion sites,
saves a timestamped evidence folder (text + screenshot + raw html + info),
and returns the page's title and cleaned text.
"""
from playwright.sync_api import sync_playwright
from bs4 import BeautifulSoup
from datetime import datetime
from pathlib import Path

PROXY = "socks5://127.0.0.1:9050"
ROOT = Path("/home/liran/darkweb-intel")


def clean(html):
    """Strip HTML down to readable words (drop scripts/styles and blank lines)."""
    soup = BeautifulSoup(html, "html.parser")
    for tag in soup(["script", "style"]):
        tag.decompose()
    lines = [line.strip() for line in soup.get_text("\n").splitlines()]
    return "\n".join(line for line in lines if line)


def scrape(url):
    """Open url through Tor; save evidence; return (folder, title, clean_text)."""
    stamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    folder = ROOT / "captures" / stamp
    folder.mkdir(parents=True, exist_ok=True)

    with sync_playwright() as p:
        browser = p.chromium.launch(proxy={"server": PROXY})
        page = browser.new_page()
        page.goto(url, timeout=60000)
        page.wait_for_timeout(10000)
        html = page.content()
        page.screenshot(path=str(folder / "page.png"), full_page=True)
        title = page.title()
        browser.close()

    text = clean(html)
    (folder / "page.html").write_text(html)     # raw html -> used for link discovery
    (folder / "page.txt").write_text(text)
    (folder / "info.txt").write_text(f"url: {url}\ntitle: {title}\ntime: {stamp}\n")
    return folder, title, text
