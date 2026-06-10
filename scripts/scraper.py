from playwright.sync_api import sync_playwright
from bs4 import BeautifulSoup
from datetime import datetime
from pathlib import Path

PROXY = "socks5://127.0.0.1:9050"


def clean(html):
    """Strip HTML down to just readable words."""
    soup = BeautifulSoup(html, "html.parser")
    for tag in soup(["script", "style"]):
        tag.decompose()
    lines = [line.strip() for line in soup.get_text("\n").splitlines()]
    return "\n".join(line for line in lines if line)


def scrape(url):
    """Open a page through Tor. Save text + screenshot + info into one timestamped folder."""
    # make a folder named by the current time
    stamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    folder = Path("captures") / stamp
    folder.mkdir(parents=True, exist_ok=True)

    with sync_playwright() as p:
        browser = p.chromium.launch(proxy={"server": PROXY})
        page = browser.new_page()
        page.goto(url, timeout=60000)

        html = page.content()
        page.screenshot(path=str(folder / "page.png"), full_page=True)
        title = page.title()
        browser.close()

    text = clean(html)
    (folder / "page.txt").write_text(text)
    (folder / "info.txt").write_text(f"url: {url}\ntitle: {title}\ntime: {stamp}\n")

    return folder, title, text


if __name__ == "__main__":
    url = "https://duckduckgogg42xjoc72x3sjasowoarfbgcmvfimaftt6twagswzczad.onion/"
    folder, title, text = scrape(url)
    print("Saved to folder:", folder)
    print("Title:", title)
    print("Characters of text:", len(text))
