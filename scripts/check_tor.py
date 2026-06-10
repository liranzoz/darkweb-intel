import httpx

PROXY = "socks5h://127.0.0.1:9050"

def get_ip(proxy=None):
    with httpx.Client(proxy=proxy, timeout=30) as c:
        return c.get("https://check.torproject.org/api/ip").json()

print("Direct:", get_ip())
print("Via Tor:", get_ip(PROXY))
