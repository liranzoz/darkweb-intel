import os
import httpx
from dotenv import load_dotenv

load_dotenv()                       # read the .env file automatically
VT_KEY = os.environ["VT_API_KEY"]


def check_hash(file_hash):
    """Ask VirusTotal about a file hash. Return clean facts. Never sends the file."""
    url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
    headers = {"x-apikey": VT_KEY}

    r = httpx.get(url, headers=headers, timeout=30)

    if r.status_code == 404:
        return {"known": False, "note": "hash not in VirusTotal"}

    data = r.json()["data"]["attributes"]
    stats = data["last_analysis_stats"]

    return {
        "known": True,
        "malicious_votes": stats["malicious"],
        "total_engines": sum(stats.values()),
        "family": data.get("popular_threat_classification", {})
                      .get("suggested_threat_label", "unknown"),
        "file_type": data.get("type_description", "unknown"),
    }


if __name__ == "__main__":
    test_hash = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
    print("Looking up:", test_hash)
    print("Result:", check_hash(test_hash))
