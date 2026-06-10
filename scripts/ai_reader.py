import json
import ollama

PROMPT = """You are a cyber threat intelligence analyst.
Read the forum post below and extract the key facts.
Return ONLY a JSON object with these fields:
- type: what kind of post (e.g. data leak for sale, malware, chatter)
- victim: who got hacked, or "unknown"
- data: what data is involved, or "unknown"
- price: the asking price, or "unknown"
- threat_actor: the seller/group name, or "unknown"

Return only the JSON, nothing else.

Forum post:
"""


def analyze(post_text):
    """Send text to the local AI, return clean parsed facts."""
    response = ollama.chat(
        model="mistral",
        messages=[{"role": "user", "content": PROMPT + post_text}],
    )
    answer = response["message"]["content"]

    # grab only the {...} part, in case the AI added chatter around it
    start = answer.find("{")
    end = answer.rfind("}") + 1
    json_text = answer[start:end]

    # turn that text into real data
    return json.loads(json_text)


if __name__ == "__main__":
    fake_post = "Selling fresh dump - Israeli insurance co, 2M users, emails+passwords, $5k. PM me."
    facts = analyze(fake_post)

    # prove it's real data now: read fields one by one
    print("Type   :", facts["type"])
    print("Victim :", facts["victim"])
    print("Price  :", facts["price"])
