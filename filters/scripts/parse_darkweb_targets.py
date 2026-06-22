import os
import re
import sys


def parse_darkweb_targets(input_file, output_file="../targets.txt"):
    onion_pattern = r"https?://[a-zA-Z0-9.-]+\.onion"
    ignore_statuses = ["offline", "down"]
    existing_links = set()

    if os.path.exists(output_file):
        with open(output_file, "r", encoding="utf-8") as f:
            for line in f:
                cleaned = line.strip()
                if cleaned:
                    existing_links.add(cleaned)

    new_links = set()
    with open(input_file, "r", encoding="utf-8") as f:
        for line in f:
            line_lower = line.lower()
            if any(status in line_lower for status in ignore_statuses):
                continue

            found_links = re.findall(onion_pattern, line)
            for link in found_links:
                cleaned_link = link.strip().rstrip("/")
                if cleaned_link not in existing_links:
                    new_links.add(cleaned_link)

    if new_links:
        with open(output_file, "a", encoding="utf-8") as f:
            for link in sorted(new_links):
                f.write(f"{link}\n")


if __name__ == "__main__":
    if len(sys.argv) > 1:
        target_file = sys.argv[1]
        parse_darkweb_targets(target_file)
    else:
        print("Please provide a file path.")
