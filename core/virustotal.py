import hashlib
import requests

VT_API_KEY = "f7c507f7399e761190941c200ff7059fad90dfd1c1f97001399cff585bb64f51"

def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for c in iter(lambda: f.read(4096), b""):
            h.update(c)
    return h.hexdigest()

def vt_check(path):
    file_hash = sha256(path)

    url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
    headers = {"x-apikey": VT_API_KEY}

    r = requests.get(url, headers=headers)
    if r.status_code != 200:
        return None

    data = r.json()
    stats = data["data"]["attributes"]["last_analysis_stats"]

    return stats
