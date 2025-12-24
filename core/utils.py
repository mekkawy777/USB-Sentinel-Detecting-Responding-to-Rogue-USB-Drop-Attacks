import hashlib

SUSPICIOUS_EXTS_HIGH = [".exe", ".bat", ".vbs", ".ps1", ".cmd"]
SUSPICIOUS_EXTS_MEDIUM = [".lnk"]
SUSPICIOUS_KEYWORDS = ["salary", "password", "secret", "confidential"]
AUTORUN_NAMES = ["autorun.inf"]


def sha256(path: str):
    try:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            while True:
                chunk = f.read(8192)
                if not chunk:
                    break
                h.update(chunk)
        return h.hexdigest()
    except Exception:
        return None


def get_threat_level(filename: str) -> str:
    name = filename.lower()

    if any(name.endswith(ext) for ext in SUSPICIOUS_EXTS_HIGH):
        return "CRITICAL"

    if any(name.endswith(ext) for ext in SUSPICIOUS_EXTS_MEDIUM):
        return "HIGH"

    if any(k in name for k in SUSPICIOUS_KEYWORDS):
        return "MEDIUM"

    if name in AUTORUN_NAMES:
        return "HIGH"

    return "LOW"
