import requests

CENTRAL_URL = "http://127.0.0.1:8080/event"

def send_event(entry):
    try:
        requests.post(CENTRAL_URL, json=entry, timeout=1)
    except Exception:
        pass
