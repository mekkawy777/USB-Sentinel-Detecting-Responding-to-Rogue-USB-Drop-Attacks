from flask import Flask, request, jsonify
from datetime import datetime

app = Flask(__name__)

AGENTS = {}   # agent_id -> metadata
EVENTS = []   # كل الأحداث

@app.route("/register", methods=["POST"])
def register():
    data = request.json
    agent_id = data["agent_id"]

    AGENTS[agent_id] = {
        "hostname": data.get("hostname"),
        "ip": request.remote_addr,
        "last_seen": datetime.utcnow().isoformat()
    }

    return {"status": "registered"}

@app.route("/event", methods=["POST"])
def event():
    data = request.json
    data["received_at"] = datetime.utcnow().isoformat()
    EVENTS.append(data)

    # تحديث last_seen
    agent_id = data.get("agent_id")
    if agent_id in AGENTS:
        AGENTS[agent_id]["last_seen"] = data["received_at"]

    return {"status": "ok"}

@app.route("/agents")
def agents():
    return jsonify(AGENTS)

@app.route("/events")
def events():
    return jsonify(EVENTS[-500:])  # آخر 500 حدث

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
