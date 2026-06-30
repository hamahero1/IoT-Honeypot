import json
from datetime import datetime, timezone
import paho.mqtt.client as mqtt

OUT = "/out/mqtt_messages.jsonl"

def now():
    return datetime.now(timezone.utc).isoformat()

def on_connect(client, userdata, flags, rc, properties=None):
    client.subscribe("#", qos=0)

def on_message(client, userdata, msg):
    payload = msg.payload.decode("utf-8", errors="replace")
    event = {
        "ts": now(),
        "service": "mqtt",
        "event": "message",
        "topic": msg.topic,
        "qos": msg.qos,
        "retain": bool(msg.retain),
        "payload": payload[:2000],
    }
    with open(OUT, "a", encoding="utf-8") as f:
        f.write(json.dumps(event, ensure_ascii=False) + "\n")

client = mqtt.Client(client_id="sniffer", clean_session=True)
client.on_connect = on_connect
client.on_message = on_message
client.connect("mqtt-device", 1883, 60)
client.loop_forever()
