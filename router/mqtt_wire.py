import socket
import time


class MQTTProtocolError(RuntimeError):
    pass


def encode_varint(value):
    encoded = bytearray()
    value = int(value)
    while True:
        digit = value % 128
        value //= 128
        if value > 0:
            digit |= 0x80
        encoded.append(digit)
        if value == 0:
            break
    return bytes(encoded)


def encode_utf8(text):
    raw = str(text).encode("utf-8")
    return len(raw).to_bytes(2, "big") + raw


def read_exact(sock, length):
    data = bytearray()
    while len(data) < length:
        chunk = sock.recv(length - len(data))
        if not chunk:
            raise MQTTProtocolError("broker closed the socket")
        data.extend(chunk)
    return bytes(data)


def read_remaining_length(sock):
    multiplier = 1
    value = 0

    while True:
        digit = read_exact(sock, 1)[0]
        value += (digit & 0x7F) * multiplier
        if (digit & 0x80) == 0:
            return value
        multiplier *= 128
        if multiplier > 128 * 128 * 128:
            raise MQTTProtocolError("invalid remaining length")


def build_connect_packet(client_id, keepalive=60):
    variable_header = (
        encode_utf8("MQTT")
        + bytes([4])  # MQTT 3.1.1
        + bytes([0x02])  # clean session
        + int(keepalive).to_bytes(2, "big")
    )
    payload = encode_utf8(client_id)
    body = variable_header + payload
    return bytes([0x10]) + encode_varint(len(body)) + body


def build_subscribe_packet(packet_id, topic_filter="#", qos=0):
    variable_header = int(packet_id).to_bytes(2, "big")
    payload = encode_utf8(topic_filter) + bytes([int(qos)])
    body = variable_header + payload
    return bytes([0x82]) + encode_varint(len(body)) + body


def build_publish_packet(topic, payload, qos=0, retain=False):
    if isinstance(payload, bytes):
        payload_bytes = payload
    else:
        payload_bytes = str(payload).encode("utf-8")

    qos = int(qos)
    fixed_header = 0x30 | ((qos & 0x03) << 1) | (0x01 if retain else 0x00)
    variable_header = encode_utf8(topic)
    if qos > 0:
        variable_header += (1).to_bytes(2, "big")
    body = variable_header + payload_bytes
    return bytes([fixed_header]) + encode_varint(len(body)) + body


def build_pingreq_packet():
    return b"\xC0\x00"


def build_disconnect_packet():
    return b"\xE0\x00"


def recv_packet(sock):
    first_byte = read_exact(sock, 1)[0]
    remaining_length = read_remaining_length(sock)
    payload = read_exact(sock, remaining_length) if remaining_length else b""
    return first_byte, payload


def open_client(host, port, client_id, keepalive=60, timeout=5.0, source_host=None):
    source_address = (source_host, 0) if source_host else None
    sock = socket.create_connection((host, int(port)), timeout=timeout, source_address=source_address)
    # The router proxy can add a small delay while it opens and bridges the
    # private broker connection, so keep the response timeout aligned with the
    # caller's connection timeout instead of using a fixed one-second window.
    sock.settimeout(timeout)
    sock.sendall(build_connect_packet(client_id=client_id, keepalive=keepalive))

    first_byte, payload = recv_packet(sock)
    packet_type = first_byte >> 4
    if packet_type != 2 or len(payload) < 2 or payload[1] != 0:
        raise MQTTProtocolError("broker rejected CONNECT")

    return sock


def subscribe(sock, topic_filter="#", packet_id=1, qos=0):
    sock.sendall(
        build_subscribe_packet(
            packet_id=packet_id,
            topic_filter=topic_filter,
            qos=qos,
        )
    )

    deadline = time.monotonic() + 5.0
    while time.monotonic() < deadline:
        try:
            first_byte, _payload = recv_packet(sock)
        except socket.timeout:
            continue

        packet_type = first_byte >> 4
        if packet_type == 9:
            return
        if packet_type == 13:
            continue

    raise MQTTProtocolError("broker did not return SUBACK")


def parse_publish_packet(first_byte, payload):
    qos = (first_byte >> 1) & 0x03
    retain = bool(first_byte & 0x01)

    if len(payload) < 2:
        raise MQTTProtocolError("PUBLISH payload missing topic length")

    topic_length = int.from_bytes(payload[:2], "big")
    if len(payload) < 2 + topic_length:
        raise MQTTProtocolError("PUBLISH payload missing topic")

    topic_start = 2
    topic_end = topic_start + topic_length
    topic = payload[topic_start:topic_end].decode("utf-8", errors="replace")

    index = topic_end
    if qos > 0:
        if len(payload) < index + 2:
            raise MQTTProtocolError("PUBLISH payload missing packet id")
        index += 2

    message = payload[index:]
    return {
        "topic": topic,
        "payload_bytes": message,
        "qos": qos,
        "retain": retain,
    }


def iter_publish_messages(sock, keepalive=60):
    keepalive = max(int(keepalive), 10)
    last_tx = time.monotonic()

    while True:
        try:
            first = sock.recv(1)
        except socket.timeout:
            if time.monotonic() - last_tx >= keepalive / 2:
                sock.sendall(build_pingreq_packet())
                last_tx = time.monotonic()
            continue

        if not first:
            raise MQTTProtocolError("broker closed the socket")

        remaining_length = read_remaining_length(sock)
        payload = read_exact(sock, remaining_length) if remaining_length else b""
        first_byte = first[0]
        packet_type = first_byte >> 4

        if packet_type == 3:
            yield parse_publish_packet(first_byte, payload)
            continue

        if packet_type == 13:
            continue


def publish_message(host, port, client_id, topic, payload, keepalive=30, timeout=5.0, source_host=None):
    sock = open_client(
        host=host,
        port=port,
        client_id=client_id,
        keepalive=keepalive,
        timeout=timeout,
        source_host=source_host,
    )
    try:
        sock.sendall(build_publish_packet(topic=topic, payload=payload, qos=0, retain=False))
        time.sleep(0.1)
        try:
            sock.sendall(build_disconnect_packet())
        except OSError:
            pass
    finally:
        sock.close()
