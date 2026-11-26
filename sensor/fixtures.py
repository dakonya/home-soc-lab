"""Create a deterministic Ethernet capture of harmless lab traffic offline."""

from __future__ import annotations

import argparse
import ipaddress
import struct
from dataclasses import dataclass
from pathlib import Path

CLIENT_IP = "192.0.2.10"
SERVER_IP = "198.51.100.20"
CLIENT_MAC = bytes.fromhex("020000000001")
SERVER_MAC = bytes.fromhex("020000000002")
FIRST_CLIENT_PORT = 41001
FIXTURE_EPOCH = 1_700_000_000
HTTP_PORT = 8000
FIN = 0x01
SYN = 0x02
PSH = 0x08
ACK = 0x10


@dataclass(frozen=True)
class Scenario:
    name: str
    protocol: str
    destination_port: int
    payload: bytes
    expected_sid: int | None = None


def http_request(
    target: str = "/",
    *,
    method: str = "GET",
    headers: tuple[tuple[str, str], ...] = (),
    body: bytes = b"",
) -> bytes:
    lines = [f"{method} {target} HTTP/1.1", "Host: service.lab.test", "Connection: close"]
    lines.extend(f"{name}: {value}" for name, value in headers)
    if body:
        lines.append(f"Content-Length: {len(body)}")
    return ("\r\n".join(lines) + "\r\n\r\n").encode("ascii") + body


def dns_question(name: str) -> bytes:
    labels = name.encode("ascii").split(b".")
    wire_name = b"".join(bytes([len(label)]) + label for label in labels) + b"\0"
    return struct.pack("!6H", 0x1234, 0x0100, 1, 0, 0, 0) + wire_name + struct.pack("!2H", 1, 1)


def scenarios() -> tuple[Scenario, ...]:
    octets = (("Content-Type", "application/octet-stream"),)
    form = (("Content-Type", "application/x-www-form-urlencoded"),)

    return (
        Scenario("canary", "http", HTTP_PORT, http_request("/soc-lab-canary"), 1000001),
        Scenario("basic-auth", "http", HTTP_PORT, http_request(headers=(("Authorization", "Basic ZHVtbXk6ZHVtbXk="),)), 1000002),
        Scenario("bearer-auth", "http", HTTP_PORT, http_request(headers=(("Authorization", "Bearer dummy-fixture-value"),)), 1000003),
        Scenario("session-cookie", "http", HTTP_PORT, http_request(headers=(("Cookie", "theme=light; session_id=dummy"),)), 1000004),
        Scenario("trace", "http", HTTP_PORT, http_request(method="TRACE"), 1000005),
        Scenario("connect", "http", HTTP_PORT, http_request("service.lab.test:443", method="CONNECT"), 1000006),
        Scenario("binary-put", "http", HTTP_PORT, http_request(method="PUT", headers=octets, body=b"dummy bytes"), 1000007),
        Scenario("uri-token", "http", HTTP_PORT, http_request("/download?kind=public&token=dummy"), 1000008),
        Scenario("admin-path", "http", HTTP_PORT, http_request("/admin/status"), 1000009),
        Scenario("backup-file", "http", HTTP_PORT, http_request("/backup/demo.sql"), 1000010),
        Scenario("debug-path", "http", HTTP_PORT, http_request("/debug/vars"), 1000011),
        Scenario("old-inventory-agent", "http", HTTP_PORT, http_request(headers=(("User-Agent", "LegacyInventory/1.4"),)), 1000012),
        Scenario("proxy-header", "http", HTTP_PORT, http_request(headers=(("X-Forwarded-For", "192.0.2.50"),)), 1000013),
        Scenario("webdav-discovery", "http", HTTP_PORT, http_request("/public/", method="PROPFIND"), 1000014),
        Scenario("form-api-key", "http", HTTP_PORT, http_request(method="POST", headers=form, body=b"mode=demo&api_key=dummy"), 1000015),
        Scenario("proxy-autodiscovery-dns", "dns", 53, dns_question("wpad.lab.test"), 1000016),
        Scenario("unicast-local-dns", "dns", 53, dns_question("printer.local"), 1000017),
        Scenario("watchlist-dns", "dns", 53, dns_question("blocked-sink.lab.test"), 1000018),
        Scenario("long-hex-dns-label", "dns", 53, dns_question("0123456789abcdef" * 3 + ".lab.test"), 1000019),
        Scenario("telnet-syn", "tcp", 23, b"", 1000020),
        Scenario("ftp-control-syn", "tcp", 21, b"", 1000021),
        Scenario("tftp-rrq", "udp", 69, b"\x00\x01public-lab.txt\x00octet\x00", 1000022),
        Scenario("normal-http", "http", HTTP_PORT, http_request("/health", headers=(("X-Demo-Authorization", "Basic fixture-only"),)), None),
        Scenario("canary-near-match", "http", HTTP_PORT, http_request("/soc-lab-canary-status"), None),
        Scenario("ordinary-cookie", "http", HTTP_PORT, http_request(headers=(("Cookie", "theme=light"),)), None),
        Scenario("binary-post", "http", HTTP_PORT, http_request(method="POST", headers=octets, body=b"dummy bytes"), None),
        Scenario("normal-form", "http", HTTP_PORT, http_request(method="POST", headers=form, body=b"api_key_hint=demo"), None),
        Scenario("ordinary-query-parameter", "http", HTTP_PORT, http_request("/download?token_count=0"), None),
        Scenario("normal-dns", "dns", 53, dns_question("service.lab.test"), None),
        Scenario("watchlist-near-match", "dns", 53, dns_question("blocked-sink.lab.test.example"), None),
        Scenario("long-dns-nonhex-label", "dns", 53, dns_question("g" * 48 + ".lab.test"), None),
        Scenario("normal-tcp-syn", "tcp", 443, b"", None),
        Scenario("normal-udp", "udp", 69, b"\x00\x04\x00\x01", None),
    )


def checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    word_total = sum(struct.unpack(f"!{len(data) // 2}H", data))
    while word_total >> 16:
        word_total = (word_total & 0xFFFF) + (word_total >> 16)
    return (~word_total) & 0xFFFF


def endpoints(reverse: bool) -> tuple[bytes, bytes, bytes, bytes]:
    client_ip = ipaddress.IPv4Address(CLIENT_IP).packed
    server_ip = ipaddress.IPv4Address(SERVER_IP).packed
    if reverse:
        return server_ip, client_ip, SERVER_MAC, CLIENT_MAC
    return client_ip, server_ip, CLIENT_MAC, SERVER_MAC


def ethernet_frame(payload: bytes, protocol: int, reverse: bool = False) -> bytes:
    source_ip, destination_ip, source_mac, destination_mac = endpoints(reverse)
    header = struct.pack(
        "!BBHHHBBH4s4s",
        0x45, 0, 20 + len(payload), 0, 0x4000, 64, protocol, 0, source_ip, destination_ip,
    )
    header = header[:10] + struct.pack("!H", checksum(header)) + header[12:]
    frame = destination_mac + source_mac + b"\x08\x00" + header + payload
    return frame.ljust(60, b"\x00")


def transport_checksum(payload: bytes, protocol: int, reverse: bool = False) -> int:
    source_ip, destination_ip, _, _ = endpoints(reverse)
    pseudo_header = struct.pack("!4s4sBBH", source_ip, destination_ip, 0, protocol, len(payload))
    return checksum(pseudo_header + payload)


def tcp_frame(
    ports: tuple[int, int],
    source_seq: int,
    acknowledgment: int,
    flags: int,
    payload: bytes = b"",
    reverse: bool = False,
) -> bytes:
    source_port, destination_port = ports[::-1] if reverse else ports
    header = struct.pack(
        "!HHIIBBHHH", source_port, destination_port, source_seq, acknowledgment,
        0x50, flags, 65535, 0, 0,
    )
    value = transport_checksum(header + payload, 6, reverse)
    header = header[:16] + struct.pack("!H", value) + header[18:]
    return ethernet_frame(header + payload, 6, reverse)


def udp_frame(ports: tuple[int, int], payload: bytes, reverse: bool = False) -> bytes:
    source_port, destination_port = ports[::-1] if reverse else ports
    header = struct.pack("!4H", source_port, destination_port, 8 + len(payload), 0)
    value = transport_checksum(header + payload, 17, reverse) or 0xFFFF
    return ethernet_frame(header[:6] + struct.pack("!H", value) + payload, 17, reverse)


def http_frames(ports: tuple[int, int], request: bytes) -> tuple[bytes, ...]:
    client_initial = 10000
    server_initial = 50000
    client_data = client_initial + 1
    server_data = server_initial + 1
    response = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK"
    if request.startswith(b"CONNECT "):
        response = b"HTTP/1.1 405 Method Not Allowed\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
    client_end = client_data + len(request)
    server_end = server_data + len(response)
    return (
        tcp_frame(ports, client_initial, 0, SYN),
        tcp_frame(ports, server_initial, client_data, SYN | ACK, reverse=True),
        tcp_frame(ports, client_data, server_data, ACK),
        tcp_frame(ports, client_data, server_data, PSH | ACK, request),
        tcp_frame(ports, server_data, client_end, PSH | ACK, response, reverse=True),
        tcp_frame(ports, client_end, server_end, FIN | ACK),
        tcp_frame(ports, server_end, client_end + 1, FIN | ACK, reverse=True),
        tcp_frame(ports, client_end + 1, server_end + 1, ACK),
    )


def frames(source_port: int, scenario: Scenario) -> tuple[bytes, ...]:
    ports = (source_port, scenario.destination_port)
    if scenario.protocol == "http":
        return http_frames(ports, scenario.payload)
    if scenario.protocol == "tcp":
        return (tcp_frame(ports, 10000, 0, SYN),)
    if scenario.protocol == "dns":
        question = scenario.payload
        answer = question[:2] + struct.pack("!5H", 0x8180, 1, 1, 0, 0) + question[12:]
        answer += struct.pack("!HHHIH4s", 0xC00C, 1, 1, 60, 4, ipaddress.IPv4Address(SERVER_IP).packed)
        return udp_frame(ports, question), udp_frame(ports, answer, reverse=True)
    return (udp_frame(ports, scenario.payload),)


def write_capture(path: Path, epoch: int) -> None:
    with path.open("wb") as capture:
        capture.write(struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        for ordinal, scenario in enumerate(scenarios()):
            for index, frame in enumerate(frames(FIRST_CLIENT_PORT + ordinal, scenario)):
                capture.write(struct.pack("<4I", epoch + ordinal, index * 1000, len(frame), len(frame)))
                capture.write(frame)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("pcap", type=Path, help="destination for the generated Ethernet capture")
    parser.add_argument("--start-time", type=int, default=FIXTURE_EPOCH, metavar="EPOCH",
                        help="override the fixed first packet timestamp with Unix seconds")
    args = parser.parse_args()
    if not 0 <= args.start_time <= 0xFFFFFFFF - len(scenarios()):
        parser.error("--start-time is outside the PCAP timestamp range")
    write_capture(args.pcap, args.start_time)


if __name__ == "__main__":
    main()
