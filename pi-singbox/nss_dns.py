#!/usr/bin/env python3
"""Tiny UDP DNS bridge backed by Python/NSS getaddrinfo.

Use this when Linux can resolve .local via getent/Python, but sing-box cannot.
It only answers A/AAAA queries and is intended to listen on 127.0.0.1:1053.
"""

from __future__ import annotations

import argparse
import socket
import struct

TYPE_A = 1
TYPE_AAAA = 28
CLASS_IN = 1
RCODE_NOERROR = 0
RCODE_FORMERR = 1
RCODE_NXDOMAIN = 3


def parse_qname(packet: bytes, offset: int = 12) -> tuple[str, int]:
    labels: list[str] = []
    while True:
        if offset >= len(packet):
            raise ValueError("truncated qname")
        length = packet[offset]
        offset += 1
        if length == 0:
            break
        if length & 0xC0:
            raise ValueError("compressed qname in query is unsupported")
        if offset + length > len(packet):
            raise ValueError("truncated label")
        labels.append(packet[offset : offset + length].decode("idna"))
        offset += length
    return ".".join(labels), offset


def encode_name(name: str) -> bytes:
    out = bytearray()
    for label in name.rstrip(".").split("."):
        raw = label.encode("idna")
        out.append(len(raw))
        out.extend(raw)
    out.append(0)
    return bytes(out)


def resolve(host: str, qtype: int) -> list[bytes]:
    family = socket.AF_INET if qtype == TYPE_A else socket.AF_INET6
    answers: list[bytes] = []
    seen: set[bytes] = set()
    for info in socket.getaddrinfo(host.rstrip("."), None, family, socket.SOCK_STREAM):
        ip = info[4][0].split("%", 1)[0]
        packed = socket.inet_pton(family, ip)
        if packed not in seen:
            answers.append(packed)
            seen.add(packed)
    return answers


def build_response(query: bytes, ttl: int) -> bytes:
    if len(query) < 12:
        raise ValueError("short query")
    ident, flags, qdcount, _, _, _ = struct.unpack("!HHHHHH", query[:12])
    if qdcount != 1:
        return struct.pack("!HHHHHH", ident, 0x8000 | RCODE_FORMERR, qdcount, 0, 0, 0) + query[12:]

    qname, after_name = parse_qname(query)
    if after_name + 4 > len(query):
        raise ValueError("truncated question")
    qtype, qclass = struct.unpack("!HH", query[after_name : after_name + 4])
    question = query[12 : after_name + 4]

    if qclass != CLASS_IN or qtype not in {TYPE_A, TYPE_AAAA}:
        return struct.pack("!HHHHHH", ident, 0x8180, 1, 0, 0, 0) + question

    try:
        records = resolve(qname, qtype)
    except socket.gaierror:
        records = []

    if not records:
        return struct.pack("!HHHHHH", ident, 0x8180 | RCODE_NXDOMAIN, 1, 0, 0, 0) + question

    answers = bytearray()
    for record in records:
        answers.extend(encode_name(qname))
        answers.extend(struct.pack("!HHIH", qtype, CLASS_IN, ttl, len(record)))
        answers.extend(record)

    return struct.pack("!HHHHHH", ident, 0x8180 | RCODE_NOERROR, 1, len(records), 0, 0) + question + bytes(answers)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--listen", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=1053)
    parser.add_argument("--ttl", type=int, default=30)
    args = parser.parse_args()

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((args.listen, args.port))
    print(f"nss-dns listening on udp://{args.listen}:{args.port}", flush=True)
    while True:
        query, addr = sock.recvfrom(4096)
        try:
            response = build_response(query, args.ttl)
        except Exception:
            if len(query) >= 2:
                ident = struct.unpack("!H", query[:2])[0]
                response = struct.pack("!HHHHHH", ident, 0x8000 | RCODE_FORMERR, 0, 0, 0, 0)
            else:
                continue
        sock.sendto(response, addr)


if __name__ == "__main__":
    main()
