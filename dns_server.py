#!/usr/bin/env python3
"""Minimal DNS server/parser."""
import struct, sys

class DNSPacket:
    def __init__(self, data=None):
        if data: self.parse(data)
        else: self.id=0; self.flags=0; self.questions=[]; self.answers=[]
    def parse(self, data):
        self.id, self.flags, qdcount = struct.unpack(">HHH", data[:6])
        ancount = struct.unpack(">H", data[6:8])[0]
        offset = 12; self.questions = []; self.answers = []
        for _ in range(qdcount):
            name, offset = self._read_name(data, offset)
            qtype, qclass = struct.unpack(">HH", data[offset:offset+4])
            self.questions.append((name, qtype, qclass)); offset += 4
    def _read_name(self, data, offset):
        parts = []
        while True:
            length = data[offset]
            if length == 0: offset += 1; break
            if length >= 192:
                ptr = struct.unpack(">H", data[offset:offset+2])[0] & 0x3fff
                name, _ = self._read_name(data, ptr); parts.append(name); offset += 2; break
            offset += 1; parts.append(data[offset:offset+length].decode()); offset += length
        return ".".join(parts), offset
    def build_response(self, records):
        resp = struct.pack(">HHHHHH", self.id, 0x8180, len(self.questions), len(records), 0, 0)
        for name, qtype, qclass in self.questions:
            for part in name.split("."): resp += bytes([len(part)]) + part.encode()
            resp += b"\x00" + struct.pack(">HH", qtype, qclass)
        for name, rtype, ttl, rdata in records:
            for part in name.split("."): resp += bytes([len(part)]) + part.encode()
            resp += b"\x00" + struct.pack(">HHIH", rtype, 1, ttl, len(rdata)) + rdata
        return resp

if __name__ == "__main__":
    # Demo: parse a crafted DNS query
    query = struct.pack(">HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0)
    for part in "example.com".split("."): query += bytes([len(part)]) + part.encode()
    query += b"\x00" + struct.pack(">HH", 1, 1)  # A record, IN class
    pkt = DNSPacket(query)
    print(f"Query ID: 0x{pkt.id:04x}")
    print(f"Questions: {pkt.questions}")
    import socket
    ip = socket.inet_aton("93.184.216.34")
    resp = pkt.build_response([("example.com", 1, 300, ip)])
    print(f"Response: {len(resp)} bytes")
