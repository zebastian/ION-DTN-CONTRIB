#!/usr/bin/env python3
"""A structure-aware network fuzzer for tcpv4cla (RFC 9174, plaintext).

Each session it opens speaks enough TCPCLv4 to get somewhere - a contact
header, a SESS_INIT, then a run of messages - and corrupts it on the way:
lengths that disagree with what follows, Transfer IDs out of nowhere,
extension items that overrun their list, node IDs that are not text,
messages of no known type, connections cut mid-message or reset.  What
the daemon must do with all of it is stay up, keep its memory to itself
(run it under a sanitizer to see that) and give back every session slot
the fuzz took.

Usage:
    netfuzz.py fuzz HOST PORT SESSIONS SEED
    netfuzz.py probe HOST PORT

"fuzz" prints "RESULT: sessions=N" when done, or "RESULT: daemon_gone=I"
if the daemon stopped answering at session I.  "probe" opens one clean
session and prints "RESULT: probe=<SESS_INIT | SESS_TERM-reason | ...>".
A seed reproduces a run exactly, as far as the daemon's timing allows.
"""

import random
import socket
import struct
import sys
import time

XFER_SEGMENT = 0x01
XFER_ACK = 0x02
XFER_REFUSE = 0x03
KEEPALIVE = 0x04
SESS_TERM = 0x05
MSG_REJECT = 0x06
SESS_INIT = 0x07

FLAG_END = 0x01
FLAG_START = 0x02

XFEREXT_LENGTH = 0x0001

CONTACT = b"dtn!\x04\x00"

# Values at the edges of the fields they go into.
EDGE64 = [0, 1, 2, 65536, (1 << 32) - 1, 1 << 32, 0x7fffffffffffffff,
          0x8000000000000000, 0xfffffffffffffffe, 0xffffffffffffffff]


def result(key, value):
    print("RESULT: %s=%s" % (key, value), flush=True)


class Fuzzer(object):

    def __init__(self, host, port, seed):
        self.host = host
        self.port = port
        self.rand = random.Random(seed)
        self.transfer_id = 0

    # --- values ----------------------------------------------------

    def chance(self, p):
        return self.rand.random() < p

    def octets(self, count):
        return bytes(self.rand.getrandbits(8) for _ in range(count))

    def u64(self):
        if self.chance(0.3):
            return self.rand.choice(EDGE64)
        return self.rand.getrandbits(self.rand.choice([8, 16, 32, 64]))

    def u32(self):
        if self.chance(0.4):
            return self.rand.choice([0, 1, 5, 13, 0x7fffffff, 0xffffffff])
        return self.rand.getrandbits(32)

    def u16(self):
        if self.chance(0.4):
            return self.rand.choice([0, 1, 8, 0xffff])
        return self.rand.getrandbits(16)

    def mutate(self, msg):
        """Flip, overwrite, drop, insert or truncate a few octets."""
        out = bytearray(msg)
        for _ in range(self.rand.randint(1, 4)):
            if not out:
                break
            i = self.rand.randrange(len(out))
            op = self.rand.random()
            if op < 0.4:
                out[i] ^= 1 << self.rand.randrange(8)
            elif op < 0.6:
                out[i] = self.rand.choice([0x00, 0x7f, 0x80, 0xff])
            elif op < 0.75:
                del out[i:i + self.rand.randint(1, 8)]
            elif op < 0.9:
                out[i:i] = self.octets(self.rand.randint(1, 8))
            else:
                del out[i:]
        return bytes(out)

    # --- messages --------------------------------------------------

    def ext_items(self):
        """An extension item list, its item lengths not always true."""
        out = b""
        for _ in range(self.rand.randint(0, 3)):
            item_type = self.rand.choice([XFEREXT_LENGTH, 0, 2, 0xffff,
                                          self.rand.getrandbits(16)])
            if item_type == XFEREXT_LENGTH and self.chance(0.7):
                value = struct.pack("!Q", self.u64())
            else:
                value = self.octets(self.rand.randint(0, 20))
            length = len(value) if self.chance(0.85) else self.u16()
            flags = self.rand.choice([0, 1, self.rand.getrandbits(8)])
            out += struct.pack("!BHH", flags, item_type, length) + value
        return out

    def contact(self):
        msg = b"dtn!" + bytes([4, self.rand.choice([0, 0, 1, 0xff])])
        return self.mutate(msg) if self.chance(0.05) else msg

    def sess_init(self):
        node_id = self.rand.choice([
            b"ipn:2.0", b"ipn:2", b"dtn://x/", b"", b"ipn:" + b"9" * 40,
            b"ipn:2.0\nforged", b"ipn:2.0\x00junk",
            self.octets(self.rand.randint(0, 64))])
        ext = self.ext_items()
        node_len = len(node_id) if self.chance(0.9) else self.u16()
        ext_len = len(ext) if self.chance(0.9) else self.u32()
        msg = (struct.pack("!BHQQH", SESS_INIT,
                           self.rand.choice([0, 0, 1, 60, 0xffff]),
                           self.rand.choice([0, 1, 1400, 65536, self.u64()]),
                           self.rand.choice([0, 1, 1 << 20, self.u64()]),
                           node_len)
               + node_id + struct.pack("!I", ext_len) + ext)
        return self.mutate(msg) if self.chance(0.05) else msg

    def segment(self):
        flags = self.rand.choice([FLAG_START | FLAG_END,
                                  FLAG_START | FLAG_END, FLAG_START, 0,
                                  FLAG_END, self.rand.getrandbits(8)])
        if flags & FLAG_START and self.chance(0.8):
            self.transfer_id += 1
        transfer_id = self.transfer_id if self.chance(0.8) else self.u64()

        msg = struct.pack("!BBQ", XFER_SEGMENT, flags, transfer_id)
        if flags & FLAG_START:
            if self.chance(0.5):
                ext = self.ext_items()
            else:
                ext = struct.pack("!BHHQ", self.rand.choice([0, 1]),
                                  XFEREXT_LENGTH, 8,
                                  self.rand.choice([0, 10, 200, 1 << 20,
                                                    self.u64()]))
            ext_len = len(ext) if self.chance(0.9) else self.u32()
            msg += struct.pack("!I", ext_len) + ext

        data = self.octets(self.rand.choice([0, 1, 10, 100, 1500, 70000]))
        if self.chance(0.92):
            data_len = len(data)
        else:
            data_len = self.rand.choice([len(data) + 1, len(data) + 100,
                                         self.u64()])
        return msg + struct.pack("!Q", data_len) + data

    def message(self):
        k = self.rand.random()
        if k < 0.45:
            msg = self.segment()
        elif k < 0.55:
            msg = struct.pack("!BBQQ", XFER_ACK, self.rand.getrandbits(8),
                              self.rand.choice([self.transfer_id,
                                                self.u64()]),
                              self.u64())
        elif k < 0.62:
            msg = struct.pack("!BBQ", XFER_REFUSE, self.rand.getrandbits(8),
                              self.rand.choice([self.transfer_id,
                                                self.u64()]))
        elif k < 0.70:
            msg = bytes([KEEPALIVE])
        elif k < 0.76:
            msg = bytes([SESS_TERM]) + self.octets(2)
        elif k < 0.83:
            msg = bytes([MSG_REJECT]) + self.octets(2)
        elif k < 0.88:
            msg = self.sess_init()	# Again, which is out of turn.
        elif k < 0.94:
            msg = (bytes([self.rand.choice([0x00, 0x08, 0xff,
                                            self.rand.getrandbits(8)])])
                   + self.octets(self.rand.randint(0, 16)))
        else:
            msg = CONTACT		# Likewise.
        return self.mutate(msg) if self.chance(0.1) else msg

    # --- sessions --------------------------------------------------

    def drain(self, sock):
        try:
            sock.settimeout(0)
            while sock.recv(65536):
                pass
        except OSError:
            pass

    def session(self):
        """One fuzzed session.  Returns False if it could not connect."""
        try:
            sock = socket.create_connection((self.host, self.port), timeout=5)
        except OSError:
            return False

        self.transfer_id = 0
        try:
            sock.sendall(self.contact())
            if self.chance(0.3):
                time.sleep(0.01)
            if self.chance(0.97):
                sock.sendall(self.sess_init())
            for _ in range(self.rand.randint(0, 25)):
                sock.sendall(self.message())
                if self.chance(0.2):
                    self.drain(sock)
                if self.chance(0.03):
                    time.sleep(0.05)
            if self.chance(0.3):	# Cut off mid-message.
                sock.sendall(self.segment()[:self.rand.randint(1, 20)])
        except OSError:
            pass	# The daemon hung up on us, as well it might.

        self.drain(sock)
        if self.chance(0.5):	# Reset rather than close.
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER,
                            struct.pack("ii", 1, 0))
        sock.close()
        return True

    def alive(self):
        try:
            socket.create_connection((self.host, self.port), timeout=3).close()
            return True
        except OSError:
            return False


def cmd_fuzz(host, port, sessions, seed):
    fuzzer = Fuzzer(host, port, seed)
    for i in range(sessions):
        if not fuzzer.session():
            # A refused connection is the session limit doing its job,
            # unless nothing is listening any more.
            time.sleep(0.5)
            if not fuzzer.alive():
                result("daemon_gone", i)
                return 1
    result("sessions", sessions)
    return 0


def cmd_probe(host, port):
    """One clean session: does the daemon still have a slot for it?"""
    node_id = b"ipn:2.0"
    sock = socket.create_connection((host, port), timeout=15)
    sock.sendall(CONTACT
                 + struct.pack("!BHQQH", SESS_INIT, 0, 65536, 1 << 20,
                               len(node_id))
                 + node_id + struct.pack("!I", 0))
    reply = b""
    try:
        while len(reply) < 9:
            chunk = sock.recv(4096)
            if not chunk:
                break
            reply += chunk
    except socket.timeout:
        pass

    if reply[6:7] == bytes([SESS_INIT]):
        outcome = "SESS_INIT"
        sock.sendall(struct.pack("!BBB", SESS_TERM, 0, 0))
    elif reply[6:7] == bytes([SESS_TERM]) and len(reply) >= 9:
        outcome = "SESS_TERM-%d" % reply[8]
    else:
        outcome = "none"
    sock.close()
    result("probe", outcome)
    return 0


def main(argv):
    if len(argv) >= 6 and argv[1] == "fuzz":
        return cmd_fuzz(argv[2], int(argv[3]), int(argv[4]), argv[5])
    if len(argv) >= 4 and argv[1] == "probe":
        return cmd_probe(argv[2], int(argv[3]))
    print(__doc__)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv))
