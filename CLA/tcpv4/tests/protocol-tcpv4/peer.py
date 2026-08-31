#!/usr/bin/env python3
"""A synthetic TCPCLv4 (RFC 9174) peer, for driving tcpv4cla's error paths.

The standard BP tools can exercise a convergence layer's happy path but
not much else: they cannot send a MSG_REJECT, refuse a transfer, stall
half way through negotiation or leave a connection unanswered.  Those are
the paths this speaks directly, over a plaintext session (tcpv4cla -T
none), so that the behaviour of each can be asserted rather than read.

Each subcommand prints "RESULT: <key>=<value>" lines for the test script
to check, and exits non-zero when the exchange itself went wrong.
"""

import socket
import struct
import sys
import time

MAGIC = b"dtn!"
VERSION = 4

XFER_SEGMENT = 0x01
XFER_ACK = 0x02
XFER_REFUSE = 0x03
KEEPALIVE = 0x04
SESS_TERM = 0x05
MSG_REJECT = 0x06
SESS_INIT = 0x07

FLAG_END = 0x01
FLAG_START = 0x02

REFUSE_COMPLETED = 0x01
REFUSE_NOT_ACCEPTABLE = 0x04

REJECT_UNEXPECTED = 0x03

TERM_BUSY = 0x03

TYPE_NAMES = {
    XFER_SEGMENT: "XFER_SEGMENT",
    XFER_ACK: "XFER_ACK",
    XFER_REFUSE: "XFER_REFUSE",
    KEEPALIVE: "KEEPALIVE",
    SESS_TERM: "SESS_TERM",
    MSG_REJECT: "MSG_REJECT",
    SESS_INIT: "SESS_INIT",
}


class Fault(Exception):
    pass


def result(key, value):
    print("RESULT: %s=%s" % (key, value), flush=True)


class Peer(object):
    """One TCPCL session, from the active (connecting) side."""

    def __init__(self, host, port, node_id="ipn:2.0", keepalive=0,
                 segment_mru=65536, transfer_mru=1048576):
        self.sock = socket.create_connection((host, port), timeout=30)
        self.sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        self.node_id = node_id
        self.keepalive = keepalive
        self.segment_mru = segment_mru
        self.transfer_mru = transfer_mru
        self.buffered = b""

    # --- framing ---------------------------------------------------

    def send(self, data):
        self.sock.sendall(data)

    def recv(self, count, timeout=15):
        """Read exactly count octets, or raise."""
        self.sock.settimeout(timeout)
        out = b""
        while len(out) < count:
            chunk = self.sock.recv(count - len(out))
            if not chunk:
                raise Fault("peer closed the connection after %d of %d octets"
                            % (len(out), count))
            out += chunk
        return out

    def recv_type(self, timeout=15):
        """The type octet of the next message, or None on a clean close."""
        self.sock.settimeout(timeout)
        try:
            chunk = self.sock.recv(1)
        except socket.timeout:
            return None
        if not chunk:
            return "closed"
        return chunk[0]

    # --- establishment ---------------------------------------------

    def contact(self, can_tls=False):
        self.send(MAGIC + bytes([VERSION, 0x01 if can_tls else 0x00]))
        reply = self.recv(6)
        if reply[:4] != MAGIC:
            raise Fault("bad contact header magic: %r" % reply[:4])
        if reply[4] != VERSION:
            raise Fault("peer speaks TCPCL version %d" % reply[4])
        return reply[5]

    def send_sess_init(self):
        node = self.node_id.encode()
        self.send(struct.pack("!BHQQH", SESS_INIT, self.keepalive,
                              self.segment_mru, self.transfer_mru, len(node))
                  + node + struct.pack("!I", 0))

    def read_sess_init(self):
        """Read the peer's SESS_INIT.  Returns its node ID."""
        msg = self.recv_type()
        if msg == SESS_TERM:
            flags, reason = struct.unpack("!BB", self.recv(2))
            raise Fault("session refused: SESS_TERM reason %d" % reason)
        if msg != SESS_INIT:
            raise Fault("expected SESS_INIT, got %s" % TYPE_NAMES.get(msg, msg))
        keepalive, seg_mru, xfer_mru, node_len = struct.unpack(
            "!HQQH", self.recv(20))
        node = self.recv(node_len).decode() if node_len else ""
        ext_len, = struct.unpack("!I", self.recv(4))
        if ext_len:
            self.recv(ext_len)
        return node

    def establish(self):
        self.contact()
        self.send_sess_init()
        return self.read_sess_init()

    # --- messages --------------------------------------------------

    def send_msg_reject(self, reason, rejected_type):
        self.send(struct.pack("!BBB", MSG_REJECT, reason, rejected_type))

    def send_xfer_refuse(self, reason, transfer_id):
        self.send(struct.pack("!BBQ", XFER_REFUSE, reason, transfer_id))

    def send_xfer_ack(self, flags, transfer_id, length):
        self.send(struct.pack("!BBQQ", XFER_ACK, flags, transfer_id, length))

    def send_sess_term(self, reason=0, reply=False):
        self.send(struct.pack("!BBB", SESS_TERM, 0x01 if reply else 0x00,
                              reason))

    def read_segment(self):
        """Read one XFER_SEGMENT, its type octet already taken."""
        flags, transfer_id = struct.unpack("!BQ", self.recv(9))
        if flags & FLAG_START:
            ext_len, = struct.unpack("!I", self.recv(4))
            if ext_len:
                self.recv(ext_len)
        data_len, = struct.unpack("!Q", self.recv(8))
        data = self.recv(data_len) if data_len else b""
        return flags, transfer_id, data

    def await_transfer(self, timeout=20):
        """Wait for the start of a transfer.  Returns its Transfer ID, or
        None if none arrived.  Anything else on the way is answered as a
        working peer would."""
        deadline = time.time() + timeout
        while time.time() < deadline:
            msg = self.recv_type(timeout=max(1, deadline - time.time()))
            if msg is None:
                continue
            if msg == "closed":
                raise Fault("session closed while awaiting a transfer")
            if msg == XFER_SEGMENT:
                flags, transfer_id, data = self.read_segment()
                return transfer_id, flags, data
            if msg == KEEPALIVE:
                continue
            if msg == SESS_TERM:
                flags, reason = struct.unpack("!BB", self.recv(2))
                raise Fault("session terminated (reason %d) while awaiting "
                            "a transfer" % reason)
            if msg == MSG_REJECT:
                reason, rejected = struct.unpack("!BB", self.recv(2))
                raise Fault("got MSG_REJECT (reason %d, type %d)"
                            % (reason, rejected))
            raise Fault("unexpected %s while awaiting a transfer"
                        % TYPE_NAMES.get(msg, msg))
        return None

    def close(self):
        try:
            self.sock.close()
        except OSError:
            pass


# --- subcommands ---------------------------------------------------------


def cmd_msgreject(host, port):
    """RFC 9174 5.1.2: a MSG_REJECT is never answered with a MSG_REJECT.

    One that names a message the session does not turn on (a KEEPALIVE)
    leaves the session running; one that names the transfer machinery
    ends it, because the two ends no longer agree about its state."""
    peer = Peer(host, port)
    peer.establish()

    peer.send_msg_reject(REJECT_UNEXPECTED, KEEPALIVE)
    replied = "none"
    deadline = time.time() + 6
    while time.time() < deadline:
        msg = peer.recv_type(timeout=2)
        if msg is None:
            continue
        if msg == "closed":
            replied = "closed"
            break
        if msg == KEEPALIVE:
            continue
        if msg == MSG_REJECT:
            peer.recv(2)
            replied = "MSG_REJECT"
            break
        if msg == SESS_TERM:
            peer.recv(2)
            replied = "SESS_TERM"
            break
        replied = TYPE_NAMES.get(msg, str(msg))
        break
    result("harmless_reject_answer", replied)

    peer.send_msg_reject(REJECT_UNEXPECTED, XFER_SEGMENT)
    answer = "none"
    deadline = time.time() + 10
    while time.time() < deadline:
        msg = peer.recv_type(timeout=2)
        if msg is None:
            continue
        if msg == "closed":
            answer = "closed"
            break
        if msg == KEEPALIVE:
            continue
        if msg == SESS_TERM:
            flags, reason = struct.unpack("!BB", peer.recv(2))
            answer = "SESS_TERM"
            break
        if msg == MSG_REJECT:
            peer.recv(2)
            answer = "MSG_REJECT"
            break
        answer = TYPE_NAMES.get(msg, str(msg))
        break
    result("transfer_reject_answer", answer)
    peer.close()
    return 0


def cmd_refuse(host, port, node_id):
    """RFC 9174 5.2.4: "Completed" says the receiver already has the
    bundle, so the sender may consider the transfer done.  Any other
    refusal leaves the bundle for BP to offer again.

    The two are told apart here: the first transfer is refused as "Not
    Acceptable" and has to come back, the second as "Completed" and must
    not."""
    peer = Peer(host, port, node_id=node_id)
    peer.establish()

    first = peer.await_transfer(timeout=30)
    if first is None:
        raise Fault("no transfer arrived to refuse")
    result("first_transfer", "yes")
    peer.send_xfer_refuse(REFUSE_NOT_ACCEPTABLE, first[0])

    second = peer.await_transfer(timeout=30)
    result("retried_after_plain_refusal", "yes" if second else "no")
    if second is None:
        peer.close()
        return 1

    peer.send_xfer_refuse(REFUSE_COMPLETED, second[0])

    third = peer.await_transfer(timeout=15)
    result("retried_after_completed", "yes" if third else "no")
    peer.close()
    return 0


def cmd_stall(host, port, count):
    """RFC 9174 7.10: connections that are opened and then left part way
    through negotiation must not be able to take every session slot on
    the node."""
    held = []
    refused = 0
    for _ in range(count):
        try:
            sock = socket.create_connection((host, port), timeout=10)
        except OSError:
            refused += 1
            continue

        sock.settimeout(5)
        try:
            #  The passive entity answers only once it has our contact
            #  header, so saying nothing keeps this connection in
            #  negotiation.  A connection over the cap is closed at once.
            if sock.recv(1) == b"":
                refused += 1
                sock.close()
                continue
        except socket.timeout:
            pass
        held.append(sock)

    result("held", len(held))
    result("refused", refused)
    for sock in held:
        sock.close()
    return 0


def cmd_busy(host, port, limit):
    """RFC 9174 6.1: a node that cannot take on another session says so
    with SESS_TERM "Busy", rather than leaving the peer to read a bare
    close as a network fault."""
    established = []
    for i in range(limit):
        peer = Peer(host, port, node_id="ipn:%d.0" % (10 + i))
        peer.establish()
        established.append(peer)
    result("established", len(established))

    over = Peer(host, port, node_id="ipn:99.0")
    over.contact()
    over.send_sess_init()
    outcome = "none"
    msg = over.recv_type(timeout=15)
    if msg == SESS_TERM:
        flags, reason = struct.unpack("!BB", over.recv(2))
        outcome = "busy" if reason == TERM_BUSY else "term-%d" % reason
    elif msg == SESS_INIT:
        outcome = "accepted"
    elif msg == "closed" or msg is None:
        outcome = "closed"
    else:
        outcome = TYPE_NAMES.get(msg, str(msg))
    result("over_limit", outcome)

    over.close()
    for peer in established:
        peer.close()
    return 0


def cmd_nodeid(host, port, node_id, seconds):
    """RFC 9174 4.6 names a peer with a node ID, not with a node number:
    a peer that calls itself dtn://... is as much a peer as an ipn: one,
    and a session to it is as routable."""
    peer = Peer(host, port, node_id=node_id)
    theirs = peer.establish()
    result("peer_node_id", theirs)
    result("established", "yes")
    time.sleep(seconds)
    peer.close()
    return 0


def cmd_listen(port, seconds):
    """A peer that accepts the TCP connection and then goes no further.

    RFC 9174 4.1 has the reconnection delay grow after a failed session,
    and a session is not established merely because the connection was
    accepted; this is the case that tells the two apart."""
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("127.0.0.1", port))
    listener.listen(16)
    listener.settimeout(1)

    started = time.time()
    stamps = []
    while time.time() - started < seconds:
        try:
            sock, _ = listener.accept()
        except socket.timeout:
            continue
        stamps.append(round(time.time() - started, 2))
        sock.close()  # No contact header: the session never establishes.

    listener.close()
    gaps = [round(b - a, 2) for a, b in zip(stamps, stamps[1:])]
    result("attempts", len(stamps))
    result("stamps", ",".join(str(s) for s in stamps))
    result("largest_gap", max(gaps) if gaps else 0)
    return 0


def main(argv):
    if len(argv) < 2:
        print(__doc__)
        return 2

    command = argv[1]
    try:
        if command == "msgreject":
            return cmd_msgreject(argv[2], int(argv[3]))
        if command == "refuse":
            return cmd_refuse(argv[2], int(argv[3]), argv[4])
        if command == "stall":
            return cmd_stall(argv[2], int(argv[3]), int(argv[4]))
        if command == "busy":
            return cmd_busy(argv[2], int(argv[3]), int(argv[4]))
        if command == "nodeid":
            return cmd_nodeid(argv[2], int(argv[3]), argv[4], int(argv[5]))
        if command == "listen":
            return cmd_listen(int(argv[2]), int(argv[3]))
    except Fault as fault:
        print("ERROR: %s" % fault, file=sys.stderr)
        return 1
    except OSError as err:
        print("ERROR: %s" % err, file=sys.stderr)
        return 1

    print("ERROR: unknown command %r" % command, file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv))
