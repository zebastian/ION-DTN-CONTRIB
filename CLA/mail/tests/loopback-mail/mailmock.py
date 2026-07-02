#!/usr/bin/env python3
"""Minimal SMTP + POP3 mock backing the mail CLA loopback test.

Accepts mail on the SMTP port into a single in-memory mailbox and serves
it on the POP3 port.  Pure stdlib; speaks just enough of both protocols
for libcurl.  Not a real mail server.
"""

import socket
import sys
import threading

MESSAGES = []
LOCK = threading.Lock()


def recvline(f):
    return f.readline()


def handle_smtp(conn):
    f = conn.makefile("rb")
    conn.sendall(b"220 mailmock ESMTP\r\n")
    while True:
        line = recvline(f)
        if not line:
            break
        cmd = line.strip().upper()
        if cmd.startswith(b"EHLO") or cmd.startswith(b"HELO"):
            conn.sendall(b"250-mailmock\r\n250 SIZE 104857600\r\n")
        elif cmd.startswith(b"MAIL") or cmd.startswith(b"RCPT"):
            conn.sendall(b"250 OK\r\n")
        elif cmd.startswith(b"DATA"):
            conn.sendall(b"354 End with <CR><LF>.<CR><LF>\r\n")
            data = bytearray()
            while True:
                dl = recvline(f)
                if not dl or dl == b".\r\n":
                    break
                if dl.startswith(b"."):
                    dl = dl[1:]           # undo dot-stuffing
                data += dl
            with LOCK:
                MESSAGES.append(bytes(data))
            conn.sendall(b"250 OK queued\r\n")
        elif cmd.startswith(b"QUIT"):
            conn.sendall(b"221 Bye\r\n")
            break
        elif cmd.startswith(b"RSET") or cmd.startswith(b"NOOP"):
            conn.sendall(b"250 OK\r\n")
        else:
            conn.sendall(b"250 OK\r\n")
    conn.close()


def handle_pop3(conn):
    f = conn.makefile("rb")
    deleted = set()
    conn.sendall(b"+OK mailmock POP3\r\n")
    while True:
        line = recvline(f)
        if not line:
            break
        parts = line.strip().split()
        if not parts:
            conn.sendall(b"-ERR\r\n")
            continue
        cmd = parts[0].upper()
        if cmd in (b"USER", b"PASS"):
            conn.sendall(b"+OK\r\n")
        elif cmd == b"CAPA":
            conn.sendall(b"+OK\r\nUSER\r\n.\r\n")
        elif cmd == b"STAT":
            with LOCK:
                live = [m for i, m in enumerate(MESSAGES) if i not in deleted]
            conn.sendall(
                ("+OK %d %d\r\n" % (len(live), sum(len(m) for m in live)))
                .encode())
        elif cmd in (b"LIST", b"UIDL"):
            with LOCK:
                snapshot = list(enumerate(MESSAGES))
            conn.sendall(b"+OK\r\n")
            for i, m in snapshot:
                if i in deleted:
                    continue
                if cmd == b"LIST":
                    conn.sendall(("%d %d\r\n" % (i + 1, len(m))).encode())
                else:
                    conn.sendall(("%d UID%d\r\n" % (i + 1, i + 1)).encode())
            conn.sendall(b".\r\n")
        elif cmd == b"RETR" and len(parts) > 1:
            idx = int(parts[1]) - 1
            with LOCK:
                msg = MESSAGES[idx] if 0 <= idx < len(MESSAGES) else None
            if msg is None or idx in deleted:
                conn.sendall(b"-ERR no such message\r\n")
                continue
            body = b"\r\n".join(
                (b"." + ln if ln.startswith(b".") else ln)
                for ln in msg.split(b"\r\n"))
            conn.sendall(b"+OK\r\n" + body + b"\r\n.\r\n")
        elif cmd == b"DELE" and len(parts) > 1:
            deleted.add(int(parts[1]) - 1)
            conn.sendall(b"+OK\r\n")
        elif cmd == b"QUIT":
            with LOCK:
                for i in sorted(deleted, reverse=True):
                    if 0 <= i < len(MESSAGES):
                        del MESSAGES[i]
            conn.sendall(b"+OK Bye\r\n")
            break
        elif cmd == b"NOOP":
            conn.sendall(b"+OK\r\n")
        else:
            conn.sendall(b"-ERR unknown\r\n")
    conn.close()


def serve(port, handler):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("127.0.0.1", port))
    s.listen(8)
    while True:
        conn, _ = s.accept()
        threading.Thread(target=handler, args=(conn,), daemon=True).start()


def main():
    smtp_port = int(sys.argv[1])
    pop_port = int(sys.argv[2])
    threading.Thread(target=serve, args=(smtp_port, handle_smtp),
                     daemon=True).start()
    threading.Thread(target=serve, args=(pop_port, handle_pop3),
                     daemon=True).start()
    threading.Event().wait()


if __name__ == "__main__":
    main()
