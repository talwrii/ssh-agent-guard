"""Shims handed to guard.star as they are. None of them takes a path."""
import os
import socket
import struct
from pathlib import Path


def my_uid():
    return os.getuid()


def recv_exact(sock, n):
    """Exactly n bytes as a list of ints, or None if the other end hung up."""
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            return None
        buf += chunk
    return list(buf)


def send(sock, values):
    sock.sendall(bytes(values))


def peer(sock):
    """pid and uid of the process on the other end, from the kernel."""
    raw = sock.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i"))
    pid, uid, _gid = struct.unpack("3i", raw)
    return {"pid": pid, "uid": uid}


def process(pid):
    """Name and parent of a process, from /proc/<pid>/stat, or None if it is gone."""
    try:
        stat = Path(f"/proc/{int(pid)}/stat").read_text()
    except OSError:
        return None
    # "pid (name) state ppid ..."; the name may itself contain spaces or ')'.
    name = stat[stat.index("(") + 1:stat.rindex(")")]
    ppid = int(stat[stat.rindex(")") + 1:].split()[1])
    return {"pid": int(pid), "ppid": ppid, "name": name}
