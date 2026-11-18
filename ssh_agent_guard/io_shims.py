"""I/O shims: every side effect ssh-agent-guard performs is in this file.

FOR_STARLARK are the shims guard.star calls (plus connect_unix, which boot.py
wraps so sockets stay opaque to Starlark). The rest are used by boot.py.
"""
import json
import os
import signal
import socket
import struct
import sys
import threading
import time
from pathlib import Path

FOR_STARLARK = ["env", "my_uid", "recv_exact", "send", "peer", "process", "log"]


# --- used by boot.py ---------------------------------------------------------

def read_starlark_source():
    return Path(__file__).with_name("guard.star").read_text()


def prepare_dir(listen_path, captive_path):
    """Make our directory (ours, 0700), refuse if a guard is already live there,
    and clear sockets left by a previous run. captive_path may be None."""
    d = Path(listen_path).parent
    d.mkdir(parents=True, exist_ok=True, mode=0o700)
    st = d.lstat()
    if d.is_symlink() or not d.is_dir() or st.st_uid != os.getuid() or st.st_mode & 0o077:
        sys.exit(f"ssh-agent-guard: {d} must be a directory owned by you with mode 0700")
    probe = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        probe.connect(listen_path)
        sys.exit(f"ssh-agent-guard: already running on {listen_path}")
    except (ConnectionRefusedError, FileNotFoundError):
        pass
    finally:
        probe.close()
    for path in (listen_path, captive_path):
        if path is None:
            continue
        p = Path(path)
        if p.is_symlink() or (p.exists() and not p.is_socket()):
            sys.exit(f"ssh-agent-guard: {path} exists and is not a socket")
        if p.exists():
            p.unlink()


def exec_under_captive_agent(captive_path, argv):
    """Replace this process with `ssh-agent -a captive_path <this program>`.

    ssh-agent then runs us again as its command, and exits by itself within
    about 10 seconds of that command dying, even on kill -9. (ssh-agent is
    setgid, so the kernel's parent-death signal can't be used instead.)
    """
    env = dict(os.environ, SSH_AGENT_GUARD_CAPTIVE=captive_path)
    cmd = ["ssh-agent", "-a", captive_path, sys.executable, "-m", "ssh_agent_guard.boot", *argv]
    os.execvpe("ssh-agent", cmd, env)


def kill_pid(pid):
    try:
        os.kill(int(pid), signal.SIGTERM)
    except (ValueError, OSError):
        pass


def listen_unix(path):
    """Listen on a unix socket only we can use (call prepare_dir first)."""
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    old = os.umask(0o177)
    try:
        s.bind(path)
    finally:
        os.umask(old)
    s.listen(16)
    return s


def serve(server, handler):
    """Accept forever; each connection runs handler(conn) in its own thread."""
    while True:
        conn, _ = server.accept()
        threading.Thread(target=handler, args=(conn,), daemon=True).start()


def connect_unix(path):
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.connect(path)
    return s


def close(sock):
    try:
        sock.close()
    except OSError:
        pass


# --- called from guard.star ------------------------------------------------

def env(name):
    return os.environ.get(name, "")


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
    """One process from /proc, or None if it is gone."""
    base = Path(f"/proc/{pid}")
    try:
        stat = (base / "stat").read_text()
        name = (base / "comm").read_text().strip()
        raw_cmdline = (base / "cmdline").read_bytes()
    except OSError:
        return None
    # stat is "pid (comm) state ppid ..."; comm may contain spaces or ')'.
    ppid = int(stat.rsplit(")", 1)[1].split()[1])
    try:
        exe = os.readlink(base / "exe")
    except OSError:
        exe = ""
    cmdline = [a.decode("utf-8", "replace") for a in raw_cmdline.split(b"\0") if a]
    return {"pid": pid, "ppid": ppid, "name": name, "exe": exe, "cmdline": cmdline}


_log_lock = threading.Lock()


def log(path, event):
    """One JSON line to stderr and, if path is set, appended to path."""
    line = json.dumps({"time": time.strftime("%Y-%m-%dT%H:%M:%S%z"), **event})
    with _log_lock:
        print(line, file=sys.stderr, flush=True)
        if path:
            p = Path(path)
            p.parent.mkdir(parents=True, exist_ok=True)
            with p.open("a") as f:
                f.write(line + "\n")
