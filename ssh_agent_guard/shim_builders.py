"""Build shims fixed to one path. The result takes no path, so the Starlark can't choose one."""
import json
import socket
import sys
import threading
import time
from pathlib import Path


def make_connect(path):
    """connect() -> socket, to this one unix socket."""
    def connect():
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.connect(path)
        return s
    return connect


def make_log(path):
    """log(event): one JSON line to stderr, and appended to this one file."""
    lock = threading.Lock()

    def log(event):
        line = json.dumps({"time": time.strftime("%Y-%m-%dT%H:%M:%S%z"), **event})
        with lock:
            print(line, file=sys.stderr, flush=True)
            p = Path(path)
            p.parent.mkdir(parents=True, exist_ok=True)
            with p.open("a") as f:
                f.write(line + "\n")
    return log
