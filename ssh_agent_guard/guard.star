# ssh-agent-guard: sits in front of ssh-agent and refuses any key added
# without the confirm constraint (ssh-add -c). ssh-agent itself then asks
# before every use of every key.
#
# This is the program. boot.py starts it; io_shims.py provides its I/O:
#   env(name)                      -> str ("" if unset)
#   my_uid()                       -> int
#   connect_unix(path)             -> socket
#   recv_exact(sock, n)            -> list of n byte values, or None at end of stream
#   send(sock, byte_values)
#   peer(sock)                     -> {"pid", "uid"} of the other end
#   process(pid)                   -> {"pid", "ppid", "name", "exe", "cmdline"} or None
#   log(path, event)

USAGE = """usage: ssh-agent-guard [--listen SOCKET] [--upstream SOCKET] [--log FILE]

Runs a captive ssh-agent and forwards requests to it from --listen, refusing
to add any key without the confirm constraint (ssh-add -c).

  --listen    socket to serve      (default: $XDG_RUNTIME_DIR/ssh-agent-guard/agent.sock)
  --upstream  use this existing agent instead of a captive one
  --log       JSON-lines log       (default: ~/.local/state/ssh-agent-guard/log.jsonl)

Then point clients at it: export SSH_AUTH_SOCK=<listen socket>"""

MAX_MESSAGE = 256 * 1024  # protocol limit
FOREVER = 1000000000  # Starlark has no while loop

# ---------------------------------------------------------------- settings

def config(argv):
    # Our own directory lives in XDG_RUNTIME_DIR (per-user, 0700). No /tmp
    # fallback: another user could create that directory first.
    runtime = env("XDG_RUNTIME_DIR")
    home = runtime + "/ssh-agent-guard" if runtime else ""
    cfg = {
        "listen": home + "/agent.sock" if home else "",
        "upstream": home + "/captive-agent.sock" if home else "",
        "captive": True,
        "log": env("HOME") + "/.local/state/ssh-agent-guard/log.jsonl",
    }
    options = {"--upstream": "upstream", "--listen": "listen", "--log": "log"}
    i = 0
    for _ in range(len(argv)):
        if i >= len(argv):
            break
        arg = argv[i]
        if arg in ("-h", "--help"):
            return {"help": USAGE}
        if arg not in options or i + 1 >= len(argv):
            return {"error": "bad argument: " + arg + "\n\n" + USAGE}
        cfg[options[arg]] = argv[i + 1]
        if arg == "--upstream":
            cfg["captive"] = False
        i += 2
    if cfg["captive"]:
        # Captive agent always lives next to the socket we serve.
        cfg["upstream"] = cfg["listen"].rsplit("/", 1)[0] + "/captive-agent.sock" if cfg["listen"] else ""
    if not cfg["listen"] or not cfg["upstream"]:
        return {"error": "XDG_RUNTIME_DIR is not set; pass --listen"}
    for key in ("listen", "upstream"):
        if len(cfg[key]) > 107:  # unix socket path limit (ASCII paths assumed)
            return {"error": "socket path too long (max 107 bytes): " + cfg[key]}
    if cfg["upstream"] == cfg["listen"]:
        return {"error": "upstream is our own socket; pass --upstream with the real agent's socket"}
    return cfg

# ---------------------------------------------------------------- the rules

PASS_THROUGH = (
    "request_identities", "sign", "remove_identity", "remove_all_identities", "remove_all_ssh1_identities",
    "remove_smartcard_key", "lock", "unlock",
)

# Returns (allowed, reason).
def decide(request):
    kind = request["type"]
    if kind in ("add_identity", "add_smartcard_key"):
        return (False, "added without confirm (use ssh-add -c)")
    if kind in ("add_id_constrained", "add_smartcard_key_constrained"):
        if request["confirm"]:
            return (True, "")
        return (False, request["problem"] or "constraints lack confirm (use ssh-add -c)")
    if kind in PASS_THROUGH:
        return (True, "")
    if kind == "extension" and request["extension"] == "session-bind@openssh.com":
        return (True, "")
    return (False, "unrecognised request")

# ---------------------------------------------------------------- connection loop

def handle_connection(conn, cfg):
    who = peer(conn)
    if who["uid"] != my_uid():
        log(cfg["log"], {"event": "refused", "reason": "other user", "pid": who["pid"], "uid": who["uid"]})
        return
    upstream = connect_unix(cfg["upstream"])

    for _ in range(FOREVER):
        body = recv_message(conn)
        if body == None:
            return
        request = describe(body[0], body[1:])
        allowed, reason = decide(request)

        if request["type"] not in ("request_identities", "sign", "extension") or not allowed:
            log(cfg["log"], {
                "event": request["type"],
                "allowed": allowed,
                "reason": reason,
                "key": request["key"],
                "pid": who["pid"],
                "chain": [p["name"] for p in process_chain(who["pid"])],
            })

        if not allowed:
            send(conn, frame([FAILURE]))
            continue

        send(upstream, frame(body))
        reply = recv_message(upstream)
        if reply == None:
            return
        send(conn, frame(reply))

def recv_message(sock):
    header = recv_exact(sock, 4)
    if header == None:
        return None
    n = u32_at(header, 0)
    if n < 1 or n > MAX_MESSAGE:
        fail("bad message length %d" % n)
    return recv_exact(sock, n)

def process_chain(pid):
    chain = []
    for _ in range(16):
        if pid <= 1:
            break
        p = process(pid)
        if p == None:
            break
        chain.append(p)
        pid = p["ppid"]
    return chain

# ---------------------------------------------------------------- describing requests

FAILURE = 5

MSG_NAMES = {
    9: "remove_all_ssh1_identities",  # obsolete, but ssh-add -D still sends it
    11: "request_identities",
    13: "sign",
    17: "add_identity",
    18: "remove_identity",
    19: "remove_all_identities",
    20: "add_smartcard_key",
    21: "remove_smartcard_key",
    22: "lock",
    23: "unlock",
    25: "add_id_constrained",
    26: "add_smartcard_key_constrained",
    27: "extension",
}

def describe(msg_type, payload):
    kind = MSG_NAMES.get(msg_type, "unknown_%d" % msg_type)
    request = {"type": kind, "key": "", "confirm": False, "problem": "", "extension": ""}

    constraints_at = None
    if kind in ("add_identity", "add_id_constrained"):
        key = parse_added_key(payload)
        request["key"] = key["label"]
        request["problem"] = key["problem"]
        constraints_at = key["end"]
    elif kind == "add_smartcard_key_constrained":
        provider = string_at(payload, 0)
        pin = string_at(payload, provider[1]) if provider != None else None
        if pin == None:
            request["problem"] = "malformed smartcard add"
        else:
            request["key"] = "smartcard " + text(provider[0])
            constraints_at = pin[1]
    elif kind == "extension":
        name = string_at(payload, 0)
        if name != None:
            request["extension"] = text(name[0])

    if constraints_at != None and kind != "add_identity":
        confirm, problem = has_confirm(payload, constraints_at)
        request["confirm"] = confirm
        request["problem"] = request["problem"] or problem
    return request

# What follows the key type name in an add message, before the comment:
# "s" is a length-prefixed string (or bignum), "b" a single byte.
# Unknown types are refused, since we can't find their constraints.
KEY_LAYOUTS = {
    "ssh-ed25519": ["s", "s"],                                    # public, private
    "ssh-rsa": ["s", "s", "s", "s", "s", "s"],                    # n, e, d, iqmp, p, q
    "ecdsa-sha2-nistp256": ["s", "s", "s"],                       # curve, Q, d
    "ecdsa-sha2-nistp384": ["s", "s", "s"],
    "ecdsa-sha2-nistp521": ["s", "s", "s"],
    "sk-ssh-ed25519@openssh.com": ["s", "s", "b", "s", "s"],      # public, application, flags, handle, reserved
    "sk-ecdsa-sha2-nistp256@openssh.com": ["s", "s", "s", "b", "s", "s"],  # curve, Q, then as above
    "ssh-ed25519-cert-v01@openssh.com": ["s", "s", "s"],          # certificate, public, private
    "ssh-rsa-cert-v01@openssh.com": ["s", "s", "s", "s", "s"],    # certificate, d, iqmp, p, q
    "ecdsa-sha2-nistp256-cert-v01@openssh.com": ["s", "s"],       # certificate, d
    "ecdsa-sha2-nistp384-cert-v01@openssh.com": ["s", "s"],
    "ecdsa-sha2-nistp521-cert-v01@openssh.com": ["s", "s"],
}

# -> {"label", "problem", "end"}; end is where the constraints start, or None.
def parse_added_key(payload):
    kind = string_at(payload, 0)
    if kind == None:
        return {"label": "?", "problem": "malformed key", "end": None}
    name = text(kind[0])
    layout = KEY_LAYOUTS.get(name)
    if layout == None:
        return {"label": name, "problem": "unsupported key type " + name, "end": None}
    off = kind[1]
    for field in layout:
        if field == "b":
            off += 1
        else:
            s = string_at(payload, off)
            if s == None:
                return {"label": name, "problem": "malformed key", "end": None}
            off = s[1]
    comment = string_at(payload, off)
    if comment == None or off > len(payload):
        return {"label": name, "problem": "malformed key", "end": None}
    label = text(comment[0]) + " (" + name + ")" if comment[0] else name
    return {"label": label, "problem": "", "end": comment[1]}

CONSTRAIN_LIFETIME = 1
CONSTRAIN_CONFIRM = 2
CONSTRAIN_MAXSIGN = 3
CONSTRAIN_EXTENSION = 255

# How to step over each constraint extension's data.
EXTENSION_LAYOUTS = {
    "restrict-destination-v00@openssh.com": ["s"],
    "associated-certs-v00@openssh.com": ["b", "s"],
}

# -> (confirm found, problem)
def has_confirm(buf, off):
    for _ in range(len(buf)):
        if off >= len(buf):
            return (False, "")
        c = buf[off]
        off += 1
        if c == CONSTRAIN_CONFIRM:
            return (True, "")
        elif c == CONSTRAIN_LIFETIME or c == CONSTRAIN_MAXSIGN:
            off += 4
        elif c == CONSTRAIN_EXTENSION:
            name = string_at(buf, off)
            if name == None:
                return (False, "malformed constraint")
            ext = text(name[0])
            layout = EXTENSION_LAYOUTS.get(ext)
            if layout == None:
                return (False, "unknown constraint extension " + ext + " before confirm")
            off = name[1]
            for field in layout:
                if field == "b":
                    off += 1
                else:
                    s = string_at(buf, off)
                    if s == None:
                        return (False, "malformed constraint")
                    off = s[1]
        else:
            return (False, "unknown constraint %d" % c)
    return (False, "")

# ---------------------------------------------------------------- bytes

# Multiplication, not <<: this Starlark's << wraps at 32 bits (0x80 << 24 is negative).
def u32_at(buf, off):
    if off < 0 or off + 4 > len(buf):
        return None
    return buf[off] * 16777216 + buf[off + 1] * 65536 + buf[off + 2] * 256 + buf[off + 3]

# (bytes, offset after) or None if truncated
def string_at(buf, off):
    n = u32_at(buf, off)
    if n == None or off + 4 + n > len(buf):
        return None
    return (buf[off + 4:off + 4 + n], off + 4 + n)

def u32_bytes(n):
    return [(n >> 24) & 255, (n >> 16) & 255, (n >> 8) & 255, n & 255]

def frame(body):
    return u32_bytes(len(body)) + body

# Printable ASCII; anything else shows as "?".
def text(values):
    return "".join([chr(b) if b >= 32 and b < 127 else "?" for b in values])
