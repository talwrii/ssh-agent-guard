"""Bootloader shim: runs guard.star's config(argv), then one Starlark run per connection."""
import sys

import starlark as sl

from . import io_shims


def _run(src, call, values, opened):
    """Evaluate guard.star plus one extra line, with the I/O shims available."""
    m = sl.Module()
    for name in io_shims.FOR_STARLARK:
        m.add_callable(name, getattr(io_shims, name))

    def connect_unix(path):
        s = io_shims.connect_unix(path)
        opened.append(s)  # closed here even if the Starlark fails
        return sl.OpaquePythonObject(s)

    m.add_callable("connect_unix", connect_unix)
    for k, v in values.items():
        m[k] = v
    sl.eval(m, sl.parse("guard.star", src + "\n" + call + "\n"), sl.Globals.standard())
    return m


def main():
    src = io_shims.read_starlark_source()
    cfg = _run(src, "boot_result = config(boot_argv)", {"boot_argv": sys.argv[1:]}, [])["boot_result"]
    if "help" in cfg:
        print(cfg["help"])
        return 0
    if "error" in cfg:
        print("ssh-agent-guard: " + cfg["error"], file=sys.stderr)
        return 2

    if cfg["captive"]:
        if io_shims.env("SSH_AGENT_GUARD_CAPTIVE") != cfg["upstream"]:
            # First start: become ssh-agent, which runs us again below as its command.
            io_shims.prepare_dir(cfg["listen"], cfg["upstream"])
            io_shims.exec_under_captive_agent(cfg["upstream"], sys.argv[1:])
        agent_pid = io_shims.env("SSH_AGENT_PID")  # set by ssh-agent for its command
    else:
        io_shims.prepare_dir(cfg["listen"], None)
        agent_pid = ""

    server = io_shims.listen_unix(cfg["listen"])
    io_shims.log(cfg["log"], {"event": "start", "listen": cfg["listen"], "upstream": cfg["upstream"],
                              "captive": cfg["captive"]})

    def on_connection(conn):
        opened = [conn]
        try:
            _run(src, "handle_connection(boot_conn, boot_config)",
                 {"boot_conn": sl.OpaquePythonObject(conn), "boot_config": cfg}, opened)
        except Exception as e:  # Starlark fail(), or an I/O error in a shim
            lines = [l.strip() for l in str(e).splitlines() if l.strip().startswith("error:")]
            io_shims.log(cfg["log"], {"event": "error", "error": lines[0] if lines else repr(e)[:300]})
        finally:
            for s in opened:
                io_shims.close(s)

    try:
        io_shims.serve(server, on_connection)
    except KeyboardInterrupt:
        return 0
    finally:
        if agent_pid:
            io_shims.kill_pid(agent_pid)


if __name__ == "__main__":
    sys.exit(main())
