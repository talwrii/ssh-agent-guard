# ssh-agent-guard

A proxy in front of a captive `ssh-agent` that refuses any key added without
the confirm constraint (`ssh-add -c`). The agent then asks before every use
of every key.

Starlark code (`guard.star`) with Python shims for bootloading (`boot.py`)
and I/O (`io_shims.py`).

## Caveats

This is not really a security tool. It is an accident prevention tool.

Accidents get easier when LLMs and other tools are running as you: a script
that quietly SSHes into a machine, a tool that reaches for your key without
you noticing. This makes that visible and puts a prompt in the way.

It does not stop anything determined. Fundamentally an SSH key is information
on your computer plus a passphrase you type in. Any process running as you,
with access to that information, can sign anything it likes. With this tool
in particular, a process can talk to the captive agent's socket directly and
skip the guard.

If you want real security you need to hide the key from your own user:
access control (e.g. running the agent as a separate user), or, more
extreme, something at the hardware level like a YubiKey, where every use
needs a physical touch.

## Usage

```sh
ssh-agent-guard            # captive agent + guard in $XDG_RUNTIME_DIR/ssh-agent-guard/
export SSH_AUTH_SOCK=$XDG_RUNTIME_DIR/ssh-agent-guard/agent.sock
ssh-add -c ~/.ssh/id_ed25519
```

`ssh-agent-guard --help` for options. The agent needs `ssh-askpass` and a
display to ask you. Decisions are logged to
`~/.local/state/ssh-agent-guard/log.jsonl`.

## Layout

```
$XDG_RUNTIME_DIR/ssh-agent-guard/    0700, checked at startup
├── agent.sock                       clients use this
└── captive-agent.sock               the real ssh-agent; only the guard should use it
```

The guard runs as `ssh-agent`'s command, so the agent exits when the guard
does (within about 10 seconds if the guard is killed).
