# ssh-agent-guard

A proxy in front of a captive `ssh-agent` that refuses any key added without
the confirm constraint (`ssh-add -c`). The agent then asks before every use
of every key.

We use an innovative to me security approach where most code is in pure
(side effect free) starlack code (`guard.star`) with Python shims for bootloading (`boot.py`)
and I/O. This acts as a sandbox without having to bother with system calls etc.

AI-generted and not very well reviewed. Security theatre / security practice.

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

`ssh-agent-guard --help` for options. Decisions are logged to
`~/.local/state/ssh-agent-guard/log.jsonl`.

## Variables

| Variable | Read by | Notes |
|---|---|---|
| `XDG_RUNTIME_DIR` | the guard | Where its directory goes. Required: there is deliberately no `/tmp` fallback. Set by your login session. |
| `SSH_AUTH_SOCK` | `ssh-add`, `ssh`, git commit signing, `ssh-keygen -Y`, anything else using the agent | Point it at `agent.sock`. This is the one that matters: `ssh-add` reads only this, never `~/.ssh/config`. |
| `DISPLAY`, `SSH_ASKPASS` | the captive `ssh-agent` | How the agent asks you before each use. It inherits them from the guard, so the guard must be started with them set. Needs `ssh-askpass` installed. Without a display, every use is refused. |
| `SSH_CONNECTION` | your shell rc (see below) | Set inside ssh sessions; use it to leave a forwarded agent alone. |

## Setting it up for a session

**Point everything at the guard.** In a shell rc file that your X session
also reads:

```sh
# Skipped in ssh sessions so a forwarded agent is kept.
if [ -z "$SSH_CONNECTION" ] && [ -n "$XDG_RUNTIME_DIR" ]; then
    export SSH_AUTH_SOCK="$XDG_RUNTIME_DIR/ssh-agent-guard/agent.sock"
fi
```

On Debian/Ubuntu, `/etc/X11/Xsession` starts its own `ssh-agent` only if
`SSH_AUTH_SOCK` is empty, so setting it from `~/.xsessionrc` both points the
session at the guard and stops that agent. Two traps there: Xsession sources
`~/.xsessionrc` with `/bin/sh` (dash, so no `function` keyword), and with
`set -e`, so any failing line stops your session starting. Wrap it:

```sh
# ~/.xsessionrc
set +e
. "$HOME/path/to/your/shellrc"
set -e
```

**Belt and braces for ssh itself.** At the *end* of `~/.ssh/config`:

```
Host *
    IdentityAgent ${XDG_RUNTIME_DIR}/ssh-agent-guard/agent.sock
    AddKeysToAgent confirm
```

The first value found for each option wins, so at the end this is only a
default: host blocks above it that set their own `IdentityAgent` keep it
(and bypass the guard for that host). It does not affect `ssh-add`.

**Start the guard at login**, before you need ssh. If it isn't running,
`SSH_AUTH_SOCK` points at nothing: ssh falls back to reading key files and
asking for the passphrase, and `ssh-add` fails. If you start it as a systemd
user service, the user manager needs your display:
`systemctl --user import-environment DISPLAY XAUTHORITY`.

## Layout

```
$XDG_RUNTIME_DIR/ssh-agent-guard/    0700, checked at startup
├── agent.sock                       clients use this
└── captive-agent.sock               the real ssh-agent; only the guard should use it
```

The guard runs as `ssh-agent`'s command, so the agent exits when the guard
does (within about 10 seconds if the guard is killed).
