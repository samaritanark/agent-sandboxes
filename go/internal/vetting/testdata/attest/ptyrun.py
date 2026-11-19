#!/usr/bin/env python3
"""Run a command on a pseudo-terminal and answer each y/N prompt in turn.
usage: ptyrun.py <reply1|reply2|...> cmd...   (a reply of EOF sends end-of-file; prompts beyond the
replies get end-of-file). Echo and output post-processing are off, so the bytes match what the
program wrote."""
import os, pty, select, sys, termios
replies, cmd = sys.argv[1].split("|"), sys.argv[2:]
pid, fd = pty.fork()
if pid == 0:
    a = termios.tcgetattr(0); a[3] &= ~termios.ECHO; a[1] &= ~termios.OPOST
    termios.tcsetattr(0, termios.TCSANOW, a)
    os.execvp(cmd[0], cmd)
out, answered = b"", 0
while True:
    r, _, _ = select.select([fd], [], [], 20)
    if not r:
        os.kill(pid, 9); break
    try:
        data = os.read(fd, 4096)
    except OSError:
        break
    if not data:
        break
    out += data
    while out.count(b"[y/N] ") > answered:
        rep = replies[answered] if answered < len(replies) else "EOF"
        os.write(fd, b"\x04" if rep == "EOF" else rep.encode() + b"\n")
        answered += 1
os.waitpid(pid, 0)
sys.stdout.buffer.write(out)
