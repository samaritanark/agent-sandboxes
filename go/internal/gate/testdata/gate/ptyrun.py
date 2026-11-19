#!/usr/bin/env python3
"""Run a command on a pseudo-terminal, answer its y/N prompt, print everything it wrote.
usage: ptyrun.py <reply|EOF> cmd...   (echo and output post-processing are off, so the bytes
match what the program wrote)"""
import os, pty, sys, termios
reply, cmd = sys.argv[1], sys.argv[2:]
pid, fd = pty.fork()
if pid == 0:
    a = termios.tcgetattr(0); a[3] &= ~termios.ECHO; a[1] &= ~termios.OPOST
    termios.tcsetattr(0, termios.TCSANOW, a)
    os.execvp(cmd[0], cmd)
out, sent = b"", False
while True:
    try:
        data = os.read(fd, 4096)
    except OSError:
        break
    if not data:
        break
    out += data
    if not sent and b"[y/N] " in out:
        os.write(fd, b"\x04" if reply == "EOF" else reply.encode() + b"\n")
        sent = True
os.waitpid(pid, 0)
sys.stdout.buffer.write(out)
