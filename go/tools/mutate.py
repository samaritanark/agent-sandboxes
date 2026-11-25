#!/usr/bin/env python3
"""Mutation testing for the differential corpora (spike S8).

Each mutant in mutants.py replaces one exact piece of source with a planted bug. The runner copies
the module, applies the mutant, runs the named test, and reports whether the corpus caught it
(the test fails) or the mutant SURVIVED (the test still passes). A survivor that is not marked
equivalent means the corpus cannot see that bug: grow the corpus before trimming it.

usage: tools/mutate.py [--jobs N] [--only SUBSTRING] [--list]
Run from the go/ directory (or anywhere: it finds go/ from its own location).
"""
import argparse, os, shutil, subprocess, sys, tempfile
from concurrent.futures import ThreadPoolExecutor

HERE = os.path.dirname(os.path.abspath(__file__))
GO = os.path.dirname(HERE)
sys.path.insert(0, HERE)
from mutants import MUTANTS  # noqa: E402


def run_one(a):
    i, m = a
    d = tempfile.mkdtemp(prefix="mut-")
    try:
        shutil.copytree(GO, d + "/go", ignore=shutil.ignore_patterns(".git"))
        p = os.path.join(d, "go", m["file"])
        s = open(p).read()
        if s.count(m["old"]) != 1:
            return i, m, "BAD-PATTERN"
        open(p, "w").write(s.replace(m["old"], m["new"]))
        r = subprocess.run(["go", "test", "-count=1", "./internal/" + m["pkg"], "-run", m["run"]],
                           cwd=d + "/go", capture_output=True, text=True, timeout=1500)
        return i, m, ("SURVIVED" if r.returncode == 0 else "caught")
    finally:
        shutil.rmtree(d, ignore_errors=True)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--jobs", type=int, default=6)
    ap.add_argument("--only", default="")
    ap.add_argument("--list", action="store_true")
    ap.add_argument("--check", action="store_true",
                    help="only verify that every planted bug's text occurs exactly once in its file")
    a = ap.parse_args()
    if a.check:
        stale = [(i, m) for i, m in enumerate(MUTANTS) if open(m["file"]).read().count(m["old"]) != 1]
        for i, m in stale:
            print("STALE", i, m["file"], "|", m["old"].replace("\n", "\\n")[:70])
        print("planted bugs: %d, stale patterns: %d" % (len(MUTANTS), len(stale)))
        sys.exit(1 if stale else 0)
    sel = [(i, m) for i, m in enumerate(MUTANTS) if a.only in m["file"] or a.only in m.get("id", "")]
    if a.list:
        for i, m in sel:
            print(i, m["file"], "|", m["old"].replace("\n", "\\n")[:70])
        return
    bad = 0
    with ThreadPoolExecutor(a.jobs) as ex:
        for i, m, res in ex.map(run_one, sel):
            eq = m.get("equivalent")
            flag = ""
            if res == "SURVIVED" and not eq:
                flag = "  <-- UNEXPECTED"
                bad += 1
            elif res == "caught" and eq:
                flag = "  <-- marked equivalent but caught"
            elif res == "BAD-PATTERN":
                flag = "  <-- fix the pattern"
                bad += 1
            print("%-11s [%3d] %s | %s%s" % (res, i, m["file"], m["old"].replace("\n", "\\n")[:60], flag), flush=True)
    print("unexpected: %d of %d" % (bad, len(sel)))
    sys.exit(1 if bad else 0)


main()
