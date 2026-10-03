#!/usr/bin/env python3
"""Mutation check for the Raft tests.

Re-introduces known Raft bugs one at a time into
crates/webjetd/src/controller/raft.rs and checks that the test suite catches
each one. The source file is always restored, also on errors or Ctrl-C.

    scripts/raft-mutations.py [mutation name ...]

Exit status: 0 if every mutation was caught, 1 if one was missed, 2 on a
setup error (missing file, or a pattern that no longer matches the source).
"""

import os
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
TARGET = ROOT / "crates" / "webjetd" / "src" / "controller" / "raft.rs"

# (code in raft.rs, buggy replacement). Whitespace in the pattern matches any
# whitespace, so reformatting the source doesn't break the patterns.
MUTATIONS = {
    "figure8: commit old-term entries by counting": (
        "if self.term_at(idx) != Some(self.term) { break; // only entries of the current term commit by counting }",
        "",
    ),
    "vote ignores log up-to-dateness": (
        "let grant = v.term == self.term && up_to_date &&",
        "let grant = v.term == self.term && (up_to_date || true) &&",
    ),
    "follower commit not bounded by proven index": (
        "self.commit = self.commit.max(a.leader_commit.min(idx));",
        "self.commit = a.leader_commit;",
    ),
    "vote not persisted": (
        "if grant { self.voted_for = Some(from); self.storage.save_meta(self.term, self.voted_for);",
        "if grant { self.voted_for = Some(from);",
    ),
    "quorum off by one": ("self.voters().len() / 2 + 1", "self.voters().len() / 2"),
    "overlapping conf changes allowed": (
        "return Err(ProposeError::ConfChangePending);",
        "let _ = 0;",
    ),
    "stale snapshot installed": (
        "if last_index <= self.commit { // Already have everything it contains: never roll back.",
        "if false {",
    ),
    "conflict truncation keeps config": ("self.configs.retain(|(i, _)| *i < idx);", ""),
    "double vote in same term": (
        "(self.voted_for.is_none() || self.voted_for == Some(from))",
        "true",
    ),
    "commit overwrite allowed": (
        "if idx <= self.commit { tracing::error!",
        "if false { tracing::error!",
    ),
}

TEST_CMD = ["cargo", "test", "-q", "-p", "webjetd", "--lib", "raft"]


def pattern(code: str) -> re.Pattern:
    """A regex for `code` where any whitespace run matches any whitespace."""
    parts = [re.escape(p) for p in code.split()]
    return re.compile(r"\s*".join(parts))


def mutate(source: str, name: str) -> str:
    old, new = MUTATIONS[name]
    found = pattern(old).findall(source)
    if len(found) != 1:
        raise LookupError(f"pattern for {name!r} matches {len(found)} places in {TARGET.name}")
    return pattern(old).sub(lambda _m: new, source, count=1)


def run_tests() -> str:
    env = {**os.environ, "WEBJET_RAFT_SEEDS": "20"}
    r = subprocess.run(TEST_CMD, cwd=ROOT, env=env, capture_output=True, text=True, check=False)
    lines = (r.stdout + r.stderr).splitlines()
    summary = [line for line in lines if line.startswith("test result") or "FAILED" in line]
    return " | ".join(summary[-2:])


def main(names: list) -> int:
    unknown = [n for n in names if n not in MUTATIONS]
    if unknown:
        print(f"unknown mutation(s): {', '.join(unknown)}", file=sys.stderr)
        return 2
    try:
        original = TARGET.read_text(encoding="utf-8")
    except OSError as e:
        print(f"cannot read {TARGET}: {e}", file=sys.stderr)
        return 2
    try:
        mutated = {n: mutate(original, n) for n in (names or list(MUTATIONS))}
    except LookupError as e:
        print(f"setup error: {e}", file=sys.stderr)
        return 2
    missed = []
    try:
        for name, source in mutated.items():
            TARGET.write_text(source, encoding="utf-8")
            out = run_tests()
            caught = "FAILED" in out
            if not caught:
                missed.append(name)
            print(f"{'CAUGHT' if caught else 'MISSED'}  {name} :: {out[-160:]}", flush=True)
    except OSError as e:
        print(f"error while mutating: {e}", file=sys.stderr)
        return 2
    finally:
        try:
            TARGET.write_text(original, encoding="utf-8")
        except OSError as e:
            print(f"FAILED TO RESTORE {TARGET}: {e}", file=sys.stderr)
    return 1 if missed else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
