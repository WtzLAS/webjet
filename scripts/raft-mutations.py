#!/usr/bin/env python3
"""Mutation check for the Raft tests: re-introduces known Raft bugs one at a
time into crates/webjetd/src/controller/raft.rs and checks that the test
suite catches each one. The source file is restored afterwards.

    scripts/raft-mutations.py [mutation name ...]

Run from the repository root.
"""
import subprocess, sys, shutil
p='crates/webjetd/src/controller/raft.rs'
orig=open(p).read()
muts = {
 "figure8: commit old-term entries by counting": ("""            if self.term_at(idx) != Some(self.term) {
                break; // only entries of the current term commit by counting
            }""", ""),
 "vote ignores log up-to-dateness": ("""                let grant = v.term == self.term && up_to_date && (""", """                let grant = v.term == self.term && (up_to_date || true) && ("""),
 "follower commit not bounded by proven index": ("""            self.commit = self.commit.max(a.leader_commit.min(idx));""", """            self.commit = a.leader_commit;"""),
 "vote not persisted": ("""                if grant {
                    self.voted_for = Some(from);
                    self.storage.save_meta(self.term, self.voted_for);""", """                if grant {
                    self.voted_for = Some(from);"""),
 "quorum off by one": ("""        self.voters().len() / 2 + 1""", """        self.voters().len() / 2"""),
 "overlapping conf changes allowed": ("""            return Err(ProposeError::ConfChangePending);""", """            let _ = 0;"""),
 "stale snapshot installed": ("""        if last_index <= self.commit {
            // Already have everything it contains: never roll back.""", """        if false {"""),
 "conflict truncation keeps config": ("""        self.configs.retain(|(i, _)| *i < idx);""", ""),
 "double vote in same term": ("""(self.voted_for.is_none() || self.voted_for == Some(from))""", """true"""),
 "commit overwrite allowed": ("""                    if idx <= self.commit {
                        tracing::error!""", """                    if false {
                        tracing::error!"""),
}
sel = sys.argv[1:] or list(muts)
res = {}
import atexit
atexit.register(lambda: open(p,'w').write(orig))
for name in sel:
    old,new = muts[name]
    assert old in orig, name
    open(p,'w').write(orig.replace(old,new,1))
    r = subprocess.run("cargo test -q -p webjetd --lib raft 2>&1 | grep -E 'test result|FAILED|^failures:' | tail -3", shell=True, capture_output=True, text=True, env={**__import__('os').environ, "WEBJET_RAFT_SEEDS":"20"})
    out=r.stdout.strip().replace("\n"," | ")
    caught = "FAILED" in out
    res[name]=(caught,out)
    print(("CAUGHT  " if caught else "MISSED  ")+name+" :: "+out[-160:], flush=True)
open(p,'w').write(orig)
missed=[k for k,(c,_) in res.items() if not c]
sys.exit(1 if missed else 0)
