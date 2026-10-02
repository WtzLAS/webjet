//! Sparse Merkle tree over the network state (§6.4, §15.4).
//!
//! Keys are `(kind, key)` pairs mapped to 256-bit paths. Hashes:
//! `leaf = BLAKE3(0x00 ‖ kind ‖ key ‖ bytes)`, `internal = BLAKE3(0x01 ‖ l ‖ r)`,
//! `empty[d]` = a fixed constant per depth. Empty subtrees prove absence.

use crate::crypto::{ctx, derive, Bytes32};
use std::collections::BTreeMap;
use std::sync::OnceLock;

pub const DEPTH: usize = 256;
/// Depth at which gossip compares subtree hashes (§10.3): 256 buckets.
pub const BUCKET_DEPTH: usize = 8;

pub mod kind {
    pub const NODE: u8 = 1;
    pub const ACCOUNT: u8 = 2;
    pub const POLICY: u8 = 3;
    pub const DNS: u8 = 4;
    pub const SEEDS: u8 = 5;
    pub const LIMITS: u8 = 6;
    pub const VALIDITY: u8 = 7;
    pub const TRANSPORT: u8 = 8;
}

pub fn path_of(kind: u8, key: &Bytes32) -> Bytes32 {
    let mut m = [0u8; 33];
    m[0] = kind;
    m[1..].copy_from_slice(key);
    derive(ctx::TREE_PATH, &m)
}

pub fn leaf_hash(kind: u8, key: &Bytes32, bytes: &[u8]) -> Bytes32 {
    let mut h = blake3::Hasher::new();
    h.update(&[0x00, kind]);
    h.update(key);
    h.update(bytes);
    *h.finalize().as_bytes()
}

pub fn internal_hash(l: &Bytes32, r: &Bytes32) -> Bytes32 {
    let mut h = blake3::Hasher::new();
    h.update(&[0x01]);
    h.update(l);
    h.update(r);
    *h.finalize().as_bytes()
}

/// `empty(d)`: the hash of an empty subtree whose root sits at depth `d`
/// (`d = 256` is a single empty leaf slot).
pub fn empty(d: usize) -> Bytes32 {
    static E: OnceLock<Vec<Bytes32>> = OnceLock::new();
    let e = E.get_or_init(|| {
        let mut v = vec![[0u8; 32]; DEPTH + 1];
        v[DEPTH] = *blake3::hash(b"webjet smt empty v1").as_bytes();
        for d in (0..DEPTH).rev() {
            v[d] = internal_hash(&v[d + 1], &v[d + 1]);
        }
        v
    });
    e[d]
}

fn bit(path: &Bytes32, i: usize) -> bool {
    (path[i / 8] >> (7 - (i % 8))) & 1 == 1
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LeafEntry {
    pub kind: u8,
    pub key: Bytes32,
    pub bytes: Vec<u8>,
    pub hash: Bytes32,
}

/// An inclusion or absence proof: siblings from the leaf level upwards,
/// with a bitmap marking which are non-empty (empty ones are omitted).
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct Proof {
    pub bitmap: Vec<u8>, // 32 bytes; bit i = sibling at depth (DEPTH - i) is present
    pub siblings: Vec<Bytes32>,
}

#[derive(Clone, Debug, Default)]
pub struct Tree {
    leaves: BTreeMap<Bytes32, LeafEntry>,
    root: Option<Bytes32>,
}

impl Tree {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn len(&self) -> usize {
        self.leaves.len()
    }

    pub fn is_empty(&self) -> bool {
        self.leaves.is_empty()
    }

    pub fn get(&self, kind: u8, key: &Bytes32) -> Option<&LeafEntry> {
        self.leaves.get(&path_of(kind, key))
    }

    pub fn get_by_path(&self, path: &Bytes32) -> Option<&LeafEntry> {
        self.leaves.get(path)
    }

    pub fn insert(&mut self, kind: u8, key: Bytes32, bytes: Vec<u8>) {
        let hash = leaf_hash(kind, &key, &bytes);
        self.leaves.insert(
            path_of(kind, &key),
            LeafEntry {
                kind,
                key,
                bytes,
                hash,
            },
        );
        self.root = None;
    }

    pub fn remove(&mut self, kind: u8, key: &Bytes32) {
        if self.leaves.remove(&path_of(kind, key)).is_some() {
            self.root = None;
        }
    }

    pub fn iter(&self) -> impl Iterator<Item = (&Bytes32, &LeafEntry)> {
        self.leaves.iter()
    }

    pub fn root(&mut self) -> Bytes32 {
        if let Some(r) = self.root {
            return r;
        }
        let items: Vec<(Bytes32, Bytes32)> =
            self.leaves.iter().map(|(p, e)| (*p, e.hash)).collect();
        let r = subtree(&items, 0);
        self.root = Some(r);
        r
    }

    /// Root without caching (for `&self` callers).
    pub fn compute_root(&self) -> Bytes32 {
        if let Some(r) = self.root {
            return r;
        }
        let items: Vec<(Bytes32, Bytes32)> =
            self.leaves.iter().map(|(p, e)| (*p, e.hash)).collect();
        subtree(&items, 0)
    }

    /// The 256 subtree hashes at `BUCKET_DEPTH`.
    pub fn buckets(&self) -> Vec<Bytes32> {
        let mut out = Vec::with_capacity(256);
        for b in 0..=255u8 {
            let items: Vec<(Bytes32, Bytes32)> = self
                .leaves
                .range(bucket_range(b))
                .map(|(p, e)| (*p, e.hash))
                .collect();
            out.push(subtree(&items, BUCKET_DEPTH));
        }
        out
    }

    pub fn bucket_entries(&self, b: u8) -> Vec<(Bytes32, Bytes32)> {
        self.leaves
            .range(bucket_range(b))
            .map(|(p, e)| (*p, e.hash))
            .collect()
    }

    pub fn prove(&self, kind: u8, key: &Bytes32) -> Proof {
        self.prove_path(&path_of(kind, key))
    }

    pub fn prove_path(&self, path: &Bytes32) -> Proof {
        let items: Vec<(Bytes32, Bytes32)> =
            self.leaves.iter().map(|(p, e)| (*p, e.hash)).collect();
        let mut sibs_top_down: Vec<Bytes32> = Vec::with_capacity(DEPTH);
        let mut slice: &[(Bytes32, Bytes32)] = &items;
        for d in 0..DEPTH {
            let split = slice.partition_point(|(p, _)| !bit(p, d));
            let (left, right) = slice.split_at(split);
            if bit(path, d) {
                sibs_top_down.push(subtree(left, d + 1));
                slice = right;
            } else {
                sibs_top_down.push(subtree(right, d + 1));
                slice = left;
            }
        }
        let mut bitmap = vec![0u8; DEPTH / 8];
        let mut siblings = Vec::new();
        // i = 0 is the sibling at the leaf level (depth 256).
        for i in 0..DEPTH {
            let d = DEPTH - 1 - i; // sibling of the node at depth d+1
            let s = sibs_top_down[d];
            if s != empty(d + 1) {
                bitmap[i / 8] |= 1 << (i % 8);
                siblings.push(s);
            }
        }
        Proof { bitmap, siblings }
    }
}

fn bucket_range(b: u8) -> std::ops::RangeInclusive<Bytes32> {
    let mut lo = [0u8; 32];
    lo[0] = b;
    let mut hi = [0xffu8; 32];
    hi[0] = b;
    lo..=hi
}

/// Hash of the subtree at depth `d` containing exactly `items` (sorted by path).
fn subtree(items: &[(Bytes32, Bytes32)], d: usize) -> Bytes32 {
    if items.is_empty() {
        return empty(d);
    }
    if items.len() == 1 {
        let (path, h) = &items[0];
        let mut acc = *h;
        for dd in (d..DEPTH).rev() {
            let e = empty(dd + 1);
            acc = if bit(path, dd) {
                internal_hash(&e, &acc)
            } else {
                internal_hash(&acc, &e)
            };
        }
        return acc;
    }
    let split = items.partition_point(|(p, _)| !bit(p, d));
    let l = subtree(&items[..split], d + 1);
    let r = subtree(&items[split..], d + 1);
    internal_hash(&l, &r)
}

/// Compute the root implied by a proof for `path` with leaf hash `leaf`
/// (`None` for absence).
pub fn root_from_proof(path: &Bytes32, leaf: Option<Bytes32>, proof: &Proof) -> Option<Bytes32> {
    if proof.bitmap.len() != DEPTH / 8 {
        return None;
    }
    let mut acc = leaf.unwrap_or_else(|| empty(DEPTH));
    let mut it = proof.siblings.iter();
    for i in 0..DEPTH {
        let d = DEPTH - 1 - i;
        let present = (proof.bitmap[i / 8] >> (i % 8)) & 1 == 1;
        let s = if present { *it.next()? } else { empty(d + 1) };
        acc = if bit(path, d) {
            internal_hash(&s, &acc)
        } else {
            internal_hash(&acc, &s)
        };
    }
    if it.next().is_some() {
        return None;
    }
    Some(acc)
}

pub fn verify_inclusion(
    root: &Bytes32,
    kind: u8,
    key: &Bytes32,
    bytes: &[u8],
    proof: &Proof,
) -> bool {
    let path = path_of(kind, key);
    root_from_proof(&path, Some(leaf_hash(kind, key, bytes)), proof).as_ref() == Some(root)
}

pub fn verify_absence(root: &Bytes32, kind: u8, key: &Bytes32, proof: &Proof) -> bool {
    root_from_proof(&path_of(kind, key), None, proof).as_ref() == Some(root)
}

impl Proof {
    pub fn to_wire(&self) -> webjet_proto::MerkleProof {
        webjet_proto::MerkleProof {
            bitmap: Some(self.bitmap.clone()),
            siblings: Some(self.siblings.iter().map(crate::crypto::k32).collect()),
        }
    }
    pub fn from_wire(p: &webjet_proto::MerkleProof) -> Self {
        Proof {
            bitmap: p.bitmap.clone().unwrap_or_default(),
            siblings: p
                .siblings
                .clone()
                .unwrap_or_default()
                .iter()
                .map(|k| k.to_bytes())
                .collect(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn empty_tree_root() {
        let mut t = Tree::new();
        assert_eq!(t.root(), empty(0));
        let p = t.prove(kind::NODE, &[1; 32]);
        assert!(verify_absence(&empty(0), kind::NODE, &[1; 32], &p));
    }

    #[test]
    fn inclusion_and_absence() {
        let mut t = Tree::new();
        for i in 0..50u8 {
            t.insert(kind::NODE, [i; 32], vec![i; 10]);
        }
        t.insert(kind::POLICY, [0; 32], b"policy".to_vec());
        let root = t.root();
        for i in 0..50u8 {
            let p = t.prove(kind::NODE, &[i; 32]);
            assert!(verify_inclusion(&root, kind::NODE, &[i; 32], &[i; 10], &p));
            assert!(!verify_inclusion(&root, kind::NODE, &[i; 32], &[i; 9], &p));
            assert!(!verify_absence(&root, kind::NODE, &[i; 32], &p));
        }
        let p = t.prove(kind::NODE, &[200; 32]);
        assert!(verify_absence(&root, kind::NODE, &[200; 32], &p));
        // Bucket hashes recombine to the root.
        let b = t.buckets();
        let mut level = b;
        while level.len() > 1 {
            level = level
                .chunks(2)
                .map(|c| internal_hash(&c[0], &c[1]))
                .collect();
        }
        assert_eq!(level[0], root);
    }

    #[test]
    fn leaf_cannot_pass_as_internal() {
        let l = [1u8; 32];
        let r = [2u8; 32];
        let mut cat = Vec::new();
        cat.extend_from_slice(&l);
        cat.extend_from_slice(&r);
        assert_ne!(
            internal_hash(&l, &r),
            *blake3::hash(&[&[0u8][..], &cat].concat()).as_bytes()
        );
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(16))]
        #[test]
        fn any_bit_flip_breaks_proof(keys in proptest::collection::btree_set(any::<[u8; 32]>(), 1..20), flip in 0usize..256) {
            let mut t = Tree::new();
            for k in &keys { t.insert(kind::ACCOUNT, *k, k.to_vec()); }
            let root = t.root();
            let k = *keys.iter().next().unwrap();
            let mut p = t.prove(kind::ACCOUNT, &k);
            prop_assert!(verify_inclusion(&root, kind::ACCOUNT, &k, &k, &p));
            if let Some(s) = p.siblings.first_mut() { s[flip / 8] ^= 1 << (flip % 8); }
            else { p.bitmap[flip / 8] ^= 1 << (flip % 8); }
            prop_assert!(!verify_inclusion(&root, kind::ACCOUNT, &k, &k, &p));
        }

        #[test]
        fn order_independent(keys in proptest::collection::vec(any::<[u8; 32]>(), 0..30)) {
            let mut a = Tree::new();
            let mut b = Tree::new();
            for k in &keys { a.insert(kind::NODE, *k, vec![1]); }
            for k in keys.iter().rev() { b.insert(kind::NODE, *k, vec![1]); }
            prop_assert_eq!(a.root(), b.root());
        }
    }
}
