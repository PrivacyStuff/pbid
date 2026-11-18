//! Append-only note tree. The pool account stores the frontier: one left node
//! per level, updated in place so no tree copy sits on the 4KiB BPF stack
//! frame. A note holder keeps the leaves and builds the path the proof needs.
//! Empty subtrees are the zero hashes, so a sibling that was never written is
//! not a secret.

use crate::error::BidError;
use crate::poseidon::{merkle_node, zero_nodes, Field};
use crate::state::MERKLE_DEPTH;

const CAPACITY: u64 = 1 << MERKLE_DEPTH;
pub const FRONTIER_LEN: usize = MERKLE_DEPTH * 32;

pub fn empty_root() -> Result<Field, BidError> {
    let mut node = [0u8; 32];
    for _ in 0..MERKLE_DEPTH {
        node = merkle_node(&node, &node)?;
    }
    Ok(node)
}

/// Appends `leaf` at position `next` and returns the new root.
pub fn frontier_append(frontier: &mut [u8], next: u32, leaf: &Field) -> Result<Field, BidError> {
    if frontier.len() != FRONTIER_LEN || u64::from(next) >= CAPACITY {
        return Err(BidError::BadAccount);
    }
    let mut zero = [0u8; 32];
    let mut current = *leaf;
    let mut cursor = next;
    for level in 0..MERKLE_DEPTH {
        let slot = &mut frontier[level * 32..level * 32 + 32];
        if cursor & 1 == 0 {
            slot.copy_from_slice(&current);
            current = merkle_node(&current, &zero)?;
        } else {
            let mut left = [0u8; 32];
            left.copy_from_slice(slot);
            current = merkle_node(&left, &current)?;
        }
        zero = merkle_node(&zero, &zero)?;
        cursor >>= 1;
    }
    Ok(current)
}

/// Leaves the client remembers. Paths match `frontier_append`.
#[derive(Clone, Default)]
pub struct NoteTree {
    leaves: alloc::vec::Vec<Field>,
}

impl NoteTree {
    pub fn new() -> Self {
        Self { leaves: alloc::vec::Vec::new() }
    }

    pub fn len(&self) -> usize {
        self.leaves.len()
    }

    pub fn is_empty(&self) -> bool {
        self.leaves.is_empty()
    }

    pub fn append(&mut self, leaf: Field) -> u32 {
        let index = self.leaves.len() as u32;
        self.leaves.push(leaf);
        index
    }

    pub fn leaf(&self, index: u32) -> Option<Field> {
        self.leaves.get(index as usize).copied()
    }

    pub fn position(&self, leaf: &Field) -> Option<u32> {
        self.leaves.iter().position(|stored| stored == leaf).map(|at| at as u32)
    }

    pub fn root(&self) -> Result<Field, BidError> {
        let zeros = zero_nodes()?;
        self.node(0, MERKLE_DEPTH, &zeros)
    }

    #[allow(clippy::type_complexity)]
    pub fn path(&self, index: u32) -> Result<([Field; MERKLE_DEPTH], [bool; MERKLE_DEPTH]), BidError> {
        if index as usize >= self.leaves.len() {
            return Err(BidError::BadAccount);
        }
        let zeros = zero_nodes()?;
        let mut siblings = [[0u8; 32]; MERKLE_DEPTH];
        let mut bits = [false; MERKLE_DEPTH];
        for level in 0..MERKLE_DEPTH {
            let node_index = index >> level;
            bits[level] = node_index & 1 == 1;
            siblings[level] = self.node(node_index ^ 1, level, &zeros)?;
        }
        Ok((siblings, bits))
    }

    fn node(&self, index: u32, level: usize, zeros: &[Field; MERKLE_DEPTH + 1]) -> Result<Field, BidError> {
        let start = (index as usize) << level;
        if start >= self.leaves.len() {
            return Ok(zeros[level]);
        }
        if level == 0 {
            return Ok(self.leaves[start]);
        }
        let left = self.node(index * 2, level - 1, zeros)?;
        let right = self.node(index * 2 + 1, level - 1, zeros)?;
        merkle_node(&left, &right)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_frontier_and_the_client_tree_agree() {
        let mut frontier = [0u8; FRONTIER_LEN];
        let mut tree = NoteTree::new();
        assert_eq!(empty_root().unwrap(), tree.root().unwrap());
        for step in 1..=5u8 {
            let leaf = [step; 32];
            let next = tree.append(leaf);
            let root = frontier_append(&mut frontier, next, &leaf).unwrap();
            assert_eq!(root, tree.root().unwrap());
        }
    }
}
