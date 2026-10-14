package main

import (
	"fmt"

	"github.com/transparency-dev/merkle/compact"
	"github.com/transparency-dev/merkle/proof"
	"github.com/transparency-dev/merkle/rfc6962"
)

var hasher = rfc6962.DefaultHasher

// tree holds one log built entirely by the stock library, the way a
// transparency-dev log stores it: leaves are appended to a compact range,
// whose visitor reports every perfect-subtree node as it is created, and
// proofs are assembled from those stored nodes by the library's own planners
// (proof.Inclusion, proof.Consistency) and Nodes.Rehash. No Tzun code, and no
// Merkle arithmetic of this program's own, is involved.
type tree struct {
	leafHashes [][]byte
	nodes      map[compact.NodeID][]byte
	// roots[n] is the root of the first n leaves; roots[0] is the empty root.
	roots [][]byte
}

// newTree appends the RAW 32-byte digests as leaves: leafHash = SHA-256(0x00 ‖ d).
func newTree(digests [][]byte) (*tree, error) {
	t := &tree{nodes: map[compact.NodeID][]byte{}, roots: [][]byte{hasher.EmptyRoot()}}
	rf := &compact.RangeFactory{Hash: hasher.HashChildren}
	cr := rf.NewEmptyRange(0)
	store := func(id compact.NodeID, h []byte) { t.nodes[id] = h }
	for _, d := range digests {
		lh := hasher.HashLeaf(d)
		t.leafHashes = append(t.leafHashes, lh)
		if err := cr.Append(lh, store); err != nil {
			return nil, err
		}
		root, err := cr.GetRootHash(nil)
		if err != nil {
			return nil, err
		}
		t.roots = append(t.roots, root)
	}
	return t, nil
}

func (t *tree) size() uint64 { return uint64(len(t.leafHashes)) }

func (t *tree) inclusionProof(index, size uint64) ([][]byte, error) {
	if size > t.size() {
		return nil, fmt.Errorf("size %d beyond the %d leaves built", size, t.size())
	}
	n, err := proof.Inclusion(index, size)
	if err != nil {
		return nil, err
	}
	return t.rehash(n)
}

func (t *tree) consistencyProof(size1, size2 uint64) ([][]byte, error) {
	if size2 > t.size() {
		return nil, fmt.Errorf("size %d beyond the %d leaves built", size2, t.size())
	}
	n, err := proof.Consistency(size1, size2)
	if err != nil {
		return nil, err
	}
	return t.rehash(n)
}

func (t *tree) rehash(n proof.Nodes) ([][]byte, error) {
	hashes := make([][]byte, len(n.IDs))
	for i, id := range n.IDs {
		h, ok := t.nodes[id]
		if !ok {
			return nil, fmt.Errorf("node %+v not stored", id)
		}
		hashes[i] = h
	}
	return n.Rehash(hashes, hasher.HashChildren)
}
