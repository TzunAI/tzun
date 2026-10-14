package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"strconv"
	"strings"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethdb/memorydb"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/ethereum/go-ethereum/trie"
)

const e2eFile = "anchor-e2e-vectors.json"

// e2eVectors is the part of anchor-e2e-vectors.json this module reads. The
// gate module in the parent directory holds the whole file to its exact keys.
type e2eVectors struct {
	Chain        string `json:"chain"`
	AnchorOrigin string `json:"anchorOrigin"`
	Manifest     struct {
		Publishers map[string][]struct {
			Address   string `json:"address"`
			Chain     string `json:"chain"`
			Namespace string `json:"namespace"`
		} `json:"publishers"`
	} `json:"manifest"`
	HeaderSource struct {
		ChainID              uint64 `json:"chainId"`
		FinalizedBlockNumber uint64 `json:"finalizedBlockNumber"`
	} `json:"headerSource"`
	Epochs []struct {
		AnchorCheckpoint string `json:"anchorCheckpoint"`
		P                string `json:"p"`
		Publication      struct {
			Kind           string   `json:"kind"`
			Chain          string   `json:"chain"`
			TransactionID  string   `json:"transactionId"`
			BlockNumber    uint64   `json:"blockNumber"`
			BlockHash      string   `json:"blockHash"`
			Publisher      string   `json:"publisher"`
			RawTransaction string   `json:"rawTransaction"`
			BlockHeader    string   `json:"blockHeader"`
			TxIndex        uint64   `json:"txIndex"`
			TxProof        []string `json:"txProof"`
		} `json:"publication"`
		CanonicalBlock struct {
			Number    uint64 `json:"number"`
			Hash      string `json:"hash"`
			Timestamp uint64 `json:"timestamp"`
		} `json:"canonicalBlock"`
	} `json:"epochs"`
}

type report struct {
	lines    []string
	failures []string
}

func (r *report) notef(format string, a ...any) { r.lines = append(r.lines, fmt.Sprintf(format, a...)) }
func (r *report) failf(format string, a ...any) {
	r.failures = append(r.failures, fmt.Sprintf(format, a...))
}

// checkFile checks every epoch's publication in the file at path.
func checkFile(path string) *report {
	r := &report{}
	b, err := os.ReadFile(path)
	if err != nil {
		r.failf("%s: %v", e2eFile, err)
		return r
	}
	var v e2eVectors
	if err := json.Unmarshal(b, &v); err != nil {
		r.failf("%s: %v", e2eFile, err)
		return r
	}
	check(r, &v)
	return r
}

// eip155 is the chain id of a CAIP-2 eip155:<id> chain.
func eip155(chain string) (*big.Int, bool) {
	id, ok := strings.CutPrefix(chain, "eip155:")
	if !ok {
		return nil, false
	}
	n, err := strconv.ParseUint(id, 10, 64)
	if err != nil || n == 0 || strconv.FormatUint(n, 10) != id {
		return nil, false
	}
	return new(big.Int).SetUint64(n), true
}

func check(r *report, v *e2eVectors) {
	const f = e2eFile
	before := len(r.failures)
	if len(v.Epochs) == 0 {
		r.failf("%s: no epochs", f)
		return
	}
	chainID, ok := eip155(v.Chain)
	if !ok {
		r.failf("%s: chain %q is not eip155:<id>", f, v.Chain)
		return
	}
	if v.HeaderSource.ChainID != chainID.Uint64() {
		r.failf("%s: headerSource.chainId %d is not %s", f, v.HeaderSource.ChainID, v.Chain)
	}
	publishers := map[common.Address]bool{}
	for _, e := range v.Manifest.Publishers[v.AnchorOrigin] {
		if id, ok := eip155(e.Chain); ok && id.Cmp(chainID) == 0 && common.IsHexAddress(e.Address) {
			publishers[common.HexToAddress(e.Address)] = true
		}
	}
	if len(publishers) == 0 {
		r.failf("%s: the manifest names no publisher on %s for %s", f, v.Chain, v.AnchorOrigin)
		return
	}

	trieNodes := 0
	for i, e := range v.Epochs {
		w := fmt.Sprintf("%s: epochs[%d]", f, i)
		pub := e.Publication
		if pub.Kind != "evm-calldata/1" || pub.Chain != v.Chain {
			r.failf("%s: publication kind %q on %q, want evm-calldata/1 on %s", w, pub.Kind, pub.Chain, v.Chain)
			continue
		}

		// The header: go-ethereum decodes the RLP, and its own hash of the
		// decoded header, and keccak256 of the bytes as stored, are the block hash.
		headerRLP, err := hexutil.Decode(pub.BlockHeader)
		if err != nil {
			r.failf("%s: blockHeader: %v", w, err)
			continue
		}
		var header types.Header
		if err := rlp.DecodeBytes(headerRLP, &header); err != nil {
			r.failf("%s: go-ethereum cannot decode the blockHeader: %v", w, err)
			continue
		}
		blockHash := common.HexToHash(pub.BlockHash)
		if !strings.EqualFold(pub.BlockHash, blockHash.Hex()) {
			r.failf("%s: blockHash %q is not 0x and 64 hex", w, pub.BlockHash)
		}
		if got := crypto.Keccak256Hash(headerRLP); got != blockHash {
			r.failf("%s: keccak256(blockHeader) is %s, not the blockHash %s", w, got.Hex(), blockHash.Hex())
		}
		if got := header.Hash(); got != blockHash {
			r.failf("%s: go-ethereum hashes the decoded header to %s, not the blockHash %s", w, got.Hex(), blockHash.Hex())
		}
		if header.Number == nil || !header.Number.IsUint64() || header.Number.Uint64() != pub.BlockNumber {
			r.failf("%s: the header's number is %v, not the blockNumber %d", w, header.Number, pub.BlockNumber)
		}
		cb := e.CanonicalBlock
		if cb.Number != pub.BlockNumber || common.HexToHash(cb.Hash) != blockHash || cb.Timestamp != header.Time {
			r.failf("%s: canonicalBlock (%d, %s, %d) is not the header's (%d, %s, %d)", w, cb.Number, cb.Hash, cb.Timestamp, pub.BlockNumber, blockHash.Hex(), header.Time)
		}
		if pub.BlockNumber > v.HeaderSource.FinalizedBlockNumber {
			r.failf("%s: block %d is above headerSource.finalizedBlockNumber %d", w, pub.BlockNumber, v.HeaderSource.FinalizedBlockNumber)
		}

		// The transactions-trie proof: go-ethereum walks it from the header's
		// transactions root at key rlp(txIndex), and it proves the raw transaction.
		raw, err := hexutil.Decode(pub.RawTransaction)
		if err != nil {
			r.failf("%s: rawTransaction: %v", w, err)
			continue
		}
		proofDB := memorydb.New()
		for j, node := range pub.TxProof {
			nb, err := hexutil.Decode(node)
			if err != nil {
				r.failf("%s: txProof[%d]: %v", w, j, err)
				continue
			}
			if err := proofDB.Put(crypto.Keccak256(nb), nb); err != nil {
				r.failf("%s: txProof[%d]: %v", w, j, err)
			}
		}
		proven, err := trie.VerifyProof(header.TxHash, rlp.AppendUint64(nil, pub.TxIndex), proofDB)
		switch {
		case err != nil:
			r.failf("%s: go-ethereum refuses the txProof from transactionsRoot %s at index %d: %v", w, header.TxHash.Hex(), pub.TxIndex, err)
		case !bytes.Equal(proven, raw):
			r.failf("%s: the txProof proves %x at index %d, not the rawTransaction", w, clip(proven), pub.TxIndex)
		default:
			trieNodes += len(pub.TxProof)
		}

		// The transaction: it decodes, hashes to its id, is signed for the
		// chain, recovers to a manifest publisher, and carries exactly P.
		var tx types.Transaction
		if err := tx.UnmarshalBinary(raw); err != nil {
			r.failf("%s: go-ethereum cannot decode the rawTransaction: %v", w, err)
			continue
		}
		if !strings.EqualFold(tx.Hash().Hex(), pub.TransactionID) {
			r.failf("%s: the rawTransaction hashes to %s, not the transactionId %s", w, tx.Hash().Hex(), pub.TransactionID)
		}
		if tx.Type() != types.DynamicFeeTxType {
			r.failf("%s: transaction type %d, want EIP-1559 (2)", w, tx.Type())
		}
		if tx.ChainId().Cmp(chainID) != 0 {
			r.failf("%s: the transaction is signed for chain %v, not %s", w, tx.ChainId(), v.Chain)
		}
		sender, err := types.Sender(types.LatestSignerForChainID(tx.ChainId()), &tx)
		if err != nil {
			r.failf("%s: go-ethereum recovers no sender: %v", w, err)
			continue
		}
		if !publishers[sender] {
			r.failf("%s: the sender %s is not a publisher the manifest names for %s", w, sender.Hex(), v.AnchorOrigin)
		}
		if !strings.EqualFold(sender.Hex(), pub.Publisher) {
			r.failf("%s: the sender %s is not the entry's publisher %s", w, sender.Hex(), pub.Publisher)
		}
		p := sha256.Sum256([]byte(e.AnchorCheckpoint))
		if hex.EncodeToString(p[:]) != e.P {
			r.failf("%s: p is %s, SHA-256 of the anchorCheckpoint is %x", w, e.P, p)
		}
		if !bytes.Equal(tx.Data(), p[:]) {
			r.failf("%s: the calldata is %x, not exactly P %x", w, tx.Data(), p)
		}
		if tx.To() == nil || *tx.To() != sender || tx.Value().Sign() != 0 {
			r.failf("%s: not a zero-value transaction to the publisher itself", w)
		}
	}

	if len(r.failures) == before {
		r.notef("%s: %d publications: each header decoded by go-ethereum hashes to its blockHash at its blockNumber and time", e2eFile, len(v.Epochs))
		r.notef("%s: each txProof (%d nodes in all) walked by go-ethereum's trie.VerifyProof from the header's transactionsRoot to the rawTransaction", e2eFile, trieNodes)
		r.notef("%s: each transaction decoded by go-ethereum: EIP-1559, signed for %s, its hash the transactionId, its sender the manifest's publisher, its calldata exactly P = SHA-256(anchorCheckpoint)", e2eFile, v.Chain)
	}
}

func clip(b []byte) []byte {
	if len(b) > 32 {
		return b[:32]
	}
	return b
}
