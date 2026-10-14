package main

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
)

// The vectors' encoding rule (edgeRules in merkle-consistency-vectors.json):
// every hash is a JSON string of exactly 64 hexadecimal digits, matched
// against the whole string. Upper and mixed case are accepted and read as the
// same bytes as lowercase. Anything else is refused: a trailing newline,
// surrounding whitespace, 63 or 65 digits, a 0x prefix, or a non-string.
//
// The rule is applied here, before a single byte reaches transparency-dev/merkle,
// because the library takes [][]byte and has no notion of hex. Go's
// hex.DecodeString is not the rule on its own: it accepts any even number of
// digits (66 digits decode to 33 bytes), and a JSON number or null never
// reaches it as a string. So each value is kept as raw JSON, checked to be a
// string, checked to be exactly 64 hex digits, and only then decoded.
// hex.DecodeString is case-insensitive, so the lowercase normalisation the
// rule asks for is implicit: "AB" and "ab" decode to the same byte.

const hashHexLen = 64

// caseRule says which letter case a hash field may use.
type caseRule int

const (
	// lowerOnly is the canonical form every generated vector uses: bare
	// lowercase hex. The valid, invalid and inclusion sections are held to it,
	// so that a mutation vector is refused by the library and never by a
	// decoding accident, and so that a regenerated proof can be compared as a
	// string.
	lowerOnly caseRule = iota
	// anyCase is the encoding rule itself, used for the encoding section.
	anyCase
)

// decodeHash applies the encoding rule to one raw JSON value.
func decodeHash(raw json.RawMessage, rule caseRule) ([]byte, error) {
	if len(raw) == 0 {
		return nil, errors.New("missing")
	}
	if raw[0] != '"' {
		return nil, fmt.Errorf("not a JSON string: %s", clip(string(raw)))
	}
	var s string
	if err := json.Unmarshal(raw, &s); err != nil {
		return nil, fmt.Errorf("not a JSON string: %v", err)
	}
	if len(s) != hashHexLen {
		return nil, fmt.Errorf("%d characters, want exactly %d hex digits: %q", len(s), hashHexLen, clip(s))
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= '0' && c <= '9', c >= 'a' && c <= 'f':
		case c >= 'A' && c <= 'F':
			if rule == lowerOnly {
				return nil, fmt.Errorf("uppercase hex digit at offset %d; generated vectors use bare lowercase hex: %q", i, clip(s))
			}
		default:
			return nil, fmt.Errorf("non-hex character %q at offset %d: %q", c, i, clip(s))
		}
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		return nil, err
	}
	return b, nil
}

// decodeProof applies the encoding rule to a proof: a JSON array whose every
// element is a hash under the rule. A null proof is refused; an empty array
// is a proof with no elements.
func decodeProof(raw json.RawMessage, rule caseRule) ([][]byte, error) {
	if len(raw) == 0 {
		return nil, errors.New("proof missing")
	}
	if raw[0] != '[' {
		return nil, fmt.Errorf("proof is not a JSON array: %s", clip(string(raw)))
	}
	var elems []json.RawMessage
	if err := json.Unmarshal(raw, &elems); err != nil {
		return nil, fmt.Errorf("proof is not a JSON array: %v", err)
	}
	out := make([][]byte, len(elems))
	for i, e := range elems {
		b, err := decodeHash(e, rule)
		if err != nil {
			return nil, fmt.Errorf("proof[%d]: %v", i, err)
		}
		out[i] = b
	}
	return out, nil
}

// proofStrings reads a proof whose elements are canonical lowercase hex and
// returns them as strings, for byte-for-byte comparison with a regenerated
// proof.
func proofStrings(raw json.RawMessage) ([]string, error) {
	if _, err := decodeProof(raw, lowerOnly); err != nil {
		return nil, err
	}
	var s []string
	if err := json.Unmarshal(raw, &s); err != nil {
		return nil, err
	}
	return s, nil
}

func clip(s string) string {
	const max = 80
	if len(s) <= max {
		return s
	}
	return s[:max] + "..."
}
