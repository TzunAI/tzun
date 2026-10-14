package main

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
)

const lowerHash = "3eadededa2abdd47f058794029e250159166b70786942c6e4f94aab497ef2585"

func TestDecodeHashAppliesTheEncodingRule(t *testing.T) {
	want, _ := hex.DecodeString(lowerHash)
	cases := []struct {
		name    string
		raw     string
		anyCase bool // accepted under the encoding rule
		lower   bool // accepted in the canonical lowercase form
	}{
		{"lowercase", `"` + lowerHash + `"`, true, true},
		{"uppercase", `"` + strings.ToUpper(lowerHash) + `"`, true, false},
		{"mixed case", `"3EADededa2abdd47f058794029e250159166b70786942c6e4f94aab497ef2585"`, true, false},
		{"a digit written as a JSON escape", `"\u0033eadededa2abdd47f058794029e250159166b70786942c6e4f94aab497ef2585"`, true, true},
		{"63 digits", `"` + lowerHash[:63] + `"`, false, false},
		{"65 digits", `"` + lowerHash + `0"`, false, false},
		{"66 digits, which hex.DecodeString alone accepts", `"` + lowerHash + `00"`, false, false},
		{"0x prefix", `"0x` + lowerHash + `"`, false, false},
		{"0x prefix, 62 digits", `"0x` + lowerHash[:62] + `"`, false, false},
		{"trailing newline", `"` + lowerHash + `\n"`, false, false},
		{"leading space", `" ` + lowerHash + `"`, false, false},
		{"trailing space", `"` + lowerHash + ` "`, false, false},
		{"non-hex letter", `"g` + lowerHash[1:] + `"`, false, false},
		{"number", `7`, false, false},
		{"null", `null`, false, false},
		{"boolean", `true`, false, false},
		{"array", `["` + lowerHash + `"]`, false, false},
		{"missing", ``, false, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			for _, rc := range []struct {
				rule caseRule
				ok   bool
			}{{anyCase, c.anyCase}, {lowerOnly, c.lower}} {
				got, err := decodeHash(json.RawMessage(c.raw), rc.rule)
				if rc.ok {
					if err != nil {
						t.Fatalf("rule %d: refused: %v", rc.rule, err)
					}
					if !bytes.Equal(got, want) {
						t.Fatalf("rule %d: decoded %x, want %x", rc.rule, got, want)
					}
				} else if err == nil {
					t.Fatalf("rule %d: accepted %s", rc.rule, c.raw)
				}
			}
		})
	}
}

// hex.DecodeString is case-insensitive, which is the rule's normalisation, but
// it is not the rule: it takes any even number of digits.
func TestHexDecodeStringAloneIsNotTheRule(t *testing.T) {
	b, err := hex.DecodeString(lowerHash + "00")
	if err != nil || len(b) != 33 {
		t.Fatalf("hex.DecodeString of 66 digits: %d bytes, %v", len(b), err)
	}
	upper, err := hex.DecodeString(strings.ToUpper(lowerHash))
	lower, _ := hex.DecodeString(lowerHash)
	if err != nil || !bytes.Equal(upper, lower) {
		t.Fatalf("uppercase decodes differently: %v", err)
	}
}

func TestDecodeHashErrorsNameTheFault(t *testing.T) {
	cases := []struct {
		raw  string
		rule caseRule
		want string
	}{
		{`"g` + lowerHash[1:] + `"`, anyCase, "non-hex character 'g' at offset 0"},
		{`"g` + lowerHash[1:] + `"`, lowerOnly, "non-hex character 'g' at offset 0"},
		{`"` + lowerHash[:5] + "G" + lowerHash[6:] + `"`, anyCase, "non-hex character 'G' at offset 5"},
		{`"` + lowerHash[:5] + "A" + lowerHash[6:] + `"`, lowerOnly, "uppercase hex digit at offset 5"},
		{`"` + lowerHash[:63] + `"`, anyCase, "63 characters, want exactly 64 hex digits"},
		{`7`, anyCase, "not a JSON string: 7"},
		{``, anyCase, "missing"},
	}
	for _, c := range cases {
		_, err := decodeHash(json.RawMessage(c.raw), c.rule)
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s under rule %d: got %v, want an error containing %q", c.raw, c.rule, err, c.want)
		}
	}
}

func TestClip(t *testing.T) {
	s80 := strings.Repeat("a", 80)
	if got := clip(s80); got != s80 {
		t.Errorf("80 characters clipped to %q", got)
	}
	if got := clip(s80 + "b"); got != s80+"..." {
		t.Errorf("81 characters clipped to %q", got)
	}
}

func TestDecodeProof(t *testing.T) {
	ok := []string{`[]`, `["` + lowerHash + `"]`, `["` + lowerHash + `","` + lowerHash + `"]`}
	for _, raw := range ok {
		if _, err := decodeProof(json.RawMessage(raw), anyCase); err != nil {
			t.Errorf("%s refused: %v", raw, err)
		}
	}
	bad := []string{`null`, ``, `{}`, `"` + lowerHash + `"`, `[7]`, `[null]`, `["` + lowerHash + `",null]`}
	for _, raw := range bad {
		if _, err := decodeProof(json.RawMessage(raw), anyCase); err == nil {
			t.Errorf("%s accepted", raw)
		}
	}
}
