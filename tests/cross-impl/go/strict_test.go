package main

import (
	"bytes"
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

// encoding/json on its own reads a case-changed, case-folded or repeated key
// without complaint, even with DisallowUnknownFields. That is why loadStrict
// runs strictKeys first.
func TestEncodingJSONAloneIsLenientWithKeys(t *testing.T) {
	type v struct {
		Source  string `json:"source"`
		Invalid []int  `json:"invalid"`
	}
	for _, c := range []struct {
		name, raw string
		want      v
	}{
		{"a key in another case", `{"Invalid":[1]}`, v{Invalid: []int{1}}},
		{"a key in capitals", `{"INVALID":[1]}`, v{Invalid: []int{1}}},
		{"a key with a long s (U+017F)", `{"ſource":"x"}`, v{Source: "x"}},
		{"a repeated key, the last one winning", `{"invalid":[1,2,3],"invalid":[4]}`, v{Invalid: []int{4}}},
		{"a key and its case variant, the last one winning", `{"invalid":[1,2,3],"Invalid":[4]}`, v{Invalid: []int{4}}},
	} {
		t.Run(c.name, func(t *testing.T) {
			dec := json.NewDecoder(strings.NewReader(c.raw))
			dec.DisallowUnknownFields()
			var got v
			if err := dec.Decode(&got); err != nil {
				t.Fatalf("encoding/json refused it: %v", err)
			}
			if !reflect.DeepEqual(got, c.want) {
				t.Fatalf("read %+v, want %+v", got, c.want)
			}
			if err := strictKeys([]byte(c.raw), reflect.TypeFor[v]()); err == nil {
				t.Fatal("strictKeys accepted it")
			}
		})
	}
}

func TestStrictKeys(t *testing.T) {
	type inner struct {
		A   *uint64         `json:"a"`
		S   *uint64         `json:"s"`
		Raw json.RawMessage `json:"raw"`
	}
	type Promoted struct {
		C *uint64 `json:"c"`
	}
	type outer struct {
		inner
		Promoted
		Q          inner   `json:"q"`
		List       []inner `json:"list"`
		P          *inner  `json:"p"`
		Ignored    int     `json:"-"`
		NoTag      int
		unexported int
	}
	_ = outer{}.unexported
	typ := reflect.TypeFor[outer]()

	ok := []string{
		`{}`,
		" \t\r\n{} \t\r\n",
		`{"a":1,"s":2,"raw":{"x":{"y":[1,{"z":2}]},"X":1},"list":[{"a":1},{"raw":[{"q":1}]}],"p":{"raw":null},"NoTag":1}`,
		`{"p":null,"list":null,"raw":1e400}`,
		`{"list":[{"a":1},{"a":1}]}`,
		`{"c":1,"q":{"a":1,"raw":{}}}`,
		`{"raw":[{"x":1},{"x":1}]}`,
	}
	for _, raw := range ok {
		if err := strictKeys([]byte(raw), typ); err != nil {
			t.Errorf("%s refused: %v", raw, err)
		}
	}

	bad := []struct{ raw, want string }{
		{`{"A":1}`, `top level: unknown field "A"; keys match exactly, and the field is "a"`},
		{`{"ſ":1}`, `top level: unknown field "ſ"; keys match exactly, and the field is "s"`},
		{`{"b":1}`, `top level: unknown field "b"`},
		{`{"list":[{"a":1},{"A":1}]}`, `list[1]: unknown field "A"; keys match exactly, and the field is "a"`},
		{`{"p":{"b":1}}`, `p: unknown field "b"`},
		{`{"inner":{}}`, `top level: unknown field "inner"`},
		{`{"Promoted":{}}`, `top level: unknown field "Promoted"`},
		{`{"q":{"c":1}}`, `q: unknown field "c"`},
		{`{"Ignored":1}`, `top level: unknown field "Ignored"`},
		{`{"-":1}`, `top level: unknown field "-"`},
		{`{"unexported":1}`, `top level: unknown field "unexported"`},
		{`{"notag":1}`, `top level: unknown field "notag"; keys match exactly, and the field is "NoTag"`},
		{`{"a":1,"a":2}`, `top level: key "a" appears twice in one object`},
		{`{"p":{"a":1,"a":1}}`, `p: key "a" appears twice in one object`},
		{`{"raw":{"x":1,"x":2}}`, `raw: key "x" appears twice in one object`},
		{`{"raw":[{"x":1,"x":2}]}`, `raw[0]: key "x" appears twice in one object`},
		{`{"list":[{"raw":{"q":{"x":1,"x":1}}}]}`, `list[0].raw.q: key "x" appears twice in one object`},
		{`{} {}`, "trailing data after the top-level value"},
		{`{}}`, "trailing data after the top-level value"},
		{`{}x`, "trailing data after the top-level value"},
		{`{"a":1`, "top level: EOF"},
		{`{"list":[{"a":1}`, "list: EOF"},
		{`{"a" 1}`, "a: invalid character '1' after object key"},
		{`{"a":1 "s":2}`, "top level: invalid character '\"' after object key:value pair"},
		{``, "top level: EOF"},
	}
	for _, c := range bad {
		err := strictKeys([]byte(c.raw), typ)
		if err == nil {
			t.Errorf("%s accepted", c.raw)
		} else if err.Error() != c.want {
			t.Errorf("%s: got %q, want %q", c.raw, err, c.want)
		}
	}
}

// A struct whose value in the file is an array, or the reverse, passes the key
// check and is refused by encoding/json.
func TestStrictKeysLeavesTypeMismatchesToEncodingJSON(t *testing.T) {
	type v struct {
		List []struct {
			A int `json:"a"`
		} `json:"list"`
		P *struct {
			A int `json:"a"`
		} `json:"p"`
	}
	for _, raw := range []string{`{"list":{"a":1,"b":2}}`, `{"p":[{"b":1}]}`} {
		if err := strictKeys([]byte(raw), reflect.TypeFor[v]()); err != nil {
			t.Errorf("%s: strictKeys: %v", raw, err)
		}
		if err := json.NewDecoder(bytes.NewReader([]byte(raw))).Decode(new(v)); err == nil {
			t.Errorf("%s: encoding/json accepted it", raw)
		}
	}
}
