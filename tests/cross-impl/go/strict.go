package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"reflect"
	"strings"
)

// strictKeys holds a vector file to the Go type it is decoded into, before
// encoding/json reads it. Every object key must be, byte for byte, the json
// name of a field of the struct type at that point in the file; no object,
// anywhere in the file, may repeat a key; and nothing may follow the top-level
// value.
//
// encoding/json does not hold a file to any of that. It matches a key to a
// field case-insensitively, with Unicode case folding, so "Invalid", "INVALID"
// and "ſource" (with a long s, U+017F) all fill a field, and
// DisallowUnknownFields does not object to them. When an object repeats a key,
// the last one wins without a word. The TypeScript and Python suites match
// keys exactly, so a file that relied on either leniency would be read one way
// here and another way there.
//
// Where the type is not a struct, or a slice of or pointer to one (a
// json.RawMessage section such as format, for one), the value may have any
// keys, but its objects still may not repeat one.
func strictKeys(b []byte, t reflect.Type) error {
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()
	if err := walkValue(dec, t, ""); err != nil {
		return err
	}
	if _, err := dec.Token(); err != io.EOF {
		return errors.New("trailing data after the top-level value")
	}
	return nil
}

// walkValue reads one JSON value from dec and checks its keys against t. A nil
// t accepts any keys.
func walkValue(dec *json.Decoder, t reflect.Type, path string) error {
	tok, err := dec.Token()
	if err != nil {
		return fmt.Errorf("%s: %v", orTop(path), err)
	}
	delim, ok := tok.(json.Delim)
	if !ok {
		return nil
	}
	for t != nil && t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	switch delim {
	case '{':
		var fields map[string]reflect.Type
		if t != nil && t.Kind() == reflect.Struct {
			fields = jsonFields(t)
		}
		seen := map[string]bool{}
		for dec.More() {
			kt, err := dec.Token()
			if err != nil {
				return fmt.Errorf("%s: %v", orTop(path), err)
			}
			key := kt.(string)
			if seen[key] {
				return fmt.Errorf("%s: key %q appears twice in one object", orTop(path), key)
			}
			seen[key] = true
			var ft reflect.Type
			if fields != nil {
				f, ok := fields[key]
				if !ok {
					return unknownKey(path, key, fields)
				}
				ft = f
			}
			if err := walkValue(dec, ft, join(path, key)); err != nil {
				return err
			}
		}
	case '[':
		var et reflect.Type
		if t != nil && t.Kind() == reflect.Slice {
			et = t.Elem()
		}
		for i := 0; dec.More(); i++ {
			if err := walkValue(dec, et, fmt.Sprintf("%s[%d]", path, i)); err != nil {
				return err
			}
		}
	}
	if _, err := dec.Token(); err != nil {
		return fmt.Errorf("%s: %v", orTop(path), err)
	}
	return nil
}

// jsonFields maps each json name of struct type t to its field's type,
// including the fields of an embedded struct.
func jsonFields(t reflect.Type) map[string]reflect.Type {
	out := map[string]reflect.Type{}
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		if f.Anonymous && f.Type.Kind() == reflect.Struct {
			for k, v := range jsonFields(f.Type) {
				out[k] = v
			}
			continue
		}
		name, _, _ := strings.Cut(f.Tag.Get("json"), ",")
		if !f.IsExported() || name == "-" {
			continue
		}
		if name == "" {
			name = f.Name
		}
		out[name] = f.Type
	}
	return out
}

func unknownKey(path, key string, fields map[string]reflect.Type) error {
	for name := range fields {
		if strings.EqualFold(name, key) {
			return fmt.Errorf("%s: unknown field %q; keys match exactly, and the field is %q", orTop(path), key, name)
		}
	}
	return fmt.Errorf("%s: unknown field %q", orTop(path), key)
}

func join(path, key string) string {
	if path == "" {
		return key
	}
	return path + "." + key
}

func orTop(path string) string {
	if path == "" {
		return "top level"
	}
	return path
}
