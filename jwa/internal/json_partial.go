// Package internal provides JSON helpers for payloads that combine a fixed set of
// typed fields with arbitrary caller-defined ones, letting a JWT carry both
// registered claims and custom extensions in a single object.
package internal

import (
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"sort"
	"strings"
	"sync"
)

// ErrReservedMember reports a custom payload naming a member that belongs to the
// registered set. The registered value is the one every guard in this library is
// written against, and a custom member displacing it takes effect during
// encoding, after each of those guards has run and passed.
var ErrReservedMember = errors.New("custom payload may not set a registered member")

// MarshalPartial encodes common and custom into one JSON object. A nil or "null"
// custom yields the encoding of common alone.
//
// The two sets of members must be disjoint. A custom member naming one that
// common reserves is an error rather than an override: common holds the
// parameters the format assigns meaning to, and the callers that populate it —
// signers setting alg, producers setting exp — have no way to observe a value
// that replaces theirs at encoding time.
//
// Reserved means every member common could contribute, not only those it did.
// Registered parameters are omitempty throughout, so an unset one encodes to
// nothing, and a rule written against the encoded object would leave exactly the
// absent parameters open.
func MarshalPartial[T any](common T, custom json.RawMessage) ([]byte, error) {
	if custom == nil || string(custom) == "null" {
		return json.Marshal(common)
	}

	serializedCommon, err := json.Marshal(common)
	if err != nil {
		return nil, fmt.Errorf("(MarshalPartial) serialize common: %w", err)
	}

	var merged map[string]json.RawMessage

	err = json.Unmarshal(serializedCommon, &merged)
	if err != nil {
		return nil, fmt.Errorf("(MarshalPartial) convert common to map: %w", err)
	}

	var customMembers map[string]json.RawMessage

	err = json.Unmarshal(custom, &customMembers)
	if err != nil {
		return nil, fmt.Errorf("(MarshalPartial) convert custom to map: %w", err)
	}

	declared := declaredMembers(reflect.TypeFor[T]())

	var reserved []string

	for name, value := range customMembers {
		_, isDeclared := declared[name]
		_, isEncoded := merged[name]

		if isDeclared || isEncoded {
			reserved = append(reserved, name)

			continue
		}

		merged[name] = value
	}

	if len(reserved) > 0 {
		// Map iteration order is random, so the names are sorted to keep one
		// input from producing several different messages.
		sort.Strings(reserved)

		return nil, fmt.Errorf("(MarshalPartial) %w: %s", ErrReservedMember, strings.Join(reserved, ", "))
	}

	mergedSerialized, err := json.Marshal(merged)
	if err != nil {
		return nil, fmt.Errorf("(MarshalPartial) serialize merged: %w", err)
	}

	return mergedSerialized, nil
}

// declaredMembersCache memoises declaredMembers, which every token issued walks
// otherwise.
var declaredMembersCache sync.Map // reflect.Type -> map[string]struct{}

// declaredMembers returns the JSON member names a struct type declares,
// including those promoted from the structs it embeds. A type with no fields to
// declare — a map, or the interface a caller passes through the generic
// parameter — yields none, and the encoded object is then the only account of
// what common contributes.
func declaredMembers(typ reflect.Type) map[string]struct{} {
	for typ != nil && typ.Kind() == reflect.Pointer {
		typ = typ.Elem()
	}

	if typ == nil || typ.Kind() != reflect.Struct {
		return nil
	}

	if cached, ok := declaredMembersCache.Load(typ); ok {
		names, _ := cached.(map[string]struct{})

		return names
	}

	names := map[string]struct{}{}

	for i := range typ.NumField() {
		field := typ.Field(i)

		tag := field.Tag.Get("json")
		if tag == "-" {
			continue
		}

		name, _, _ := strings.Cut(tag, ",")

		// An embedded struct with no name of its own promotes its members into
		// the enclosing object, so they are the enclosing type's members too.
		// encoding/json promotes them even when the embedded type is unexported,
		// which is why this runs before the exported check; an embedded
		// non-struct is a plain member named after its type.
		if field.Anonymous && name == "" {
			if promoted := declaredMembers(field.Type); promoted != nil {
				for member := range promoted {
					names[member] = struct{}{}
				}

				continue
			}
		}

		if !field.IsExported() {
			continue
		}

		if name == "" {
			name = field.Name
		}

		names[name] = struct{}{}
	}

	declaredMembersCache.Store(typ, names)

	return names
}

// UnmarshalPartial decodes the typed fields of src into a value of type T and
// returns src unchanged alongside it, so the caller can later decode its own
// custom fields from the same bytes.
func UnmarshalPartial[T any](src []byte) (T, json.RawMessage, error) {
	var common T

	err := json.Unmarshal(src, &common)
	if err != nil {
		return common, nil, fmt.Errorf("(UnmarshalPartial) unmarshal common: %w", err)
	}

	return common, src, nil
}
