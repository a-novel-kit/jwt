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

// ErrReservedMember reports a custom payload naming a member of the registered
// set. Every guard in this library reads the registered value; a custom member
// displaces it during encoding, once those guards have run and passed.
var ErrReservedMember = errors.New("custom payload may not set a registered member")

// MarshalPartial encodes common and custom into one JSON object. A nil or "null"
// custom yields the encoding of common alone.
//
// The two sets must be disjoint: a custom member naming one that common reserves
// is an error. Reserved covers every member common declares, not only those it
// encoded — registered parameters are omitempty, so an unset one encodes to
// nothing and would otherwise stay open to a custom value.
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
// including those promoted from embedded structs. A non-struct — a map, or the
// interface a caller reaches the generic parameter through — yields none,
// leaving the encoded object as the only account of common's members.
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

		// An embedded struct promotes its members into the enclosing object, and
		// encoding/json does so even when the embedded type is unexported —
		// hence promotion before the exported check.
		//
		// An embedded non-struct falls through to be named after its type, which
		// is how encoding/json encodes it: `struct{ MyString }` emits
		// {"MyString":…}. It is a member like any other, so it is reserved like
		// any other.
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
// returns the members left over, so the caller can decode its own custom fields
// from them.
//
// The members T declares are removed from that remainder, which makes this the
// inverse of MarshalPartial: what the typed value carries comes back out of the
// typed value, and re-encoding the pair reproduces src. Returning src whole
// would put every registered member in the custom half, and encoding it again
// would be rejected as an override of the value it was read from.
func UnmarshalPartial[T any](src []byte) (T, json.RawMessage, error) {
	var common T

	err := json.Unmarshal(src, &common)
	if err != nil {
		return common, nil, fmt.Errorf("(UnmarshalPartial) unmarshal common: %w", err)
	}

	declared := declaredMembers(reflect.TypeFor[T]())
	if len(declared) == 0 {
		return common, src, nil
	}

	var members map[string]json.RawMessage

	err = json.Unmarshal(src, &members)
	if err != nil {
		return common, nil, fmt.Errorf("(UnmarshalPartial) convert source to map: %w", err)
	}

	for name := range declared {
		delete(members, name)
	}

	custom, err := json.Marshal(members)
	if err != nil {
		return common, nil, fmt.Errorf("(UnmarshalPartial) serialize custom: %w", err)
	}

	return common, custom, nil
}
