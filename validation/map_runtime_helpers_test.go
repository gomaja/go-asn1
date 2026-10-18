package validation

import (
	"bytes"
	"errors"
	"reflect"
	"testing"

	mapber "github.com/gomaja/go-asn1/telecom/ss7/gsm_map/runtime/ber"
)

type mapBERValue interface {
	UnmarshalBER([]byte, ...mapber.DecodeOption) error
	MarshalBER(...mapber.EncodeOption) ([]byte, error)
	MarshalDER() ([]byte, error)
}

func replaysMAPExactly(t *testing.T, name string, value mapBERValue, wire []byte) {
	t.Helper()
	if err := value.UnmarshalBER(wire); err != nil {
		t.Fatalf("%s decode: %v", name, err)
	}
	for kind, encode := range map[string]func() ([]byte, error){
		"BER": func() ([]byte, error) { return value.MarshalBER() },
		"DER": value.MarshalDER,
	} {
		if out, err := encode(); err != nil || !bytes.Equal(out, wire) {
			t.Fatalf("%s %s = %x, %v; want %x", name, kind, out, err, wire)
		}
	}
}

// Preserve the complete pre-migration diagnostic contract separately from
// the owned runtime's new provenance and internal report bookkeeping.
func mapConstraintFields(v mapber.Violation) mapber.Violation {
	return mapber.Violation{Path: v.Path, Constraint: v.Constraint,
		ObservedLength: v.ObservedLength, ObservedValue: v.ObservedValue,
		ObservedValueLength: v.ObservedValueLength, OctetOffset: v.OctetOffset}
}

func requireMAPProvenance(t *testing.T, v mapber.Violation) {
	t.Helper()
	if v.Rule.Document == "" || v.Rule.Edition == "" || v.Rule.Clause == "" || v.Source == "" {
		t.Fatalf("missing constraint provenance: %+v", v)
	}
}

func requireMAPConstraint(t *testing.T, err error, want mapber.Violation) {
	t.Helper()
	// ValidationError bounds observations and records their full byte length.
	if want.ObservedValueLength == 0 {
		want.ObservedValueLength = len(want.ObservedValue)
	}
	var violation *mapber.ValidationError
	if !errors.As(err, &violation) {
		t.Fatalf("constraint = %v, want %+v", err, want)
	}
	if got := mapConstraintFields(violation.Violation); !reflect.DeepEqual(got, want) {
		t.Fatalf("constraint = %+v, want %+v", got, want)
	}
	requireMAPProvenance(t, violation.Violation)
	if violation.Offset != nil {
		var element *mapber.ElementError
		if !errors.As(err, &element) || element.Offset() != *violation.Offset || !reflect.DeepEqual(element.ChildIndexes(), violation.ChildIndexes) {
			t.Fatalf("constraint location = %v, %+v", err, violation.Violation)
		}
	}
}

func requireMAPViolations(t *testing.T, log *mapber.ViolationLog, want ...mapber.Violation) {
	t.Helper()
	got := log.Snapshot()
	if len(got) != len(want) {
		t.Fatalf("violations = %+v, want %+v", got, want)
	}
	remaining := make([]mapber.Violation, len(got))
	for i, v := range got {
		requireMAPProvenance(t, v)
		remaining[i] = mapConstraintFields(v)
	}
	for _, record := range want {
		if record.ObservedValueLength == 0 {
			record.ObservedValueLength = len(record.ObservedValue)
		}
		found := false
		for i, candidate := range remaining {
			if reflect.DeepEqual(candidate, record) {
				remaining = append(remaining[:i], remaining[i+1:]...)
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("violations = %+v, want %+v", got, want)
		}
	}
}
