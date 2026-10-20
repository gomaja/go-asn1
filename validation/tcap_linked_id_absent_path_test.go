package validation

import (
	"errors"
	"testing"

	"github.com/gomaja/go-asn1/telecom/ss7/tcap"
	tcapber "github.com/gomaja/go-asn1/telecom/ss7/tcap/runtime/ber"
)

// go-asn1 #193: a Q.773 (06/1997) §4.1.1 finding on an Invoke's absent linked
// ID (linkedId absent [1] IMPLICIT NULL, X.880 (07/1994) Annex A) names the
// linked ID, not the argument. The zero length is in long form (81 81 00).
func TestTCAPLinkedIDAbsentFindingPath(t *testing.T) {
	const path = "begin.components.element[0].basicROS.invoke.linkedId.absent"
	wire := mustHex(t, "62104801016c0ba109020101818100020101")
	var tolerant tcap.TCMessage
	var log tcapber.ViolationLog
	if err := tolerant.UnmarshalBER(wire, tcapber.WithTolerance(&log)); err != nil {
		t.Fatalf("tolerant decode = %v", err)
	}
	found := false
	for _, v := range log.Snapshot() {
		if v.Constraint == "Q.773 §4.1.1: short-length" {
			found = true
			if v.Path != path {
				t.Errorf("short-length record path = %q; want %q", v.Path, path)
			}
		}
	}
	if !found {
		t.Fatalf("records = %+v; want a Q.773 §4.1.1 short-length record", log.Snapshot())
	}
	var strict tcap.TCMessage
	var refusal *tcapber.ValidationError
	if err := strict.UnmarshalBER(wire); !errors.As(err, &refusal) || refusal.Path != path {
		t.Fatalf("strict decode = %v; want a refusal at %s", err, path)
	}
}
