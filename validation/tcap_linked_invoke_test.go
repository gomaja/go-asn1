package validation

import (
	"bytes"
	"testing"

	"github.com/gomaja/go-asn1/telecom/ss7/tcap"
)

// ITU-T X.880 (07/1994) Annex A, Invoke permits linkedId absent or present.
func TestLinkedInvokeBER(t *testing.T) {
	for _, tc := range []struct {
		name    string
		wireHex string
		linked  bool
	}{
		{"present", "62134804010203046c0ba10902010380010102013c", true},
		{"absent", "62104804010203046c08a10602010302013c", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			wire := mustHex(t, tc.wireHex)
			var message tcap.TCMessage
			if err := message.UnmarshalBER(wire); err != nil {
				t.Fatalf("decode %s: %v", tc.wireHex, err)
			}
			reencoded, err := message.MarshalBER()
			if err != nil {
				t.Fatalf("encode %s: %v", tc.wireHex, err)
			}
			if !bytes.Equal(reencoded, wire) {
				t.Fatalf("round trip %x, want %x", reencoded, wire)
			}
			if message.Choice != tcap.TCMessageChoiceBegin || message.Begin == nil || message.Begin.Components == nil {
				t.Fatal("missing Begin components")
			}
			components := message.Begin.Components.Values
			if len(components) != 1 || components[0].BasicROS == nil || components[0].BasicROS.Invoke == nil {
				t.Fatal("missing Invoke component")
			}
			linked := components[0].BasicROS.Invoke.LinkedId
			if (linked != nil) != tc.linked {
				t.Fatalf("linkedId present = %v, want %v", linked != nil, tc.linked)
			}
			if tc.linked && (linked.Present == nil || !linked.Present.IsInt64() || linked.Present.Int64() != 1) {
				t.Fatalf("linkedId = %+v, want present 1", linked)
			}
		})
	}
}
