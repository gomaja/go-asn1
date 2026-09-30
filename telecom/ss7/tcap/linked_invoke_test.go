package tcap

import (
	"bytes"
	"encoding/hex"
	"testing"
)

// ITU-T X.880 (07/1994) Annex A, Invoke permits linkedId absent or present.
func TestLinkedInvokeBER(t *testing.T) {
	for _, wireHex := range []string{
		"62134804010203046c0ba10902010380010102013c",
		"62104804010203046c08a10602010302013c",
	} {
		wire, err := hex.DecodeString(wireHex)
		if err != nil {
			t.Fatal(err)
		}
		var message TCMessage
		if err := message.UnmarshalBER(wire); err != nil {
			t.Fatalf("decode %s: %v", wireHex, err)
		}
		reencoded, err := message.MarshalBER()
		if err != nil {
			t.Fatalf("encode %s: %v", wireHex, err)
		}
		if !bytes.Equal(reencoded, wire) {
			t.Fatalf("round trip %x, want %x", reencoded, wire)
		}
	}
}
