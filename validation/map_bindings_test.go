package validation

import (
	"bytes"
	"encoding/hex"
	"testing"

	gsm_map "github.com/gomaja/go-asn1/telecom/ss7/gsm_map"
	"github.com/gomaja/go-asn1/telecom/ss7/gsm_map/bindings"
)

// go-asn1 #192: composite codec factories live in gsm_map/bindings and agree
// with the root types' own wire methods, byte for byte.
func TestMAPBindingsMatchRootWireMethods(t *testing.T) {
	wire, err := hex.DecodeString("30110403123456810491214365040491436587") // synthetic UpdateLocationArg
	if err != nil {
		t.Fatal(err)
	}
	codec := bindings.UpdateLocationArgCodec()
	if !codec.Valid() {
		t.Fatal("bindings.UpdateLocationArgCodec is not valid")
	}
	value, err := codec.DecodeBER(wire)
	if err != nil {
		t.Fatalf("bindings decode: %v", err)
	}
	var root gsm_map.UpdateLocationArg
	if err := root.UnmarshalBER(wire); err != nil {
		t.Fatalf("root decode: %v", err)
	}
	viaCodec, err := codec.EncodeBER(value)
	if err != nil {
		t.Fatal(err)
	}
	viaRoot, err := root.MarshalBER()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(viaCodec, wire) || !bytes.Equal(viaRoot, wire) {
		t.Fatalf("replay differs: codec %x, root %x, want %x", viaCodec, viaRoot, wire)
	}
	argument, ok := bindings.UpdateLocationOperation().Argument()
	if !ok || !argument.Valid() {
		t.Fatal("UpdateLocationOperation has no valid argument codec")
	}
	if _, err := argument.DecodeBER(wire); err != nil {
		t.Fatalf("operation argument decode: %v", err)
	}
	derCodec, errCodec := codec.EncodeDER(value)
	derRoot, errRoot := root.MarshalDER()
	if errCodec != nil || errRoot != nil || !bytes.Equal(derCodec, derRoot) {
		t.Fatalf("DER differs: codec %x %v, root %x %v", derCodec, errCodec, derRoot, errRoot)
	}
}

// A zero ValueCodec reports itself invalid at the new package boundary.
func TestMAPBindingsZeroValueCodecIsInvalid(t *testing.T) {
	var zero gsm_map.ValueCodec[gsm_map.UpdateLocationArg]
	if zero.Valid() {
		t.Fatal("zero ValueCodec reports valid")
	}
}
