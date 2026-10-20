package validation

import (
	"bytes"
	"encoding/hex"
	"errors"
	"sync"
	"testing"

	gsm_map "github.com/gomaja/go-asn1/telecom/ss7/gsm_map"
	"github.com/gomaja/go-asn1/telecom/ss7/gsm_map/ros"
	mapber "github.com/gomaja/go-asn1/telecom/ss7/gsm_map/runtime/ber"
)

func mapFormHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// Synthetic AnyTimeInterrogationArg values in TS 29.002 §17.1.1 form.
var mapFormInputs = []string{
	"3012a0058003214365a180800000008303912143",
	"3012a0058003214366a180800000008303912144",
}

// go-asn1 #195: a form tracker supplied by the caller carries no state from one
// decode into the next.
func TestMAPFormOptionsReuseAcrossDecodes(t *testing.T) {
	for name, opts := range map[string][]mapber.DecodeOption{
		"TrackBERForm": mapber.TrackBERForm(nil),
		"TrackMAPForm": mapber.TrackMAPForm(nil),
		"tolerant":     mapber.TrackMAPForm([]mapber.DecodeOption{mapber.WithTolerance(new(mapber.ViolationLog))}),
	} {
		for round := 0; round < 3; round++ {
			for _, input := range mapFormInputs {
				wire := mapFormHex(t, input)
				var v gsm_map.AnyTimeInterrogationArg
				if err := v.UnmarshalBER(wire, opts...); err != nil {
					t.Fatalf("%s round %d: reused options refused %s: %v", name, round, input, err)
				}
				out, err := v.MarshalBER()
				if err != nil || !bytes.Equal(out, wire) {
					t.Fatalf("%s round %d: replay = %x, %v; want %s", name, round, out, err, input)
				}
			}
		}
	}
}

// go-asn1 #195: one options slice shared between goroutines; run with -race.
func TestMAPFormOptionsSharedAcrossGoroutines(t *testing.T) {
	opts := mapber.TrackMAPForm(nil)
	var wg sync.WaitGroup
	errs := make(chan error, 16)
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for round := 0; round < 50; round++ {
				wire := mapFormHex(t, mapFormInputs[(g+round)%2])
				var v gsm_map.AnyTimeInterrogationArg
				if err := v.UnmarshalBER(wire, opts...); err != nil {
					errs <- err
					return
				}
				if out, err := v.MarshalBER(); err != nil || !bytes.Equal(out, wire) {
					errs <- errors.New("shared options changed the replay")
					return
				}
			}
		}(g)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatal(err)
	}
}

// A raw BER walk cannot tell MAP-defined content from foreign open values, so
// a standalone scan with the MAP profile refuses instead of passing silently,
// also after the same options served a typed decode.
func TestMAPStandaloneProfileScanRefuses(t *testing.T) {
	wire := mapFormHex(t, "318100")
	opts := mapber.TrackMAPForm(nil)
	if err := mapber.ValidateBERElement(wire, opts...); !errors.Is(err, mapber.ErrInvalidValue) {
		t.Fatalf("standalone MAP profile scan = %v, want ErrInvalidValue", err)
	}
	var v gsm_map.AnyTimeInterrogationArg
	if err := v.UnmarshalBER(mapFormHex(t, mapFormInputs[0]), opts...); err != nil {
		t.Fatal(err)
	}
	if err := mapber.ValidateBERElement(wire, opts...); !errors.Is(err, mapber.ErrInvalidValue) {
		t.Fatalf("standalone MAP profile scan after a typed decode = %v, want ErrInvalidValue", err)
	}
	if err := mapber.ValidateBERElement(wire); err != nil {
		t.Fatalf("generic BER scan = %v", err)
	}
}

// The root selects the syntax: an X.880 ROS root keeps generic BER (X.690 §8)
// even when the caller passes the MAP form tracker.
func TestMAPROSRootKeepsGenericBERWithCallerTracker(t *testing.T) {
	wire := mapFormHex(t, "30810a02010102010204810112")
	if _, err := ros.InvokeCodec().DecodeBER(wire); err != nil {
		t.Fatalf("ROS Invoke without options: %v", err)
	}
	if _, err := ros.InvokeCodec().DecodeBER(wire, mapber.TrackMAPForm(nil)...); err != nil {
		t.Fatalf("ROS Invoke with a caller TrackMAPForm: %v", err)
	}
}
