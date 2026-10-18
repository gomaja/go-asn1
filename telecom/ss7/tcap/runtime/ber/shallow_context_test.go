// Code generated from ASN.1 module "TCAPMessages". DO NOT EDIT.

// Runtime source: runtime/ber/shallow_context_test.go; SHA-256 1187d175c2bd9df81dc7e1074e6e7e1c4a3defe387168ce7ff3e0aa6d70f9196.
package ber

import (
	"errors"
	"strings"
	"testing"
)

// A shallow decoder still validates each ordinary child. Its diagnostic state
// must not copy the complete option ancestry at every generated boundary.
func TestGeneratedShallowContextAllocationBound(t *testing.T) {
	wire := []byte{0x30, 3, 2, 1, 1}
	measure := testing.Benchmark(func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			options := TrackTCAPForm(nil, "TCMessage")
			owned, err := OwnGeneratedBERInput(wire, options)
			if err != nil {
				b.Fatal(err)
			}
			data, options, err := PrepareGeneratedBERInput(owned, options)
			if err != nil {
				b.Fatal(err)
			}
			for range 12 {
				options = ChildDecodeOptions(options, "child")
				options = TrackTCAPForm(options, "Invoke")
				options = LocateDecodedElement(data, "Invoke", options)
				options, finish := StageDecodeReports(options)
				finish(true)
				if err := ValidateBERElement(data, options...); err != nil {
					b.Fatal(err)
				}
			}
		}
	})
	t.Logf("bytes/op=%d allocs/op=%d", measure.AllocedBytesPerOp(), measure.AllocsPerOp())
	if measure.AllocedBytesPerOp() > 16000 {
		t.Fatalf("shallow context allocated %d bytes per 12 boundaries; want <=16000", measure.AllocedBytesPerOp())
	}
}

func TestGeneratedShallowContextRechecksChangedChildren(t *testing.T) {
	for _, mode := range []DecodeOption{nil, ForceGeneratedBERLightForTesting()} {
		options := []DecodeOption{}
		if mode != nil {
			options = append(options, mode)
		}
		options = TrackTCAPForm(options, "TCMessage")
		owned, err := OwnGeneratedBERInput([]byte{0x30, 3, 2, 1, 1}, options)
		if err != nil {
			t.Fatal(err)
		}
		data, options, err := PrepareGeneratedBERInput(owned, options)
		if err != nil {
			t.Fatal(err)
		}
		child := ChildDecodeOptions(options, "child")
		data[3] = 0 // INTEGER with empty contents, followed by a stray octet.
		if err := ValidateBERElement(data[2:], child...); err == nil {
			t.Fatal("changed child bypassed ordinary validation")
		}
		if _, _, err := PrepareGeneratedBERInput(data[2:], child); err == nil {
			t.Fatal("changed child bypassed preparation")
		}
		if err := ValidateBERElement([]byte{2, 0}, child...); !errors.Is(err, ErrInvalidValue) {
			t.Fatalf("detached invalid INTEGER: %v", err)
		}
	}
}

func TestGeneratedPathMarkerAllocationBound(t *testing.T) {
	wire := []byte{0x30, 3, 2, 1, 1}
	options := TrackBERForm([]DecodeOption{ForceGeneratedBERProofForTesting()})
	data, err := OwnGeneratedBERInput(wire, options)
	if err != nil {
		t.Fatal(err)
	}
	_, options, err = PrepareGeneratedBERInput(data, options)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"outer", "inner", "value"} {
		options = ChildDecodeOptions(options, name)
	}
	options = LocateDecodedElement(data, "Invoke", options)
	allocations := testing.AllocsPerRun(100, func() { MarkPreflightTarget(options, "leaf", data[2:]) })
	if allocations > 1 {
		t.Fatalf("successful field marker allocated %.0f times; want at most one", allocations)
	}
	config, err := decodeOptions(options)
	if err != nil {
		t.Fatal(err)
	}
	if got, _ := config.location.origin.mark("outer.inner.value.leaf"); got != 2 {
		t.Fatalf("received offset=%d want 2", got)
	}
	if err := CheckDecodedValue(options, "leaf", "Q.773 §4.2.2.2: Invoke ID range", "200"); err == nil || err.(*ValidationError).Path != "outer.inner.value.leaf" {
		t.Fatalf("diagnostic path: %v", err)
	}
}

func TestGeneratedShallowChildUsesReconstructedWorkingInput(t *testing.T) {
	options := TrackTCAPForm(nil, "TCMessage")
	data, err := OwnGeneratedBERInput([]byte{0x62, 3, 2, 1, 1}, options)
	if err != nil {
		t.Fatal(err)
	}
	_, options, err = PrepareGeneratedBERInput(data, options)
	if err != nil {
		t.Fatal(err)
	}
	// An IMPLICIT aggregate has a private reconstructed identifier. Copying it
	// again loses its relationship with the received-location marker.
	reconstructed := append([]byte(nil), data...)
	reconstructed[0] = 0x30
	child := ChildDecodeOptions(options, "begin")
	working, err := OwnGeneratedBERInput(reconstructed, child)
	if err != nil {
		t.Fatal(err)
	}
	if !sameBERSlice(working, reconstructed) {
		t.Fatal("shallow child copied an already reconstructed working input")
	}
}

func TestGeneratedLocatedContextAllocationBound(t *testing.T) {
	options := TrackBERForm([]DecodeOption{ForceGeneratedBERProofForTesting()})
	data, err := OwnGeneratedBERInput([]byte{0x30, 3, 2, 1, 1}, options)
	if err != nil {
		t.Fatal(err)
	}
	_, options, err = PrepareGeneratedBERInput(data, options)
	if err != nil {
		t.Fatal(err)
	}
	options = LocateDecodedElement(data, "Invoke", options)
	allocations := testing.AllocsPerRun(100, func() {
		child := LocateDecodedElement(data[2:], "InvokeId", options)
		if len(child) != 1 {
			t.Fatal("lost generated context")
		}
	})
	if allocations > 2 {
		t.Fatalf("located child context allocated %.0f times; want at most two", allocations)
	}
}

func TestGeneratedShallowCompletionWithoutCapture(t *testing.T) {
	options := TrackBERForm(nil)
	data, err := OwnGeneratedBERInput([]byte{0x04, 1, 'A'}, options)
	if err != nil {
		t.Fatal(err)
	}
	_, options, err = PrepareGeneratedBERInput(data, options)
	if err != nil {
		t.Fatal(err)
	}
	value := struct{ Data byte }{'A'}
	encodes := 0
	if err := CompleteGeneratedBERDecode(options, &value, func(v *struct{ Data byte }, opts ...EncodeOption) ([]byte, error) {
		encodes++
		return []byte{4, 1, v.Data}, nil
	}); err != nil {
		t.Fatal(err)
	}
	if encodes != 0 {
		t.Fatalf("completion prepared replay without capturing a node: %d encodes", encodes)
	}
}

func TestGeneratedShallowCompletionWithOnlyChildCapture(t *testing.T) {
	options := TrackBERForm(nil)
	data, err := OwnGeneratedBERInput([]byte{0x30, 3, 4, 1, 'A'}, options)
	if err != nil {
		t.Fatal(err)
	}
	data, options, err = PrepareGeneratedBERInput(data, options)
	if err != nil {
		t.Fatal(err)
	}
	if node := CaptureGeneratedBERReplay(data[2:], ChildDecodeOptions(options, "field")); node == nil {
		t.Fatal("child capture missing")
	}
	value := struct{ Data byte }{'A'}
	encodes := 0
	if err := CompleteGeneratedBERDecode(options, &value, func(v *struct{ Data byte }, opts ...EncodeOption) ([]byte, error) {
		encodes++
		return []byte{4, 1, v.Data}, nil
	}); err != nil {
		t.Fatal(err)
	}
	if encodes != 0 {
		t.Fatalf("child capture prepared a root replay: %d encodes", encodes)
	}
}

func TestGeneratedShallowPreparationWithoutOwnershipCompletesReplay(t *testing.T) {
	type value struct {
		Data []byte
		Node *ReplayNode
	}
	wire := []byte{4, 0x81, 1, 'A'}
	data, options, err := PrepareGeneratedBERInput(wire, TrackBERForm(nil))
	if err != nil {
		t.Fatal(err)
	}
	v := value{Data: data[len(data)-1:], Node: CaptureGeneratedBERReplay(data, options)}
	encodes := 0
	encode := func(v *value, opts ...EncodeOption) ([]byte, error) {
		encodes++
		prepared, err := PrepareBERReplay(v.Node, opts, nil, v)
		if err != nil {
			return nil, err
		}
		return PreserveEncodedBERNode(append([]byte{4, 1}, v.Data...), v.Node, prepared), nil
	}
	if err := CompleteGeneratedBERDecode(options, &v, encode); err != nil {
		t.Fatal(err)
	}
	if encodes != 1 {
		t.Fatalf("standalone light completion encoded baseline %d times; want one", encodes)
	}
	prepared, err := PrepareBERReplay(v.Node, nil, func(mode EncodeOption) ([]byte, error) { return encode(&v, mode) }, &v)
	if err != nil {
		t.Fatal(err)
	}
	got, ok := PreparedBERReplay(v.Node, prepared)
	if !ok || string(got) != string(wire) {
		t.Fatalf("standalone received replay=%x enabled=%t", got, ok)
	}
}

func TestGeneratedFirstDiagnosticPathGrowthBound(t *testing.T) {
	options := TrackBERForm([]DecodeOption{ForceGeneratedBERProofForTesting()})
	data, err := OwnGeneratedBERInput([]byte{5, 0}, options)
	if err != nil {
		t.Fatal(err)
	}
	_, options, err = PrepareGeneratedBERInput(data, options)
	if err != nil {
		t.Fatal(err)
	}
	for _, depth := range []int{64, 512} {
		want := strings.Repeat("child.", depth) + "leaf"
		result := testing.Benchmark(func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				child := options
				for range depth {
					child = ChildDecodeOptions(child, "child")
				}
				err := CheckDecodedValue(child, "leaf", "test constraint", "1")
				if err == nil || err.(*ValidationError).Path != want {
					b.Fatalf("diagnostic path at depth %d: %v", depth, err)
				}
			}
		})
		t.Logf("depth=%d bytes/op=%d", depth, result.AllocedBytesPerOp())
		if result.AllocedBytesPerOp() > int64(1200*depth+4096) {
			t.Fatalf("first path lookup exceeded linear memory bound at depth %d: %d bytes/op", depth, result.AllocedBytesPerOp())
		}
	}
}
