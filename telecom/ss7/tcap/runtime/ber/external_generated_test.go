// Code generated from ASN.1 module "TCAPMessages". DO NOT EDIT.

// Runtime source: runtime/ber/external_generated_test.go; SHA-256 bdc3854da88f06e38ea7e06796bd57a57a97a379defa571cb1929c11a6c76309.
package ber

import (
	"bytes"
	"errors"
	"fmt"
	"testing"
)

func TestGeneratedExternalEntryPoints(t *testing.T) {
	for _, mode := range []struct {
		name   string
		option DecodeOption
	}{
		{"adaptive", nil}, {"light", ForceGeneratedBERLightForTesting()}, {"proof", ForceGeneratedBERProofForTesting()},
	} {
		for _, tolerant := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/tolerant=%t", mode.name, tolerant), func(t *testing.T) {
				prepare := func(data []byte) ([]byte, []DecodeOption, *ViolationLog) {
					var log ViolationLog
					var opts []DecodeOption
					if mode.option != nil {
						opts = append(opts, mode.option)
					}
					if tolerant {
						opts = append(opts, WithTolerance(&log))
					}
					opts = TrackBERForm(opts)
					owned, err := OwnGeneratedBERInput(data, opts)
					if err != nil {
						t.Fatal(err)
					}
					return owned, opts, &log
				}
				for _, text := range []string{"2808060130a003040141", "28080601308103616263", "28080601308203006162", "280a060130a00530030c0141"} {
					wire := structureWire(t, text)
					for _, tagging := range []string{"", "EXPLICIT", "IMPLICIT"} {
						input := bytes.Clone(wire)
						if tagging == "EXPLICIT" {
							input = append(append([]byte{0x6b}, EncodeLength(len(wire))...), wire...)
						}
						if tagging == "IMPLICIT" {
							input[0] = 0x6b
						}
						owned, opts, log := prepare(input)
						value, prepared, context, err := DecodeGeneratedExternal(owned, opts, tagging)
						if err != nil {
							t.Fatalf("%s/%s: %v", text, tagging, err)
						}
						if !bytes.Equal(prepared, input) || len(log.Snapshot()) != 0 {
							t.Fatalf("changed input or reports: %+v", log.Snapshot())
						}
						fresh, err := EncodeExternal(value)
						if err != nil {
							t.Fatal(err)
						}
						if !bytes.Equal(fresh, wire) {
							t.Fatalf("replay=%x want=%x", fresh, wire)
						}
						// Prepared options returned by this call have no reusable skip.
						bad := structureWire(t, "280b060130a006300430303030")
						if _, _, err := DecodeExternal(bad, context...); !errors.Is(err, ErrTruncated) {
							t.Fatalf("detached context bypass: %v", err)
						}
					}
					list := append(append([]byte{0x30}, EncodeLength(2*len(wire))...), wire...)
					list = append(list, wire...)
					owned, opts, log := prepare(list)
					values, prepared, context, err := DecodeGeneratedExternalSequence(owned, opts)
					if err != nil || len(values) != 2 || !bytes.Equal(prepared, list) || len(log.Snapshot()) != 0 {
						t.Fatalf("list=%+v err=%v reports=%+v", values, err, log.Snapshot())
					}
					var out []byte
					for _, v := range values {
						b, e := EncodeExternal(v)
						if e != nil {
							t.Fatal(e)
						}
						out = append(out, b...)
					}
					if !bytes.Equal(out, list[2:]) {
						t.Fatalf("list replay=%x want=%x", out, list[2:])
					}
					bad := structureWire(t, "280b060130a006300430303030")
					if _, _, err := DecodeExternal(bad, context...); !errors.Is(err, ErrTruncated) {
						t.Fatalf("list context bypass: %v", err)
					}
				}
				bad := structureWire(t, "280b060130a006300430303030")
				for _, opts := range [][]DecodeOption{nil, TrackBERForm(nil), LocateDecodedElement(bad, "Caller.external", nil)} {
					if _, _, _, err := DecodeGeneratedExternal(bad, opts, ""); !errors.Is(err, ErrTruncated) {
						t.Fatalf("caller-made options: %v", err)
					}
				}
				// A primitive wrapper did not validate its contents as child elements.
				primitive := append(append([]byte{4}, EncodeLength(len(bad))...), bad...)
				owned, opts, _ := prepare(primitive)
				if _, _, _, err := DecodeGeneratedExternal(owned, opts, "EXPLICIT"); !errors.Is(err, ErrInvalidTag) {
					t.Fatalf("primitive wrapper: %v", err)
				}
				owned, opts, _ = prepare(primitive)
				if _, _, _, err := DecodeGeneratedExternalSequence(owned, opts); !errors.Is(err, ErrUnexpectedElement) {
					t.Fatalf("primitive list: %v", err)
				}
			})
		}
	}
}

// X.690 (02/2021) §§8.1 and 8.18: every direct child is a separate
// encoding. List growth must not allocate more than linearly in its children.
func TestGeneratedExternalSequenceLinearAllocations(t *testing.T) {
	child := structureWire(t, "2808060130a003040141")
	for _, mode := range []struct {
		name   string
		option DecodeOption
	}{
		{"adaptive", nil}, {"light", ForceGeneratedBERLightForTesting()}, {"proof", ForceGeneratedBERProofForTesting()},
	} {
		var previous float64
		for _, size := range []int{16, 64, 256} {
			contents := bytes.Repeat(child, size)
			wire := append(append([]byte{0x30}, EncodeLength(len(contents))...), contents...)
			count := testing.AllocsPerRun(5, func() {
				var opts []DecodeOption
				if mode.option != nil {
					opts = append(opts, mode.option)
				}
				opts = TrackBERForm(opts)
				owned, err := OwnGeneratedBERInput(wire, opts)
				if err != nil {
					t.Fatal(err)
				}
				values, _, _, err := DecodeGeneratedExternalSequence(owned, opts)
				if err != nil || len(values) != size {
					t.Fatalf("%s/%d values=%d err=%v", mode.name, size, len(values), err)
				}
			})
			t.Logf("%s size=%d allocations=%.0f", mode.name, size, count)
			if previous > 0 && count > 5*previous {
				t.Fatalf("%s allocations grew superlinearly: %.0f -> %.0f", mode.name, previous, count)
			}
			previous = count
		}
	}
}

func TestGeneratedExternalCallerOptions(t *testing.T) {
	wire := structureWire(t, "280a060130a00530030c0141")
	for _, opts := range [][]DecodeOption{nil, TrackBERForm(nil), {ForceGeneratedBERProofForTesting()}} {
		value, _, context, err := DecodeGeneratedExternal(wire, opts, "")
		if err != nil {
			t.Fatal(err)
		}
		out, err := EncodeExternal(value)
		if err != nil || !bytes.Equal(out, wire) {
			t.Fatalf("caller replay=%x err=%v", out, err)
		}
		changed := bytes.Clone(wire)
		changed[len(changed)-1] = 0xff
		if _, _, _, err = DecodeGeneratedExternal(changed, context, ""); !errors.Is(err, ErrInvalidValue) {
			t.Fatalf("caller context bypass=%v", err)
		}
	}
	for _, option := range []DecodeOption{ForceGeneratedBERLightForTesting(), ForceGeneratedBERProofForTesting()} {
		opts := TrackBERForm([]DecodeOption{option})
		owned, err := OwnGeneratedBERInput(wire, opts)
		if err != nil {
			t.Fatal(err)
		}
		data, context, err := PrepareGeneratedBERInput(owned, opts)
		if err != nil {
			t.Fatal(err)
		}
		data[len(data)-1] = 0xff
		if _, _, _, err = DecodeGeneratedExternal(data, context, ""); !errors.Is(err, ErrInvalidValue) {
			t.Fatalf("changed prepared span=%v", err)
		}
	}
}
