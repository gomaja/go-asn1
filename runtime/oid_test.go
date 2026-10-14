package runtime_test

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math"
	"reflect"
	"strings"
	"testing"
	"unsafe"

	"github.com/gomaja/go-asn1/runtime"
	"github.com/gomaja/go-asn1/runtime/ber"
	"github.com/gomaja/go-asn1/runtime/per"
)

// Pins cross-checked with pycrate 0.7.11. The UUID is X.667 (10/2012) §8;
// arc packing and minimality are X.690 (02/2021) §§8.19–8.20. PER applies
// those contents per X.691 (02/2021) §§24–25.
func TestOIDOracleVectors(t *testing.T) {
	for _, tc := range []struct {
		text, contents string
		relative       bool
	}{
		{"2.25.329800735698586629295641978511506172918", "6983f09da7ebcfdee0c7a1a7b2c0948cc8f9d776", false},
		{"1.2.18446744073709551615", "2a81ffffffffffffffff7f", false},
		{"1.2.18446744073709551616", "2a82808080808080808000", false},
		{"2.18446744073709551615", "8280808080808080804f", false},
		{"2.18446744073709551616", "82808080808080808050", false},
		{"2.999.3", "883703", false},
		{"329800735698586629295641978511506172918", "83f09da7ebcfdee0c7a1a7b2c0948cc8f9d776", true},
		{"18446744073709551615", "81ffffffffffffffff7f", true},
		{"18446744073709551616", "82808080808080808000", true},
	} {
		t.Run(tc.text, func(t *testing.T) {
			contents, _ := hex.DecodeString(tc.contents)
			wire := append([]byte{6, byte(len(contents))}, contents...)
			if tc.relative {
				wire[0] = 13
			}
			var gotWire []byte
			var err error
			if tc.relative {
				v, e := runtime.ParseRelativeObjectIdentifier(tc.text)
				if e != nil {
					t.Fatal(e)
				}
				if v.String() != tc.text {
					t.Fatalf("text %q, want %q", v.String(), tc.text)
				}
				if !bytes.Equal(v.Bytes(), contents) {
					t.Fatalf("contents %x", v.Bytes())
				}

			}
			if tc.relative {
				v, e := runtime.ParseRelativeObjectIdentifier(tc.text)
				if e != nil {
					t.Fatal(e)
				}
				got, n, e := ber.DecodeRelativeObjectIdentifier(wire)
				if e != nil || n != len(wire) || got != v {
					t.Fatalf("BER %v %d %v", got, n, e)
				}
				gotWire, err = ber.EncodeRelativeObjectIdentifierChecked(got)
			} else {
				v, e := runtime.ParseObjectIdentifier(tc.text)
				if e != nil {
					t.Fatal(e)
				}
				if v.String() != tc.text {
					t.Fatalf("text %q, want %q", v.String(), tc.text)
				}
				if !bytes.Equal(v.Bytes(), contents) {
					t.Fatalf("contents %x", v.Bytes())
				}
				got, n, e := ber.DecodeObjectIdentifier(wire)
				if e != nil || n != len(wire) || got != v {
					t.Fatalf("BER %v %d %v", got, n, e)
				}
				gotWire, err = ber.EncodeObjectIdentifier(got)
			}
			if err != nil || !bytes.Equal(gotWire, wire) {
				t.Fatalf("BER replay %x %v", gotWire, err)
			}
			if err := ber.ValidateDERElement(gotWire); err != nil {
				t.Fatal(err)
			}
			for _, aligned := range []bool{false, true} {
				bb := per.NewBitBuffer()
				if tc.relative {
					v := runtime.MustRelativeObjectIdentifier(tc.text)
					enc := per.EncodeRelativeObjectIdentifier
					dec := per.DecodeRelativeObjectIdentifier
					if aligned {
						enc = per.EncodeRelativeObjectIdentifierAligned
						dec = per.DecodeRelativeObjectIdentifierAligned
					}
					if e := enc(bb, v); e != nil {
						t.Fatal(e)
					}
					got, e := dec(per.NewBitBufferFromBytes(bb.Bytes()))
					if e != nil || got != v {
						t.Fatalf("PER %v %v", got, e)
					}
					replay := per.NewBitBuffer()
					if e := enc(replay, got); e != nil {
						t.Fatal(e)
					}
					if !bytes.Equal(replay.Bytes(), bb.Bytes()) {
						t.Fatal("PER replay")
					}
				} else {
					v := runtime.MustObjectIdentifier(tc.text)
					enc := per.EncodeObjectIdentifier
					dec := per.DecodeObjectIdentifier
					if aligned {
						enc = per.EncodeObjectIdentifierAligned
						dec = per.DecodeObjectIdentifierAligned
					}
					if e := enc(bb, v); e != nil {
						t.Fatal(e)
					}
					got, e := dec(per.NewBitBufferFromBytes(bb.Bytes()))
					if e != nil || got != v {
						t.Fatalf("PER %v %v", got, e)
					}
					replay := per.NewBitBuffer()
					if e := enc(replay, got); e != nil {
						t.Fatal(e)
					}
					if !bytes.Equal(replay.Bytes(), bb.Bytes()) {
						t.Fatal("PER replay")
					}
				}
				want := append([]byte{byte(len(contents))}, contents...)
				if !bytes.Equal(bb.Bytes(), want) {
					t.Fatalf("PER aligned=%v %x want %x", aligned, bb.Bytes(), want)
				}
			}
		})
	}
}

func TestOIDImmutableComparableAndText(t *testing.T) {
	if unsafe.Sizeof(runtime.ObjectIdentifier{}) != unsafe.Sizeof("") {
		t.Fatal("layout")
	}
	arcs := []uint64{2, math.MaxUint64, 3}
	v, err := runtime.ObjectIdentifierFromArcs(arcs...)
	if err != nil {
		t.Fatal(err)
	}
	arcs[1] = 0
	copy := runtime.MustObjectIdentifier("2.18446744073709551615.3")
	if v != copy || !v.Equal(copy) || v.Equal(runtime.MustObjectIdentifier("1.2")) {
		t.Fatal("equal")
	}
	m := map[runtime.ObjectIdentifier]string{v: "value"}
	if m[copy] != "value" {
		t.Fatal("map key")
	}
	small, ok := v.Arcs()
	if !ok || !reflect.DeepEqual(small, []uint64{2, math.MaxUint64, 3}) {
		t.Fatal(small, ok)
	}
	small[1] = 0
	bs := v.Bytes()
	bs[0] = 0
	bigArcs := v.BigArcs()
	bigArcs[1].SetInt64(0)
	if v != copy || v.String() != copy.String() {
		t.Fatal("mutable access")
	}
	bigOID := runtime.MustObjectIdentifier("2.25.329800735698586629295641978511506172918")
	if a, ok := bigOID.Arcs(); ok || a != nil {
		t.Fatal("truncated large arc")
	}
	if bigOID.BigArcs()[2].String() != "329800735698586629295641978511506172918" {
		t.Fatal("big arc")
	}
	text, err := bigOID.MarshalText()
	if err != nil || string(text) != bigOID.String() {
		t.Fatal(text, err)
	}
	var decoded runtime.ObjectIdentifier
	if err := decoded.UnmarshalText(text); err != nil || decoded != bigOID {
		t.Fatal(decoded, err)
	}
	wire, err := json.Marshal(bigOID)
	if err != nil || string(wire) != `"2.25.329800735698586629295641978511506172918"` {
		t.Fatal(string(wire), err)
	}
	if err := json.Unmarshal(wire, &decoded); err != nil || decoded != bigOID {
		t.Fatal(decoded, err)
	}
	keyWire, err := json.Marshal(map[runtime.ObjectIdentifier]int{bigOID: 1})
	if err != nil {
		t.Fatal(err)
	}
	var keys map[runtime.ObjectIdentifier]int
	if err := json.Unmarshal(keyWire, &keys); err != nil || keys[bigOID] != 1 {
		t.Fatal(string(keyWire), err)
	}
	for _, bad := range []string{"", "1", "3.0", "1.40", "0.40", "1..2", "1.2.", "1.02", "+1.2", "1.-2", " 1.2", "1.2a", "1.2e3"} {
		if err := decoded.UnmarshalText([]byte(bad)); err == nil || decoded != bigOID {
			t.Fatalf("accepted or modified %q", bad)
		}
	}
	for _, bad := range []string{`null`, `[]`, `123`, `"1.40"`, `"1.2`} {
		if err := json.Unmarshal([]byte(bad), &decoded); err == nil || decoded != bigOID {
			t.Fatalf("accepted or modified %s", bad)
		}
	}
	var zero runtime.ObjectIdentifier
	if _, err := zero.MarshalJSON(); err == nil {
		t.Fatal("zero JSON")
	}
	if _, err := zero.MarshalText(); err == nil {
		t.Fatal("zero text")
	}
	if _, ok := zero.Arcs(); ok || zero.BigArcs() != nil || zero.String() != "" || !zero.IsZero() {
		t.Fatal("zero")
	}
	relative := runtime.MustRelativeObjectIdentifier("18446744073709551616.0")
	mr := map[runtime.RelativeObjectIdentifier]int{relative: 1}
	other := runtime.MustRelativeObjectIdentifierFromEncoded(relative.Encoded())
	if mr[other] != 1 || !relative.Equal(other) || relative.Equal(runtime.MustRelativeObjectIdentifier("0")) {
		t.Fatal("relative map")
	}
	rb, _ := json.Marshal(relative)
	var rd runtime.RelativeObjectIdentifier
	if err := json.Unmarshal(rb, &rd); err != nil || rd != relative {
		t.Fatal(rd, err)
	}
	if _, ok := relative.Arcs(); ok {
		t.Fatal("relative large")
	}
	a := relative.BigArcs()
	a[0].SetInt64(0)
	if relative.String() != "18446744073709551616.0" {
		t.Fatal("relative mutable")
	}
}

func TestOIDInvalidWireAndLimits(t *testing.T) {
	for _, contents := range [][]byte{nil, {0x80, 0}, {0x2a, 0x80, 0}, {0x81}, {0x2a, 0x81}} {
		for _, relative := range []bool{false, true} {
			wire := append([]byte{6, byte(len(contents))}, contents...)
			if relative {
				wire[0] = 13
			}
			if relative {
				if _, _, err := ber.DecodeRelativeObjectIdentifier(wire); err == nil {
					t.Fatal("BER relative", wire)
				}
			} else {
				if _, _, err := ber.DecodeObjectIdentifier(wire); err == nil {
					t.Fatal("BER", wire)
				}
			}
			payload := append([]byte{byte(len(contents))}, contents...)
			for _, aligned := range []bool{false, true} {
				bb := per.NewBitBufferFromBytes(payload)
				var err error
				if relative {
					if aligned {
						_, err = per.DecodeRelativeObjectIdentifierAligned(bb)
					} else {
						_, err = per.DecodeRelativeObjectIdentifier(bb)
					}
				} else {
					if aligned {
						_, err = per.DecodeObjectIdentifierAligned(bb)
					} else {
						_, err = per.DecodeObjectIdentifier(bb)
					}
				}
				if err == nil {
					t.Fatal("PER", payload, relative, aligned)
				}
			}
		}
	}
	v := runtime.MustObjectIdentifierFromEncoded(strings.Repeat("\x01", 128))
	wire, err := ber.EncodeObjectIdentifier(v)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := ber.DecodeObjectIdentifier(wire, ber.WithDecodeLimits(ber.DecodeLimits{MaxWork: len(wire) - 1})); !errors.Is(err, ber.ErrResourceLimit) {
		t.Fatal(err)
	}
	if got, _, err := ber.DecodeObjectIdentifier(wire, ber.WithDecodeLimits(ber.DecodeLimits{MaxWork: len(wire)})); err != nil || got != v {
		t.Fatal(got, err)
	}
	r := runtime.MustRelativeObjectIdentifierFromEncoded(v.Encoded())
	rw, _ := ber.EncodeRelativeObjectIdentifierChecked(r)
	if _, _, err := ber.DecodeRelativeObjectIdentifier(rw, ber.WithDecodeLimits(ber.DecodeLimits{MaxWork: len(rw) - 1})); !errors.Is(err, ber.ErrResourceLimit) {
		t.Fatal(err)
	}
}

func TestOIDDecodeLinearAllocationBound(t *testing.T) {
	for _, size := range []int{128, 1024, 8192, 65536} {
		wire, err := ber.EncodeObjectIdentifier(runtime.MustObjectIdentifierFromEncoded("\x81" + strings.Repeat("\x80", size-2) + "\x00"))
		if err != nil {
			t.Fatal(err)
		}
		var got runtime.ObjectIdentifier
		measurement := testing.Benchmark(func(b *testing.B) {
			for b.Loop() {
				var e error
				got, _, e = ber.DecodeObjectIdentifier(wire)
				if e != nil {
					b.Fatal(e)
				}
			}
		})
		if len(got.Encoded()) != size || measurement.AllocedBytesPerOp() > int64(size*2+256) || measurement.AllocsPerOp() > 2 || measurement.NsPerOp() > int64(size)*100 {
			t.Fatalf("size=%d %s %s", size, measurement.String(), measurement.MemString())
		}
		t.Logf("size=%d %s %s", size, measurement.String(), measurement.MemString())
	}
}

func FuzzOIDContents(f *testing.F) {
	for _, seed := range [][]byte{nil, {0x2a}, {0x80, 0}, {0x2a, 0x81}, {0x2a, 0x82, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0}} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, contents []byte) {
		if len(contents) > 4096 {
			t.Skip()
		}
		v, err := runtime.ObjectIdentifierFromEncoded(string(contents))
		if err != nil {
			return
		}
		if !bytes.Equal(v.Bytes(), contents) {
			t.Fatal("changed contents")
		}
		text, textErr := v.StringChecked()
		if textErr == nil {
			reparsed, err := runtime.ParseObjectIdentifier(text)
			if err != nil || reparsed != v {
				t.Fatalf("text roundtrip %x %v", contents, err)
			}
		} else if !errors.Is(textErr, runtime.ErrOIDTextLimit) {
			t.Fatal(textErr)
		}
		wire, err := ber.EncodeObjectIdentifier(v)
		if err != nil {
			t.Fatal(err)
		}
		got, n, err := ber.DecodeObjectIdentifier(wire)
		if err != nil || n != len(wire) || got != v {
			t.Fatal("BER roundtrip", err)
		}
	})
}

func FuzzOIDWire(f *testing.F) {
	for _, wire := range []string{"06146983f09da7ebcfdee0c7a1a7b2c0948cc8f9d776", "060b2a82808080808080808000", "0d0a82808080808080808000", "0600", "06028000", "060181"} {
		b, _ := hex.DecodeString(wire)
		f.Add(b)
	}
	f.Fuzz(func(t *testing.T, wire []byte) {
		if len(wire) > 4096 {
			t.Skip()
		}
		if v, _, err := ber.DecodeObjectIdentifier(wire); err == nil {
			encoded, err := ber.EncodeObjectIdentifier(v)
			if err != nil {
				t.Fatal(err)
			}
			got, _, err := ber.DecodeObjectIdentifier(encoded)
			if err != nil || got != v {
				t.Fatal("BER", err)
			}
		}
		if v, _, err := ber.DecodeRelativeObjectIdentifier(wire); err == nil {
			encoded, err := ber.EncodeRelativeObjectIdentifierChecked(v)
			if err != nil {
				t.Fatal(err)
			}
			got, _, err := ber.DecodeRelativeObjectIdentifier(encoded)
			if err != nil || got != v {
				t.Fatal("relative BER", err)
			}
		}
		for _, aligned := range []bool{false, true} {
			dec := per.DecodeObjectIdentifier
			enc := per.EncodeObjectIdentifier
			if aligned {
				dec = per.DecodeObjectIdentifierAligned
				enc = per.EncodeObjectIdentifierAligned
			}
			if v, err := dec(per.NewBitBufferFromBytes(wire)); err == nil {
				bb := per.NewBitBuffer()
				if err := enc(bb, v); err != nil {
					t.Fatal(err)
				}
				got, err := dec(per.NewBitBufferFromBytes(bb.Bytes()))
				if err != nil || got != v {
					t.Fatal("PER", err)
				}
			}
			rdec := per.DecodeRelativeObjectIdentifier
			renc := per.EncodeRelativeObjectIdentifier
			if aligned {
				rdec = per.DecodeRelativeObjectIdentifierAligned
				renc = per.EncodeRelativeObjectIdentifierAligned
			}
			if v, err := rdec(per.NewBitBufferFromBytes(wire)); err == nil {
				bb := per.NewBitBuffer()
				if err := renc(bb, v); err != nil {
					t.Fatal(err)
				}
				got, err := rdec(per.NewBitBufferFromBytes(bb.Bytes()))
				if err != nil || got != v {
					t.Fatal("relative PER", err)
				}
			}
		}
	})
}

func FuzzOIDText(f *testing.F) {
	for _, text := range []string{"1.2", "2.25.329800735698586629295641978511506172918", "18446744073709551616.1", "1..2", "1.40", "0", "0.0"} {
		f.Add(text)
	}
	f.Fuzz(func(t *testing.T, text string) {
		if len(text) > 4096 {
			t.Skip()
		}
		if v, err := runtime.ParseObjectIdentifier(text); err == nil {
			if v.String() != text {
				t.Fatal("text canonicality")
			}
			got, err := runtime.ObjectIdentifierFromEncoded(v.Encoded())
			if err != nil || got != v {
				t.Fatal(err)
			}
		}
		if v, err := runtime.ParseRelativeObjectIdentifier(text); err == nil {
			if v.String() != text {
				t.Fatal("relative text canonicality")
			}
			got, err := runtime.RelativeObjectIdentifierFromEncoded(v.Encoded())
			if err != nil || got != v {
				t.Fatal(err)
			}
		}
	})
}

func TestExternalJSONOmitsAbsentIdentifier(t *testing.T) {
	v := runtime.External{Encoding: runtime.ExternalOctetAligned, OctetAligned: []byte{1, 2, 3}}
	data, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	var got runtime.External
	if err := json.Unmarshal(data, &got); err != nil || !got.DirectReference.IsZero() {
		t.Fatal(got, err)
	}
	if bytes.Contains(data, []byte("DirectReference")) {
		t.Fatal("absent reference emitted", string(data))
	}
	v.DirectReference = runtime.MustObjectIdentifier("2.25.329800735698586629295641978511506172918")
	data, err = json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(data, &got); err != nil || got.DirectReference != v.DirectReference {
		t.Fatal("lost direct reference", err)
	}
}

func TestOIDWireOwnsContents(t *testing.T) {
	wire := []byte{6, 2, 0x2a, 3}
	value, _, err := ber.DecodeObjectIdentifier(wire)
	if err != nil {
		t.Fatal(err)
	}
	wire[2] = 0
	if value.String() != "1.2.3" {
		t.Fatal("OID retained mutable wire")
	}
	relativeWire := []byte{13, 2, 3, 4}
	relative, _, err := ber.DecodeRelativeObjectIdentifier(relativeWire)
	if err != nil {
		t.Fatal(err)
	}
	relativeWire[3] = 5
	if relative.String() != "3.4" {
		t.Fatal("relative OID retained mutable wire")
	}
}
