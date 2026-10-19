// Code generated from MAP runtime source. DO NOT EDIT.

// Runtime source: runtime/oid_limits_test.go; SHA-256 928fdb2f5d6cccab7afc1eb6a2ba53a4635e4d5802bbb31d58e97d930c8327bf.
package runtime_test

import (
	"errors"
	"math/big"
	"strings"
	"testing"

	"github.com/gomaja/go-asn1/telecom/ss7/gsm_map/runtime"
)

func TestOIDDecimalResourceLimits(t *testing.T) {
	for _, relative := range []bool{false, true} {
		parse := func(s string) error { _, e := runtime.ParseObjectIdentifier(s); return e }
		prefix := "2."
		if relative {
			prefix = ""
			parse = func(s string) error { _, e := runtime.ParseRelativeObjectIdentifier(s); return e }
		}
		if err := parse(prefix + strings.Repeat("9", 1024)); err != nil {
			t.Fatalf("at digit limit: %v", err)
		}
		if err := parse(prefix + strings.Repeat("9", 1025)); err == nil {
			t.Error("accepted arc above digit limit")
		}
		text := strings.Repeat("1.", 4095) + "1"
		if !relative {
			text = "2." + strings.Repeat("1.", 4094) + "1"
		}
		if err := parse(text); err != nil {
			t.Fatalf("at arc limit: %v", err)
		}
		if err := parse(text + ".1"); err == nil {
			t.Error("accepted above arc limit")
		}
		text = strings.Repeat("9", 256) + strings.Repeat("."+strings.Repeat("9", 255), 255)
		if !relative {
			text = "2." + text[2:]
		}
		if len(text) != 65536 {
			t.Fatal(len(text))
		}
		if err := parse(text); err != nil {
			t.Fatalf("at text limit: %v", err)
		}
		if err := parse(text + "9"); err == nil {
			t.Error("accepted above text limit")
		}
	}
}

// A 1025-digit value can still fit the 486-group binary preflight bound.
// Divide into base-128 digits independently of the runtime's bit-packing path.
func oidExcessDecimalDigitsContents() string {
	n := new(big.Int).Exp(big.NewInt(10), big.NewInt(1024), nil)
	divisor := big.NewInt(128)
	var digits []byte
	remainder := new(big.Int)
	for n.Sign() != 0 {
		n.QuoRem(n, divisor, remainder)
		digits = append(digits, byte(remainder.Uint64()))
	}
	for left, right := 0, len(digits)-1; left < right; left, right = left+1, right-1 {
		digits[left], digits[right] = digits[right], digits[left]
	}
	for i := range len(digits) - 1 {
		digits[i] |= 128
	}
	return string(digits)
}

func TestOIDFormattingResourceLimits(t *testing.T) {
	digitArc := runtime.MustRelativeObjectIdentifier(strings.Repeat("9", 1024))
	// Wire decode has no decimal-materialization limit.
	enc := digitArc.Encoded()
	for _, contents := range []string{oidExcessDecimalDigitsContents(), enc[:len(enc)-1] + string([]byte{enc[len(enc)-1] | 128, 0}), strings.Repeat("\x01", 4097), strings.Repeat(enc, 65)} {
		oid, err := runtime.RelativeObjectIdentifierFromEncoded(contents)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := oid.MarshalText(); err == nil {
			t.Errorf("formatted oversized value (%d octets)", len(contents))
		}
	}
}

func TestOIDJSONResourceBound(t *testing.T) {
	for _, relative := range []bool{false, true} {
		for _, size := range []int{1 << 20, 4 << 20} {
			raw := []byte(`"` + strings.Repeat("1", size) + `"`)
			measurement := testing.Benchmark(func(b *testing.B) {
				for b.Loop() {
					var err error
					if relative {
						var v runtime.RelativeObjectIdentifier
						err = v.UnmarshalJSON(raw)
					} else {
						var v runtime.ObjectIdentifier
						err = v.UnmarshalJSON(raw)
					}
					if !errors.Is(err, runtime.ErrOIDTextLimit) {
						b.Fatal(err)
					}
				}
			})
			if measurement.AllocedBytesPerOp() > 256 {
				t.Fatalf("JSON relative=%v size=%d: %s", relative, size, measurement.MemString())
			}
		}
	}
}

func requireOIDTextLimit(t *testing.T, err error, resource string, limit int) {
	t.Helper()
	var typed *runtime.OIDTextLimitError
	if !errors.Is(err, runtime.ErrOIDTextLimit) || !errors.As(err, &typed) || typed.Resource != resource || typed.Limit != limit || typed.Error() == "" {
		t.Fatalf("error=%v, want %s limit %d", err, resource, limit)
	}
}

func TestOIDFormattingBoundariesAndErrors(t *testing.T) {
	for _, relative := range []bool{false, true} {
		for _, text := range []string{strings.Repeat("9", 1024), strings.Repeat("1.", 4095) + "1", strings.Repeat("9", 256) + strings.Repeat("."+strings.Repeat("9", 255), 255)} {
			if !relative {
				text = "2." + text
				if len(text) > 65536 {
					text = text[:65536]
				} else if strings.Count(text, ".") == 4096 {
					text = text[:len(text)-2]
				}
			}
			var contents string
			if relative {
				v, e := runtime.ParseRelativeObjectIdentifier(text)
				if e != nil {
					t.Fatal(e)
				}
				contents = v.Encoded()
			} else {
				v, e := runtime.ParseObjectIdentifier(text)
				if e != nil {
					t.Fatal(e)
				}
				contents = v.Encoded()
			}
			format := func() (string, error) {
				v, e := runtime.ObjectIdentifierFromEncoded(contents)
				if e != nil {
					t.Fatal(e)
				}
				return v.StringChecked()
			}
			if relative {
				format = func() (string, error) {
					v, e := runtime.RelativeObjectIdentifierFromEncoded(contents)
					if e != nil {
						t.Fatal(e)
					}
					return v.StringChecked()
				}
			}
			if got, e := format(); e != nil || got != text {
				t.Fatalf("boundary len=%d got len=%d err=%v", len(text), len(got), e)
			}
		}
		digitArc := runtime.MustRelativeObjectIdentifier(strings.Repeat("9", 1024)).Encoded()
		cases := []struct {
			contents, resource string
			limit              int
		}{
			{oidExcessDecimalDigitsContents(), "digits per arc", 1024},
			{digitArc[:len(digitArc)-1] + string([]byte{digitArc[len(digitArc)-1] | 128, 0}), "digits per arc", 1024},
			{strings.Repeat("\x01", 4097), "arc count", 4096},
			{strings.Repeat(digitArc, 65), "text length", 65536},
		}
		for _, tc := range cases {
			contents := tc.contents
			var checked func() (string, error)
			var plain func() string
			var marshal func() ([]byte, error)
			var marshalJSON func() ([]byte, error)
			if relative {
				v, e := runtime.RelativeObjectIdentifierFromEncoded(contents)
				if e != nil {
					t.Fatal(e)
				}
				checked = v.StringChecked
				plain = v.String
				marshal = v.MarshalText
				marshalJSON = v.MarshalJSON
			} else {
				v, e := runtime.ObjectIdentifierFromEncoded("\x50" + contents)
				if e != nil {
					t.Fatal(e)
				}
				checked = v.StringChecked
				plain = v.String
				marshal = v.MarshalText
				marshalJSON = v.MarshalJSON
			}
			text, err := checked()
			if text != "" {
				t.Fatal("partial text returned")
			}
			requireOIDTextLimit(t, err, tc.resource, tc.limit)
			_, err = marshal()
			requireOIDTextLimit(t, err, tc.resource, tc.limit)
			_, err = marshalJSON()
			requireOIDTextLimit(t, err, tc.resource, tc.limit)
			func() {
				defer func() {
					err, ok := recover().(error)
					if !ok {
						t.Fatal("String did not panic with error")
					}
					requireOIDTextLimit(t, err, tc.resource, tc.limit)
				}()
				plain()
			}()
		}
	}
}

func TestOIDParsingLimitErrorsAreTransactional(t *testing.T) {
	for _, tc := range []struct {
		text, resource string
		limit          int
	}{
		{"2." + strings.Repeat("9", 1025), "digits per arc", 1024},
		{"2." + strings.Repeat("1.", 4095) + "1", "arc count", 4096},
		{strings.Repeat("1", 65537), "text length", 65536},
	} {
		v := runtime.MustObjectIdentifier("1.2")
		prior := v
		requireOIDTextLimit(t, v.UnmarshalText([]byte(tc.text)), tc.resource, tc.limit)
		requireOIDTextLimit(t, v.UnmarshalJSON([]byte(`"`+tc.text+`"`)), tc.resource, tc.limit)
		if v != prior {
			t.Fatal("failed parse modified receiver")
		}
		relative := runtime.MustRelativeObjectIdentifier("1")
		priorRelative := relative
		requireOIDTextLimit(t, relative.UnmarshalText([]byte(tc.text)), tc.resource, tc.limit)
		requireOIDTextLimit(t, relative.UnmarshalJSON([]byte(`"`+tc.text+`"`)), tc.resource, tc.limit)
		if relative != priorRelative {
			t.Fatal("failed relative parse modified receiver")
		}
	}
}

func TestOIDUint64CombinedRootBoundaries(t *testing.T) {
	for _, delta := range []uint64{0, 1, 79, 80, 81} {
		second := ^uint64(0) - delta
		v, err := runtime.ObjectIdentifierFromArcs(2, second)
		if err != nil {
			t.Fatal(err)
		}
		arcs, ok := v.Arcs()
		if !ok || len(arcs) != 2 || arcs[0] != 2 || arcs[1] != second {
			t.Fatal(arcs, ok)
		}
		if v.String() != v.BigArcs()[0].String()+"."+v.BigArcs()[1].String() {
			t.Fatal("incorrect combined root")
		}
	}
}

func TestOIDFormattingWidthPreflightBound(t *testing.T) {
	for _, size := range []int{1024, 8192, 65536, 1 << 20} {
		oid, err := runtime.ObjectIdentifierFromEncoded("\x2a\x81" + strings.Repeat("\x80", size-2) + "\x00")
		if err != nil {
			t.Fatal(err)
		}
		operation := func() {
			_, e := oid.StringChecked()
			if !errors.Is(e, runtime.ErrOIDTextLimit) {
				t.Fatal(e)
			}
		}
		allocated, _ := allocationCost(t, 5, operation)
		// Repeated scans can be quadratic without allocating more memory.
		elapsed := minimumTime(t, operation)
		if int64(allocated) > 256 || elapsed.Nanoseconds() > 100000 {
			t.Fatalf("size=%d time=%s bytes=%d", size, elapsed, allocated)
		}
		t.Logf("size=%d time=%s bytes=%d", size, elapsed, allocated)
	}
}
