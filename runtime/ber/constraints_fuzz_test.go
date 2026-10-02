package ber

import "testing"

func FuzzBERConstraintTolerance(f *testing.F) {
	f.Add([]byte{0x04, 0x01, 0xaa})
	f.Add([]byte{0x04, 0x02, 0xaa, 0xbb})
	f.Add([]byte{0x04, 0x81, 0x01, 0xaa})
	f.Add([]byte{0x24, 0x04, 0x04, 0x02, 0xaa, 0xbb})
	f.Fuzz(func(t *testing.T, wire []byte) {
		for _, tolerant := range []bool{false, true} {
			var reports ViolationLog
			var options []DecodeOption
			if tolerant {
				options = append(options, WithConstraintTolerance(&reports))
			}
			value, _, err := DecodeOctetString(wire, options...)
			if err != nil || len(value) == 2 {
				continue
			}
			err = CheckDecodedLength(options, "field", "SIZE (2)", len(value))
			if tolerant && (err != nil || len(reports.Snapshot()) != 1) {
				t.Fatalf("tolerant length check: error=%v reports=%+v", err, reports.Snapshot())
			}
			if !tolerant && err == nil {
				t.Fatal("strict length check admitted an out-of-range value")
			}
		}
	})
}
