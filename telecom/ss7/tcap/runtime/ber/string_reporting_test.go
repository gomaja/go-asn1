// Code generated from ASN.1 module "TCAPMessages". DO NOT EDIT.

// Runtime source: runtime/ber/string_reporting_test.go; SHA-256 c8d92d6076efaf63f9ae40e3726aca81806b96dd82f7d69230b9d28c9abfa10f.
package ber

import (
	"errors"
	"fmt"
	"reflect"
	"testing"
)

// X.690 (02/2021) §§8.1.1–8.1.5, 8.23.4–8.23.5: a deferred
// contents error and a later framing error retain their own identifier.
func TestStringContentsFailureLocations(t *testing.T) {
	for _, row := range []struct {
		wire    string
		offset  int
		indexes []int
		cause   error
		text    string
	}{
		{"300805003004120241ff", 6, []int{1, 0}, ErrInvalidValue, "ber: invalid value encoding: NumericString digits and space (X.680 (02/2021) §41.2 Table 9; X.690 (02/2021) §8.23.4)"},
		{"300a05003006120241ff0201", 10, []int{1, 1}, ErrTruncated, ErrTruncated.Error()},
	} {
		t.Run(row.wire, func(t *testing.T) {
			err := ValidateBERElement(structureWire(t, row.wire))
			var located *ElementError
			if !errors.As(err, &located) || !errors.Is(err, row.cause) || err.Error() != row.text {
				t.Fatalf("error %T %v", err, err)
			}
			if located.Offset() != row.offset || !reflect.DeepEqual(located.ChildIndexes(), row.indexes) {
				t.Fatalf("location %d %v", located.Offset(), located.ChildIndexes())
			}
		})
	}
}

// X.690 (02/2021) §§8.18.1, 8.23.3–8.23.5, 8.23.10; X.680
// (02/2021) §41 Tables 8–10: records identify the enclosing string,
// while OctetOffset counts its concatenated contents across segments.
func TestStringToleranceRecordLocations(t *testing.T) {
	for _, number := range []byte{12, 18, 19, 22, 26} {
		for _, bad := range []int{1, 2} {
			contents := []byte{'1', 255}
			if bad == 2 {
				contents = append(contents, 255)
			}
			primitive := append([]byte{number, byte(len(contents))}, contents...)
			segments := append([]byte{4, 1, '1', 0x24, byte(bad + 2), 4, byte(bad)}, contents[1:]...)
			definite := append([]byte{number | 0x20, byte(len(segments))}, segments...)
			indefinite := append([]byte{number | 0x20, 0x80}, segments...)
			indefinite = append(indefinite, 0, 0)
			for _, shape := range []struct {
				name string
				wire []byte
			}{{"primitive", primitive}, {"nested segments", definite}, {"indefinite", indefinite}} {
				externalValue := append([]byte{6, 3, 42, 3, 4, 0xa0, byte(len(shape.wire))}, shape.wire...)
				external := append([]byte{0x28, byte(len(externalValue))}, externalValue...)
				for _, row := range []struct {
					name    string
					wire    []byte
					offset  int
					indexes []int
					entry   int
				}{
					{"root", shape.wire, 0, nil, 0},
					{"sequence", append([]byte{0x30, byte(len(shape.wire))}, shape.wire...), 2, []int{0}, 0},
					{"two strings", append(append([]byte{0x30, byte(len(shape.wire) * 2)}, shape.wire...), shape.wire...), 2, []int{0}, 0},
					{"external", external, 9, []int{1, 0}, 1},
					{"external value", externalValue, 7, []int{1, 0}, 2},
					{"external in sequence", append([]byte{0x30, byte(len(external))}, external...), 11, []int{0, 1, 0}, 0},
				} {
					t.Run(fmt.Sprintf("tag%d/bad%d/%s/%s", number, bad, shape.name, row.name), func(t *testing.T) {
						var log ViolationLog
						options := []DecodeOption{WithTolerance(&log)}
						var err error
						switch row.entry {
						case 0:
							err = ValidateBERElement(row.wire, options...)
						case 1:
							_, _, err = DecodeExternal(row.wire, options...)
						case 2:
							_, err = DecodeExternalValue(row.wire, options...)
						}
						if err != nil {
							t.Fatal(err)
						}
						records := log.Snapshot()
						count := bad
						if row.name == "two strings" {
							count *= 2
						}
						if len(records) != count {
							t.Fatalf("records %d want %d", len(records), count)
						}
						for i, record := range records {
							offset, indexes := row.offset, row.indexes
							if row.name == "two strings" && i >= bad {
								offset += len(shape.wire)
								indexes = []int{1}
							}
							path := ""
							for _, index := range indexes {
								if path != "" {
									path += "."
								}
								path += fmt.Sprintf("child[%d]", index)
							}
							if record.Offset == nil || *record.Offset != offset || record.Path != path || record.ChildIndexes != nil || record.Source != "" || record.OctetOffset == nil || *record.OctetOffset != i%bad+1 || record.ObservedValue != "ff" {
								t.Fatalf("record %d: %+v; want offset=%d path=%q indexes=%v octet=%d", i, record, offset, path, indexes, i%bad+1)
							}
						}
					})
				}
			}
		}
	}
}

// Identical bad octets occupy distinct report-budget positions, including
// when preflight records have the same physical string identifier.
func TestStringRecordBudgetCountsEveryOctet(t *testing.T) {
	for _, number := range []byte{12, 18, 19, 22, 26} {
		var log ViolationLog
		options, finish := StageDecodeReports([]DecodeOption{WithTolerance(&log), WithDiagnosticLimits(DiagnosticLimits{MaxRecords: 1})})
		err := ValidateBERElement([]byte{number, 2, 255, 255}, options...)
		finish(err == nil)
		if !errors.Is(err, ErrResourceLimit) || len(log.Snapshot()) != 0 {
			t.Fatalf("tag %d: error %v records %d", number, err, len(log.Snapshot()))
		}
	}
}

func TestStringToleranceIssueRecords(t *testing.T) {
	for _, row := range []struct {
		wire, path    string
		offset, entry int
	}{
		{"0c01ff", "", 0, 0},
		{"30030c01ff", "child[0]", 2, 0},
		{"30031601ff", "child[0]", 2, 0},
		{"06032a0304a0031601ff", "child[1].child[0]", 7, 1},
	} {
		t.Run(row.wire, func(t *testing.T) {
			var log ViolationLog
			var err error
			if row.entry == 0 {
				err = ValidateBERElement(structureWire(t, row.wire), WithTolerance(&log))
			} else {
				_, err = DecodeExternalValue(structureWire(t, row.wire), WithTolerance(&log))
			}
			if err != nil {
				t.Fatal(err)
			}
			records := log.Snapshot()
			if len(records) != 1 || records[0].Offset == nil || *records[0].Offset != row.offset || records[0].Path != row.path || records[0].OctetOffset == nil || *records[0].OctetOffset != 0 {
				t.Fatalf("records: %+v", records)
			}
		})
	}
}
