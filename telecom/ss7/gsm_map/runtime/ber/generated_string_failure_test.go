// Code generated from MAP runtime source. DO NOT EDIT.

// Runtime source: runtime/ber/generated_string_failure_test.go; SHA-256 002166318ea14da02a2a897d661504e38b2dd46e4c63954d61185438624a9f2a.
package ber

import (
	"errors"
	"reflect"
	"testing"
)

// A real decode has already scanned these segments. Craft an inconsistent
// pending candidate to exercise the defensive failure's diagnostic location.
func TestGeneratedStringSegmentFailureLocation(t *testing.T) {
	for _, path := range []string{"", "extensions.element[1].open"} {
		config, err := decodeOptions(nil)
		if err != nil {
			t.Fatal(err)
		}
		config.form = &berFormState{mapPending: &mapProfileState{contents: &deferredStringState{
			offsets: []int{23}, byOffset: map[int]*deferredStringContents{23: {
				data: []byte{0x36, 3, 4, 2, 'x'}, number: 22,
				position: Violation{Path: path, Offset: new(23), ChildIndexes: []int{1, 2}},
			}},
		}}}
		err = finishGeneratedStringContents(config)
		var located *ElementError
		if !errors.Is(err, ErrTruncated) || !errors.As(err, &located) {
			t.Fatalf("unlocated failure: %T %v", err, err)
		}
		if located.Offset() != 23 || !reflect.DeepEqual(located.ChildIndexes(), []int{1, 2}) {
			t.Fatalf("location %d %v", located.Offset(), located.ChildIndexes())
		}
		var named *preflightPathError
		if path != "" {
			if !errors.As(err, &named) || named.path != path {
				t.Fatalf("path: %v", err)
			}
		} else if errors.As(err, &named) {
			t.Fatalf("unexpected path: %v", err)
		}
	}
}
