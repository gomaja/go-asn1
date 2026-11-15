// Code generated from ASN.1 module "TCAPMessages". DO NOT EDIT.

// Runtime source: runtime/ber/choice_alternative_tags_test.go; SHA-256 53a83e8ec006304cb09c4dc18e5090f44ae66d5a0d8d66c873b1153456c9e12e.
package ber

import (
	"fmt"
	"github.com/gomaja/go-asn1/telecom/ss7/tcap/runtime/tag"
	"testing"
)

// X.880 (07/1994) Annex A and Q.773 (06/1997) Annex A select
// CHOICE alternatives by class and number, including malformed values.
func TestTCAPChoiceAlternativeTags(t *testing.T) {
	for _, row := range []struct {
		parent tcapKind
		number int
		class  tag.Class
		suffix string
	}{
		{tcapKindComponentPortion, 1, tag.ClassContextSpecific, "element[1].basicROS.invoke"},
		{tcapKindComponentPortion, 2, tag.ClassContextSpecific, "element[1].basicROS.returnResult"},
		{tcapKindComponentPortion, 3, tag.ClassContextSpecific, "element[1].basicROS.returnError"},
		{tcapKindComponentPortion, 4, tag.ClassContextSpecific, "element[1].basicROS.reject"},
		{tcapKindComponentPortion, 7, tag.ClassContextSpecific, "element[1].returnResultNotLast"},
		{tcapKindUniDialogueContent, 0, tag.ClassApplication, "unidialoguePDU"},
	} {
		for _, class := range []tag.Class{tag.ClassUniversal, tag.ClassApplication, tag.ClassContextSpecific, tag.ClassPrivate} {
			for _, number := range []int{row.number, 9} {
				t.Run(fmt.Sprintf("%d/%d/%d/%d", row.parent, row.number, class, number), func(t *testing.T) {
					identifier := tag.Tag{Class: class, Number: number, Constructed: true}
					index := 1
					if row.parent == tcapKindUniDialogueContent {
						index = 0
					}
					kind := tcapElementType(tcapKindUnknown, row.parent, identifier, index, false, 0)
					want := "child[0]"
					if row.parent == tcapKindComponentPortion {
						want = "element[1]"
					}
					if class == row.class && number == row.number {
						want = row.suffix
					}
					if got := tcapPathSegment("", row.parent, kind, identifier, index, false, 0); got != want {
						t.Fatalf("path=%s, want %s", got, want)
					}
				})
			}
		}
	}
	for _, parent := range []tcapKind{tcapKindInvoke, tcapKindReturnResult, tcapKindReturnError, tcapKindReject} {
		for _, class := range []tag.Class{tag.ClassUniversal, tag.ClassApplication, tag.ClassContextSpecific, tag.ClassPrivate} {
			for _, number := range []int{2, 5, 9} {
				t.Run(fmt.Sprintf("invokeId/%d/%d/%d", parent, class, number), func(t *testing.T) {
					identifier := tag.Tag{Class: class, Number: number}
					kind := tcapElementType(tcapKindUnknown, parent, identifier, 0, false, 0)
					want := "invokeId"
					if class == tag.ClassUniversal {
						if number == 2 {
							want += ".present"
						}
						if number == 5 {
							want += ".absent"
						}
					}
					if got := tcapPathSegment("", parent, kind, identifier, 0, false, 0); got != want {
						t.Fatalf("path=%s, want %s", got, want)
					}
				})
			}
		}
	}
}
