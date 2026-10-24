// Code generated from the locked X2AP source closure. DO NOT EDIT.

package x2ap

import (
	reflect "reflect"
	testing "testing"
)

func TestASN1VectorPathRejectsNegativeIndex(t *testing.T) {
	if _, err := asn1VectorValueAtPath(reflect.ValueOf([]int{1}), "[-1]"); err == nil {
		t.Fatal("asn1VectorValueAtPath accepted a negative index")
	}
}
