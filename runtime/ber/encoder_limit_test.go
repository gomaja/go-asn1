package ber

import (
	"errors"
	"math"
	"testing"

	"github.com/gomaja/go-asn1/runtime/tag"
)

func TestBERWorkBudgetRejectsHostBoundBeforeIncrement(t *testing.T) {
	budget := berWorkBudget{elements: math.MaxInt, limits: DecodeLimits{MaxElements: math.MaxInt, MaxWork: math.MaxInt}}
	if err := budget.charge(0); !errors.Is(err, ErrResourceLimit) {
		t.Fatalf("charge after host limit = %v, want ErrResourceLimit", err)
	}
	if budget.elements != math.MaxInt {
		t.Fatalf("rejected charge changed element count to %d", budget.elements)
	}
}

func TestBERWorkBudgetRejectsConfiguredBoundBeforeIncrement(t *testing.T) {
	budget := berWorkBudget{elements: 2, limits: DecodeLimits{MaxElements: 2, MaxWork: 4}}
	if err := budget.charge(0); !errors.Is(err, ErrResourceLimit) {
		t.Fatalf("charge after configured limit = %v, want ErrResourceLimit", err)
	}
	if budget.elements != 2 {
		t.Fatalf("rejected charge changed element count to %d", budget.elements)
	}
}

func TestBEREncodeTLVRejectsCapacityBeforeAllocation(t *testing.T) {
	if _, err := encodeTLVWithLimit(tag.Tag{Class: tag.ClassUniversal, Number: tag.TagOctetString}, []byte{1}, 2); !errors.Is(err, ErrInvalidValue) {
		t.Fatalf("capacity error = %v, want ErrInvalidValue", err)
	}
	if got, err := encodeTLVWithLimit(tag.Tag{Class: tag.ClassUniversal, Number: tag.TagOctetString}, []byte{1}, 3); err != nil || string(got) != "\x04\x01\x01" {
		t.Fatalf("exact capacity = %x, %v", got, err)
	}
}

func TestBEREncodeCapacityRejectsHostOverflow(t *testing.T) {
	if _, err := checkedBERCapacity(math.MaxInt, math.MaxInt, 1); !errors.Is(err, ErrInvalidValue) {
		t.Fatalf("host overflow error = %v, want ErrInvalidValue", err)
	}
	if got, err := checkedBERCapacity(math.MaxInt, math.MaxInt-1, 1); err != nil || got != math.MaxInt {
		t.Fatalf("exact host capacity = %d, %v", got, err)
	}
}

func TestBERConstructedIndefiniteRejectsCapacityBeforeAllocation(t *testing.T) {
	tagValue := tag.Tag{Class: tag.ClassUniversal, Number: tag.TagSequence}
	if _, err := encodeConstructedIndefiniteWithLimit(tagValue, []byte{1}, 4); !errors.Is(err, ErrInvalidValue) {
		t.Fatalf("capacity error = %v, want ErrInvalidValue", err)
	}
	if got, err := encodeConstructedIndefiniteWithLimit(tagValue, []byte{1}, 5); err != nil || string(got) != "\x30\x80\x01\x00\x00" {
		t.Fatalf("exact capacity = %x, %v", got, err)
	}
}

func TestBERBitStringValueRejectsCapacityBeforeAllocation(t *testing.T) {
	if _, err := encodeBitStringValueWithLimit([]byte{0x80}, 7, 1); !errors.Is(err, ErrInvalidValue) {
		t.Fatalf("capacity error = %v, want ErrInvalidValue", err)
	}
	if got, err := encodeBitStringValueWithLimit([]byte{0x80}, 7, 2); err != nil || string(got) != "\x07\x80" {
		t.Fatalf("exact capacity = %x, %v", got, err)
	}
}

func TestBERBitStringTLVRejectsCapacityBeforeAllocation(t *testing.T) {
	if _, err := encodeBitStringWithLimit([]byte{0x80}, 7, 3); !errors.Is(err, ErrInvalidValue) {
		t.Fatalf("capacity error = %v, want ErrInvalidValue", err)
	}
	if got, err := encodeBitStringWithLimit([]byte{0x80}, 7, 4); err != nil || string(got) != "\x03\x02\x07\x80" {
		t.Fatalf("exact capacity = %x, %v", got, err)
	}
}
