package ber

import (
	"fmt"

	"github.com/gomaja/go-asn1/runtime/tag"
)

// ValidateBERElement checks one complete BER TLV with a single linear scan.
// X.690 (02/2021) §§8.1.3 and 8.7 permit indefinite constructed values;
// the limits are operational safeguards, not restrictions in X.690.
func ValidateBERElement(data []byte, options ...DecodeOption) error {
	limits, err := decodeLimits(options)
	if err != nil {
		return err
	}
	if len(data) == 0 {
		return ErrTruncated
	}
	if len(data) > limits.MaxWork {
		return fmt.Errorf("%w: BER total-work limit exceeded", ErrInvalidValue)
	}
	type frame struct {
		end        int
		indefinite bool
	}
	stack := []frame{{end: len(data)}}
	pos, elements := 0, 0
	for len(stack) != 0 {
		parent := stack[len(stack)-1]
		if pos == parent.end {
			if parent.indefinite {
				return ErrTruncated
			}
			stack = stack[:len(stack)-1]
			continue
		}
		if pos > parent.end {
			return ErrInvalidLength
		}
		if len(stack) == 1 && elements > 0 {
			return ErrExtraData
		}
		if parent.indefinite && pos+2 <= parent.end && data[pos] == 0 && data[pos+1] == 0 {
			pos += 2
			stack = stack[:len(stack)-1]
			continue
		}
		t, tagLen, err := DecodeTag(data[pos:parent.end])
		if err != nil {
			return err
		}
		length, indefinite, lenLen, err := DecodeLength(data[pos+tagLen : parent.end])
		if err != nil {
			return err
		}
		if t.Class == tag.ClassUniversal && t.Number == 0 {
			return fmt.Errorf("%w: standalone BER end-of-contents", ErrInvalidTag)
		}
		elements++
		if elements > limits.MaxElements {
			return fmt.Errorf("%w: BER element limit exceeded", ErrInvalidValue)
		}
		start := pos + tagLen + lenLen
		if indefinite {
			if !t.Constructed {
				return ErrIndefiniteLength
			}
			if len(stack) > limits.MaxDepth {
				return fmt.Errorf("%w: BER nesting depth exceeded", ErrInvalidValue)
			}
			stack = append(stack, frame{end: parent.end, indefinite: true})
			pos = start
			continue
		}
		end := start + length
		if end < start || end > parent.end {
			return ErrTruncated
		}
		if t.Constructed {
			if len(stack) > limits.MaxDepth {
				return fmt.Errorf("%w: BER nesting depth exceeded", ErrInvalidValue)
			}
			stack = append(stack, frame{end: end})
			pos = start
		} else {
			pos = end
		}
	}
	if pos != len(data) {
		return ErrExtraData
	}
	return nil
}
