// Code generated from X2AP runtime source. DO NOT EDIT.

// Runtime source: runtime/aper/integer_contents.go; SHA-256 8f07d0949e71f01add68b42af3ebc3d1813d0e33fc0a22d74eefe4f93deb80f2.
package aper

import "fmt"

// decodeIntegerContentsAligned reads all INTEGER contents before a carrier
// decision. X.691 (02/2021) §§11.7.4, 11.8.3 and 11.9.3.8 permit interleaved
// fragments. The common fragment reader checks their wire rules; ReadBytes
// checks remaining input and charges work and storage before allocation.
// Keep the first fragment directly so ordinary integers need no extra copy.
func decodeIntegerContentsAligned(bb *BitBuffer) ([]byte, error) {
	var data []byte
	_, err := DecodeLengthFragments(bb, true, func(offset, length int64) error {
		if length < 0 || length > int64(bb.BitsRemaining()/8) {
			return fmt.Errorf("%w: INTEGER requires %d octets with %d bits remaining", ErrTruncated, length, bb.BitsRemaining())
		}
		fragment, err := bb.ReadBytes(int(length))
		if err != nil {
			return err
		}
		if offset == 0 {
			data = fragment
			return nil
		}
		data, err = AppendValues(bb, data, fragment...)
		return err
	})
	return data, err
}
