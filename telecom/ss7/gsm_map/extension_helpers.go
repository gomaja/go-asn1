package gsm_map

import (
	"fmt"

	"github.com/gomaja/go-asn1/runtime/ber"
)

func captureRawExtensions(content []byte, offset int, typeName string) ([][]byte, []bool, int64, error) {
	var extData [][]byte
	var extPresent []bool
	for offset < len(content) {
		_, n, _, err := ber.DecodeTLV(content[offset:])
		if err != nil {
			return nil, nil, 0, &ber.DecodeError{Offset: offset, TypeName: typeName, Cause: err}
		}
		extData = append(extData, append([]byte(nil), content[offset:offset+n]...))
		extPresent = append(extPresent, true)
		offset += n
	}
	return extData, extPresent, int64(len(extData)), nil
}

func validateDERRawExtensions(exts [][]byte) error {
	for i, ext := range exts {
		n, err := validateDERTLV(ext)
		if err != nil {
			return fmt.Errorf("encoding extension %d: %w", i, err)
		}
		if n != len(ext) {
			return fmt.Errorf("encoding extension %d: %w", i, ber.ErrExtraData)
		}
	}
	return nil
}

func validateDERTLV(data []byte) (int, error) {
	t, tagLen, err := ber.DecodeTag(data)
	if err != nil {
		return 0, err
	}
	length, indefinite, lenLen, err := ber.DecodeLength(data[tagLen:])
	if err != nil {
		return 0, err
	}
	if indefinite {
		return 0, ber.ErrIndefiniteLength
	}

	headerLen := tagLen + lenLen
	end := headerLen + length
	if end > len(data) {
		return 0, ber.ErrTruncated
	}
	if t.Constructed {
		offset := headerLen
		for offset < end {
			n, err := validateDERTLV(data[offset:end])
			if err != nil {
				return 0, err
			}
			offset += n
		}
	}
	return end, nil
}
