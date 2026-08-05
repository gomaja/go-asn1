package sgp22

import (
	"fmt"

	"github.com/gomaja/go-asn1/runtime/ber"
	"github.com/gomaja/go-asn1/runtime/tag"
)

func encodeTaggedResponseChoice(tagNumber int, inner []byte) []byte {
	return ber.EncodeConstructed(tag.Tag{
		Class:       tag.ClassContextSpecific,
		Number:      tagNumber,
		Constructed: true,
	}, inner)
}

func decodeTaggedResponseChoice(typeName string, tagNumber int, data []byte) ([]byte, error) {
	decodedTag, content, total, err := ber.DecodeConstructedContent(data)
	if err != nil {
		return nil, fmt.Errorf("decoding %s CHOICE: %w", typeName, err)
	}
	if decodedTag.Class != tag.ClassContextSpecific || decodedTag.Number != tagNumber || !decodedTag.Constructed {
		return nil, fmt.Errorf("decoding %s CHOICE: %w: expected tag [CONTEXT %d], got %s", typeName, ber.ErrInvalidTag, tagNumber, decodedTag)
	}
	if total != len(data) {
		return nil, &ber.DecodeError{Offset: total, TypeName: typeName, Cause: ber.ErrExtraData}
	}
	if len(content) == 0 {
		return nil, fmt.Errorf("empty content for %s CHOICE", typeName)
	}
	return content, nil
}
