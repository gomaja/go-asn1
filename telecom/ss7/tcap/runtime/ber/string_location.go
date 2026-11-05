// Code generated from ASN.1 module "TCAPMessages". DO NOT EDIT.

// Runtime source: runtime/ber/string_location.go; SHA-256 52cd75a2308b824d8823771fea03c535f8361fc5d78720bb8b8757224e2da488.
package ber

import (
	"fmt"
)

// A structural scan knows the physical identifier before a generated decoder
// supplies its field name. Preserve that original position across both passes.
func scannedUTF8Location(data []byte, offset int, stack []berScanFrame, index int, config decodeConfig, options []DecodeOption, recordOrigin ...stringReportOrigin) (Violation, error) {
	v := Violation{Path: qualifyConstraintPath(options, "")}
	if !config.tolerant {
		return v, nil
	}
	var relative []int
	if len(stack) > 1 {
		for _, ancestor := range stack[2:] {
			relative = append(relative, ancestor.index)
		}
		relative = append(relative, index)
	}
	v.ChildIndexes = relative
	if config.location != nil {
		// Root slices and reconstructed IMPLICIT child buffers map through
		// their decode location to the received identifier.
		absolute, ok := config.location.wireOffset(data[offset:])
		if !ok {
			return Violation{}, ErrInvalidLength
		}
		offset = absolute
		// String records retain only the physical offset and local path;
		// their reporting step discards ancestry metadata.
	}
	if len(recordOrigin) != 0 && config.location == nil {
		origin := recordOrigin[0]
		absolute, ok := berSubsliceOffset(origin.input, data[offset:])
		if !ok {
			return Violation{}, ErrInvalidLength
		}
		offset = absolute
		relative = append([]int{externalChoiceIndex(origin.external), 0}, relative...)
		v.ChildIndexes = relative
	}
	v.Offset = new(offset)
	for _, child := range relative {
		v.Path = joinUTF8Path(v.Path, fmt.Sprintf("child[%d]", child))
	}
	return v, nil
}

func joinUTF8Path(prefix, leaf string) string {
	if prefix == "" {
		return leaf
	}
	if leaf == "" {
		return prefix
	}
	return prefix + "." + leaf
}
