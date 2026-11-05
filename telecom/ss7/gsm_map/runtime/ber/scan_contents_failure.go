// Code generated from MAP runtime source. DO NOT EDIT.

// Runtime source: runtime/ber/scan_contents_failure.go; SHA-256 4de7d837507d7db5ab2295fdd36589c2752b53d81993303a2b272d211a7e95d9.
package ber

// X.690 (02/2021) §§8.1.1–8.1.5: keep scanning the complete structure
// after a newly enforced string-contents finding. Existing framing failures
// retain precedence; a structurally complete value returns its first finding.
func scanContentsFailure(data []byte, offset int, stack []berScanFrame, index int, config decodeConfig, options []DecodeOption, cause error) *ElementError {
	var indexes []int
	if len(stack) > 1 {
		for _, ancestor := range stack[2:] {
			indexes = append(indexes, ancestor.index)
		}
		indexes = append(indexes, index)
	}
	if config.location != nil {
		if absolute, ok := config.location.wireOffset(data[offset:]); ok {
			offset = absolute
			indexes, _ = config.location.decodeOrigin().ancestry(absolute)
		} else {
			base := config.location.receivedOffset()
			if found, ok := config.location.decodeOrigin().mark(qualifyConstraintPath(options, "")); ok {
				base = found
			}
			if offset <= len(config.location.rootInput())-base {
				offset += base
				indexes, _ = config.location.decodeOrigin().ancestry(offset)
			}
		}
	}
	return &ElementError{offset: offset, childIndexes: indexes, cause: cause}
}
