// Code generated from MAP runtime source. DO NOT EDIT.

// Runtime source: runtime/ber/restricted_scan.go; SHA-256 e845fa03d01ca4f76f11673010b8d4454c2343697fa7886be99d7550ce86d184.
package ber

// Keep the X.690 (02/2021) §§8.23–8.25 accumulator and diagnostic dispatch
// outside the structural scan's common path. Only a checked restricted string
// calls these helpers; its logical value still uses the same structural pass.
type restrictedScanState struct {
	value         restrictedStringState
	depth, octets int
	source        *byte
}

func (s *restrictedScanState) finish(data []byte, offset int, stack []berScanFrame, index int, config decodeConfig, options []DecodeOption) (error, bool) {
	if err := s.value.finish(); err != nil {
		if config.generatedContents || config.form != nil && (config.form.lightInput != nil || config.form.validated != nil) {
			if err := deferGeneratedStringContents(data, offset, stack, index, s.value.number, config, options); err != nil {
				return err, true
			}
		} else {
			s.depth = 0
			return err, false
		}
	}
	s.depth = 0
	return nil, false
}

func (s *restrictedScanState) consumePrimitive(data []byte, offset, start, end int, stack []berScanFrame, index int, config decodeConfig, options []DecodeOption, report bool, number int) (finding error, fatal bool) {
	source, logicalOffset := (*byte)(nil), 0
	if start < end {
		source = &data[start]
	}
	if s.depth != 0 {
		number, source, logicalOffset = s.value.number, s.source, s.octets
	}
	if isAlphabetString(number) {
		// Unlike UTF8String, generated restricted alphabets are checked only
		// in opaque intervals. A reconstructed IMPLICIT buffer must therefore
		// retain findings; scannedUTF8Location maps its identifier through
		// decodeLocation.wireOffset to the received value (X.690 (02/2021)
		// §§8.14, 8.23.3–8.23.5). The root scan already owns UTF8String reports.
		if (report || config.generatedContents) && !validAlphabetContents(number, data[start:end]) {
			rootOffset, rootIndex, rootStack := offset, index, stack
			if s.depth != 0 {
				root := stack[s.depth-1]
				rootOffset, rootIndex, rootStack = root.offset, root.index, stack[:s.depth-1]
			}
			if config.generatedContents || config.form != nil && (config.form.lightInput != nil || config.form.validated != nil) {
				if err := deferGeneratedStringContents(data, rootOffset, rootStack, rootIndex, number, config, options); err != nil {
					return err, true
				}
			} else {
				position, err := scannedUTF8Location(data, rootOffset, rootStack, rootIndex, config, options)
				if err != nil {
					return err, true
				}
				if err := checkAlphabetString(number, data[start:end], source, logicalOffset, config, options, true, &position); err != nil {
					if config.tolerant {
						return err, true
					}
					finding = err
				}
			}
		}
	} else if s.depth != 0 {
		s.value.consume(data[start:end])
	} else if err := validateRestrictedStringContents(number, data[start:end]); err != nil {
		if config.generatedContents || config.form != nil && (config.form.lightInput != nil || config.form.validated != nil) {
			if err := deferGeneratedStringContents(data, offset, stack, index, number, config, options); err != nil {
				return err, true
			}
		} else {
			finding = err
		}
	}
	if s.depth != 0 {
		s.octets += end - start
	}
	return finding, false
}
