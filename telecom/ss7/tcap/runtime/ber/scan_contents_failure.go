// Code generated from ASN.1 module "TCAPMessages". DO NOT EDIT.

// Runtime source: runtime/ber/scan_contents_failure.go; SHA-256 a0757fee88e42a2e994ae72a46e831a0faa3b70998681d05771c6bb4afde9687.
package ber

import (
	"strings"
)

// X.690 (02/2021) §§8.1.1–8.1.5: keep scanning the complete structure
// after a newly enforced string-contents finding. Existing framing failures
// retain precedence; a structurally complete value returns its first finding.
func scanContentsFailure(data []byte, offset int, stack []berScanFrame, index int, config decodeConfig, options []DecodeOption, cause error) *ElementError {
	path := ""
	root := tcapRootKind(config.profileType)
	if root != tcapKindUnknown && root != tcapKindUnclassified && config.profile && !config.profileNested && offset >= 0 && offset < len(data) && len(stack) > 0 {
		identifier, _, err := DecodeTag(data[offset:])
		if err == nil {
			var parent berScanFrame
			for _, frame := range stack {
				parent = frame
			}
			kind := tcapElementType(tcapRootKind(config.profileType), parent.profileType, identifier, index, len(stack) == 1, parent.dialogueSyntax)
			if len(stack) > 1 {
				if child, _, sequence := tcapSequenceElementType(parent.profileType, identifier, parent.profileField, parent.dialogueSyntax); sequence {
					kind = child
				}
			}
			path = tcapElementPath(data, stack, kind, identifier, index, config, options)
			if config.location != nil && config.location.segments() != nil && config.location.segments().path != "" {
				path = strings.Join([]string{config.location.segments().path, path}, ".")
			}
		}
	}
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
	return &ElementError{offset: offset, childIndexes: indexes, cause: cause, path: path}
}
