// Code generated from LPPa runtime source. DO NOT EDIT.

// Runtime source: runtime/aper/terminal_padding_type.go; SHA-256 468265c559fe419cd451c43bbace200b0ba7902a6794e4deef58b655a9b83502.
package aper

import "reflect"

// A primitive table codec has no generated component scope. Under the explicit
// policy, use its named Go value type for the complete encoding's source path.
// X.691 (02/2021) §§11.1.4, 11.2.1.
func capturePrimitivePadding[T any](bb *BitBuffer) (CompletePadding, error) {
	path := "open type"
	if bb.budget != nil && bb.budget.nonzeroTerminalPadding {
		if name := reflect.TypeFor[T]().Name(); name != "" {
			path = name
		}
	}
	return captureNamedPadding(bb, "open type", path)
}
