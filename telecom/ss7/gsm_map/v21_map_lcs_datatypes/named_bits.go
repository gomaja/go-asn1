// Code generated from ASN.1. DO NOT EDIT.

package v21_map_lcs_datatypes

import (
	"github.com/gomaja/go-asn1/telecom/ss7/gsm_map/runtime/ber"
)

// NewLCSDeferredLocationEventType constructs ASN.1 MAP-LCS-DataTypes.DeferredLocationEventType (X.680 (02/2021) §22.7; X.690 (02/2021) §8.6.2.4).
func NewLCSDeferredLocationEventType(set ...int) (LCSDeferredLocationEventType, error) {
	value, err := ber.NewNamedBitString([]ber.NamedBitSizeSet{{{Min: 1, Max: 16}}}, set...)
	return namedBitBuilderResult(value, err, "MAP-LCS-DataTypes.DeferredLocationEventType")
}

// NewLCSSupportedGADShapes constructs ASN.1 MAP-LCS-DataTypes.SupportedGADShapes (X.680 (02/2021) §22.7; X.690 (02/2021) §8.6.2.4).
func NewLCSSupportedGADShapes(set ...int) (LCSSupportedGADShapes, error) {
	value, err := ber.NewNamedBitString([]ber.NamedBitSizeSet{{{Min: 7, Max: 16}}}, set...)
	return namedBitBuilderResult(value, err, "MAP-LCS-DataTypes.SupportedGADShapes")
}
