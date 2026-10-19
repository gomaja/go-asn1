// Code generated from ASN.1. DO NOT EDIT.

package v21_map_sm_datatypes

import (
	"github.com/gomaja/go-asn1/telecom/ss7/gsm_map/runtime/ber"
)

// NewSMMWStatus constructs ASN.1 MAP-SM-DataTypes.MW-Status (X.680 (02/2021) §22.7; X.690 (02/2021) §8.6.2.4).
func NewSMMWStatus(set ...int) (SMMWStatus, error) {
	value, err := ber.NewNamedBitString([]ber.NamedBitSizeSet{{{Min: 6, Max: 16}}}, set...)
	return namedBitBuilderResult(value, err, "MAP-SM-DataTypes.MW-Status")
}
